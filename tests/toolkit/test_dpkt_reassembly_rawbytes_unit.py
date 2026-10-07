"""The DPKT adapters hand on the wire octets, and leave the packet alone.

GitHub issue #1297. :mod:`pcapkit.toolkit.dpkt` built the header and payload of
every reassembly and flow-tracing record by calling ``.pack()`` on the DPKT
layer. DPKT recomputes a zeroed checksum or length while packing *and writes it
back into the packet*, so the records no longer matched the capture, and the
first adapter to run changed what every later one saw. The adapters now slice the
record octets that :class:`~pcapkit.foundation.engines.dpkt.DPKT` attaches to the
frame.

Slicing needs the layer's offset in those octets, and that cannot be read off
``len()``: :meth:`dpkt.ip6.IP6.__len__` sums ``len()`` of the extension headers
rather than their wire lengths, which is 12 octets plus the rest of the frame for
an Authentication header and 8 octets short for a Routing header whose Hdr Ext
Len is odd. :class:`~dpkt.ip6.IP6ExtensionHeader` records the wire length in
``length``, which is what :meth:`dpkt.ip6.IP6.unpack` walks the buffer by, so
that is what the offset is built from -- and the slice is then checked against
the layer's own header before it is handed back.

Every frame below is written to a PCAP file and read back through the engine, so
the tests exercise the path a capture actually takes rather than a packet with a
buffer bolted on by hand. :class:`DPKTUnbufferedFallbackTests` is the exception,
and says why.

"""
from __future__ import annotations

import importlib.util
import os
import struct
import tempfile
import unittest
import warnings

from tests._support import close_extractor, reimport_once_per_class, sample_path

HAS_DPKT = importlib.util.find_spec('dpkt') is not None
RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: Ethernet header, destination then source then EtherType.
ETH_IPV4 = b'\xbb' * 6 + b'\xaa' * 6 + b'\x08\x00'
ETH_IPV6 = b'\xbb' * 6 + b'\xaa' * 6 + b'\x86\xdd'

#: IPv4 carrying SCTP, with a zero header checksum and a Total Length (0x38)
#: that DPKT's own serialisation would rewrite. The issue's own repro.
IPV4_SCTP = (bytes.fromhex('450000380000000040840000c0a80001c0a80002')
             + bytes.fromhex('c35000501122334400000000' '00030013')
             + b'\x41' * 15 + b'\x00' * 5)
#: IPv4 carrying TCP with a payload, both checksums zero -- the pair DPKT
#: recomputes together, in :meth:`dpkt.ip.IP.__bytes__`.
IPV4_TCP = (bytes.fromhex('4500002c00010000400600000a0000010a000002')
            + struct.pack('>HHIIBBHHH', 1234, 80, 10, 5, 5 << 4, 0x18, 1024, 0, 0)
            + b'data')
#: What ``IPV4_TCP`` comes back as once DPKT has re-serialised it: the IPv4
#: header checksum and the TCP checksum both filled in. Pinned so that the
#: unbuffered fallback is a measured value rather than an assumption.
IPV4_TCP_REPACKED = (bytes.fromhex('4500002c00010000400666c90a0000010a000002')
                     + struct.pack('>HHIIBBHHH', 1234, 80, 10, 5, 5 << 4, 0x18, 1024, 0xb9d2, 0)
                     + b'data')

#: TCP segment used by every extension-header frame below, checksum zero.
TCP_SEGMENT = struct.pack('>HHIIBBHHH', 1000, 2000, 1, 2, 5 << 4, 0x18, 100, 0, 0) + b'X' * 30
#: Fragment header (:rfc:`8200#section-4.5`) whose Next Header is TCP.
FRAG_HDR = struct.pack('>BBHI', 6, 0, 0x0001, 0x1234)


def ipv6(payload: 'bytes', nxt: 'int') -> 'bytes':
    """Build an IPv6 header over ``payload``, whose Next Header is ``nxt``."""
    return struct.pack('>IHBB16s16s', 0x60000000, len(payload), nxt, 64,
                       b'\x20\x01' + b'\x00' * 13 + b'\x01',
                       b'\x20\x01' + b'\x00' * 13 + b'\x02') + payload


def opts_hdr(nxt: 'int', ext_len: 'int' = 0) -> 'bytes':
    """Build a Hop-by-Hop or Destination Options header (:rfc:`8200#section-4.3`).

    ``ext_len`` is the Hdr Ext Len field, i.e. the length in 8-octet units not
    counting the first 8, so the header is ``(ext_len + 1) * 8`` octets. The body
    is one PadN option filling the rest.

    """
    body_len = (ext_len + 1) * 8 - 4
    return struct.pack('>BBBB', nxt, ext_len, 1, body_len) + b'\x00' * body_len


def routing_hdr(nxt: 'int', ext_len: 'int') -> 'bytes':
    """Build a Routing header (:rfc:`8200#section-4.4`) of ``ext_len`` 8-octet units.

    An *odd* ``ext_len`` is the case that matters: DPKT keeps whole 16-octet
    addresses, so ``len()`` of the parsed header comes out 8 octets short of the
    ``ext_len * 8 + 8`` the wire declares.

    """
    return struct.pack('>BBBBI', nxt, ext_len, 4, 1, 0) + b'\x01' * (ext_len * 8)


def ah_hdr(nxt: 'int', ext_len: 'int' = 4) -> 'bytes':
    """Build an Authentication header (:rfc:`4302#section-2`).

    ``ext_len`` is the Payload Length field: the header's length in 4-octet units
    minus two, so the header is ``(ext_len + 2) * 4`` octets. DPKT leaves
    :attr:`dpkt.dpkt.Packet.data` untrimmed here, so ``len()`` of the parsed
    header swallows everything that follows it in the frame.

    """
    return (struct.pack('>BBHII', nxt, ext_len, 0, 1, 2)
            + b'\xaa' * ((ext_len + 2) * 4 - 12))


#: ``(label, frame, wire IPv4/IPv6 datagram)`` for the plain cases.
FRAMES = (
    ('ipv4 sctp', ETH_IPV4 + IPV4_SCTP, IPV4_SCTP),
    ('ipv4 tcp', ETH_IPV4 + IPV4_TCP, IPV4_TCP),
    ('ipv6 frag udp', ETH_IPV6 + ipv6(
        struct.pack('>BBHI', 17, 0, 0x0001, 4321)
        + struct.pack('>HHHH', 53, 53, 12, 0) + b'udp!', 44), None),
    ('ipv6 tcp', ETH_IPV6 + ipv6(TCP_SEGMENT, 6), None),
)

#: ``(label, frame)`` for one TCP segment behind each extension header DPKT can
#: parse, including both the headers whose ``len()`` disagrees with the wire and
#: the ones whose does not, so a fix that broke the agreeing cases is visible.
EXT_HDR_FRAMES = (
    ('hop-by-hop', ETH_IPV6 + ipv6(opts_hdr(6) + TCP_SEGMENT, 0)),
    ('hop-by-hop len 1', ETH_IPV6 + ipv6(opts_hdr(6, 1) + TCP_SEGMENT, 0)),
    ('destination options', ETH_IPV6 + ipv6(opts_hdr(6) + TCP_SEGMENT, 60)),
    ('destination options twice',
     ETH_IPV6 + ipv6(opts_hdr(60) + opts_hdr(6) + TCP_SEGMENT, 60)),
    ('routing len 2', ETH_IPV6 + ipv6(routing_hdr(6, 2) + TCP_SEGMENT, 43)),
    ('routing len 3 (odd)', ETH_IPV6 + ipv6(routing_hdr(6, 3) + TCP_SEGMENT, 43)),
    ('routing len 4', ETH_IPV6 + ipv6(routing_hdr(6, 4) + TCP_SEGMENT, 43)),
    ('authentication', ETH_IPV6 + ipv6(ah_hdr(6) + TCP_SEGMENT, 51)),
    ('authentication len 5', ETH_IPV6 + ipv6(ah_hdr(6, 5) + TCP_SEGMENT, 51)),
    ('authentication len 7', ETH_IPV6 + ipv6(ah_hdr(6, 7) + TCP_SEGMENT, 51)),
    ('authentication then destination options',
     ETH_IPV6 + ipv6(ah_hdr(60) + opts_hdr(6) + TCP_SEGMENT, 51)),
    ('hop-by-hop then routing len 3',
     ETH_IPV6 + ipv6(opts_hdr(43) + routing_hdr(6, 3) + TCP_SEGMENT, 0)),
)

#: An IPv6 fragment sitting behind an Authentication header, and the length of
#: the headers that precede its Fragment header: 40 + 24.
AH_FRAG_FRAME = ETH_IPV6 + ipv6(ah_hdr(44) + FRAG_HDR + TCP_SEGMENT, 51)
AH_FRAG_IHL = 40 + 24


def write_pcap(frames: 'tuple[bytes, ...]') -> 'str':
    """Write ``frames`` to a temporary Ethernet PCAP file and return its path."""
    fd, path = tempfile.mkstemp(suffix='.pcap')
    with os.fdopen(fd, 'wb') as file:
        file.write(struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for index, frame in enumerate(frames):
            file.write(struct.pack('<IIII', 1_600_000_000 + index, 0, len(frame), len(frame)))
            file.write(frame)
    return path


@unittest.skipUnless(HAS_RUNTIME and HAS_DPKT, 'runtime dependencies not installed')
class DPKTReassemblyRawBytesTests(unittest.TestCase):
    """Records sliced from the wire, and no adapter mutating the frame."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _extract(self, path: 'str', engine: 'str' = 'dpkt'):
        import pcapkit

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            extractor = pcapkit.extract(fin=path, nofile=True, store=True, engine=engine)
        self.addCleanup(close_extractor, extractor)
        return extractor

    def _read_back(self, frames: 'tuple[bytes, ...]'):
        """Write ``frames`` to a capture and read them back through the engine."""
        path = write_pcap(frames)
        self.addCleanup(os.remove, path)
        read = self._extract(path).frame
        self.assertEqual(len(read), len(frames))
        return read

    def _frames(self):
        return self._read_back(tuple(frame for _, frame, _ in FRAMES))

    def test_ipv4_record_is_the_wire_datagram(self) -> None:
        from pcapkit.toolkit import dpkt as toolkit

        for frame, (label, _, wire) in zip(self._frames()[:2], FRAMES[:2]):
            with self.subTest(frame=label):
                data = toolkit.ipv4_reassembly(frame, 0.0)
                self.assertEqual(bytes(data.header), wire[:20])
                self.assertEqual(bytes(data.payload), wire[20:])
                # the zeroed checksums are the capture's, not ones DPKT computed
                self.assertEqual(frame.ip.sum, 0)
                self.assertEqual(frame.ip.data.sum, 0)

    def test_ipv6_record_is_the_wire_fragment(self) -> None:
        from pcapkit.toolkit import dpkt as toolkit

        wire = FRAMES[2][1][len(ETH_IPV6):]
        data = toolkit.ipv6_reassembly(self._frames()[2], 0.0)
        self.assertEqual(bytes(data.header), wire[:40])
        self.assertEqual(bytes(data.payload), wire[48:])

    def test_tcp_records_carry_the_wire_header(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit import dpkt as toolkit

        frames = self._frames()
        for index, segment in ((1, IPV4_TCP[20:]), (3, TCP_SEGMENT)):
            frame = frames[index]
            for data in (toolkit.tcp_reassembly(frame, 0.0),
                         toolkit.tcp_traceflow(frame, 0.0, data_link=LinkType.ETHERNET)):
                with self.subTest(record=type(data).__name__, frame=FRAMES[index][0]):
                    self.assertEqual(bytes(data.header), segment[:20])
                    self.assertEqual(bytes(data.payload), segment[20:])

    def test_tcp_header_is_found_behind_every_extension_header(self) -> None:
        """One TCP segment per extension header DPKT can parse.

        The Authentication header and the odd-length Routing header are the two
        whose ``len()`` disagrees with the wire; before the offset was taken from
        ``length`` the first returned an empty header and the second returned the
        Routing header's own trailing octets.

        """
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit import dpkt as toolkit

        frames = self._read_back(tuple(frame for _, frame in EXT_HDR_FRAMES))
        for frame, (label, _) in zip(frames, EXT_HDR_FRAMES):
            with self.subTest(ext_hdr=label):
                for data in (toolkit.tcp_reassembly(frame, 0.0),
                             toolkit.tcp_traceflow(frame, 0.0, data_link=LinkType.ETHERNET)):
                    self.assertEqual(bytes(data.header), TCP_SEGMENT[:20])
                    self.assertEqual(bytes(data.payload), TCP_SEGMENT[20:])

    def test_ipv6_fragment_behind_an_authentication_header(self) -> None:
        """``ipv6_hdr_len`` counted a fixed list of types and missed this one."""
        from pcapkit.toolkit import dpkt as toolkit

        frame = self._read_back((AH_FRAG_FRAME,))[0]
        wire = AH_FRAG_FRAME[len(ETH_IPV6):]

        self.assertEqual(toolkit.ipv6_hdr_len(frame.ip6), AH_FRAG_IHL)
        data = toolkit.ipv6_reassembly(frame, 0.0)
        self.assertEqual(data.ihl, AH_FRAG_IHL)
        self.assertEqual(bytes(data.header), wire[:AH_FRAG_IHL])
        self.assertEqual(bytes(data.payload), TCP_SEGMENT)

    def test_packet2dict_reports_the_captured_frame(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit import dpkt as toolkit

        for frame, (label, wire, _) in zip(self._frames(), FRAMES):
            with self.subTest(frame=label):
                info = toolkit.packet2dict(frame, 0.0, data_link=LinkType.ETHERNET)
                self.assertEqual(info['packet'], wire)

    def test_no_adapter_changes_what_the_next_one_sees(self) -> None:
        """Every adapter, run twice over each frame, leaves it as captured."""
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit import dpkt as toolkit

        for frame, (label, wire, _) in zip(self._frames(), FRAMES):
            for _ in range(2):
                for adapter in (toolkit.ipv4_reassembly, toolkit.ipv6_reassembly,
                                toolkit.tcp_reassembly):
                    adapter(frame, 0.0)
                toolkit.tcp_traceflow(frame, 0.0, data_link=LinkType.ETHERNET)
            with self.subTest(frame=label):
                # every frame here has its checksums zeroed on the wire, which is
                # exactly what DPKT's own serialisation would have filled in
                ip = frame.data
                self.assertEqual(getattr(ip, 'sum', 0), 0)
                self.assertEqual(getattr(ip.data, 'sum', 0), 0)
                # and the frame still reports the octets it was read from
                info = toolkit.packet2dict(frame, 0.0, data_link=LinkType.ETHERNET)
                self.assertEqual(info['packet'], wire)

    def test_options_transport_matches_the_default_engine(self) -> None:
        """Before the fix, 33 of this capture's IPv4 datagrams came back rewritten.

        The number of datagrams is counted here rather than pinned: the capture is
        generated by ``make samples``, and that is not currently reproducible --
        the same commit produces a 43-frame and a 44-frame file in different
        worktrees -- so any absolute count is flaky whichever value it picks.

        """
        from pcapkit.toolkit import dpkt as toolkit
        from pcapkit.toolkit import pcap as toolkit_pcap

        try:
            path = sample_path('options-transport.pcap')
        except FileNotFoundError as exc:
            self.skipTest(str(exc))

        frames = self._extract(path).frame
        defaults = self._extract(path, engine='default').frame
        self.assertEqual(len(frames), len(defaults))

        compared = 0
        for index, (frame, default) in enumerate(zip(frames, defaults), start=1):
            expected = toolkit_pcap.ipv4_reassembly(default)
            data = toolkit.ipv4_reassembly(frame, 0.0)
            self.assertEqual(data is None, expected is None, index)
            if data is None:
                continue
            compared += 1
            with self.subTest(frame=index):
                self.assertEqual(bytes(data.header), bytes(expected.header))
                self.assertEqual(bytes(data.payload), bytes(expected.payload))
                self.assertEqual(data.ihl, expected.ihl)
                self.assertEqual(data.tl, expected.tl)
        self.assertGreater(compared, 0, 'no IPv4 datagram was compared')


@unittest.skipUnless(HAS_RUNTIME and HAS_DPKT, 'runtime dependencies not installed')
class DPKTUnbufferedFallbackTests(unittest.TestCase):
    """What the adapters return for a packet that never came through the engine.

    A packet built by hand carries no record octets, so there is nothing to slice
    and the adapters fall back to DPKT's re-serialisation. That fallback differs
    from the wire -- which is the whole of #1297 -- so what it returns is pinned
    here rather than left to be discovered. Unlike the class above, these tests
    name :func:`~pcapkit.toolkit.dpkt.attach_buffer` and
    :func:`~pcapkit.toolkit.dpkt.packet2bytes` directly, so they are a test of
    that API rather than of the adapters' behaviour.

    """

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_a_hand_built_packet_is_not_mutated(self) -> None:
        import dpkt

        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit import dpkt as toolkit

        packet = dpkt.ethernet.Ethernet(ETH_IPV4 + IPV4_TCP)
        toolkit.packet2dict(packet, 0.0, data_link=LinkType.ETHERNET)
        toolkit.ipv4_reassembly(packet, 0.0)
        toolkit.tcp_reassembly(packet, 0.0)
        toolkit.tcp_traceflow(packet, 0.0, data_link=LinkType.ETHERNET)
        self.assertEqual(packet.ip.sum, 0)
        self.assertEqual(packet.ip.tcp.sum, 0)

    def test_the_unbuffered_fallback_returns_dpkts_serialisation(self) -> None:
        """Which differs from the wire in exactly the fields DPKT recomputes."""
        import dpkt

        from pcapkit.toolkit import dpkt as toolkit

        data = toolkit.ipv4_reassembly(dpkt.ethernet.Ethernet(ETH_IPV4 + IPV4_TCP), 0.0)
        self.assertEqual(bytes(data.header) + bytes(data.payload), IPV4_TCP_REPACKED)
        self.assertNotEqual(IPV4_TCP_REPACKED, IPV4_TCP)

        # the TCP layer alone round-trips: dpkt.tcp.TCP.__bytes__ recomputes
        # nothing, the pseudo-header checksum being dpkt.ip.IP.__bytes__'s doing
        tcp = toolkit.tcp_reassembly(dpkt.ethernet.Ethernet(ETH_IPV4 + IPV4_TCP), 0.0)
        self.assertEqual(bytes(tcp.header), IPV4_TCP[20:40])

    def test_attaching_the_buffer_makes_the_octets_the_wires_again(self) -> None:
        import dpkt

        from pcapkit.toolkit import dpkt as toolkit

        frame = ETH_IPV4 + IPV4_TCP
        packet = dpkt.ethernet.Ethernet(frame)
        toolkit.attach_buffer(packet, frame)
        self.assertEqual(toolkit.packet2bytes(packet), frame)
        data = toolkit.ipv4_reassembly(packet, 0.0)
        self.assertEqual(bytes(data.header) + bytes(data.payload), IPV4_TCP)

    def test_a_misplaced_slice_is_refused_rather_than_returned(self) -> None:
        """A buffer that is not the packet's own cannot be sliced into."""
        import dpkt

        from pcapkit.toolkit import dpkt as toolkit
        from pcapkit.utilities.exceptions import ProtocolError

        frame = ETH_IPV4 + IPV4_TCP
        packet = dpkt.ethernet.Ethernet(frame)
        # one octet short at the front, so every layer sits one octet early
        toolkit.attach_buffer(packet, frame[1:])
        with self.assertRaises(ProtocolError):
            toolkit.ipv4_reassembly(packet, 0.0)


if __name__ == '__main__':
    unittest.main()
