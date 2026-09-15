from __future__ import annotations

import importlib.util
from ipaddress import ip_address
import os
import socket
import struct
import tempfile
import types
import unittest
import warnings

from tests._support import close_extractor, purge_modules, sample_path

HAS_DPKT = importlib.util.find_spec('dpkt') is not None
RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: NOP, NOP, Timestamp (kind 8, length 10) -- 12 octets, the option block a
#: modern established TCP segment actually carries.
TCP_TIMESTAMP_OPTS = b'\x01\x01\x08\x0a' + struct.pack('>II', 0x4C0A9AFB, 0xD6175129)
#: NOP, NOP, NOP, End of Option List -- 4 octets of IPv4 options, enough to push
#: the internet header length past the fixed 20-octet struct size.
IPV4_NOP_OPTS = b'\x01\x01\x01\x00'
#: A protocol number reserved for experimentation (:rfc:`3692`), which
#: :mod:`dpkt` has no dissector for. Using it keeps ``IP.data`` as the raw
#: octets that were handed in, so the fixtures stay byte-exact.
IP_PROTO_EXPERIMENTAL = 253


class FakeHeader:
    length = 8


class FakeFragment:
    """Stand-in for :class:`dpkt.ip6.IP6FragmentHeader`.

    The attribute surface mirrors the real class deliberately: ``nxt`` is the
    Next Header field, ``frag_off`` is the fragment offset in 8-octet units and
    ``m_flag`` is the More Fragments flag. In particular there is **no** ``nh``
    attribute, because the real :class:`dpkt.ip6.IP6FragmentHeader` has none --
    a fake that invented one is exactly what let the defect behind the
    ``AttributeError`` reach a release unnoticed.

    """

    __hdr_len__ = 8
    #: Next Header (6 == TCP), the value that belongs in the buffer identifier.
    nxt = 6
    #: Fragment offset, in 8-octet units, so the byte offset is ``2 * 8``.
    frag_off = 2
    m_flag = 1
    #: Identification, deliberately different from :attr:`FakeIPv6.flow`, so a
    #: buffer identifier keyed on the wrong one of the two is visible.
    id = 4321

    def __len__(self) -> int:
        return 8


class FakeIPv6:
    __hdr_len__ = 40
    src = ip_address('2001:db8::1').packed
    dst = ip_address('2001:db8::2').packed
    flow = 7

    def __init__(self, frag: FakeFragment | None = None) -> None:
        self.extension_hdrs = {0: FakeHeader()}
        if frag is not None:
            self.extension_hdrs[44] = frag

    def __len__(self) -> int:
        return len(self.pack())

    def pack(self) -> bytes:
        return b'I' * 40 + b'H' * 8 + b'F' * 8 + b'PAYLOAD'


class TCP:
    __hdr_fields__ = ('sport', 'dport', 'seq', 'ack', 'flags')
    __hdr_len__ = 4
    #: Data Offset, in 32-bit words. ``off * 4`` has to agree with the header
    #: portion of :meth:`pack`, the way it does on a real :class:`dpkt.tcp.TCP`.
    off = 1
    sport = 2345
    dport = 443
    seq = 20
    ack = 15
    flags = 0b00010011
    data = b'ip6'

    def pack(self) -> bytes:
        return b'HEADip6'


class FakeTCPIPv6:
    __hdr_fields__ = ('src', 'dst')
    src = ip_address('2001:db8::10').packed
    dst = ip_address('2001:db8::20').packed

    def __init__(self) -> None:
        self.data = TCP()


class FakeDPKTPacket:
    __hdr_fields__ = ('link',)
    link = 1

    def __init__(self) -> None:
        self.ip6 = FakeTCPIPv6()
        self.data = self.ip6

    def pack(self) -> bytes:
        return b'packet'


@unittest.skipUnless(HAS_RUNTIME and HAS_DPKT, 'runtime dependencies not installed')
class DPKTToolkitTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def _make_ipv4_tcp_packet(self, *, df: bool = False, fragmented: bool = False):
        import dpkt

        eth = dpkt.ethernet.Ethernet(
            src=b'\xaa' * 6,
            dst=b'\xbb' * 6,
            type=dpkt.ethernet.ETH_TYPE_IP,
        )
        ipv4 = dpkt.ip.IP(
            src=socket.inet_aton('192.0.2.1'),
            dst=socket.inet_aton('198.51.100.1'),
            p=dpkt.ip.IP_PROTO_TCP,
            id=123,
        )
        ipv4.df = int(df)
        ipv4.mf = int(fragmented and not df)
        ipv4.offset = 2 if fragmented and not df else 0
        ipv4.data = dpkt.tcp.TCP(
            sport=1234,
            dport=80,
            seq=10,
            ack=5,
            flags=dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK,
            data=b'data',
        )
        ipv4.len = len(ipv4)
        eth.data = ipv4
        return dpkt.ethernet.Ethernet(bytes(eth))

    def test_packet_chain_dict_and_ipv4_reassembly_with_real_dpkt_packet(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit import dpkt as toolkit

        packet = self._make_ipv4_tcp_packet()
        self.assertEqual(toolkit.packet2chain(packet), 'Ethernet:IP:TCP')
        converted = toolkit.packet2dict(packet, 123.5, data_link=LinkType.ETHERNET)
        self.assertEqual(converted['timestamp'], 123.5)
        self.assertEqual(converted['packet'], packet.pack())
        self.assertIn('IP', converted['ETHERNET'])

        fragment = self._make_ipv4_tcp_packet(fragmented=True)
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            reassembled = toolkit.ipv4_reassembly(fragment, count=4)
        self.assertIsNotNone(reassembled)
        assert reassembled is not None
        self.assertEqual(reassembled.num, 4)
        self.assertEqual(reassembled.bufid[0], ip_address('192.0.2.1'))
        self.assertEqual(reassembled.bufid[1], ip_address('198.51.100.1'))
        self.assertEqual(reassembled.bufid[2], 123)
        self.assertTrue(reassembled.mf)
        # the split is at the internet header length, which ``hl`` carries in
        # 32-bit words -- not at the fixed 20-octet struct size
        self.assertEqual(bytes(reassembled.payload),
                         fragment.ip.pack()[fragment.ip.hl * 4:])

        self.assertIsNone(toolkit.ipv4_reassembly(types.SimpleNamespace(), count=1))
        self.assertIsNone(toolkit.ipv4_reassembly(self._make_ipv4_tcp_packet(df=True), count=1))

    def test_tcp_reassembly_and_traceflow_accept_dpkt_data_payload_tcp(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit import dpkt as toolkit

        packet = self._make_ipv4_tcp_packet()
        tcp = toolkit.tcp_reassembly(packet, count=9)
        self.assertIsNotNone(tcp)
        assert tcp is not None
        self.assertEqual(tcp.bufid[1], 1234)
        self.assertEqual(tcp.bufid[3], 80)
        self.assertTrue(tcp.syn)
        self.assertFalse(tcp.fin)
        # ``last`` is the sequence number of the payload's last octet, not of
        # the one after it, so ``b'data'`` at sequence number 10 ends at 13
        self.assertEqual(tcp.len, 4)
        self.assertEqual(tcp.first, 10)
        self.assertEqual(tcp.last, 13)
        self.assertEqual(tcp.last - tcp.first + 1, tcp.len)

        flow = toolkit.tcp_traceflow(packet, 50.25, data_link=LinkType.ETHERNET, count=9)
        self.assertIsNotNone(flow)
        assert flow is not None
        self.assertEqual(flow.index, 9)
        self.assertEqual(flow.protocol, LinkType.ETHERNET)
        self.assertTrue(flow.syn)
        self.assertFalse(flow.fin)
        self.assertEqual(flow.timestamp, 50.25)

        self.assertIsNone(toolkit.tcp_reassembly(types.SimpleNamespace(), count=1))
        self.assertIsNone(toolkit.tcp_traceflow(types.SimpleNamespace(), 1.0,
                                                data_link=LinkType.ETHERNET, count=1))
        raw_ip = types.SimpleNamespace(src=b'\x7f\x00\x00\x01', dst=b'\x7f\x00\x00\x01',
                                       data=b'not tcp')
        self.assertIsNone(toolkit.tcp_reassembly(types.SimpleNamespace(ip=raw_ip), count=1))
        self.assertIsNone(toolkit.tcp_traceflow(types.SimpleNamespace(ip=raw_ip), 1.0,
                                                data_link=LinkType.ETHERNET, count=1))

    def test_tcp_helpers_cover_ipv6_and_data_payload_fallback(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit import dpkt as toolkit

        packet = FakeDPKTPacket()
        tcp = toolkit.tcp_reassembly(packet, count=12)
        self.assertIsNotNone(tcp)
        assert tcp is not None
        self.assertEqual(tcp.bufid[0], ip_address('2001:db8::10'))
        self.assertEqual(tcp.bufid[2], ip_address('2001:db8::20'))
        self.assertTrue(tcp.syn)
        self.assertTrue(tcp.fin)
        self.assertEqual(bytes(tcp.payload), b'ip6')

        flow = toolkit.tcp_traceflow(packet, 60.5, data_link=LinkType.ETHERNET, count=12)
        self.assertIsNotNone(flow)
        assert flow is not None
        self.assertEqual(flow.index, 12)
        self.assertEqual(flow.src, ip_address('2001:db8::10'))
        self.assertEqual(flow.dst, ip_address('2001:db8::20'))
        self.assertTrue(flow.syn)
        self.assertTrue(flow.fin)
        self.assertEqual(flow.frame['ETHERNET']['FakeTCPIPv6']['TCP']['sport'], 2345)

    def test_ipv6_header_length_and_reassembly_with_fragment_fake(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.toolkit import dpkt as toolkit

        frag = FakeFragment()
        ipv6 = FakeIPv6(frag)
        self.assertEqual(toolkit.ipv6_hdr_len(ipv6), 48)

        packet = types.SimpleNamespace(ip6=ipv6)
        reassembled = toolkit.ipv6_reassembly(packet, count=5)
        self.assertIsNotNone(reassembled)
        assert reassembled is not None
        self.assertEqual(reassembled.num, 5)
        self.assertEqual(reassembled.bufid[0], ip_address('2001:db8::1'))
        self.assertEqual(reassembled.bufid[1], ip_address('2001:db8::2'))
        # the fragment header's Identification, not the IPv6 header's Flow Label
        # -- ``bufid[2]`` feeds ``DatagramID.id``
        self.assertEqual(reassembled.bufid[2], frag.id)
        self.assertNotEqual(reassembled.bufid[2], ipv6.flow)
        # the buffer identifier carries the Next Header field of the fragment
        # header, as a registry enum rather than its name
        self.assertEqual(reassembled.bufid[3], TransType.get(frag.nxt))
        # the fragment offset is stored in 8-octet units on the wire and the
        # reassembly machinery indexes the datagram buffer in octets
        self.assertEqual(reassembled.fo, frag.frag_off * 8)
        self.assertTrue(reassembled.mf)
        self.assertEqual(reassembled.ihl, 48)
        self.assertEqual(bytes(reassembled.payload), b'PAYLOAD')

        self.assertIsNone(toolkit.ipv6_reassembly(types.SimpleNamespace(), count=1))
        self.assertIsNone(toolkit.ipv6_reassembly(types.SimpleNamespace(ip6=FakeIPv6()), count=1))


# ---------------------------------------------------------------------------
# regression tests
# ---------------------------------------------------------------------------


def _make_tcp_segment_with_options(payload: bytes, *, opts: bytes = TCP_TIMESTAMP_OPTS):
    """Build an Ethernet/IPv4/TCP packet whose TCP header carries options.

    The packet is serialised and parsed back, so the object under test comes off
    the same code path a captured frame does.

    """
    import dpkt

    tcp = dpkt.tcp.TCP(
        sport=1234, dport=80, seq=100, ack=1,
        flags=dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, data=payload,
    )
    tcp.opts = opts
    tcp.off = (tcp.__hdr_len__ + len(opts)) // 4

    ipv4 = dpkt.ip.IP(
        src=socket.inet_aton('192.0.2.1'), dst=socket.inet_aton('198.51.100.1'),
        p=dpkt.ip.IP_PROTO_TCP, id=4242,
    )
    ipv4.df = 0
    ipv4.data = tcp
    ipv4.len = len(ipv4)

    eth = dpkt.ethernet.Ethernet(src=b'\xaa' * 6, dst=b'\xbb' * 6,
                                 type=dpkt.ethernet.ETH_TYPE_IP)
    eth.data = ipv4
    return dpkt.ethernet.Ethernet(bytes(eth))


def _make_ipv4_with_options(body: bytes, *, opts: bytes = IPV4_NOP_OPTS):
    """Build an Ethernet/IPv4 packet whose internet header carries options."""
    import dpkt

    ipv4 = dpkt.ip.IP(
        src=socket.inet_aton('192.0.2.1'), dst=socket.inet_aton('198.51.100.1'),
        p=IP_PROTO_EXPERIMENTAL, id=7,
    )
    ipv4.df = 0
    ipv4.mf = 0
    ipv4.offset = 0
    ipv4.opts = opts
    ipv4._v_hl = (4 << 4) | ((ipv4.__hdr_len__ + len(opts)) // 4)
    ipv4.data = body
    ipv4.len = ipv4.__hdr_len__ + len(opts) + len(body)

    eth = dpkt.ethernet.Ethernet(src=b'\xaa' * 6, dst=b'\xbb' * 6,
                                 type=dpkt.ethernet.ETH_TYPE_IP)
    eth.data = ipv4
    return dpkt.ethernet.Ethernet(bytes(eth))


def _make_ipv4_fragment(*, offset_units: int, mf: bool, body: bytes):
    """Build an Ethernet/IPv4 fragment at ``offset_units`` 8-octet units."""
    import dpkt

    ipv4 = dpkt.ip.IP(
        src=socket.inet_aton('192.0.2.1'), dst=socket.inet_aton('198.51.100.1'),
        p=IP_PROTO_EXPERIMENTAL, id=555,
    )
    ipv4.df = 0
    ipv4.data = body
    ipv4.len = ipv4.__hdr_len__ + len(body)
    ipv4.offset = offset_units
    ipv4.mf = int(mf)

    eth = dpkt.ethernet.Ethernet(src=b'\xaa' * 6, dst=b'\xbb' * 6,
                                 type=dpkt.ethernet.ETH_TYPE_IP)
    eth.data = ipv4
    return dpkt.ethernet.Ethernet(bytes(eth))


def _ipv6_fragment_bytes(*, offset_units: int, mf: bool, body: bytes,
                         ident: int = 110308, nxt: int = 17, flow: int = 0) -> bytes:
    """Serialise an IPv6 packet carrying a Fragment header, as wire octets.

    Built by hand rather than through :mod:`dpkt`'s constructors so the Fragment
    header is unambiguously the one :rfc:`8200#section-4.5` describes: a 13-bit
    Fragment Offset counted in 8-octet units, two reserved bits, then the More
    Fragments flag, which is why ``offset_units`` is shifted left by three.

    ``flow`` is the IPv6 header's Flow Label, kept separate from ``ident`` so a
    buffer identifier keyed on the wrong one of the two is visible.

    """
    frag_hdr = struct.pack('>BBHI', nxt, 0,
                           (offset_units << 3) | (1 if mf else 0), ident)
    payload = frag_hdr + body
    header = struct.pack('>IHBB', (6 << 28) | flow, len(payload), 44, 64)
    header += socket.inet_pton(socket.AF_INET6, '2001:db8::1')
    header += socket.inet_pton(socket.AF_INET6, '2001:db8::2')
    return header + payload


def _ipv6_fragment_frame(*, offset_units: int, mf: bool, body: bytes,
                         ident: int = 110308, nxt: int = 17, flow: int = 0) -> bytes:
    """Wrap :func:`_ipv6_fragment_bytes` in an Ethernet frame."""
    return b'\xbb' * 6 + b'\xaa' * 6 + b'\x86\xdd' + _ipv6_fragment_bytes(
        offset_units=offset_units, mf=mf, body=body, ident=ident, nxt=nxt, flow=flow,
    )


@unittest.skipUnless(HAS_RUNTIME and HAS_DPKT, 'runtime dependencies not installed')
class DPKTTCPHeaderSplitTests(unittest.TestCase):
    """The TCP header is delimited by Data Offset, not by the struct size.

    :class:`dpkt.tcp.TCP` serialises as ``pack_hdr() + opts + data``, and
    ``__hdr_len__`` is the fixed 20-octet struct size, so slicing at
    ``__hdr_len__`` leaves the option octets at the head of the *payload*. The
    invariants below are the ones that hold for any segment whatsoever, which is
    why they are asserted rather than a particular octet count.

    """

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_header_ends_at_data_offset_and_len_matches_payload(self) -> None:
        from pcapkit.toolkit import dpkt as toolkit

        body = b'GET /index.html HTTP/1.1\r\n\r\n'
        packet = _make_tcp_segment_with_options(body)
        tcp = packet.ip.data

        # the fixture has to actually exercise the defect
        self.assertGreater(len(tcp.opts), 0)
        self.assertGreater(tcp.off * 4, tcp.__hdr_len__)

        data = toolkit.tcp_reassembly(packet, count=1)
        self.assertIsNotNone(data)
        assert data is not None

        # the header is exactly ``dataofs * 4`` octets ...
        self.assertEqual(len(data.header), tcp.off * 4)
        # ... and therefore ends with the option block rather than dropping it
        self.assertTrue(bytes(data.header).endswith(bytes(tcp.opts)))

        # the reported length and the payload cannot disagree
        self.assertEqual(data.len, len(data.payload))
        # the payload starts at the real application bytes
        self.assertEqual(bytes(data.payload), body)
        self.assertFalse(bytes(data.payload).startswith(bytes(tcp.opts)))

        # header and payload together reconstitute the segment
        self.assertEqual(bytes(data.header) + bytes(data.payload), tcp.pack())
        # and the sequence numbers span exactly the payload
        self.assertEqual(data.last - data.first + 1, data.len)

    def test_option_only_segment_yields_empty_payload(self) -> None:
        """A pure ACK carrying options has no payload at all."""
        from pcapkit.toolkit import dpkt as toolkit

        packet = _make_tcp_segment_with_options(b'')
        tcp = packet.ip.data
        self.assertGreater(len(tcp.opts), 0)

        data = toolkit.tcp_reassembly(packet, count=1)
        assert data is not None
        self.assertEqual(data.len, 0)
        self.assertEqual(len(data.payload), 0)
        self.assertEqual(len(data.header), tcp.off * 4)

    def test_every_tcp_frame_of_the_sample_capture_holds_the_invariants(self) -> None:
        """The invariants hold for every TCP frame of a real capture."""
        import dpkt

        from pcapkit.toolkit import dpkt as toolkit

        try:
            path = sample_path('test.pcap')
        except FileNotFoundError as exc:
            self.skipTest(str(exc))

        with open(path, 'rb') as file:
            frames = list(dpkt.pcap.Reader(file))

        checked = with_options = 0
        for index, (_, buf) in enumerate(frames, start=1):
            packet = dpkt.ethernet.Ethernet(buf)
            ip = getattr(packet, 'ip', None) or getattr(packet, 'ip6', None)
            if ip is None:
                continue
            tcp = getattr(ip, 'tcp', None)
            if tcp is None and type(getattr(ip, 'data', None)).__name__ == 'TCP':
                tcp = ip.data
            if tcp is None:
                continue

            data = toolkit.tcp_reassembly(packet, count=index)
            assert data is not None
            with self.subTest(frame=index):
                self.assertEqual(len(data.header), tcp.off * 4)
                self.assertEqual(data.len, len(data.payload))
                self.assertEqual(bytes(data.payload), bytes(tcp.data))
                self.assertEqual(bytes(data.header) + bytes(data.payload), tcp.pack())
            checked += 1
            if len(tcp.opts):
                with_options += 1

        self.assertGreater(checked, 0, 'sample capture carried no TCP frames')
        self.assertGreater(with_options, 0,
                           'sample capture carried no TCP options, so it cannot '
                           'exercise the Data Offset split')


@unittest.skipUnless(HAS_RUNTIME and HAS_DPKT, 'runtime dependencies not installed')
class DPKTIPv4ReassemblyFieldTests(unittest.TestCase):
    """The IPv4 path carries the same class of defect as the TCP one."""

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_header_ends_at_internet_header_length_with_options(self) -> None:
        from pcapkit.toolkit import dpkt as toolkit

        body = b'Y' * 100
        packet = _make_ipv4_with_options(body)
        ipv4 = packet.ip

        # the fixture has to actually exercise the defect
        self.assertEqual(ipv4.hl * 4, ipv4.__hdr_len__ + len(IPV4_NOP_OPTS))
        self.assertGreater(ipv4.hl * 4, ipv4.__hdr_len__)

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            data = toolkit.ipv4_reassembly(packet, count=1)
        self.assertIsNotNone(data)
        assert data is not None

        self.assertEqual(data.ihl, ipv4.hl * 4)
        self.assertEqual(len(data.header), ipv4.hl * 4)
        self.assertTrue(bytes(data.header).endswith(IPV4_NOP_OPTS))
        self.assertEqual(bytes(data.payload), body)
        self.assertFalse(bytes(data.payload).startswith(IPV4_NOP_OPTS))
        # the reassembly machinery derives the payload length as ``tl - ihl``,
        # so that difference has to be the payload it was handed
        self.assertEqual(data.tl - data.ihl, len(data.payload))

    def test_fragment_offset_is_reported_in_octets(self) -> None:
        """``IP.off`` is the raw flags-plus-offset word, not the offset."""
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.toolkit import dpkt as toolkit

        offset_units = 179
        packet = _make_ipv4_fragment(offset_units=offset_units, mf=True, body=b'B' * 200)
        ipv4 = packet.ip

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            data = toolkit.ipv4_reassembly(packet, count=1)
        assert data is not None

        self.assertEqual(ipv4.offset, offset_units)
        # the buffer is indexed in octets, and the wire field is in 8-octet units
        self.assertEqual(data.fo, offset_units * 8)
        self.assertTrue(data.mf)
        # the buffer identifier's protocol slot is a registry enum, which is what
        # ``Reassembly.submit`` hands to ``Protocol.analyze``
        self.assertIsInstance(data.bufid[3], TransType)
        self.assertEqual(data.bufid[3], TransType.get(ipv4.p))

    def test_reassembly_reconstructs_a_fragmented_datagram(self) -> None:
        """End to end: two IPv4 fragments come back as the original payload."""
        from pcapkit.foundation.reassembly.ipv4 import IPv4
        from pcapkit.toolkit import dpkt as toolkit

        body = bytes(range(256)) * 6          # 1536 octets, a multiple of 8
        first, second = body[:1024], body[1024:]

        reasm = IPv4(strict=True)
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            for index, (offset_units, mf, chunk) in enumerate((
                (0, True, first),
                (len(first) // 8, False, second),
            ), start=1):
                packet = _make_ipv4_fragment(offset_units=offset_units, mf=mf, body=chunk)
                data = toolkit.ipv4_reassembly(packet, count=index)
                assert data is not None
                reasm(data)

        datagrams = list(reasm.datagram)
        self.assertEqual(len(datagrams), 1)
        self.assertTrue(datagrams[0].completed)
        self.assertEqual(bytes(datagrams[0].payload), body)


@unittest.skipUnless(HAS_RUNTIME and HAS_DPKT, 'runtime dependencies not installed')
class DPKTIPv6ReassemblyTests(unittest.TestCase):
    """IPv6 reassembly against a real :class:`dpkt.ip6.IP6FragmentHeader`."""

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_reads_the_real_fragment_header_attributes(self) -> None:
        import dpkt

        from pcapkit.const.reg.transtype import TransType
        from pcapkit.toolkit import dpkt as toolkit

        offset_units, body = 175, b'B' * 200
        ipv6 = dpkt.ip6.IP6(_ipv6_fragment_bytes(
            offset_units=offset_units, mf=False, body=body,
        ))
        frag = ipv6.extension_hdrs.get(44)
        self.assertIsNotNone(frag)
        assert frag is not None

        # the real class exposes ``nxt``/``frag_off``/``m_flag`` and no ``nh``
        self.assertFalse(hasattr(frag, 'nh'))
        self.assertEqual(frag.nxt, dpkt.ip.IP_PROTO_UDP)
        self.assertEqual(frag.frag_off, offset_units)
        # ``frag_off`` is the 13-bit Fragment Offset, already shifted out of the
        # flags word, and *not* the raw 16-bit ``_frag_off_resv_m`` -- which is
        # what makes the ``* 8`` below a scaling into octets rather than a second
        # scaling on top of one DPKT had already applied
        self.assertEqual(frag._frag_off_resv_m, offset_units << 3)
        self.assertEqual(frag.frag_off, frag._frag_off_resv_m >> 3)
        self.assertNotEqual(frag.frag_off, frag._frag_off_resv_m)

        data = toolkit.ipv6_reassembly(types.SimpleNamespace(ip6=ipv6), count=3)
        self.assertIsNotNone(data)
        assert data is not None

        # the Next Header field of the fragment header, as a registry enum
        self.assertIsInstance(data.bufid[3], TransType)
        self.assertEqual(data.bufid[3], TransType.get(frag.nxt))
        # the offset is in 8-octet units on the wire, octets in the buffer
        self.assertEqual(data.fo, offset_units * 8)
        self.assertFalse(data.mf)
        # only the headers before the fragment header
        self.assertEqual(data.ihl, ipv6.__hdr_len__)
        self.assertEqual(len(data.header), ipv6.__hdr_len__)
        # the payload follows the 8-octet fragment header ...
        self.assertEqual(bytes(data.payload), body)
        # ... and ``tl - ihl`` has to be that payload's length, not 8 more
        self.assertEqual(data.tl - data.ihl, len(data.payload))

    def test_offset_is_scaled_once_into_octets(self) -> None:
        """``fo`` is the octet offset, so it is neither ``frag_off`` nor ``* 64``.

        The three candidate readings of the field are pinned against each other
        rather than only the right one being asserted, because the failure mode
        that matters is an offset scaled the wrong number of times: an unscaled
        ``fo`` overlaps the fragments and a doubly scaled one leaves holes, and
        both still look like plausible integers.

        """
        import dpkt

        from pcapkit.toolkit import dpkt as toolkit

        offset_units = 181
        ipv6 = dpkt.ip6.IP6(_ipv6_fragment_bytes(
            offset_units=offset_units, mf=True, body=b'C' * 64,
        ))
        data = toolkit.ipv6_reassembly(types.SimpleNamespace(ip6=ipv6), count=1)
        assert data is not None

        self.assertEqual(data.fo, 1448)               # 181 units of 8 octets
        self.assertNotEqual(data.fo, offset_units)    # not left in 8-octet units
        self.assertNotEqual(data.fo, offset_units * 64)  # not scaled twice

    def test_buffer_identifier_is_keyed_on_the_fragment_identification(self) -> None:
        """``bufid[2]`` is the Fragment header's Identification, not the Flow Label.

        The Flow Label is optional and routinely zero, so keying on it merges
        unrelated datagrams between one address pair. The fixture gives the two a
        different value so the wrong one cannot pass by coincidence.

        """
        import dpkt

        from pcapkit.toolkit import dpkt as toolkit

        ident, flow = 110308, 0x12345
        ipv6 = dpkt.ip6.IP6(_ipv6_fragment_bytes(
            offset_units=0, mf=True, body=b'D' * 32, ident=ident, flow=flow,
        ))
        self.assertEqual(ipv6.flow, flow)
        self.assertEqual(ipv6.extension_hdrs[44].id, ident)

        data = toolkit.ipv6_reassembly(types.SimpleNamespace(ip6=ipv6), count=1)
        assert data is not None

        self.assertEqual(data.bufid[2], ident)
        self.assertNotEqual(data.bufid[2], flow)

    def test_two_datagrams_sharing_a_flow_label_stay_separate(self) -> None:
        """Distinct identifications must not be merged into one datagram.

        This is the consequence a single fragmented datagram cannot show: both
        datagrams below share source, destination, Next Header *and* Flow Label,
        so a buffer identifier keyed on the label puts all four fragments into
        one buffer and the payloads overwrite one another.

        """
        import dpkt

        from pcapkit.foundation.reassembly.ipv6 import IPv6
        from pcapkit.toolkit import dpkt as toolkit

        first, second = b'E' * 64, b'F' * 64
        third, fourth = b'G' * 64, b'H' * 64

        reasm = IPv6(strict=True)
        for index, (ident, offset_units, mf, chunk) in enumerate((
            (1000, 0, True, first),
            (2000, 0, True, third),
            (1000, 8, False, second),
            (2000, 8, False, fourth),
        ), start=1):
            ipv6 = dpkt.ip6.IP6(_ipv6_fragment_bytes(
                offset_units=offset_units, mf=mf, body=chunk, ident=ident, flow=0x12345,
            ))
            data = toolkit.ipv6_reassembly(types.SimpleNamespace(ip6=ipv6), count=index)
            assert data is not None
            reasm(data)

        datagrams = list(reasm.datagram)
        self.assertEqual(len(datagrams), 2)
        payloads = {datagram.id.id: bytes(datagram.payload) for datagram in datagrams}
        self.assertEqual(sorted(payloads), [1000, 2000])
        self.assertEqual(payloads[1000], first + second)
        self.assertEqual(payloads[2000], third + fourth)

    def test_reassembly_reconstructs_a_fragmented_datagram(self) -> None:
        import dpkt

        from pcapkit.foundation.reassembly.ipv6 import IPv6
        from pcapkit.toolkit import dpkt as toolkit

        body = bytes(range(256)) * 6          # 1536 octets, a multiple of 8
        first, second = body[:1024], body[1024:]

        reasm = IPv6(strict=True)
        for index, (offset_units, mf, chunk) in enumerate((
            (0, True, first),
            (len(first) // 8, False, second),
        ), start=1):
            ipv6 = dpkt.ip6.IP6(_ipv6_fragment_bytes(
                offset_units=offset_units, mf=mf, body=chunk,
            ))
            data = toolkit.ipv6_reassembly(types.SimpleNamespace(ip6=ipv6), count=index)
            assert data is not None
            reasm(data)

        datagrams = list(reasm.datagram)
        self.assertEqual(len(datagrams), 1)
        self.assertTrue(datagrams[0].completed)
        self.assertEqual(bytes(datagrams[0].payload), body)

    def test_engine_reassembles_ipv6_fragments_end_to_end(self) -> None:
        """The whole ``engine='dpkt'`` path, from a capture file in."""
        import dpkt

        import pcapkit

        body = bytes(range(256)) * 6
        first, second = body[:1024], body[1024:]

        handle = tempfile.NamedTemporaryFile(suffix='.pcap', delete=False)
        try:
            writer = dpkt.pcap.Writer(handle)
            writer.writepkt(_ipv6_fragment_frame(offset_units=0, mf=True, body=first), ts=1.0)
            writer.writepkt(
                _ipv6_fragment_frame(offset_units=len(first) // 8, mf=False, body=second),
                ts=1.1,
            )
            handle.close()

            extractor = pcapkit.extract(fin=handle.name, nofile=True, store=False,
                                        engine='dpkt', ipv6=True, reassembly=True,
                                        reasm_strict=True)
            try:
                datagrams = list(extractor.reassembly.ipv6)
            finally:
                close_extractor(extractor)
        finally:
            os.unlink(handle.name)

        self.assertEqual(len(datagrams), 1)
        self.assertTrue(datagrams[0].completed)
        self.assertEqual(bytes(datagrams[0].payload), body)


@unittest.skipUnless(HAS_RUNTIME and HAS_DPKT, 'runtime dependencies not installed')
class DPKTEngineParityTests(unittest.TestCase):
    """The ``dpkt`` engine must agree with the default engine octet for octet.

    This is the check that would have caught the Data Offset defect: the split
    was wrong in a way that left the datagram *lengths* untouched, because the
    reassembly buffer is indexed by sequence number, so only a byte-level
    comparison against a known-good engine shows it.

    """

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def _reassemble(self, path: str, engine: str):
        import pcapkit

        extractor = pcapkit.extract(fin=path, nofile=True, store=False, engine=engine,
                                    tcp=True, reassembly=True, reasm_strict=True)
        try:
            return [
                (
                    datagram.completed,
                    datagram.payload if isinstance(datagram.payload, bytes)
                    else b''.join(datagram.payload),
                )
                for datagram in extractor.reassembly.tcp
            ]
        finally:
            close_extractor(extractor)

    def test_tcp_reassembly_matches_the_default_engine(self) -> None:
        try:
            path = sample_path('test.pcap')
        except FileNotFoundError as exc:
            self.skipTest(str(exc))

        default = self._reassemble(path, 'default')
        dpkt_out = self._reassemble(path, 'dpkt')

        self.assertGreater(len(default), 0, 'sample capture reassembled nothing')
        self.assertEqual(len(dpkt_out), len(default))
        for index, (expected, actual) in enumerate(zip(default, dpkt_out)):
            with self.subTest(datagram=index):
                self.assertEqual(actual[0], expected[0])
                self.assertEqual(actual[1], expected[1])


if __name__ == '__main__':
    unittest.main()
