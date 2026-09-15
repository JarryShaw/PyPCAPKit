from __future__ import annotations

import importlib.util
from ipaddress import ip_address
import types
import unittest

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


class FakeFrame:
    linktype = None

    def __init__(self, layers: dict[str, object], info: types.SimpleNamespace,
                 *, linktype: object = None) -> None:
        self.layers = layers
        self.info = info
        self.linktype = linktype

    def __contains__(self, name: str) -> bool:
        return name in self.layers

    def __getitem__(self, name: str) -> object:
        return self.layers[name]


def flags(*, df: bool = False, mf: bool = False, syn: bool = False,
          fin: bool = False, rst: bool = False) -> types.SimpleNamespace:
    return types.SimpleNamespace(df=df, mf=mf, syn=syn, fin=fin, rst=rst)


def port(value: int) -> types.SimpleNamespace:
    return types.SimpleNamespace(port=value)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class PCAPToolkitTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def _make_ipv4(self, *, df: bool = False):
        from pcapkit.const.reg.transtype import TransType

        return types.SimpleNamespace(
            info=types.SimpleNamespace(
                src=ip_address('192.0.2.1'),
                dst=ip_address('198.51.100.1'),
                id=123,
                protocol=TransType.TCP,
                offset=2,
                hdr_len=20,
                flags=flags(df=df, mf=not df),
                len=28,
            ),
            packet=types.SimpleNamespace(header=b'I' * 20, payload=b'ipv4data'),
        )

    def _make_ipv6(self, *, with_fragment: bool = True):
        from pcapkit.const.ipv6.extension_header import ExtensionHeader
        from pcapkit.const.reg.transtype import TransType

        # NOTE: ``offset`` here stands in for ``Data_IPv6_Frag.offset``, which is in
        # octets (the 8-octet on-wire units are scaled in ``IPv6_Frag.read``), so the
        # toolkit passes it through to ``fo`` unscaled. ``id`` is deliberately
        # different from the IPv6 header's flow label below, so that a ``bufid``
        # keyed on the wrong one of the two is visible.
        fragment = types.SimpleNamespace(
            info=types.SimpleNamespace(next=TransType.TCP, offset=8, mf=True, id=4321),
        )
        extension_headers = {ExtensionHeader.IPv6_Frag: fragment} if with_fragment else {}
        return types.SimpleNamespace(
            extension_headers=extension_headers,
            info=types.SimpleNamespace(
                src=ip_address('2001:db8::1'),
                dst=ip_address('2001:db8::2'),
                label=7,
                hdr_len=48,
                raw_len=10,
                fragment=types.SimpleNamespace(header=b'V' * 48, payload=b'v6data'),
            ),
        )

    def _make_tcp(self, *, seq: int = 10, payload: bytes = b'tcpdata',
                  syn: bool = True, fin: bool = False, rst: bool = True):
        return types.SimpleNamespace(
            info=types.SimpleNamespace(
                srcport=port(1234),
                dstport=port(80),
                ack=5,
                seq=seq,
                flags=flags(syn=syn, fin=fin, rst=rst),
            ),
            packet=types.SimpleNamespace(header=b'T' * 20, payload=payload),
        )

    def _make_pcap_frame(self, *, include_tcp: bool = True,
                         ipv4_df: bool = False, seq: int = 10,
                         payload: bytes = b'tcpdata', number: int = 9,
                         syn: bool = True, fin: bool = False,
                         rst: bool = True) -> FakeFrame:
        layers = {
            'IPv4': self._make_ipv4(df=ipv4_df),
        }
        layers['IP'] = layers['IPv4']
        if include_tcp:
            layers['TCP'] = self._make_tcp(seq=seq, payload=payload,
                                           syn=syn, fin=fin, rst=rst)
        return FakeFrame(layers, types.SimpleNamespace(number=number, time_epoch='50.25'))

    def _make_pcapng_frame(self, *, include_tcp: bool = True,
                           ipv4_df: bool = False, seq: int = 10,
                           payload: bytes = b'tcpdata'):
        from pcapkit.const.reg.linktype import LinkType

        layers = {
            'IPv4': self._make_ipv4(df=ipv4_df),
        }
        layers['IP'] = layers['IPv4']
        if include_tcp:
            layers['TCP'] = self._make_tcp(seq=seq, payload=payload)
        return FakeFrame(
            layers,
            types.SimpleNamespace(number=11, timestamp_epoch=60.5,
                                  timestamp='ts', captured_len=4,
                                  original_len=5, packet=b'abcd'),
            linktype=LinkType.ETHERNET,
        )

    def test_pcap_ipv4_ipv6_tcp_and_traceflow_helpers(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit import pcap as toolkit

        frame = self._make_pcap_frame()
        ipv4 = toolkit.ipv4_reassembly(frame)
        self.assertIsNotNone(ipv4)
        assert ipv4 is not None
        self.assertEqual(ipv4.num, 9)
        self.assertEqual(ipv4.bufid[0], ip_address('192.0.2.1'))
        self.assertEqual(ipv4.bufid[2], 123)
        self.assertTrue(ipv4.mf)
        self.assertEqual(ipv4.header, b'I' * 20)
        self.assertEqual(bytes(ipv4.payload), b'ipv4data')

        self.assertIsNone(toolkit.ipv4_reassembly(FakeFrame({}, types.SimpleNamespace(number=1))))
        self.assertIsNone(toolkit.ipv4_reassembly(self._make_pcap_frame(ipv4_df=True)))

        v6_frame = FakeFrame({'IPv6': self._make_ipv6()},
                             types.SimpleNamespace(number=10, time_epoch='51.0'))
        v6 = toolkit.ipv6_reassembly(v6_frame)
        self.assertIsNotNone(v6)
        assert v6 is not None
        self.assertEqual(v6.bufid[0], ip_address('2001:db8::1'))
        # ``bufid[2]`` is the identification slot -- ``DatagramID.id`` is built from
        # it -- so it must carry the IPv6 Fragment header's identification and not
        # the IPv6 header's flow label, which does not identify a datagram at all
        # (:rfc:`8200#section-4.5`).
        self.assertEqual(v6.bufid[2], 4321)
        self.assertNotEqual(v6.bufid[2], 7)
        self.assertEqual(v6.fo, 8)
        self.assertTrue(v6.mf)
        self.assertEqual(v6.header, b'V' * 48)
        self.assertEqual(bytes(v6.payload), b'v6data')
        self.assertIsNone(toolkit.ipv6_reassembly(FakeFrame({}, types.SimpleNamespace(number=1))))
        self.assertIsNone(toolkit.ipv6_reassembly(
            FakeFrame({'IPv6': self._make_ipv6(with_fragment=False)},
                      types.SimpleNamespace(number=1)),
        ))

        tcp = toolkit.tcp_reassembly(frame)
        self.assertIsNotNone(tcp)
        assert tcp is not None
        self.assertEqual(tcp.bufid[1], 1234)
        self.assertEqual(tcp.bufid[3], 80)
        self.assertTrue(tcp.syn)
        self.assertTrue(tcp.rst)
        # ``first``/``last`` bound the payload in absolute sequence numbers and
        # ``last`` is inclusive, so the two describe exactly ``len`` octets --
        # ``seq`` is 10 and the payload is the seven octets of ``b'tcpdata'``.
        self.assertEqual(tcp.len, 7)
        self.assertEqual(tcp.first, 10)
        self.assertEqual(tcp.last, 16)
        self.assertEqual(tcp.last - tcp.first + 1, tcp.len)
        self.assertIsNone(toolkit.tcp_reassembly(self._make_pcap_frame(include_tcp=False)))

        flow = toolkit.tcp_traceflow(frame, data_link=LinkType.ETHERNET)
        self.assertIsNotNone(flow)
        assert flow is not None
        self.assertEqual(flow.protocol, LinkType.ETHERNET)
        self.assertEqual(flow.index, 9)
        self.assertEqual(flow.timestamp, 50.25)
        self.assertTrue(flow.syn)
        self.assertIsNone(toolkit.tcp_traceflow(self._make_pcap_frame(include_tcp=False),
                                                data_link=LinkType.ETHERNET))

    def test_pcapng_helpers_and_block_to_frame_timestamp_scaling(self) -> None:
        from pcapkit.toolkit import pcapng as toolkit

        frame = self._make_pcapng_frame()
        ipv4 = toolkit.ipv4_reassembly(frame)
        self.assertIsNotNone(ipv4)
        assert ipv4 is not None
        self.assertEqual(ipv4.num, 11)
        self.assertEqual(ipv4.bufid[0], ip_address('192.0.2.1'))
        self.assertEqual(bytes(ipv4.payload), b'ipv4data')
        self.assertIsNone(toolkit.ipv4_reassembly(FakeFrame({}, frame.info)))
        self.assertIsNone(toolkit.ipv4_reassembly(self._make_pcapng_frame(ipv4_df=True)))

        v6_frame = FakeFrame({'IPv6': self._make_ipv6()}, frame.info, linktype=frame.linktype)
        v6 = toolkit.ipv6_reassembly(v6_frame)
        self.assertIsNotNone(v6)
        assert v6 is not None
        self.assertEqual(v6.bufid[0], ip_address('2001:db8::1'))
        # the PCAPNG engine keys the buffer the same way the PCAP engine does
        self.assertEqual(v6.bufid[2], 4321)
        self.assertNotEqual(v6.bufid[2], 7)
        self.assertEqual(v6.fo, 8)
        self.assertEqual(v6.header, b'V' * 48)
        self.assertIsNone(toolkit.ipv6_reassembly(FakeFrame({}, frame.info)))
        self.assertIsNone(toolkit.ipv6_reassembly(
            FakeFrame({'IPv6': self._make_ipv6(with_fragment=False)}, frame.info),
        ))

        tcp = toolkit.tcp_reassembly(frame)
        self.assertIsNotNone(tcp)
        assert tcp is not None
        self.assertEqual(tcp.bufid[1], 1234)
        # same inclusive bounds as the PCAP engine above -- the two toolkits
        # must agree, or a stream reassembles differently per capture format
        self.assertEqual(tcp.len, 7)
        self.assertEqual(tcp.first, 10)
        self.assertEqual(tcp.last, 16)
        self.assertEqual(tcp.last - tcp.first + 1, tcp.len)
        self.assertIsNone(toolkit.tcp_reassembly(self._make_pcapng_frame(include_tcp=False)))

        flow = toolkit.tcp_traceflow(frame)
        self.assertIsNotNone(flow)
        assert flow is not None
        self.assertEqual(flow.protocol, frame.linktype)
        self.assertEqual(flow.index, 11)
        self.assertEqual(flow.timestamp, 60.5)
        self.assertEqual(flow.frame.frame_info.ts_sec, 60)
        self.assertEqual(flow.frame.frame_info.ts_usec, 500000)
        self.assertIsNone(toolkit.tcp_traceflow(self._make_pcapng_frame(include_tcp=False)))

        block = types.SimpleNamespace(timestamp_epoch=10.25, timestamp='time',
                                      captured_len=4, original_len=5,
                                      number=7, packet=b'abcd')
        pcap_frame = toolkit.block2frame(block)
        self.assertEqual(pcap_frame.frame_info.ts_sec, 10)
        self.assertEqual(pcap_frame.frame_info.ts_usec, 250000)
        self.assertEqual(pcap_frame.packet, b'abcd')

        pcap_frame_ns = toolkit.block2frame(block, nanosecond=True)
        self.assertEqual(pcap_frame_ns.frame_info.ts_usec, 250000000)

    def test_tcp_reassembly_descriptor_bounds_are_absolute_and_inclusive(self) -> None:
        """The segment descriptor handed to the reassembler (GitHub issue #349).

        ``first`` and ``last`` are absolute TCP sequence numbers bounding the
        payload, and ``last`` is the sequence number of its final octet rather
        than of the octet after it. Both matter: the reassembler holds its
        :rfc:`815` hole descriptor list in the same absolute space and treats
        both bounds as inclusive, so a descriptor that is relative, or exclusive
        at the top end, silently corrupts the hole list -- and this is not
        visible at a sequence number of zero, which is why a realistic one is
        used here.

        Both the PCAP and the PCAP-NG toolkit are checked, and against each
        other, since they feed the one reassembler and a stream must not
        reassemble differently depending on the capture format it arrived in.

        """
        from pcapkit.toolkit import pcap, pcapng

        # a realistic initial sequence number, plus the 1448 octets an Ethernet
        # path carries with a timestamp option in the TCP header
        seq = 0xC0DE1234
        payload = bytes(range(256)) * 5 + bytes(168)
        self.assertEqual(len(payload), 1448)

        for (name, toolkit, frame) in (
            ('pcap', pcap, self._make_pcap_frame(seq=seq, payload=payload)),
            ('pcapng', pcapng, self._make_pcapng_frame(seq=seq, payload=payload)),
        ):
            with self.subTest(engine=name):
                tcp = toolkit.tcp_reassembly(frame)
                self.assertIsNotNone(tcp)
                assert tcp is not None

                self.assertEqual(tcp.dsn, seq)
                self.assertEqual(tcp.len, 1448)
                self.assertEqual(tcp.first, seq)             # absolute, not an offset
                self.assertEqual(tcp.last, seq + 1447)       # inclusive, not seq + 1448
                self.assertEqual(tcp.last - tcp.first + 1, tcp.len)
                self.assertEqual(bytes(tcp.payload), payload)

        # a segment carrying no payload bounds an empty range, i.e. ``last`` one
        # below ``first``, rather than claiming the octet it does not carry
        empty = pcap.tcp_reassembly(self._make_pcap_frame(seq=seq, payload=b''))
        self.assertIsNotNone(empty)
        assert empty is not None
        self.assertEqual(empty.len, 0)
        self.assertEqual((empty.first, empty.last), (seq, seq - 1))

    def test_tcp_reassembly_descriptor_drives_the_reassembler(self) -> None:
        """The descriptor the toolkit builds reassembles to the octets sent.

        Guards the seam rather than either side of it: the toolkit and the
        reassembler each looked self-consistent while disagreeing about what
        ``first`` and ``last`` meant.

        """
        from pcapkit.foundation.reassembly.tcp import TCP
        from pcapkit.toolkit import pcap

        class Analyzer:
            @classmethod
            def analyze(cls, ports: tuple[int, int], payload: bytes) -> bytes:
                return payload

        class TestTCP(TCP):
            __protocol_type__ = Analyzer

        seq = 0xC0DE1234
        reasm = TestTCP()

        # three data segments and then a bare RST at the sequence number after
        # the data, which is what makes the reassembler submit the buffer
        deliveries = ((1, 0, b'first-', False), (2, 6, b'second-', False),
                      (3, 13, b'third', False), (4, 18, b'', True))
        for (number, offset, payload, rst) in deliveries:
            frame = self._make_pcap_frame(seq=seq + offset, payload=payload,
                                          number=number, syn=False, rst=rst)
            packet = pcap.tcp_reassembly(frame)
            self.assertIsNotNone(packet)
            assert packet is not None
            reasm(packet)

        datagram, = reasm.datagram
        self.assertTrue(datagram.completed)
        self.assertEqual(datagram.payload, b'first-second-third')


if __name__ == '__main__':
    unittest.main()
