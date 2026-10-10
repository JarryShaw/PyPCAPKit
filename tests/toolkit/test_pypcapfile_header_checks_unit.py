"""The header checks :mod:`pcapkit.toolkit.pypcapfile` makes as the default engine does.

`pypcapfile`_ slices an IPv4 header at its IHL however few octets were captured,
never parses its options, has no IPv6 decoder and no AH decoder, and reads a TCP
Data Offset below 5 words as if it were 5. The toolkit reads such frames as the
default engine does instead: GH#1590 (Data Offset below 5), GH#1591 (IHL past
the packet), GH#1592 (IPv4 in IPv6), GH#1593 (TCP behind an IPv4 AH header) and
GH#1596 (IPv4 options the default engine rejects).

These tests use stand-ins for `pypcapfile`_'s decoders, so run without it. The
ones that read real captures with both engines need it, so live in
:mod:`tests.toolkit.test_pypcapfile_unit`, which the PyPCAPFile CI cell runs.

.. _pypcapfile: https://github.com/kisom/pypcapfile

"""
from __future__ import annotations

import unittest
import warnings
from unittest import mock

from tests._support import reimport_once_per_class
from tests.foundation import _roundtrip as wire
from tests.toolkit import test_pypcapfile_unit as base


@unittest.skipUnless(base.HAS_RUNTIME, 'runtime dependencies not installed')
class PyPCAPFileHeaderCheckTests(unittest.TestCase):
    """Stand-ins for the decoded layers, so `pypcapfile`_ is not needed."""

    decline = base.PyPCAPFileTCPOverIPv6Tests.decline

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_data_offset_below_5_is_no_tcp(self) -> None:
        # C.f. #1590: no TCP input, and no warning either.
        for words in range(5):
            with self.subTest(words=words):
                segment = base.data_offset(base.make_tcp(b'data'), words)
                frame = base.FakeEthernet(base.FakeIP(segment))
                self.assertEqual(self.decline(base.make_packet(frame)), [])

    def test_ipv4_header_past_the_packet_is_no_ipv4(self) -> None:
        # C.f. #1591: pypcapfile slices the 60-octet header of a 40-octet packet
        # as 20 octets of options and no payload.
        from pcapkit.toolkit.pypcapfile import ipv4_reassembly

        for label, layer in (
            ('udp', base.FakeIP(b'', p=17, hl=15, opt=b'\x01' * 20, len=40)),
            ('tcp', base.FakeIP(b'', hl=15, opt=base.make_tcp(b''), len=40)),
            ('one option word short', base.FakeIP(b'', p=17, hl=7, opt=b'\x01' * 4, len=24)),
        ):
            with self.subTest(case=label):
                packet = base.make_packet(base.FakeEthernet(layer))
                self.assertIsNone(ipv4_reassembly(packet, count=1))
                self.assertEqual(self.decline(packet), [])

    def test_ipv4_options_the_default_engine_rejects_are_no_ipv4(self) -> None:
        # C.f. #1596: a fragment with such options is no IPv4 input, a segment
        # behind them no TCP input; one with options it accepts is both.
        from pcapkit.toolkit.pypcapfile import ipv4_reassembly

        for options in base.BAD_IPV4_OPTIONS:
            with self.subTest(options=options.hex()):
                packet = base.make_packet(base.FakeEthernet(base.FakeIP(b'x' * 16, p=17, hl=6,
                                                                         opt=options)))
                self.assertIsNone(ipv4_reassembly(packet, count=1))
                tcp = base.make_packet(base.FakeEthernet(base.FakeIP(base.make_tcp(b'data'), hl=6,
                                                                      opt=options)))
                self.assertEqual(self.decline(tcp), [])
        for options in base.GOOD_IPV4_OPTIONS:
            with self.subTest(options=options.hex()):
                packet = base.make_packet(base.FakeEthernet(base.FakeIP(b'x' * 16, p=17, hl=6,
                                                                         opt=options)))
                data = ipv4_reassembly(packet, count=1)
                self.assertIsNotNone(data)
                self.assertEqual(data.header[20:], options)

    def test_options_are_parsed_once_per_frame(self) -> None:
        # The adapters each fetch a frame's network layer; the default engine's
        # parser is asked once between them, and not at all without options.
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit import pypcapfile

        pypcapfile._default_accepts.cache_clear()
        real = pypcapfile.Protocol_IPv4
        frames = [base.FakeEthernet(base.FakeIP(b'x' * 16, p=17, hl=6, opt=options))
                  for options in (*base.GOOD_IPV4_OPTIONS, base.BAD_IPV4_OPTIONS[0])]
        frames.append(base.FakeEthernet(base.FakeIP(b'x' * 16, p=17)))
        with mock.patch.object(pypcapfile, 'Protocol_IPv4', side_effect=real) as parser:
            for count, frame in enumerate(frames, start=1):
                packet = base.make_packet(frame)
                pypcapfile.ipv4_reassembly(packet, count=count)
                pypcapfile.tcp_reassembly(packet, count=count)
                pypcapfile.tcp_traceflow(packet, data_link=LinkType.ETHERNET, count=count)
        self.assertEqual([call.args[0][20:] for call in parser.call_args_list],
                         [*base.GOOD_IPV4_OPTIONS, base.BAD_IPV4_OPTIONS[0]])

    def test_parsing_options_leaves_the_warnings_filters_and_the_logger_level_alone(self) -> None:
        import logging

        from pcapkit.toolkit.pypcapfile import ipv4_reassembly

        logger = logging.getLogger('pcapkit')
        level, filters = logger.level, list(warnings.filters)
        for count, options in enumerate((*base.BAD_IPV4_OPTIONS, *base.GOOD_IPV4_OPTIONS), start=1):
            frame = base.FakeEthernet(base.FakeIP(b'x' * 16, p=17, hl=6, opt=options))
            ipv4_reassembly(base.make_packet(frame), count=count)
            self.assertEqual(warnings.filters, filters)
            self.assertEqual(logger.level, level)

    def test_ipv4_in_ipv6_is_found(self) -> None:
        # C.f. #1592: the first IPv4 packet inside IPv6, however it is wrapped,
        # goes to pypcapfile's own IPv4 decoder.
        from pcapkit.toolkit.pypcapfile import _ipv4_in_ipv6

        inner = base.udp_fragment()
        for label, frame in (
            ('4in6', base.ipv6_frame(wire.ipv6(inner, nxt=4))),
            ('802.1Q, 4in6', base.tagged_frame(wire.ipv6(inner, nxt=4), 0x86DD, base.C_TAG)),
            ('hop-by-hop', base.ipv6_frame(wire.ipv6(bytes([4, 0, 1, 4, 0, 0, 0, 0]) + inner, nxt=0))),
            ('first fragment', base.ipv6_frame(wire.ipv6_fragment(inner, mf=True, nxt=4))),
            ('ah', base.ipv6_frame(wire.ipv6(base.ah(4) + inner, nxt=51))),
            ('4in6in6', base.ipv6_frame(wire.ipv6(wire.ipv6(inner, nxt=4), nxt=41))),
            ('ethernet padding', base.ipv6_frame(wire.ipv6(inner, nxt=4) + bytes(6))),
        ):
            with self.subTest(case=label), mock.patch.dict('sys.modules', base.fake_ip_decoder()) as modules:
                IP = modules['pcapfile.protocols.network.ip'].IP
                self.assertIsInstance(_ipv4_in_ipv6(base.make_packet(frame)), IP)
                self.assertEqual(IP.calls, [(inner, 0)])

    def test_no_ipv4_in_ipv6_where_the_default_engine_finds_none(self) -> None:
        from pcapkit.toolkit.pypcapfile import _ipv4_in_ipv6

        inner = base.udp_fragment()
        for label, frame, decoded in (
            ('ipv4 over ethernet', base.FakeEthernet(base.FakeIP(inner, p=4)), False),
            ('ipv6, udp', base.ipv6_frame(wire.ipv6(wire.udp(b'x'), nxt=17)), False),
            ('ipv6 later fragment', base.ipv6_frame(wire.ipv6_fragment(inner, offset=8, nxt=4)), False),
            ('ipv6 truncated', base.ipv6_frame(wire.ipv6(inner, nxt=4)[:39]), False),
            ('esp', base.ipv6_frame(wire.ipv6(bytes(8) + inner, nxt=50)), False),
            ('802.1Q, no ipv6 header', base.tagged_frame(b'', 0x86DD, base.C_TAG), False),
            ('undecoded frame', b'\x00' * 20, False),
            # pypcapfile never decodes IPv6, so has nothing to warn of
            ('inner ihl 4', base.ipv6_frame(wire.ipv6(base.ihl(inner, 4), nxt=4)), True),
            ('inner ihl past the packet', base.ipv6_frame(wire.ipv6(base.ihl(inner, 15), nxt=4)), True),
        ):
            with self.subTest(case=label), warnings.catch_warnings(record=True) as caught, \
                    mock.patch.dict('sys.modules', base.fake_ip_decoder()) as modules:
                warnings.simplefilter('always')
                IP = modules['pcapfile.protocols.network.ip'].IP
                self.assertIsNone(_ipv4_in_ipv6(base.make_packet(frame)))
                self.assertEqual(bool(IP.calls), decoded)
                self.assertEqual(caught, [])

    def test_transport_reads_tcp_behind_ah(self) -> None:
        # C.f. #1593: the default engine dissects AH over IPv4, and the TCP behind it.
        from pcapkit.toolkit.pypcapfile import _transport

        segment = base.make_tcp(b'data')
        options = base.make_tcp(b'data', options=b'\x02\x04\x05\xb4')  # MSS
        for label, payload, want in (
            ('ah', base.ah(6) + segment, segment),
            ('ah of the fixed part only', base.ah(6, 1) + segment, segment),
            ('two ah', base.ah(51) + base.ah(6, 1) + segment, segment),
            ('ah, tcp options', base.ah(6) + options, options),
        ):
            with self.subTest(case=label):
                self.assertEqual(_transport(base.FakeIP(payload, p=51)), want)

    def test_no_tcp_behind_ah_where_the_default_engine_finds_none(self) -> None:
        # Behind AH there is no fall-back to the raw octets (#1518), so a TCP
        # header its parser rejects is no TCP -- and no TCP over IPv6 either.
        from pcapkit.toolkit.pypcapfile import _transport

        segment = base.make_tcp(b'data')
        for label, payload, fields in (
            ('payload length 0', base.ah(6, 0) + segment, {}),
            ('ah cut short', base.ah(6)[:15], {}),
            ('ah under the fixed part', base.ah(6)[:11], {}),
            ('ah, udp', base.ah(17) + wire.udp(b'x'), {}),
            ('ah, tcp truncated', base.ah(6) + segment[:19], {}),
            ('ah, data offset 4', base.ah(6) + base.data_offset(segment, 4), {}),
            ('ah, data offset past the capture', base.ah(6) + base.data_offset(segment, 9), {}),
            ('ah, mss option of length 3', base.ah(6) + base.make_tcp(b'', options=b'\x02\x03\x00\x00'), {}),
            ('later fragment', base.ah(6) + segment, {'off': 3}),
        ):
            with self.subTest(case=label):
                layer = base.FakeIP(payload, p=51, **fields)
                self.assertIsNone(_transport(layer))
                self.assertEqual(self.decline(base.make_packet(base.FakeEthernet(layer))), [])

    def test_transport_reads_tcp_behind_ipv6_extension_headers(self) -> None:
        # C.f. #1597: inside IPv4 too, the default engine dissects these headers
        # and what each one's Next Header names.
        from pcapkit.toolkit.pypcapfile import _transport

        segment = base.make_tcp(b'data')
        cases = [(label, protocol, header) for label, protocol, header in base.IPV4_EXTENSION_HEADERS]
        cases += [('hop-by-hop, destination options', 0, base.options_header(60) + base.options_header(6)),
                  ('destination options, ah', 60, base.options_header(51) + base.ah(6)),
                  ('ah, hop-by-hop', 51, base.ah(0) + base.options_header(6))]
        for label, protocol, header in cases:
            with self.subTest(case=label):
                self.assertEqual(_transport(base.FakeIP(header + segment, p=protocol)), segment)

    def test_no_tcp_behind_ipv6_extension_headers_where_the_default_engine_finds_none(self) -> None:
        from pcapkit.toolkit.pypcapfile import _transport

        segment = base.make_tcp(b'data')
        for label, protocol, payload in (
            ('padn of length 9', 60, base.options_header(6, b'\x01\x09' + bytes(4)) + segment),
            ('header length past the packet', 60, bytes([6, 9]) + bytes(6) + segment),
            ('cut short', 0, base.options_header(6)[:4]),
            # read as raw octets, as fewer were captured than the header needs
            ('routing header cut short', 43, bytes([6, 0, 0, 0])),
            ('routing type 3, under its addresses', 43, bytes([6, 0, 3, 1]) + bytes(4) + segment),
            ('hip header length 3', 139, bytes([6, 3, 0x01, 0x21]) + bytes(28) + segment),
            ('shim6, whose parser refuses ipv4', 140, bytes([6, 0, 0x80, 0]) + bytes(4) + segment),
            ('no next header', 59, segment),
            ('tcp option of length 3', 60,
             base.options_header(6) + base.make_tcp(b'', options=b'\x02\x03\x00\x00')),
        ):
            with self.subTest(case=label):
                layer = base.FakeIP(payload, p=protocol)
                self.assertIsNone(_transport(layer))
                self.assertEqual(self.decline(base.make_packet(base.FakeEthernet(layer))), [])

    def test_extension_headers_are_parsed_once_per_frame(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit import pypcapfile

        pypcapfile._default_extension_header.cache_clear()
        layer = base.FakeIP(base.options_header(60) + base.options_header(17) + wire.udp(b'x'), p=0)
        packet = base.make_packet(base.FakeEthernet(layer))
        pypcapfile.ipv4_reassembly(packet, count=1)
        pypcapfile.tcp_reassembly(packet, count=1)
        pypcapfile.tcp_traceflow(packet, data_link=LinkType.ETHERNET, count=1)
        self.assertEqual(pypcapfile._default_extension_header.cache_info().misses, 2)

    def test_tunnelled_tcp_behind_ah_warns(self) -> None:
        tcp4 = wire.ipv4(base.TCP_SEGMENT, proto=6)
        for label, frame in (
            ('4in4 behind ah', base.tunnel(base.ah(4) + tcp4, 51)),
            ('6in4 behind ah', base.tunnel(base.ah(41) + wire.ipv6(base.TCP_SEGMENT, nxt=6), 51)),
            ('4in4, inner ah', base.tunnel(wire.ipv4(base.ah(6) + base.TCP_SEGMENT, proto=51), 4)),
            ('4in4 behind destination options', base.tunnel(base.options_header(4) + tcp4, 60)),
        ):
            with self.subTest(case=label):
                messages = self.decline(base.make_packet(frame))
                self.assertEqual(len(messages), 1, messages)
                self.assertTrue(messages[0].startswith('Frame 1: TCP tunnelled in IP'), messages)


if __name__ == '__main__':
    unittest.main()
