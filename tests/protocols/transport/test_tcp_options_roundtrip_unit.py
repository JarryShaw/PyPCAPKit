"""#1151 -- ``from_data`` re-emits a parsed TCP option list octet for octet.

:meth:`TCP._make_tcp_options <pcapkit.protocols.transport.tcp.TCP._make_tcp_options>`
keeps the ``NOP`` and ``EOOL`` options it is given, in place, and pads only the
end of the list to a 32-bit boundary. A parsed segment therefore rebuilds with
the same options in the same order and the same data offset.

The option lists below are copied from the SYN segments of the fixture captures,
so the module reads no capture and runs on a fresh checkout.

"""
from __future__ import annotations

import importlib.util
import unittest

from tests._support import reimport_once_per_class

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: TCP option lists as captured, keyed by where they were seen.
CAPTURED_OPTIONS = {
    # MSS, SACK-permitted, timestamps, NOP, window scale: 20 octets.
    'http.pcap': '020405b40402080a31d626a00000000001030306',
    # MSS, NOP, window scale, NOP, NOP, timestamps, SACK-permitted, EOOL and
    # one octet of zero padding after it: 24 octets.
    'tcp.pcap': '020405b4010303060101080a31bcd7fd92520e1704020000',
    # NOP, NOP, timestamps: 12 octets.
    'stream.pcap': '0101080a31d42b65925ed8b7',
}


def segment(options: 'bytes') -> 'bytes':
    """Return a TCP header carrying ``options`` and no payload.

    The ports are not registered to any application protocol, so the rebuild
    does not depend on a payload parser.

    """
    offset = (20 + len(options)) // 4
    return (b'\x30\x39\x30\x3a'           # ports 12345 -> 12346
            + bytes.fromhex('0000000100000000')
            + bytes([offset << 4, 0x02])  # data offset, SYN
            + b'\xff\xff\x00\x00\x00\x00'  # window, checksum, urgent pointer
            + options)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TCPOptionsRoundTripUnitTests(unittest.TestCase):
    """TCP option lists survive a parse and ``from_data`` rebuild unchanged."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_from_data_reproduces_captured_options(self) -> None:
        """A parsed segment rebuilds to its own octets, data offset included."""
        from pcapkit.protocols.transport.tcp import TCP

        for source, options in CAPTURED_OPTIONS.items():
            with self.subTest(source=source):
                raw = segment(bytes.fromhex(options))
                rebuilt = TCP.from_data(TCP(raw).info)
                self.assertEqual(rebuilt.data.hex(), raw.hex())

    def test_from_data_keeps_option_order(self) -> None:
        """The rebuilt segment parses to the same option kinds, in the same order."""
        from pcapkit.protocols.transport.tcp import TCP

        for source, options in CAPTURED_OPTIONS.items():
            with self.subTest(source=source):
                parsed = TCP(segment(bytes.fromhex(options))).info.options
                rebuilt = TCP.from_data(TCP(segment(bytes.fromhex(options))).info).info.options
                self.assertEqual([code for code, _ in rebuilt.items(multi=True)],
                                 [code for code, _ in parsed.items(multi=True)])

    def test_make_pads_the_end_of_the_list_only(self) -> None:
        """Options built from scratch are padded once, after the last option."""
        from pcapkit.const.tcp.option import Option as Enum_Option
        from pcapkit.protocols.transport.tcp import TCP

        tcp = TCP(srcport=12345, dstport=12346, options=[
            (Enum_Option.Window_Scale, {'shift': 7}),
            (Enum_Option.Maximum_Segment_Size, {'mss': 1460}),
        ])
        self.assertEqual(tcp.data[12] >> 4, 7)
        self.assertEqual(tcp.data[20:].hex(), '030307020405b400')

    def test_make_keeps_explicit_nop_options(self) -> None:
        """``NOP`` options passed to ``make()`` are emitted where they were given."""
        from pcapkit.const.tcp.option import Option as Enum_Option
        from pcapkit.protocols.transport.tcp import TCP

        tcp = TCP(srcport=12345, dstport=12346, options=[
            (Enum_Option.No_Operation, {}),
            (Enum_Option.No_Operation, {}),
            (Enum_Option.Timestamps, {'tsval': 1, 'tsecr': 2}),
        ])
        self.assertEqual(tcp.data[12] >> 4, 8)
        self.assertEqual(tcp.data[20:].hex(), '0101080a0000000100000002')


if __name__ == '__main__':
    unittest.main()
