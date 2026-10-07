# -*- coding: utf-8 -*-
"""TCP headers and options rebuild byte for byte.

GitHub issues #1211, #1218 and #1219, all found by the transport round-trip
audit (#1202). Each case is a whole TCP segment, and
:meth:`~pcapkit.protocols.protocol.ProtocolBase.from_data` over the parsed
segment has to reproduce it:

* #1211 -- the reserved bits of the header (octet 12, bits 4-6), of the POC-SP
  option (``Filler``) and of the Quick-Start Response option (``Resv.`` and
  ``R``) were written back as zero;
* #1218 -- the octets after an End of Option List option were dropped, and the
  Data Offset was recomputed from what was left, shrinking the header; they
  are kept now, but only while the options still end with that option, so an
  edited option list still builds;
* #1219 -- the User Timeout option lost its ``G`` bit, the maker choosing the
  granularity by the size of the value instead; the parsed unit is kept while
  the value still fits in it.

Every case builds its own octets in memory and reads no capture. :class:`TCP`
is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, not at module load.

"""

import datetime
import unittest

from tests._support import reimport_once_per_class

#: TCP header without its offset/flags octets: ports 1234 and 80, sequence 1,
#: acknowledgement 2; the window, checksum and urgent pointer follow them.
HEAD = bytes.fromhex('04d2' '0050' '00000001' '00000002')
TAIL = bytes.fromhex('03e8' 'abcd' '0000')

#: ACK flag, the only one set.
ACK = 0x10

#: ``name -> (octet 12, option octets)``; ``None`` for octet 12 means a Data
#: Offset matching the options, with the reserved bits and ``NS`` clear.
SEGMENTS = {
    # 1211
    'header-reserved': (0x5e, ''),
    'header-reserved-ns': (0x5f, ''),
    'pocsp-reserved': (None, '0a033f00'),
    'qs-reserved': (None, '1b08834012345679'),
    'qs-reserved-all': (None, '1b08f340fffffffc'),
    # 1218
    'eool-then-options': (None, '00010101 020405b4'),
    'eool-then-zeros': (None, '020405b4 00000000'),
    'eool-then-octets': (None, '020405b4 00aabbcc'),
    'mss-nop-eool-padded': (None, '020405b4 0100 000000000000'),
    # 1219
    'uto-minutes': (None, '1c048005'),
    'uto-seconds': (None, '1c04012c'),
    'uto-minutes-small': (None, '1c048001'),
}


def segment(octet12: 'int | None', option: str, payload: bytes = b'PAY') -> bytes:
    """Build a TCP segment carrying ``option`` and ``payload``."""
    opt = bytes.fromhex(option.replace(' ', ''))
    assert len(opt) % 4 == 0, option
    if octet12 is None:
        octet12 = (5 + len(opt) // 4) << 4
    return HEAD + bytes([octet12, ACK]) + TAIL + opt + payload


class TestTCPRoundTrip(unittest.TestCase):
    """Pin the wire form of the TCP header fields and options the audit flagged."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def parse(self, name: str) -> 'tuple[bytes, object]':
        from pcapkit.protocols.transport.tcp import TCP

        raw = segment(*SEGMENTS[name])
        return raw, TCP(raw, len(raw))

    def option(self, name: str, kind: str) -> 'object':
        from pcapkit.const.tcp.option import Option

        _, tcp = self.parse(name)
        return tcp.info.options[getattr(Option, kind)]

    def test_from_data_rebuilds_byte_for_byte(self) -> None:
        from pcapkit.protocols.transport.tcp import TCP

        for name in SEGMENTS:
            with self.subTest(segment=name):
                raw, tcp = self.parse(name)
                self.assertEqual(TCP.from_data(tcp.info).data.hex(), raw.hex())

    def test_header_reserved_bits_are_kept(self) -> None:
        for name, reserved in (('header-reserved', 0b111), ('header-reserved-ns', 0b111)):
            with self.subTest(segment=name):
                _, tcp = self.parse(name)
                self.assertEqual(tcp.info.flags.reserved, reserved)
        _, tcp = self.parse('header-reserved-ns')
        self.assertTrue(tcp.info.flags.ns)

    def test_make_writes_the_header_reserved_bits(self) -> None:
        from pcapkit.protocols.transport.tcp import TCP

        data = object.__new__(TCP).make(reserved=0b101, ns=True).pack()
        self.assertEqual(data[12], 0x5b)

    def test_option_reserved_bits_are_kept(self) -> None:
        pocsp = self.option('pocsp-reserved', 'Partial_Order_Service_Profile')
        self.assertEqual((pocsp.start, pocsp.end, pocsp.reserved), (False, False, 0x3f))

        qs = self.option('qs-reserved', 'Quick_Start_Response')
        self.assertEqual((qs.reserved, qs.nonce_reserved), (0x8, 0b01))
        self.assertEqual(qs.nonce, 0x12345679 >> 2)

        qs = self.option('qs-reserved-all', 'Quick_Start_Response')
        self.assertEqual((qs.reserved, qs.nonce_reserved), (0xf, 0b00))

    def test_octets_after_eool_are_kept(self) -> None:
        cases = {
            'eool-then-options': bytes.fromhex('010101020405b4'),
            'eool-then-zeros': bytes(3),
            'eool-then-octets': bytes.fromhex('aabbcc'),
        }
        for name, padding in cases.items():
            with self.subTest(segment=name):
                raw, tcp = self.parse(name)
                self.assertEqual(tcp.info.padding, padding)
                self.assertEqual(tcp.info.hdr_len, raw[12] >> 4 << 2)

    def test_header_keeps_its_length_after_eool(self) -> None:
        from pcapkit.protocols.transport.tcp import TCP

        raw, tcp = self.parse('eool-then-options')
        rebuilt = TCP.from_data(tcp.info).data
        self.assertEqual(rebuilt[12] >> 4, 7)
        self.assertEqual(rebuilt[28:], b'PAY')

    def test_padding_is_dropped_once_the_eool_is_edited_out(self) -> None:
        from pcapkit.const.tcp.option import Option
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.transport.tcp import TCP

        _, tcp = self.parse('mss-nop-eool-padded')
        self.assertEqual(tcp.info.padding, bytes(6))
        mss, nop, eool = Option.Maximum_Segment_Size, Option.No_Operation, Option.End_of_Option_List

        #: ``removed kinds -> (Data Offset, option kinds read back)``; the
        #: options left over are aligned with NOPs and an EOOL as for any list.
        cases = {
            'eool': ({eool}, 7, [mss, nop, nop, nop, eool]),
            'nop-and-eool': ({nop, eool}, 6, [mss]),
            'every-option': ({mss, nop, eool}, 5, None),
        }
        for name, (removed, offset, kinds) in cases.items():
            with self.subTest(removed=name):
                kept = OrderedMultiDict()
                for kind, opt in tcp.info.options.items(multi=True):
                    if kind not in removed:
                        kept.add(kind, opt)
                kwargs = TCP._make_data(tcp.info)
                kwargs['options'] = kept

                rebuilt = TCP(**kwargs).data
                self.assertEqual(rebuilt[12] >> 4, offset)
                self.assertEqual(rebuilt[offset * 4:], b'PAY')

                info = TCP(rebuilt, len(rebuilt)).info
                if kinds is None:
                    self.assertNotIn('options', info)
                else:
                    self.assertEqual([kind for kind, _ in info.options.items(multi=True)], kinds)

    def test_make_drops_padding_without_eool(self) -> None:
        from pcapkit.const.tcp.option import Option
        from pcapkit.protocols.transport.tcp import TCP

        proto = object.__new__(TCP)
        self.assertEqual(proto.make(padding=b'\x01').pack()[12] >> 4, 5)
        made = proto.make(options=[(Option.Maximum_Segment_Size, {'mss': 1460})], padding=b'\x01')
        self.assertEqual(made.pack()[12] >> 4, 6)

    def test_user_timeout_keeps_its_granularity(self) -> None:
        cases = {
            'uto-minutes': (True, datetime.timedelta(minutes=5)),
            'uto-seconds': (False, datetime.timedelta(seconds=300)),
            'uto-minutes-small': (True, datetime.timedelta(minutes=1)),
        }
        for name, (granularity, timeout) in cases.items():
            with self.subTest(segment=name):
                opt = self.option(name, 'User_Timeout_Option')
                self.assertEqual((opt.granularity, opt.timeout), (granularity, timeout))

    def test_make_honours_an_explicit_granularity(self) -> None:
        from pcapkit.const.tcp.option import Option
        from pcapkit.protocols.transport.tcp import TCP

        proto = object.__new__(TCP)
        code = Option.User_Timeout_Option
        minutes = proto._make_mode_timeout(code, timeout=300, granularity=True)
        self.assertEqual(minutes.pack().hex(), '1c048005')
        seconds = proto._make_mode_timeout(code, timeout=300)
        self.assertEqual(seconds.pack().hex(), '1c04012c')
        # 40000 seconds does not fit in 15 bits, so minutes are chosen: 666.
        large = proto._make_mode_timeout(code, timeout=40000)
        self.assertEqual(large.pack().hex(), '1c04829a')
        large = proto._make_mode_timeout(code, timeout=40000, granularity=False)
        self.assertEqual(large.pack().hex(), '1c04829a')

    def test_edited_user_timeout_switches_unit_when_it_no_longer_fits(self) -> None:
        from pcapkit.protocols.data.transport.tcp import UserTimeout
        from pcapkit.protocols.transport.tcp import TCP
        from pcapkit.utilities.exceptions import ProtocolError

        proto = object.__new__(TCP)
        cases = {
            # parsed in seconds, edited past 15 bits of seconds -> minutes
            'uto-seconds': (datetime.timedelta(seconds=40000), '1c04829a'),
            # parsed in minutes, edited to a part of a minute -> seconds
            'uto-minutes': (datetime.timedelta(seconds=90), '1c04005a'),
        }
        for name, (timeout, wire) in cases.items():
            with self.subTest(segment=name):
                opt = self.option(name, 'User_Timeout_Option')
                edited = UserTimeout(kind=opt.kind, length=opt.length, timeout=timeout,
                                     granularity=opt.granularity)
                self.assertEqual(proto._make_mode_timeout(opt.kind, edited).pack().hex(), wire)

        opt = self.option('uto-seconds', 'User_Timeout_Option')
        with self.assertRaisesRegex(ProtocolError, r'too large: 1966080 seconds'):
            proto._make_mode_timeout(opt.kind, timeout=0x8000 * 60)


if __name__ == '__main__':
    unittest.main()
