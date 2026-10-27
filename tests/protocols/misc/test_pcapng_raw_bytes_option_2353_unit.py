# -*- coding: UTF-8 -*-
"""Tests for raw ``bytes`` option/record items in PCAP-NG block makers (issue #2353).

``_make_pcapng_options`` and ``_make_nrb_records`` resolve the byte order for
raw ``bytes`` items from the instance's ``_byte`` when set, from the bound
section context otherwise, and from ``sys.byteorder`` when no context is bound.

The option tests observe the resolved byte order through the duplicate-option
check: a raw ``if_name`` option followed by a typed ``if_name`` option is
rejected with ``ProtocolError`` only when both decode to the same code, i.e.
when the raw header is encoded in the resolved byte order. The remaining
option assertions compare the built octets against the equivalent typed-option
build, parse the result back through a real section context and read the
option's actual payload, and check a ``from_data`` rebuild is byte-exact.

The records maker's decoded type is only compared against the all-zero
end-record sentinel, which is byte-order invariant, so its resolved byte order
is not observable from the outside; the NRB test pins the produced octets
against the typed build instead.
"""

import struct
import sys
import unittest

__all__ = ['RawBytesOptionTest', 'RawBytesRecordTest']


def _raw_option(code: 'int', data: 'bytes', byteorder: 'str') -> 'bytes':
    """A raw ``bytes`` option item encoded in the given byte order."""
    fmt = '<HH' if byteorder == 'little' else '>HH'
    return struct.pack(fmt, code, len(data)) + data + b'\x00' * (-len(data) % 4)


class RawBytesOptionTest(unittest.TestCase):
    """Test making blocks with a raw ``bytes`` option item."""

    def test_raw_option_matches_typed_build_without_context(self) -> 'None':
        """A raw bytes option builds octets identical to the typed build (no context)."""
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.protocols.misc.pcapng import PCAPNG

        block = {'linktype': 1, 'snaplen': 0x40000}
        typed = PCAPNG(num=1, sct=1, ctx=None, type=0x00000001,
                       block=dict(block, options=[(OptionType.opt_comment, {'comment': 'hello'})]))
        raw = PCAPNG(num=1, sct=1, ctx=None, type=0x00000001,
                     block=dict(block, options=[_raw_option(1, b'hello', sys.byteorder)]))
        self.assertEqual(raw.data, typed.data)

    def test_raw_option_roundtrips_in_little_endian_section(self) -> 'None':
        """Little-endian section: raw bytes option parses back with its payload."""
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.foundation.engines.pcapng import Context
        from pcapkit.protocols.misc.pcapng import PCAPNG

        shb_bytes = PCAPNG(num=0, sct=1, ctx=None, type=0x0A0D0D0A,
                           block={'byteorder': 'little'}).data
        shb = PCAPNG(shb_bytes, len(shb_bytes), num=0, sct=1, ctx=None)
        ctx = Context(shb.info)

        block = {'linktype': 1, 'snaplen': 0x40000}
        typed = PCAPNG(num=1, sct=1, ctx=ctx, type=0x00000001,
                       block=dict(block, options=[(OptionType.opt_comment, {'comment': 'hello'})]))
        raw = PCAPNG(num=1, sct=1, ctx=ctx, type=0x00000001,
                     block=dict(block, options=[_raw_option(1, b'hello', 'little')]))
        self.assertEqual(raw.data, typed.data)

        parsed = PCAPNG(raw.data, len(raw.data), num=1, sct=1, ctx=ctx)
        comment = parsed.info.options[OptionType.opt_comment].comment
        self.assertEqual(comment, 'hello')
        self.assertEqual(PCAPNG.from_data(parsed.info, num=1, sct=1, ctx=ctx).data, raw.data)

    def test_raw_option_roundtrips_in_big_endian_section(self) -> 'None':
        """Big-endian section: raw bytes option is encoded in the section byte order."""
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.foundation.engines.pcapng import Context
        from pcapkit.protocols.misc.pcapng import PCAPNG

        shb_bytes = PCAPNG(num=0, sct=1, ctx=None, type=0x0A0D0D0A,
                           block={'byteorder': 'big'}).data
        shb = PCAPNG(shb_bytes, len(shb_bytes), num=0, sct=1, ctx=None)
        ctx = Context(shb.info)

        block = {'linktype': 1, 'snaplen': 0x40000}
        typed = PCAPNG(num=1, sct=1, ctx=ctx, type=0x00000001,
                       block=dict(block, options=[(OptionType.opt_comment, {'comment': 'hello'})]))
        raw = PCAPNG(num=1, sct=1, ctx=ctx, type=0x00000001,
                     block=dict(block, options=[_raw_option(1, b'hello', 'big')]))
        self.assertEqual(raw.data, typed.data)

        parsed = PCAPNG(raw.data, len(raw.data), num=1, sct=1, ctx=ctx)
        comment = parsed.info.options[OptionType.opt_comment].comment
        self.assertEqual(comment, 'hello')
        self.assertEqual(PCAPNG.from_data(parsed.info, num=1, sct=1, ctx=ctx).data, raw.data)

    def test_duplicate_check_observes_resolved_byte_order(self) -> 'None':
        """A raw ``if_name`` option followed by a typed one is rejected (dup check)
        only when the raw header decodes to the same code, i.e. when it is
        encoded in the resolved byte order."""
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.foundation.engines.pcapng import Context
        from pcapkit.protocols.misc.pcapng import PCAPNG
        from pcapkit.utilities.exceptions import ProtocolError

        block = {'linktype': 1, 'snaplen': 0x40000}

        with self.subTest(section='little'):
            shb_bytes = PCAPNG(num=0, sct=1, ctx=None, type=0x0A0D0D0A,
                               block={'byteorder': 'little'}).data
            ctx = Context(PCAPNG(shb_bytes, len(shb_bytes), num=0, sct=1, ctx=None).info)
            with self.assertRaises(ProtocolError):
                PCAPNG(num=1, sct=1, ctx=ctx, type=0x00000001,
                       block=dict(block, options=[_raw_option(2, b'eth0', 'little'),
                                                  (OptionType.if_name, {'name': 'eth0'})]))

        with self.subTest(section='big'):
            shb_bytes = PCAPNG(num=0, sct=1, ctx=None, type=0x0A0D0D0A,
                               block={'byteorder': 'big'}).data
            ctx = Context(PCAPNG(shb_bytes, len(shb_bytes), num=0, sct=1, ctx=None).info)
            with self.assertRaises(ProtocolError):
                PCAPNG(num=1, sct=1, ctx=ctx, type=0x00000001,
                       block=dict(block, options=[_raw_option(2, b'eth0', 'big'),
                                                  (OptionType.if_name, {'name': 'eth0'})]))

        with self.subTest(section='none'):
            with self.assertRaises(ProtocolError):
                PCAPNG(num=1, sct=1, ctx=None, type=0x00000001,
                       block=dict(block, options=[_raw_option(2, b'eth0', sys.byteorder),
                                                  (OptionType.if_name, {'name': 'eth0'})]))


    def test_byte_order_tiers_are_pinned(self) -> 'None':
        """``_byte`` set by an earlier SHB build takes precedence over the
        host byte order, and the host byte order is used on a fresh instance
        with no context."""
        from unittest import mock

        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.protocols.misc.pcapng import PCAPNG
        from pcapkit.utilities.exceptions import ProtocolError

        block = {'linktype': 1, 'snaplen': 0x40000}

        with self.subTest(tier='_byte'):
            instance = PCAPNG(num=0, sct=1, ctx=None, type=0x0A0D0D0A,
                              block={'byteorder': 'big'})
            with self.assertRaises(ProtocolError):
                instance.make(0x00000001, kind='Interface Description Block',
                              block=dict(block, options=[_raw_option(2, b'eth0', 'big'),
                                                         (OptionType.if_name, {'name': 'eth0'})]))

        with self.subTest(tier='host'):
            with mock.patch.object(sys, 'byteorder', 'big'):
                with self.assertRaises(ProtocolError):
                    PCAPNG(num=1, sct=1, ctx=None, type=0x00000001,
                           block=dict(block, options=[_raw_option(2, b'eth0', 'big'),
                                                      (OptionType.if_name, {'name': 'eth0'})]))


class RawBytesRecordTest(unittest.TestCase):
    """Test making an NRB with a raw ``bytes`` record item."""

    def test_raw_record_matches_typed_build_without_context(self) -> 'None':
        """A raw bytes record builds octets identical to the typed build (no context)."""
        from pcapkit.const.pcapng.record_type import RecordType
        from pcapkit.protocols.misc.pcapng import PCAPNG

        typed = PCAPNG(num=1, sct=1, ctx=None, type=0x00000004,
                       block={'records': [(RecordType.nrb_record_ipv4,
                                           {'ip': '8.8.8.8', 'names': ['1.1.1.1']})]})
        # the typed IPv4 record builder writes the padded length into the
        # header, so the raw item is padded before encoding
        raw = PCAPNG(num=1, sct=1, ctx=None, type=0x00000004,
                     block={'records': [_raw_option(1, b'\x08\x08\x08\x081.1.1.1\x00',
                                                    sys.byteorder)]})
        self.assertEqual(raw.data, typed.data)


if __name__ == '__main__':
    unittest.main()
