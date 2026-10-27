# -*- coding: UTF-8 -*-
"""Tests for raw ``bytes`` option/record items in PCAP-NG block makers (issue #2353).

``_make_pcapng_options`` and ``_make_nrb_records`` read ``self._byte`` for raw
``bytes`` items, although only the SHB (and the systemd journal entry maker)
ever set that attribute. The byte order therefore comes from the bound section
context when one exists, and from ``sys.byteorder`` otherwise.

The assertions compare the built octets against the equivalent typed-option
build, parse the result back with a real section context and read the option's
actual payload, and check a ``from_data`` rebuild is byte-exact.
"""

import unittest

__all__ = ['RawBytesOptionTest', 'RawBytesRecordTest']


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
                     block=dict(block, options=[b'\x01\x00\x05\x00hello\x00\x00\x00']))
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
                     block=dict(block, options=[b'\x01\x00\x05\x00hello\x00\x00\x00']))
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
                     block=dict(block, options=[b'\x00\x01\x00\x05hello\x00\x00\x00']))
        self.assertEqual(raw.data, typed.data)

        parsed = PCAPNG(raw.data, len(raw.data), num=1, sct=1, ctx=ctx)
        comment = parsed.info.options[OptionType.opt_comment].comment
        self.assertEqual(comment, 'hello')
        self.assertEqual(PCAPNG.from_data(parsed.info, num=1, sct=1, ctx=ctx).data, raw.data)


class RawBytesRecordTest(unittest.TestCase):
    """Test making an NRB with a raw ``bytes`` record item."""

    def test_raw_record_matches_typed_build_without_context(self) -> 'None':
        """A raw bytes record builds octets identical to the typed build (no context)."""
        from pcapkit.const.pcapng.record_type import RecordType
        from pcapkit.protocols.misc.pcapng import PCAPNG

        typed = PCAPNG(num=1, sct=1, ctx=None, type=0x00000004,
                       block={'records': [(RecordType.nrb_record_ipv4,
                                           {'ip': '8.8.8.8', 'names': ['1.1.1.1']})]})
        raw = PCAPNG(num=1, sct=1, ctx=None, type=0x00000004,
                     block={'records': [b'\x01\x00\x0c\x00\x08\x08\x08\x081.1.1.1\x00']})
        self.assertEqual(raw.data, typed.data)


if __name__ == '__main__':
    unittest.main()
