# -*- coding: utf-8 -*-
"""GitHub issue #2614: PCAP-NG's signed, sentinel and address fields on the base helpers.

The signed and sentinel fields were reviewed one by one against the PCAP-NG
specification (draft-ietf-opsawg-pcapng):

* ``if_tsoffset`` is a signed 64-bit integer with no sentinel, so a value its
  64 bits cannot hold raises through
  :meth:`~pcapkit.protocols.protocol.Protocol._make_sint` rather than being
  written truncated, which read back as another value;
* ``if_tzone`` gets the same check over 32 bits, by pcapkit's choice so that
  it round-trips (#2617): the specification fixes only its length, and the
  value is signed because the schema's ``Int32Field`` reads it so (#1340);
* the IDB's SnapLen is unsigned, and its sentinel -- 0, no limit -- is in range,
  so it is checked by :meth:`~pcapkit.protocols.protocol.Protocol._make_uint`;
* the obsolete Packet Block's Drops Count is a 16-bit counter the schema's
  ``UInt16Field`` reads unsigned, and its "not available" sentinel, ``xFFFF`` in
  hexadecimal (Appendix A, Drops Count), is in range -- like SnapLen's -- so it is
  checked by :meth:`~pcapkit.protocols.protocol.Protocol._make_uint` over 16 bits.
  The specification never spells it -1 and the reader returns 65535, so there is
  no spelling for masking to keep, and a ``-1``, a value past ``0xFFFF`` or a
  :obj:`bool` is refused rather than written as another count;
* the SHB's Section Length is signed, and the specification spells its "not
  specified" -1 as ``0xFFFFFFFFFFFFFFFF`` as well, the reader returning -1. So
  :meth:`~pcapkit.protocols.protocol.Protocol._make_sint` takes ``-2 ** 63`` to
  ``2 ** 64 - 1``, both spellings of the sentinel write the same octets, and the
  field's own packing maps the unsigned spelling onto the signed one -- the only
  masking left. A value past either end, a :obj:`bool` or a non-integer is
  refused (#2617). That is what sets it apart from Drops Count above, whose
  sentinel has no signed spelling.

``if_tsoffset`` and ``if_tzone`` are checked over the signed range alone, which
already refuses a :obj:`bool` and a value past either end: neither has a
sentinel, so no second spelling is needed, and one would read back as another
value (#2617).

The EUI-64 address of ``if_EUIaddr`` goes through the base MAC address pair with
``size=8``, so the module keeps no address pattern of its own.

The padding sites on :func:`~pcapkit.corekit.schema.padding.pad_length` that no
other test reaches are pinned too: a custom block's data before its options, its
option area, and a Simple Packet Block whose data ends exactly at the padding of
its original length.

Every case builds its own octets in memory and reads no capture.

:mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import datetime
import struct
import sys
import unittest
import warnings
from typing import TYPE_CHECKING

from tests.protocols.misc.test_pcapng_roundtrip2_unit import PCAPNGTestCase

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): exercises the integer bounds of signed and unsigned fields,
#: which are ``int`` and :mod:`struct` edge cases.
__tier__ = 'ALL'


class TestPCAPNGValueHelpers(PCAPNGTestCase):
    """Pin how the reviewed PCAP-NG fields check, pack and parse back."""

    def _idb(self, snaplen: 'Any' = 0x40000, **options: 'Any') -> 'Any':
        """Make an Ethernet Interface Description Block with the given options."""
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.protocols.misc.pcapng import PCAPNG

        return PCAPNG(num=2, sct=1, ctx=self._context(), type=BlockType.Interface_Description_Block,
                      block={'linktype': LinkType.ETHERNET, 'snaplen': snaplen,
                             'options': [(OptionType[code], args) for code, args in options.items()]})

    def _reparse(self, made: 'Any') -> 'Any':
        """Parse the octets of a made block back into its data model."""
        return self._parse(made.data).info

    def assertRefused(self, message: 'str', **kwargs: 'Any') -> None:  # pylint: disable=invalid-name
        """Making an IDB from ``kwargs`` raises :exc:`ProtocolError` with exactly ``message``."""
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaises(ProtocolError) as context:
            self._idb(**kwargs)
        self.assertEqual(str(context.exception), message)

    def test_tzone_outside_the_signed_field_is_refused(self) -> None:
        for tzone, shown in ((2 ** 31, 2 ** 31), (-2 ** 31 - 1, -2 ** 31 - 1), (2 ** 40, 2 ** 40),
                             (datetime.timedelta(seconds=2 ** 31), 2 ** 31), (True, True)):
            with self.subTest(tzone=tzone):
                self.assertRefused(f'PCAP-NG: invalid [if_tzone] tzone: {shown!r}', if_tzone={'tzone': tzone})

    def test_tzone_bounds_read_back_unchanged(self) -> None:
        from pcapkit.const.pcapng.option_type import OptionType

        for seconds in (-2 ** 31, -86400, -1, 0, 3600, 2 ** 31 - 1):
            with self.subTest(tzone=seconds):
                # an offset of a day or more warns as it is read, and is kept (#1340)
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    info = self._reparse(self._idb(if_tzone={'tzone': seconds}))
                zone = info.options[OptionType.if_tzone].timezone
                offset = zone if isinstance(zone, datetime.timedelta) else zone.utcoffset(None)
                self.assertEqual(offset, datetime.timedelta(seconds=seconds))

    def test_tsoffset_outside_the_signed_field_is_refused(self) -> None:
        # ``None`` is refused rather than written as zero, a non-integer rather than failing to pack
        for offset in (2 ** 63, -2 ** 63 - 1, True, 1.5, None, '1'):
            with self.subTest(offset=offset):
                self.assertRefused(f'PCAP-NG: invalid [if_tsoffset] offset: {offset!r}',
                                   if_tsoffset={'offset': offset})

    def test_tsoffset_bounds_read_back_unchanged(self) -> None:
        from pcapkit.const.pcapng.option_type import OptionType

        for offset in (-2 ** 63, -1, 0, 1, 2 ** 63 - 1):
            with self.subTest(offset=offset):
                info = self._reparse(self._idb(if_tsoffset={'offset': offset}))
                self.assertEqual(info.options[OptionType.if_tsoffset].offset, offset)

    def test_snaplen_is_checked_by_make_uint(self) -> None:
        for snaplen in (-1, 2 ** 32, True, 1.5, '1'):
            with self.subTest(snaplen=snaplen):
                self.assertRefused(f'PCAP-NG: invalid [IDB] snaplen: {snaplen!r}', snaplen=snaplen)

    def test_snaplen_bounds_read_back_unchanged(self) -> None:
        for snaplen in (0, 1, 0xFFFF_FFFF):
            with self.subTest(snaplen=snaplen):
                self.assertEqual(self._reparse(self._idb(snaplen=snaplen)).snaplen, snaplen)

    def test_eui_address_is_the_base_mac_pair(self) -> None:
        import pcapkit.protocols.misc.pcapng as module
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.protocols.misc.pcapng import PCAPNG
        from pcapkit.protocols.protocol import ProtocolBase

        self.assertFalse(hasattr(module, 'PAT_EUI_ADDR'))
        for name in ('_read_eui_addr', '_make_eui_addr'):
            with self.subTest(name=name):
                self.assertFalse(hasattr(PCAPNG, name))
        self.assertIs(PCAPNG._read_mac_addr, ProtocolBase._read_mac_addr)

        made = self._idb(if_EUIaddr={'interface': '02-34-56-FF-FE-78-9A-BC'})
        self.assertIn(bytes.fromhex('023456fffe789abc'), made.data)
        self.assertEqual(self._reparse(made).options[OptionType.if_EUIaddr].interface,
                         '02:34:56:ff:fe:78:9a:bc')
        for interface in ('02:34:56:ff:fe:78:9a', '02:34:56:ff:fe:78:9a:bc:de'):
            with self.subTest(interface=interface):
                self.assertRefused(f'PCAP-NG: invalid EUI address: {interface!r}',
                                   if_EUIaddr={'interface': interface})


class TestPCAPNGSectionLength(PCAPNGTestCase):
    """Pin the SHB's Section Length: signed 64 bits, with the unsigned spelling of the same bits."""

    #: Section Length is octets 16 to 24 of an SHB: type, length, magic, versions.
    FIELD = slice(16, 24)

    def _shb(self, **block: 'Any') -> 'Any':
        """Make a little-endian section header block from the given fields."""
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.protocols.misc.pcapng import PCAPNG

        return PCAPNG(num=0, sct=1, ctx=None, type=BlockType.Section_Header_Block,
                      block={'byteorder': 'little', **block})

    def test_section_length_outside_the_field_is_refused(self) -> None:
        """Each was written masked or failed bare: ``2**64`` as 0, ``True`` as 1, ``None`` as the sentinel."""
        from pcapkit.utilities.exceptions import ProtocolError

        for section_length in (2 ** 64, -2 ** 63 - 1, 2 ** 70, True, False, 1.5, None, '1'):
            with self.subTest(section_length=section_length):
                with self.assertRaises(ProtocolError) as context:
                    self._shb(section_length=section_length)
                self.assertEqual(str(context.exception),
                                 f'PCAP-NG: invalid [SHB] section_length: {section_length!r}')

    def test_section_length_edges_write_the_octets_of_their_bits(self) -> None:
        """Either spelling of a 64-bit pattern writes it; the reader returns the signed one."""
        made = {}
        for section_length in (-2 ** 63, -1, 0, 1024, 2 ** 63 - 1, 2 ** 63, 2 ** 64 - 1):
            with self.subTest(section_length=section_length):
                made[section_length] = self._shb(section_length=section_length).data
                self.assertEqual(made[section_length][self.FIELD],
                                 (section_length % 2 ** 64).to_bytes(8, 'little'))
                signed = section_length - 2 ** 64 if section_length >= 2 ** 63 else section_length
                self.assertEqual(self._parse(made[section_length]).info.section_length, signed)
        # the two spellings of each pattern write one block, whole
        self.assertEqual(made[-1], made[2 ** 64 - 1])
        self.assertEqual(made[-2 ** 63], made[2 ** 63])
        self.assertEqual(made[-1][self.FIELD], b'\xff' * 8)

    def test_section_length_defaults_to_the_sentinel(self) -> None:
        """A block made without one is "not specified", whichever spelling is given."""
        default = self._shb().data
        self.assertEqual(default[self.FIELD], b'\xff' * 8)
        self.assertEqual(default, self._shb(section_length=-1).data)
        self.assertEqual(default, self._shb(section_length=0xFFFF_FFFF_FFFF_FFFF).data)
        self.assertEqual(self._parse(default).info.section_length, -1)

    def test_section_length_of_a_data_model_is_checked_too(self) -> None:
        """A parsed block rebuilds byte-exact; one given a value the field cannot hold is refused."""
        from pcapkit.protocols.misc.pcapng import PCAPNG
        from pcapkit.utilities.exceptions import ProtocolError

        for section_length in (-1, 0, 1024):
            with self.subTest(section_length=section_length):
                self.assertRebuilds(self._shb(section_length=section_length).data)

        info = self._parse(self._shb(section_length=1024).data).info
        for section_length in (2 ** 64, -2 ** 63 - 1, True):
            with self.subTest(section_length=section_length):
                info.__update__([('section_length', section_length)])
                with self.assertRaises(ProtocolError) as raised:
                    PCAPNG.from_data(info, num=0, sct=1, ctx=None)
                self.assertEqual(str(raised.exception),
                                 f'PCAP-NG: invalid [SHB] section_length: {section_length!r}')


class TestPCAPNGPacketBlockDropCount(PCAPNGTestCase):
    """Pin the Packet Block's Drops Count: unsigned 16 bits, checked and not masked."""

    def _packet_block(self, context: 'Any' = None, **block: 'Any') -> 'Any':
        """Make an obsolete Packet Block from the given fields, whose warning is silenced."""
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.protocols.misc.pcapng import PCAPNG

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            return PCAPNG(num=2, sct=1, ctx=self._context() if context is None else context,
                          type=BlockType.Packet_Block,
                          block={'packet_data': b'abcd', 'timestamp': 0, **block})

    def test_drop_count_outside_the_unsigned_field_is_refused(self) -> None:
        """Each was written masked: -1 as 0xFFFF, 65536 as 0, ``True`` as 1, ``None`` raised bare."""
        from pcapkit.utilities.exceptions import ProtocolError

        for drop_count in (-1, 0x1_0000, -0xFFFF, 2 ** 32, True, False, 1.5, None, '1'):
            with self.subTest(drop_count=drop_count):
                with self.assertRaises(ProtocolError) as context:
                    self._packet_block(drop_count=drop_count)
                self.assertEqual(str(context.exception), f'PCAP-NG: invalid [PB] drop_count: {drop_count!r}')

    def test_drop_count_bounds_read_back_unchanged(self) -> None:
        """0 and 1 are counts, ``0xFFFF`` is "not available"; the reader returns 65535 for it, never -1."""
        for drop_count in (0, 1, 0x7FFF, 0x8000, 0xFFFF):
            with self.subTest(drop_count=drop_count):
                made = self._packet_block(drop_count=drop_count)
                # Block Type, Block Total Length, Interface ID, then Drops Count
                self.assertEqual(made.data[10:12], drop_count.to_bytes(2, sys.byteorder))
                self.assertEqual(made.info.drop_count, drop_count)
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    self.assertEqual(self._parse(made.data).info.drop_count, drop_count)

    def test_drop_count_defaults_to_zero_and_the_sentinel_rebuilds(self) -> None:
        """A block made without one counts no drops; one parsed with the sentinel rebuilds with it."""
        context = self._context()
        self.assertEqual(self._packet_block(context).info.drop_count, 0)
        sentinel = self._packet_block(context, drop_count=0xFFFF)
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            self.assertRebuilds(sentinel.data, context)
            self.assertEqual(self._parse(sentinel.data, context).info.drop_count, 0xFFFF)

    def test_drop_count_of_a_data_model_is_checked_too(self) -> None:
        """The data model path of the maker checks the field as the keyword path does."""
        from pcapkit.protocols.misc.pcapng import PCAPNG
        from pcapkit.utilities.exceptions import ProtocolError

        context = self._context()
        info = self._packet_block(context, drop_count=3).info
        for drop_count in (-1, 0x1_0000, True):
            with self.subTest(drop_count=drop_count):
                info.__update__([('drop_count', drop_count)])
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    with self.assertRaises(ProtocolError) as raised:
                        PCAPNG.from_data(info, num=2, sct=1, ctx=context)
                self.assertEqual(str(raised.exception), f'PCAP-NG: invalid [PB] drop_count: {drop_count!r}')


class TestPCAPNGPadLength(PCAPNGTestCase):
    """Pin the padding sites that only a custom block or a clipped SPB reaches."""

    def _custom(self, type_: 'Any', data: 'bytes', options: 'Any') -> 'Any':
        """Make a custom block of ``type_`` with private enterprise number 1."""
        from pcapkit.protocols.misc.pcapng import PCAPNG

        return PCAPNG(num=2, sct=1, ctx=None, type=type_, block={'pen': 1, 'data': data, 'options': options})

    def _custom_types(self) -> 'Any':
        """Both custom block types, which one maker makes."""
        from pcapkit.const.pcapng.block_type import BlockType

        return (BlockType.Custom_Block_that_rewriters_can_copy_into_new_files,
                BlockType.Custom_Block_that_rewriters_should_not_copy_into_new_files)

    def test_custom_data_is_padded_before_its_options(self) -> None:
        from pcapkit.const.pcapng.option_type import OptionType

        comment = bytes.fromhex('01000200 68690000')  # opt_comment 'hi', padded
        for type_ in self._custom_types():
            for data in (b'o', b'od', b'odd'):
                with self.subTest(type=type_, data=data):
                    made = self._custom(type_, data, [(OptionType.opt_comment, {'comment': 'hi'})])
                    self.assertEqual(made.info.data, data + bytes(4 - len(data)) + comment)
                    self.assertEqual(made.info.length, 28)
                    self.assertRebuilds(made.data)

    def test_custom_option_area_is_padded(self) -> None:
        """An option area of seven octets is written whole, with one pad octet after it."""
        area = bytes.fromhex('01000300 616263')  # opt_comment 'abc', unpadded
        for type_ in self._custom_types():
            with self.subTest(type=type_):
                made = self._custom(type_, b'', area)
                self.assertEqual(made.info.data, area + b'\x00')
                self.assertEqual(made.info.length, 24)
                self.assertEqual(made.info.length, len(made.data))

    def test_spb_data_ending_at_its_padding_is_not_past_original_len(self) -> None:
        """Eight octets past a snaplen of 2 end at the padding of ``original_len=5``."""
        body = struct.pack('<I', 5) + b'abcdefgh'
        octets = struct.pack('<II', 3, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
        context = self._context(snaplen=2)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            parsed = self._parse(octets, context)
        messages = [str(item.message) for item in caught]
        self.assertEqual(parsed.info.captured_len, 8)
        self.assertTrue(any('exceeds the snaplen of 2' in text for text in messages), messages)
        self.assertFalse(any('exceeds the original length' in text for text in messages), messages)
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            self.assertRebuilds(octets, context)


if __name__ == '__main__':
    unittest.main()
