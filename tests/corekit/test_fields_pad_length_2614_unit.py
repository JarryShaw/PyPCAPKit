# -*- coding: utf-8 -*-
"""``pad_length`` and ``PaddingField(align=...)`` size padding to a boundary.

GitHub issue #2614 found the octets that reach the next ``N``-octet boundary
spelled several ways, ``-n % 4``, ``(4 - n % 4) % 4`` and ``(n + 3) // 4 * 4``
among them. :func:`~pcapkit.corekit.fields.strings.pad_length` states it once, and
:class:`~pcapkit.corekit.fields.strings.PaddingField` takes ``align`` and
``after`` so a schema says what it aligns rather than how.

The expected values here never call ``pad_length``: :func:`spec_pad` counts the
octets up to the boundary one at a time, as the specifications word it. The
PCAP-NG cases check every schema in
:mod:`pcapkit.protocols.schema.misc.pcapng` that sizes its padding with
``align``, so a site sized against the wrong field or boundary fails by name.

:mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, not at module load.

"""

import struct
import unittest
import warnings
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): exercises integer edge cases -- operands of ``%`` far past
#: any wire field's width -- as ``test_fields_strings`` does.
__tier__ = 'ALL'

#: Boundaries checked, the ones the schemas use and odd ones besides.
ALIGNS = (1, 2, 3, 4, 7, 8, 16)

#: Lengths far past any wire field, where a width-limited formula would wrap.
LARGE = (2**16 - 1, 2**32 + 1, 2**64, 2**64 + 3, 10**30 + 7)


def spec_pad(length: int, align: int) -> int:
    """Octets added to ``length`` until it is a multiple of ``align``, counted one at a time."""
    pad = 0
    while (length + pad) % align:
        pad += 1
    return pad


class PadLengthTests(unittest.TestCase):
    """:func:`~pcapkit.corekit.fields.strings.pad_length` itself."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

        from pcapkit.corekit.fields.strings import pad_length

        self.pad_length = pad_length

    def test_boundaries(self) -> None:
        for align in ALIGNS:
            for length, expected in ((0, 0), (1, (align - 1) % align), (align - 1, 1 % align),
                                     (align, 0), (align + 1, (align - 1) % align), (2 * align, 0)):
                with self.subTest(align=align, length=length):
                    self.assertEqual(self.pad_length(length, align), expected)

    def test_matches_the_count_up_to_the_boundary(self) -> None:
        for align in ALIGNS:
            for length in range(0, 4 * align + 2):
                with self.subTest(align=align, length=length):
                    self.assertEqual(self.pad_length(length, align), spec_pad(length, align))

    def test_large_lengths(self) -> None:
        for align in ALIGNS:
            for length in LARGE:
                with self.subTest(align=align, length=length):
                    pad = self.pad_length(length, align)
                    self.assertEqual((length + pad) % align, 0)
                    self.assertTrue(0 <= pad < align)

    def test_result_is_an_int(self) -> None:
        self.assertIs(type(self.pad_length(5, 4)), int)

    def test_non_positive_align_is_refused(self) -> None:
        from pcapkit.utilities.exceptions import FieldValueError

        for align in (0, -1, -4):
            with self.subTest(align=align):
                with self.assertRaisesRegex(FieldValueError, 'align must be positive'):
                    self.pad_length(4, align)
        self.assertTrue(issubclass(FieldValueError, ValueError))

    def test_non_int_align_is_refused(self) -> None:
        from pcapkit.utilities.exceptions import IntError

        for align in (4.0, True, False, None, '4', b'\x04'):
            with self.subTest(align=align):
                with self.assertRaisesRegex(IntError, 'align must be an int'):
                    self.pad_length(4, align)  # type: ignore[arg-type]
        self.assertTrue(issubclass(IntError, TypeError))


class PaddingFieldAlignTests(unittest.TestCase):
    """:class:`~pcapkit.corekit.fields.strings.PaddingField` with ``align`` and ``after``."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

        from pcapkit.corekit.fields.strings import PaddingField

        self.PaddingField = PaddingField

    def test_after_a_field_name(self) -> None:
        field = self.PaddingField(align=4, after='length')
        for length in (0, 1, 3, 4, 5, 7, 8) + LARGE:
            with self.subTest(length=length):
                self.assertEqual(field({'length': length}).length, spec_pad(length, 4))

    def test_after_a_callable(self) -> None:
        field = self.PaddingField(align=8, after=lambda pkt: len(pkt['data']))
        for size in range(0, 18):
            with self.subTest(size=size):
                self.assertEqual(field({'data': bytes(size)}).length, spec_pad(size, 8))

    def test_each_packet_resolves_its_own_width(self) -> None:
        field = self.PaddingField(align=4, after='length')
        self.assertEqual(field({'length': 5}).length, 3)
        self.assertEqual(field({'length': 8}).length, 0)

    def test_length_callers_are_unchanged(self) -> None:
        self.assertEqual(self.PaddingField(length=3).length, 3)
        self.assertEqual(self.PaddingField(3).length, 3)
        self.assertEqual(self.PaddingField(length=lambda pkt: pkt['n'])({'n': 2}).length, 2)

    def test_pack_and_unpack_in_a_schema(self) -> None:
        from pcapkit.corekit.fields.numbers import UInt8Field, UInt16Field
        from pcapkit.corekit.fields.strings import BytesField
        from pcapkit.protocols.schema.schema import Schema, schema_final

        @schema_final
        class TLV(Schema):
            """A value padded to four octets, then a trailing octet."""

            length: 'int' = UInt16Field()
            value: 'bytes' = BytesField(length=lambda pkt: pkt['length'])
            padding: 'bytes' = self.PaddingField(align=4, after='length')
            tail: 'int' = UInt8Field()

        for value in (b'', b'a', b'abc', b'abcd', b'abcde'):
            with self.subTest(value=value):
                built = TLV(length=len(value), value=value, tail=9).pack()
                expected = len(value).to_bytes(2, 'big') + value + bytes(spec_pad(len(value), 4)) + b'\x09'
                self.assertEqual(built, expected)

        # captured non-zero padding parses at the right width and rebuilds as captured
        raw = b'\x00\x03abc\xee\x09'
        parsed = TLV.unpack(raw, len(raw), None)
        self.assertEqual(parsed.padding, b'\xee')
        self.assertEqual(parsed.tail, 9)
        self.assertEqual(parsed.pack(), raw)

    def test_bad_declarations_are_refused_at_declaration(self) -> None:
        from pcapkit.utilities.exceptions import FieldValueError, IntError

        for kwargs, kind, message in (
                ({}, FieldValueError, 'needs a length or align'),
                ({'length': 2, 'align': 4, 'after': 'length'}, FieldValueError, 'not both'),
                ({'after': 'length'}, FieldValueError, 'after needs align'),
                ({'align': 4}, FieldValueError, 'align needs after'),
                ({'align': 4, 'after': 3}, FieldValueError, 'align needs after'),
                ({'align': 0, 'after': 'length'}, FieldValueError, 'align must be positive'),
                ({'align': -4, 'after': 'length'}, FieldValueError, 'align must be positive'),
                ({'align': 4.0, 'after': 'length'}, IntError, 'align must be an int'),
                ({'align': True, 'after': 'length'}, IntError, 'align must be an int'),
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaisesRegex(kind, message):
                    self.PaddingField(**kwargs)


class PCAPNGAlignedPaddingTests(unittest.TestCase):
    """Every PCAP-NG ``align`` site pads its value to a 32-bit boundary.

    The PCAP-NG specification pads an option's value, a name resolution
    record's value, and a block's packet or secrets data to 32 bits, and counts
    none of that padding in the length that precedes it.

    """

    def setUp(self) -> None:
        reimport_once_per_class(self)

        from pcapkit.protocols.schema.misc import pcapng

        self.pcapng = pcapng

    def _length_sized(self) -> 'dict[str, type]':
        """Options and records, whose padding follows their ``length`` field."""
        found = {}
        for name, obj in vars(self.pcapng).items():
            if (isinstance(obj, type) and obj.__module__ == self.pcapng.__name__
                    and issubclass(obj, (self.pcapng.Option, self.pcapng.NameResolutionRecord))
                    and 'padding' in obj.__fields__):
                found[name] = obj
        return found

    def test_options_and_records_pad_their_value(self) -> None:
        found = self._length_sized()
        for name in ('CommentOption', 'CustomOption', 'UnknownOption', 'IF_NameOption',
                     'EPB_HashOption', 'IPv4Record', 'UnknownRecord'):
            self.assertIn(name, found)
        for name, cls in found.items():
            field = cls.__fields__['padding']
            for length in range(0, 9):
                with self.subTest(schema=name, length=length):
                    self.assertEqual(field({'length': length}).length, spec_pad(length, 4))

    def test_packet_blocks_pad_their_packet_data(self) -> None:
        for name, key in (('EnhancedPacketBlock', 'captured_len'), ('PacketBlock', 'captured_length')):
            field = getattr(self.pcapng, name).__fields__['padding_data']
            for size in range(0, 9):
                with self.subTest(schema=name, captured=size):
                    packet = {key: size, 'length': 32 + 64}
                    self.assertEqual(field(packet).length, spec_pad(size, 4))

    def _parse(self, octets: 'bytes') -> 'tuple[Any, bytes, list[str]]':
        """Parse ``octets`` as one little-endian block, rebuild it, and keep the warnings."""
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.foundation.engines.pcapng import Context
        from pcapkit.protocols.misc.pcapng import PCAPNG

        section = PCAPNG(num=0, sct=1, ctx=None, type=BlockType.Section_Header_Block, block={})
        context = Context(section.info)  # type: Any
        interface = PCAPNG(num=1, sct=1, ctx=context, type=BlockType.Interface_Description_Block,
                           block={'linktype': LinkType.ETHERNET, 'snaplen': 0x40000})
        context.interfaces.append(interface.info)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            parsed = PCAPNG(octets, len(octets), num=2, sct=1, ctx=context)
            rebuilt = PCAPNG.from_data(parsed.info, num=2, sct=1, ctx=context).data
        return parsed, rebuilt, [str(item.message) for item in caught]

    def test_simple_packet_block_pads_its_packet_data(self) -> None:
        field = self.pcapng.SimplePacketBlock.__fields__['padding']
        for size in range(0, 9):
            with self.subTest(size=size):
                self.assertEqual(field({'packet_data': bytes(size)}).length, spec_pad(size, 4))

    def test_simple_packet_block_padding_is_not_packet_data(self) -> None:
        """Five octets of an ``original_len`` of five, then three of padding.

        The block's area is the octets past its 16 of framing. From the data's
        own five octets up to the data and its padding, the data stays
        ``original_len`` octets and the rest is padding, even where the area
        stops short of the padding; only an area past both keeps the excess as
        data (#1384, #1414).

        """
        for area, expected in ((5, 5), (6, 5), (7, 5), (8, 5), (9, 9), (12, 12)):
            with self.subTest(area=area):
                packet = {'length': 16 + area, 'original_len': 5}
                self.assertEqual(self.pcapng._spb_data_length(packet), expected)  # pylint: disable=protected-access

        octets = struct.pack('<III', 3, 24, 5) + b'abcde' + b'\xee\xee\xee' + struct.pack('<I', 24)
        parsed, rebuilt, _ = self._parse(octets)
        self.assertEqual(parsed.info.captured_len, 5)
        self.assertEqual(parsed.packet.payload, b'abcde')
        self.assertEqual(parsed.__header__.block.padding, b'\xee\xee\xee')
        self.assertEqual(rebuilt.hex(), octets.hex())

    def test_decryption_secrets_block_pads_its_secrets(self) -> None:
        field = self.pcapng.DecryptionSecretsBlock.__fields__['padding_data']
        for size in range(0, 9):
            with self.subTest(size=size):
                packet = {'secrets_length': size, 'length': 20 + 64}
                self.assertEqual(field(packet).length, spec_pad(size, 4))

    def test_decryption_secrets_block_pads_only_the_secrets_it_holds(self) -> None:
        """An over-declared Secrets Length pads the secrets the block holds (#1980)."""
        field = self.pcapng.DecryptionSecretsBlock.__fields__['padding_data']
        for held in (4, 5, 6, 7):
            for declared in (held + 1, held + 2, held + 3):
                with self.subTest(held=held, declared=declared):
                    self.assertNotEqual(spec_pad(held, 4), spec_pad(declared, 4))
                    packet = {'secrets_length': declared, 'length': 20 + held}
                    self.assertEqual(field(packet).length, spec_pad(held, 4))

        for declared in (5, 6, 7):
            with self.subTest(block='abcd', declared=declared):
                octets = (struct.pack('<IIII', 10, 24, 0x12345678, declared) + b'abcd'
                          + struct.pack('<I', 24))
                parsed, rebuilt, messages = self._parse(octets)
                block = parsed.__header__.block
                self.assertEqual(block.padding_data, b'')
                self.assertEqual(block.length2, 24)
                self.assertEqual(rebuilt.hex(), octets.hex())
                self.assertFalse(any('block length mismatch' in text for text in messages), messages)

    def test_comment_option_packs_to_the_specification(self) -> None:
        """``opt_comment`` of five octets: four of header, five of value, three of padding."""
        from pcapkit.const.pcapng.option_type import OptionType

        option = self.pcapng.CommentOption(type=OptionType.opt_comment, length=5, comment='hello')
        raw = option.pack({'byteorder': 'big'})
        self.assertEqual(raw, b'\x00\x01\x00\x05hello\x00\x00\x00')
