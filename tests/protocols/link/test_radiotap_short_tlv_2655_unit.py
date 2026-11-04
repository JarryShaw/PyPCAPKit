# -*- coding: utf-8 -*-
"""GitHub issue #2655: a radiotap TLV item a producer cut short is decoded.

radiotap.org's TLV page has parsers take an item whose data stops before its
layout ends, since a producer may leave out the octets it does not fill at the
end, and those octets are zeros. :class:`~pcapkit.protocols.link.radiotap.protocol.Radiotap`
decodes such an item as its layout padded with the zeros, records the cut as
``__short_read__``, as ``Schema.unpack`` does, and writes the octets back as
captured, through ``from_data`` and through ``make()``.

Each case cuts a U-SIG, S1G, EHT or vendor item at a field boundary or inside a
field. Its control is the same item with the zeros put back, which is whole, so
it records no cut and decodes to the same values. Every step is quiet, and an item
whose zeros the padding limits of :mod:`pcapkit.utilities.config` refuse stays
raw, quietly too.

Each test imports :mod:`pcapkit` itself, after
:func:`~tests._support.reimport_once_per_class`.

"""

import contextlib
import logging
import struct
import sys
import threading
import unittest
import warnings
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Iterator

#: The presence word selecting the TLV fields, bit 28, alone.
PRESENT = 1 << 28

#: Each item whole, by name: its TLV type, and its data from the type's page on
#: radiotap.org, every subfield holding non-zero octets throughout.
WHOLE = {
    'U-SIG': (33, struct.pack('<III', 0x11223344, 0x55667788, 0x99AABBCC)),
    'S1G': (32, struct.pack('<HHH', 0x0103, 0x0405, 0x0607)),
    'EHT': (34, struct.pack('<10I', 0x00000003, *(0x01010101 * number for number in range(1, 10)))
            + struct.pack('<I', 0xA1A2A3A4)),
    'vendor': (30, bytes.fromhex('001374') + struct.pack('<BHH', 0x01, 0x0505, 0) + b'\xaa\xbb'),
}

#: The U-SIG ``common`` word of :data:`WHOLE`, ``0x11223344``, split into its
#: subfields by hand: bits 12 to 31 hold them, and bits 0 to 11 are known bits.
COMMON = {'phy_version': 3, 'bandwidth': 4, 'ul_dl': 0, 'bss_color': 0x24, 'txop': 8,
          'known': 0x344}

#: Each cut: the item, the octets of its data kept, the octets of its layout
#: (the length its control is padded back to), the ``__short_read__`` the cut
#: gives, and the subfields it decodes to, worked out by hand.
CUTS = {
    'U-SIG at a field boundary': ('U-SIG', 8, 12, ('mask', 0),
                                  {'common': COMMON, 'value': 0x55667788, 'mask': 0}),
    'U-SIG inside a field': ('U-SIG', 6, 12, ('value', 2),
                             {'common': COMMON, 'value': 0x7788, 'mask': 0}),
    'S1G at a field boundary': ('S1G', 4, 6, ('data2', 0), {'known': 0x0103, 'data1': 0x0405, 'data2': 0}),
    'S1G inside a field': ('S1G', 3, 6, ('data1', 1), {'known': 0x0103, 'data1': 0x05, 'data2': 0}),
    'EHT at a field boundary': ('EHT', 4, 40, ('data', 0), {'known': 3, 'data': (0,) * 9, 'user_info': ()}),
    'EHT inside a field': ('EHT', 14, 40, ('data', 10),
                           {'known': 3, 'data': (0x01010101, 0x02020202, 0x0303) + (0,) * 6, 'user_info': ()}),
    'EHT 1 octet into a user word': ('EHT', 41, 44, ('user_info', 1),
                                     {'known': 3, 'data': tuple(0x01010101 * number for number in range(1, 10)),
                                      'user_info': (0xA4,)}),
    'EHT inside a user word': ('EHT', 42, 44, ('user_info', 2),
                               {'known': 3, 'data': tuple(0x01010101 * number for number in range(1, 10)),
                                'user_info': (0xA3A4,)}),
    'EHT 3 octets into a user word': ('EHT', 43, 44, ('user_info', 3),
                                      {'known': 3, 'data': tuple(0x01010101 * number for number in range(1, 10)),
                                       'user_info': (0xA2A3A4,)}),
    'vendor at a field boundary': ('vendor', 4, 8, ('presence_type', 0),
                                   {'oui': bytes.fromhex('001374'), 'subtype': 1, 'presence_type': 0,
                                    'reserved': 0, 'data': b''}),
    'vendor inside a field': ('vendor', 5, 8, ('presence_type', 1),
                              {'oui': bytes.fromhex('001374'), 'subtype': 1, 'presence_type': 0x05,
                               'reserved': 0, 'data': b''}),
}


def _item(tlv_type: int, data: bytes) -> bytes:
    """A TLV item: its type, its length, its data, and padding to 4 octets."""
    return struct.pack('<HH', tlv_type, len(data)) + data + bytes(-len(data) % 4)


def _radiotap(item: bytes) -> bytes:
    """A radiotap header whose only field is the TLV list holding ``item``."""
    return struct.pack('<BBHI', 0, 0, 8 + len(item), PRESENT) + item


def _subfields(data) -> 'dict':  # type: ignore[no-untyped-def]
    """The subfields of an item's decoded data, its cut left out."""
    return {name: value for name, value in data.items() if name not in ('type', '__short_read__')}


class TestRadiotapShortTLV(unittest.TestCase):
    """Pin the decoding of a TLV item cut short, and its writing back."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _parse(self, raw: bytes):  # type: ignore[no-untyped-def]
        from pcapkit.protocols.link.radiotap.protocol import Radiotap

        parsed = Radiotap(raw, len(raw))
        self.assertEqual(parsed.data, raw)
        return parsed

    def _cut(self, case: str) -> 'tuple[bytes, int, bytes]':
        """The header holding ``case``'s item, its TLV type, and the item's data."""
        name, keep, _, _, _ = CUTS[case]
        tlv_type, whole = WHOLE[name]
        return _radiotap(_item(tlv_type, whole[:keep])), tlv_type, whole[:keep]

    def test_a_short_item_decodes_as_its_layout_padded_with_zeros(self) -> None:
        """The cut item decodes as its control does, and only it records the cut."""
        for case, (name, keep, layout, record, values) in CUTS.items():
            with self.subTest(case=case):
                raw, tlv_type, data = self._cut(case)
                (item,) = self._parse(raw).info.decoded[28].tlvs
                (control,) = self._parse(_radiotap(_item(tlv_type, data + bytes(layout - keep)))).info.decoded[28].tlvs

                self.assertEqual((item.type, item.length), (tlv_type, keep))
                self.assertIs(type(item.data), type(control.data))
                self.assertEqual(_subfields(item.data), values)
                self.assertEqual(_subfields(control.data), values)
                self.assertEqual(item.data['__short_read__'], record)
                self.assertNotIn('__short_read__', control.data)

        for name, (tlv_type, whole) in WHOLE.items():
            with self.subTest(whole=name):
                (item,) = self._parse(_radiotap(_item(tlv_type, whole))).info.decoded[28].tlvs
                self.assertNotIsInstance(item.data, bytes)
                self.assertNotIn('__short_read__', item.data)

        # data past a layout of fixed size stays raw
        for name in ('U-SIG', 'S1G'):
            with self.subTest(long=name):
                tlv_type, whole = WHOLE[name]
                (item,) = self._parse(_radiotap(_item(tlv_type, whole + b'\x01'))).info.decoded[28].tlvs
                self.assertEqual(item.data, whole + b'\x01')

    def test_a_registered_layout_decodes_a_cut_item(self) -> None:
        """A layout registered for a TLV type, its tail taking the rest, decodes an item cut short of its head."""
        from unittest import mock

        from pcapkit.const.radiotap.field_type import FieldType
        from pcapkit.corekit.fields.collections import ListField
        from pcapkit.corekit.fields.numbers import UInt16Field
        from pcapkit.corekit.infoclass import info_final
        from pcapkit.foundation.registry import register_radiotap_field
        from pcapkit.protocols.link.radiotap.data import RadiotapField as DataField
        from pcapkit.protocols.link.radiotap.protocol import Radiotap
        from pcapkit.protocols.link.radiotap.schema import RadiotapField
        from pcapkit.protocols.schema import schema_final

        # a list of no item type is the octets it spans, so the tail is not of whole items
        @schema_final
        class TaggedSchema(RadiotapField):
            tag = UInt16Field(byteorder='little')
            body = ListField(length=lambda pkt: pkt['__length__'])

        @info_final
        class Tagged(DataField):
            tag: int
            body: bytes

        def parser(field_type, schema):  # type: ignore[no-untyped-def]
            return Tagged(type=field_type, tag=schema.tag, body=schema.body)

        def constructor(field_type, entry):  # type: ignore[no-untyped-def]
            return TaggedSchema(tag=entry['tag'], body=entry['body'])

        #: The item's data, to its tag, body and cut.
        cases = {
            b'\x34': (0x34, b'', ('tag', 1)),
            b'\x34\x12': (0x1234, b'', None),
            b'\x34\x12\xab\xcd\xef': (0x1234, b'\xab\xcd\xef', None),
        }
        with mock.patch.dict(Radiotap.__field__), mock.patch.dict(RadiotapField.registry):
            register_radiotap_field(FieldType.get(35), (parser, constructor), schema=TaggedSchema)
            for data, (tag, body, record) in cases.items():
                with self.subTest(data=data.hex()):
                    raw = _radiotap(_item(35, data))
                    parsed = self._parse(raw)
                    (item,) = parsed.info.decoded[28].tlvs
                    self.assertIsInstance(item.data, Tagged)
                    self.assertEqual((item.data.tag, item.data.body, item.data.get('__short_read__')),
                                     (tag, body, record))
                    self.assertEqual(Radiotap(present=(PRESENT,), fields=parsed.info.decoded).data.hex(), raw.hex())

    def test_from_data_rebuilds_a_short_item_as_captured(self) -> None:
        """``from_data`` of the info, and of its dict, writes the cut octets and decodes them again."""
        from pcapkit.protocols.link.radiotap.protocol import Radiotap

        for case, (_, _, _, record, _) in CUTS.items():
            raw, _, _ = self._cut(case)
            parsed = self._parse(raw)
            for info in (parsed.info, parsed.info.to_dict()):
                with self.subTest(case=case, data=type(info).__name__):
                    rebuilt = Radiotap.from_data(info)
                    self.assertEqual(rebuilt.data.hex(), raw.hex())
                    (item,) = rebuilt.info.decoded[28].tlvs
                    self.assertEqual(item.data['__short_read__'], record)

    def test_make_writes_a_short_item_as_captured(self) -> None:
        """``make()`` writes the cut octets from ``decoded``, from an item's dict, and from a hand-written cut."""
        from pcapkit.protocols.link.radiotap.protocol import Radiotap

        for case, (_, _, _, record, values) in CUTS.items():
            raw, tlv_type, _ = self._cut(case)
            parsed = self._parse(raw)
            (item,) = parsed.info.decoded[28].tlvs
            given = {
                'decoded': parsed.info.decoded,
                'dict': [(28, {'tlvs': [{'type': tlv_type, 'data': item.data.to_dict()}]})],
                'hand-written': [(28, {'tlvs': [{'type': tlv_type,
                                                 'data': {**values, '__short_read__': record}}]})],
                # a JSON round trip turns the record into a list
                'list record': [(28, {'tlvs': [{'type': tlv_type,
                                                'data': {**values, '__short_read__': list(record)}}]})],
            }
            for how, fields in given.items():
                with self.subTest(case=case, fields=how):
                    made = Radiotap(present=(PRESENT,), fields=fields)
                    self.assertEqual(made.data.hex(), raw.hex())

    @contextlib.contextmanager
    def _assert_quiet(self) -> 'Iterator[None]':
        """Fail if the block warns, logs to ``pcapkit`` at any level, or replaces an exception hook."""
        logger = logging.getLogger('pcapkit')
        records = []  # type: list[logging.LogRecord]
        handler = logging.Handler(logging.DEBUG)
        handler.emit = records.append  # type: ignore[assignment,method-assign]
        level, hooks = logger.level, (sys.excepthook, threading.excepthook)
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
        try:
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter('always')
                yield
        finally:
            logger.removeHandler(handler)
            logger.setLevel(level)
        self.assertEqual([str(warning.message) for warning in caught], [])
        self.assertEqual([record.getMessage() for record in records], [])
        self.assertEqual((sys.excepthook, threading.excepthook), hooks)

    def test_a_short_item_decodes_quietly(self) -> None:
        """Parsing, rebuilding and making a cut item warns of nothing and logs nothing."""
        from pcapkit.protocols.link.radiotap.protocol import Radiotap

        for case in CUTS:
            with self.subTest(case=case):
                raw, _, _ = self._cut(case)
                with self._assert_quiet():
                    parsed = Radiotap(raw, len(raw))
                    Radiotap.from_data(parsed.info)
                    Radiotap(present=(PRESENT,), fields=parsed.info.decoded)
                (item,) = parsed.info.decoded[28].tlvs
                self.assertNotIsInstance(item.data, bytes)

    def test_a_cut_the_padding_limit_refuses_stays_raw_quietly(self) -> None:
        """Under a zero-padding limit too low for the layout the cut item stays raw, quietly; by default it decodes."""
        from unittest import mock

        from pcapkit.protocols.link.radiotap.protocol import Radiotap
        from pcapkit.utilities import config

        for case in CUTS:
            with self.subTest(case=case):
                raw, _, data = self._cut(case)
                with mock.patch.object(config, 'MAX_ZERO_PAD_LENGTH', 1), self._assert_quiet():
                    parsed = Radiotap(raw, len(raw))
                    self.assertEqual(Radiotap.from_data(parsed.info).data.hex(), raw.hex())
                    self.assertEqual(Radiotap(present=(PRESENT,), fields=parsed.info.decoded).data.hex(), raw.hex())
                (item,) = parsed.info.decoded[28].tlvs
                self.assertEqual(item.data, data)

                (item,) = self._parse(raw).info.decoded[28].tlvs
                self.assertNotIsInstance(item.data, bytes)

    def test_make_refuses_a_malformed_cut(self) -> None:
        """A ``__short_read__`` that names no field and a count, or a vendor TLV cut short before its data, raises."""
        from pcapkit.protocols.link.radiotap.protocol import Radiotap
        from pcapkit.utilities.exceptions import ProtocolError

        usig = {'common': COMMON, 'value': 2, 'mask': 3}
        # whole, the item builds, so each refusal below is its record's
        Radiotap(present=(PRESENT,), fields=[(28, {'tlvs': [{'type': 33, 'data': usig}]})])
        for record in (('nosuch', 0), ('mask', -1), ('mask', True), ('mask', '0'), ('mask',), 'mask'):
            with self.subTest(record=record):
                with self.assertRaises(ProtocolError):
                    Radiotap(present=(PRESENT,),
                             fields=[(28, {'tlvs': [{'type': 33, 'data': {**usig, '__short_read__': record}}]})])

        vendor = {'oui': bytes.fromhex('001374'), 'subtype': 1, 'presence_type': 5, 'data': b'\xaa',
                  '__short_read__': ('presence_type', 1)}
        with self.assertRaises(ProtocolError):
            Radiotap(present=(PRESENT,), fields=[(28, {'tlvs': [{'type': 30, 'data': vendor}]})])


if __name__ == '__main__':
    unittest.main()
