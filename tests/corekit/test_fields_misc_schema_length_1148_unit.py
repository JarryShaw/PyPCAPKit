# -*- coding: utf-8 -*-
"""A length-less ``SchemaField`` sizes its nested schema by what is left to read.

GitHub issue #1148. ``SchemaField``'s default length is ``-1``, meaning "not
declared", and :meth:`SchemaField.unpack
<pcapkit.corekit.fields.misc.SchemaField.unpack>` passed that ``-1`` straight on
as the nested schema's length. The nested schema's ``__length__`` therefore
started negative, and every sub-field it read warned ``packet length < 0`` --
six warnings per HIP ``Locator`` and per MH ``CGAParameter``, on input that
parses correctly.

The nested schema is now told the true remainder of the buffer. A remainder of
zero is passed as a declared length, so a truncated item is still reported as
malformed data rather than as the quiet end-of-stream signal that
:func:`~pcapkit.utilities.decorators.prepare` raises for a derived zero.
"""

import unittest
import warnings

from pcapkit.const.hip.parameter import Parameter as Enum_Parameter
from pcapkit.const.mh.option import Option as Enum_Option
from pcapkit.corekit.fields.collections import ListField
from pcapkit.corekit.fields.misc import SchemaField
from pcapkit.corekit.fields.numbers import UInt8Field, UInt16Field
from pcapkit.protocols.schema.internet.hip import LocatorSetParameter
from pcapkit.protocols.schema.internet.mh import CGAParametersOption
from pcapkit.protocols.schema.schema import Schema
from pcapkit.utilities.exceptions import FieldValueError
from pcapkit.utilities.warnings import SchemaWarning

#: One plain IPv6 locator: traffic, type 0, ``Locator Length`` 4, flags, lifetime.
LOCATOR = bytes([0, 0, 4, 1]) + (16).to_bytes(4, 'big') + bytes(range(16))

#: One CGA Parameters structure with a 6-octet public key and no extensions.
CGA_PARAMETER = b'\x11' * 16 + b'\x22' * 8 + b'\x01' + bytes([0x30, 4]) + b'ABCD'


class Pair(Schema):
    """Four-octet schema used as a list item."""

    a: 'int' = UInt16Field()
    b: 'int' = UInt16Field()


class LengthLessList(Schema):
    """A list of :class:`Pair` items declared without a length."""

    n: 'int' = UInt8Field()
    items: 'list[Pair]' = ListField(length=lambda pkt: pkt['n'], item_type=SchemaField(schema=Pair))


class ShortFixedList(Schema):
    """A list of :class:`Pair` items declared one octet shorter than they are."""

    n: 'int' = UInt8Field()
    items: 'list[Pair]' = ListField(length=lambda pkt: pkt['n'], item_type=SchemaField(length=3, schema=Pair))


def locator_set(count: 'int', truncate: 'int' = 0) -> 'bytes':
    body = LOCATOR * count
    raw = int(Enum_Parameter.LOCATOR_SET).to_bytes(2, 'big') + len(body).to_bytes(2, 'big') + body
    raw += b'\x00' * (-len(raw) % 8)
    return raw[:len(raw) - truncate]


def cga_option(body: 'bytes') -> 'bytes':
    return bytes([int(Enum_Option.CGA_Parameters), len(CGA_PARAMETER)]) + body


class LengthLessSchemaFieldTests(unittest.TestCase):

    def unpack(self, schema: 'type[Schema]', data: 'bytes') -> 'tuple[Schema, list[str]]':
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            result = schema.unpack(data)
        return result, [str(w.message) for w in caught if issubclass(w.category, SchemaWarning)]

    def test_hip_locators_do_not_warn(self) -> 'None':
        for count in (1, 2, 3):
            with self.subTest(count=count):
                param, warned = self.unpack(LocatorSetParameter, locator_set(count))
                self.assertEqual(warned, [])
                self.assertEqual(len(param.locators), count)
                self.assertEqual(param.locators[-1].lifetime, 16)

    def test_mh_cga_parameter_does_not_warn(self) -> 'None':
        option, warned = self.unpack(CGAParametersOption, cga_option(CGA_PARAMETER))
        self.assertEqual(warned, [])
        self.assertEqual(len(option.parameters), 1)
        self.assertEqual(option.parameters[0].public_key, b'0\x04ABCD')

    def test_length_less_items_do_not_warn(self) -> 'None':
        result, warned = self.unpack(LengthLessList, b'\x08' + bytes(range(8)))
        self.assertEqual(warned, [])
        self.assertEqual([(item.a, item.b) for item in result.items], [(0x0001, 0x0203), (0x0405, 0x0607)])

    def test_truncated_variable_item_still_warns_and_raises(self) -> 'None':
        # A remainder of zero must not become ``prepare``'s quiet
        # ``StreamEOFError``, which an extractor reads as end of capture.
        for name, schema, data in (
            ('hip', LocatorSetParameter, locator_set(2, truncate=10)),
            ('mh', CGAParametersOption, cga_option(CGA_PARAMETER[:-3])),
        ):
            with self.subTest(name=name):
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter('always')
                    with self.assertRaises(FieldValueError):
                        schema.unpack(data)
                self.assertTrue(any(issubclass(w.category, SchemaWarning) for w in caught))

    def test_fixed_length_item_running_short_still_warns(self) -> 'None':
        _, warned = self.unpack(ShortFixedList, b'\x06' + bytes(range(6)))
        self.assertEqual(warned, ['packet length < 0: -1'] * 2)


if __name__ == '__main__':
    unittest.main()
