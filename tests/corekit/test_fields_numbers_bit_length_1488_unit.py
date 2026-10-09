# -*- coding: utf-8 -*-
"""A number field keeps the bits outside its ``bit_length`` as captured.

GitHub issue #1488: :meth:`NumberField.post_process
<pcapkit.corekit.fields.numbers.NumberField.post_process>` masked the decoded
value to ``bit_length`` bits and :meth:`~pcapkit.corekit.fields.numbers.NumberField.pre_process`
masked it again, so ``UInt16Field(bit_length=12)`` read ``ffff`` and packed
``0fff``. The parsed value now records the bits it does not interpret, and a
value a caller supplies is still truncated to ``bit_length`` bits.

Every case builds its own octets in memory and reads no capture. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import copy
import io
import pickle
import unittest

from tests._support import reimport_once_per_class

#: Octets of a two-octet field, as hex.
WIRES = ('0000', '0001', '0fff', 'ffff', 'f000', '8000', '0800', 'f7ff', 'a5a5')


class TestBitLengthRoundTrip(unittest.TestCase):
    """``pack(unpack(b)) == b`` for a field narrower than its octets."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_unsigned_wire_round_trips(self) -> None:
        from pcapkit.corekit.fields.numbers import UInt16Field

        for order in ('big', 'little'):
            for wire in WIRES:
                with self.subTest(order=order, wire=wire):
                    raw = bytes.fromhex(wire)
                    value = UInt16Field(bit_length=12, byteorder=order)({}).unpack(raw, {})
                    self.assertEqual(value, int.from_bytes(raw, order) & 0xFFF)
                    packed = UInt16Field(bit_length=12, byteorder=order)({}).pack(value, {})
                    self.assertEqual(packed.hex(), wire)

    def test_signed_wire_round_trips(self) -> None:
        from pcapkit.corekit.fields.numbers import Int16Field

        for wire in WIRES:
            with self.subTest(wire=wire):
                raw = bytes.fromhex(wire)
                low = int.from_bytes(raw, 'big') & 0xFFF
                value = Int16Field(bit_length=12)({}).unpack(raw, {})
                self.assertEqual(value, low - 0x1000 if low & 0x800 else low)
                self.assertEqual(Int16Field(bit_length=12)({}).pack(value, {}).hex(), wire)

    def test_odd_width_wire_round_trips(self) -> None:
        from pcapkit.corekit.fields.numbers import NumberField

        for wire in ('ffffff', 'f00000', '000001', '123456'):
            with self.subTest(wire=wire):
                raw = bytes.fromhex(wire)
                value = NumberField(length=3, bit_length=20)({}).unpack(raw, {})
                self.assertEqual(value, int(wire, 16) & 0xFFFFF)
                self.assertEqual(NumberField(length=3, bit_length=20)({}).pack(value, {}).hex(), wire)

    def test_enum_wire_round_trips(self) -> None:
        from pcapkit.const.vlan.priority_level import PriorityLevel
        from pcapkit.corekit.fields.numbers import EnumField

        for namespace in (None, PriorityLevel):
            for octet in range(256):
                with self.subTest(namespace=namespace, octet=octet):
                    raw = bytes([octet])
                    value = EnumField(length=1, bit_length=3, namespace=namespace)({}).unpack(raw, {})
                    self.assertEqual(value, octet & 7)
                    if namespace is not None:
                        self.assertIsInstance(value, PriorityLevel)
                        self.assertEqual(value.name, PriorityLevel(octet & 7).name)
                    packed = EnumField(length=1, bit_length=3, namespace=namespace)({}).pack(value, {})
                    self.assertEqual(packed, raw)
        self.assertEqual(len(PriorityLevel.__members__), 8)

    def test_captured_bits_survive_copy_and_pickle(self) -> None:
        from pcapkit.const.vlan.priority_level import PriorityLevel
        from pcapkit.corekit.fields.numbers import EnumField, UInt16Field

        number = UInt16Field(bit_length=12)({}).unpack(b'\xff\xff', {})
        member = EnumField(length=1, bit_length=3, namespace=PriorityLevel)({}).unpack(b'\xff', {})
        for clone in (copy.copy, copy.deepcopy, lambda v: pickle.loads(pickle.dumps(v))):
            with self.subTest(clone=clone):
                self.assertEqual(UInt16Field(bit_length=12)({}).pack(clone(number), {}), b'\xff\xff')
                self.assertEqual(EnumField(length=1, bit_length=3, namespace=PriorityLevel)({})
                                 .pack(clone(member), {}), b'\xff')

    def test_value_without_spare_bits_is_a_plain_int(self) -> None:
        from pcapkit.corekit.fields.numbers import Int16Field, UInt16Field

        self.assertIs(type(UInt16Field(bit_length=12)({}).unpack(b'\x0f\xff', {})), int)
        self.assertIs(type(Int16Field(bit_length=12)({}).unpack(b'\xff\xff', {})), int)
        self.assertIs(type(UInt16Field()({}).unpack(b'\xff\xff', {})), int)

    def test_schema_round_trips(self) -> None:
        from pcapkit.corekit.fields.numbers import UInt8Field, UInt16Field
        from pcapkit.protocols.schema.schema import Schema

        class T(Schema):
            a: 'int' = UInt16Field(bit_length=12)
            b: 'int' = UInt8Field(bit_length=1)

        data = b'\xab\xcd\xfe'
        schema = T.unpack(io.BytesIO(data), 3, {'__length__': 3})
        self.assertEqual((schema.a, schema.b), (0xBCD, 0))
        self.assertEqual(schema.pack(), data)
        self.assertEqual(T.from_dict(schema.to_dict()).pack(), data)
        self.assertEqual(T(a=schema.a, b=schema.b).pack({}), data)


class TestBitLengthSuppliedValue(unittest.TestCase):
    """A value a caller supplies is truncated to ``bit_length`` bits, as before."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_unsigned_value_is_truncated(self) -> None:
        from pcapkit.corekit.fields.numbers import UInt16Field

        for value, wire in ((0, '0000'), (0xFFF, '0fff'), (0x1FFF, '0fff'), (0xFFFF, '0fff'),
                            (0xF000, '0000')):
            with self.subTest(value=hex(value)):
                self.assertEqual(UInt16Field(bit_length=12)({}).pack(value, {}).hex(), wire)

    def test_signed_value_is_sign_extended(self) -> None:
        from pcapkit.corekit.fields.numbers import Int16Field

        for value, wire in ((-1, 'ffff'), (0xFFF, 'ffff'), (2047, '07ff'), (-2048, 'f800')):
            with self.subTest(value=value):
                self.assertEqual(Int16Field(bit_length=12)({}).pack(value, {}).hex(), wire)

    def test_derived_value_drops_the_captured_bits(self) -> None:
        from pcapkit.const.vlan.priority_level import PriorityLevel
        from pcapkit.corekit.fields.numbers import EnumField, UInt16Field

        value = UInt16Field(bit_length=12)({}).unpack(b'\xff\xfe', {})
        self.assertEqual(UInt16Field(bit_length=12)({}).pack(value + 1, {}), b'\x0f\xff')
        self.assertEqual(UInt16Field(bit_length=12)({}).pack(int(value), {}), b'\x0f\xfe')
        self.assertEqual(EnumField(length=1, bit_length=3, namespace=PriorityLevel)({})
                         .pack(PriorityLevel(7), {}), b'\x07')


class TestBitLengthCaptureIsScoped(unittest.TestCase):
    """Only a field shaped like the capturing one honours the captured bits."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_number_packed_by_another_field(self) -> None:
        from pcapkit.corekit.fields.numbers import Int16Field, UInt8Field, UInt16Field

        value = UInt16Field(bit_length=12)({}).unpack(b'\xff\xff', {})
        others = {
            'full width': (lambda: UInt16Field(), '0fff'),
            'narrower bit_length': (lambda: UInt16Field(bit_length=8), '00ff'),
            'shorter octets': (lambda: UInt8Field(), 'ff'),
            'other byte order': (lambda: UInt16Field(bit_length=12, byteorder='little'), 'ff0f'),
            'other sign': (lambda: Int16Field(bit_length=12), 'ffff'),
        }
        for label, (make, wire) in others.items():
            with self.subTest(label):
                want = make()({}).pack(int(value), {})
                self.assertEqual(want.hex(), wire)
                self.assertEqual(make()({}).pack(value, {}), want)

    def test_same_shape_through_a_callable_length(self) -> None:
        from pcapkit.corekit.fields.numbers import NumberField, UInt16Field

        value = UInt16Field(bit_length=12)({}).unpack(b'\xff\xff', {})
        field = NumberField(length=lambda pkt: pkt['n'], bit_length=12)
        self.assertEqual(field({'n': 2}).pack(value, {'n': 2}), b'\xff\xff')

    def test_enum_member_packed_by_another_field(self) -> None:
        from pcapkit.const.vlan.priority_level import PriorityLevel
        from pcapkit.corekit.fields.numbers import EnumField, UInt8Field

        for namespace in (None, PriorityLevel):
            member = EnumField(length=1, bit_length=3, namespace=namespace)({}).unpack(b'\xff', {})
            others = {
                'UInt8Field': lambda: UInt8Field(),
                'full-width EnumField': lambda: EnumField(length=1, namespace=namespace),
                'narrower bit_length': lambda: EnumField(length=1, bit_length=2, namespace=namespace),
            }
            for label, make in others.items():
                with self.subTest(namespace=namespace, field=label):
                    self.assertEqual(make()({}).pack(member, {}),
                                     make()({}).pack(member.value, {}))
            with self.subTest(namespace=namespace, field='UInt8Field octets'):
                self.assertEqual(UInt8Field()({}).pack(member, {}), b'\x07')


if __name__ == '__main__':
    unittest.main()
