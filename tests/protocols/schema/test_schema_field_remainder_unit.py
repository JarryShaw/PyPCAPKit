# -*- coding: utf-8 -*-
"""A :class:`~pcapkit.corekit.fields.misc.SchemaField`'s unread octets survive a rebuild.

GitHub issue #1380: a nested schema may read less than its
:class:`~pcapkit.corekit.fields.misc.SchemaField`'s declared span. Parsing then
packing kept the octets it left unread (#1292), but a schema rebuilt through
:meth:`~pcapkit.protocols.schema.schema.Schema.from_dict`, or a protocol rebuilt
through :meth:`~pcapkit.protocols.protocol.ProtocolBase.from_data`, had never
been unpacked and zero-filled them. They now travel with the nested value as its
``__remainder__``.

No shipped schema declares a :class:`~pcapkit.corekit.fields.misc.SchemaField`
directly, so the schemas and the protocol here are built in the test. Everything
from :mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, not at module load.

"""

import unittest
import warnings

from tests._support import reimport_once_per_class

#: ``n`` = 3, a 3-octet span whose nested schema reads only ``02``, then ``tail``.
RAW = bytes.fromhex('0302eeee04')


def _nested_schemas():  # type: ignore[no-untyped-def]
    """An outer schema whose nested schema reads less than its span."""
    from pcapkit.corekit.fields.misc import SchemaField
    from pcapkit.corekit.fields.numbers import UInt8Field
    from pcapkit.protocols.schema.schema import Schema, schema_final

    @schema_final
    class Inner(Schema):
        x: int = UInt8Field()

    @schema_final
    class Outer(Schema):
        n: int = UInt8Field()
        inner: Inner = SchemaField(length=lambda pkt: pkt['n'], schema=Inner)
        tail: int = UInt8Field()

    return Inner, Outer


#: A 6-octet span whose nested schema reads ``k`` = 2 and ``aabb``, then ``tail``.
SIZED_RAW = bytes.fromhex('02aabbccddee04')


def _sized_schemas():  # type: ignore[no-untyped-def]
    """An outer schema whose nested schema's own width depends on its values."""
    from pcapkit.corekit.fields.misc import SchemaField
    from pcapkit.corekit.fields.numbers import UInt8Field
    from pcapkit.corekit.fields.strings import BytesField
    from pcapkit.protocols.schema.schema import Schema, schema_final

    @schema_final
    class Inner(Schema):
        k: int = UInt8Field()
        body: bytes = BytesField(length=lambda pkt: pkt['k'])

    @schema_final
    class Outer(Schema):
        inner: Inner = SchemaField(length=6, schema=Inner)
        tail: int = UInt8Field()

    return Inner, Outer


def _protocol(outer):  # type: ignore[no-untyped-def]
    """A protocol over ``outer`` whose data model holds the nested schema's mapping."""
    from pcapkit.corekit.infoclass import info_final
    from pcapkit.corekit.protochain import ProtoChain
    from pcapkit.protocols.data.data import Data
    from pcapkit.protocols.protocol import ProtocolBase

    @info_final
    class OuterData(Data):
        n: int
        inner: dict
        tail: int

    class OuterProtocol(ProtocolBase, schema=outer, data=OuterData):  # type: ignore[call-arg,misc]
        __layer__ = 'Internet'

        @property
        def name(self):  # type: ignore[no-untyped-def]
            return 'Outer'

        @property
        def length(self):  # type: ignore[no-untyped-def]
            return len(self.__header__)

        def read(self, length=None, **kwargs):  # type: ignore[no-untyped-def]
            from pcapkit.protocols.misc.null import NoPayload

            schema = self.__header__
            self._next = NoPayload()
            self._protos = ProtoChain(type(self), self.alias, basis=self._next.protochain)
            # NOTE: A made header still holds the mapping ``make`` was given.
            inner = schema.inner if isinstance(schema.inner, dict) else schema.inner.to_dict()
            return OuterData(n=schema.n, inner=inner, tail=schema.tail)

        def make(self, n=0, inner=None, tail=0, **kwargs):  # type: ignore[no-untyped-def]
            return outer(n=n, inner=inner, tail=tail)

        @classmethod
        def __index__(cls):  # type: ignore[no-untyped-def,override]
            return 250

    return OuterProtocol


class TestSchemaFieldRemainder(unittest.TestCase):
    """Pin the unread octets of a nested schema through every rebuild."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_to_dict_carries_the_remainder(self) -> None:
        _, outer = _nested_schemas()

        parsed = outer.unpack(RAW, len(RAW), None)
        self.assertEqual(parsed.to_dict(), {
            'n': 3, 'inner': {'x': 2, '__remainder__': b'\xee\xee', '__remainder_offset__': 1}, 'tail': 4,
        })

    def test_from_dict_rebuilds_byte_exactly(self) -> None:
        _, outer = _nested_schemas()

        parsed = outer.unpack(RAW, len(RAW), None)
        with warnings.catch_warnings():
            warnings.simplefilter('error')
            rebuilt = outer.from_dict(parsed.to_dict())
            packed = rebuilt.pack()
        self.assertEqual(packed, RAW)

    def test_parsed_nested_schema_keeps_its_remainder(self) -> None:
        _, outer = _nested_schemas()

        parsed = outer.unpack(RAW, len(RAW), None)
        self.assertEqual(outer(n=3, inner=parsed.inner, tail=4).pack(), RAW)

    def test_remainder_is_not_a_field(self) -> None:
        _, outer = _nested_schemas()

        inner = outer.unpack(RAW, len(RAW), None).inner
        self.assertEqual(dict(inner), {'x': 2})
        self.assertEqual(bytes(inner), b'\x02')
        with self.assertRaises(KeyError):
            inner['__remainder__']  # pylint: disable=pointless-statement,unsubscriptable-object

    def test_remainder_that_no_longer_fits_is_dropped(self) -> None:
        _, outer = _nested_schemas()

        data = outer.unpack(RAW, len(RAW), None).to_dict()
        data['n'] = 2
        self.assertEqual(outer.from_dict(data).pack(), bytes.fromhex('02020004'))

    def test_shrunk_in_place_is_zero_filled(self) -> None:
        _, outer = _sized_schemas()

        parsed = outer.unpack(SIZED_RAW, len(SIZED_RAW), None)
        parsed.inner.body = b'\xaa'
        parsed.inner.k = 1
        self.assertEqual(parsed.pack(), bytes.fromhex('01aa0000000004'))

    def test_shrunk_through_from_dict_is_zero_filled(self) -> None:
        _, outer = _sized_schemas()

        data = outer.unpack(SIZED_RAW, len(SIZED_RAW), None).to_dict()
        data['inner'].update(k=1, body=b'\xaa')
        self.assertEqual(outer.from_dict(data).pack(), bytes.fromhex('01aa0000000004'))

    def test_grown_through_from_dict_is_zero_filled(self) -> None:
        _, outer = _sized_schemas()

        data = outer.unpack(SIZED_RAW, len(SIZED_RAW), None).to_dict()
        data['inner'].update(k=4, body=b'\xaa\xbb\xcc\xdd')
        self.assertEqual(outer.from_dict(data).pack(), bytes.fromhex('04aabbccdd0004'))

    def test_sized_round_trips_byte_exactly(self) -> None:
        _, outer = _sized_schemas()

        parsed = outer.unpack(SIZED_RAW, len(SIZED_RAW), None)
        self.assertEqual(parsed.pack(), SIZED_RAW)
        self.assertEqual(outer.from_dict(parsed.to_dict()).pack(), SIZED_RAW)

    def test_no_remainder_without_unread_octets(self) -> None:
        _, outer = _nested_schemas()

        raw = bytes.fromhex('010204')
        parsed = outer.unpack(raw, len(raw), None)
        self.assertNotIn('__remainder__', parsed.to_dict()['inner'])
        self.assertEqual(outer.from_dict(parsed.to_dict()).pack(), raw)

    def test_protocol_from_data_rebuilds_byte_exactly(self) -> None:
        _, outer = _nested_schemas()
        protocol = _protocol(outer)

        parsed = protocol(RAW, len(RAW))
        self.assertEqual(bytes(protocol.from_data(parsed.info)), RAW)
        self.assertEqual(bytes(protocol.from_data(parsed.info.to_dict())), RAW)


if __name__ == '__main__':
    unittest.main()
