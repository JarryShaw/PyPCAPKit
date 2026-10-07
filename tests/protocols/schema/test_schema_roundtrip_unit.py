# -*- coding: utf-8 -*-
"""Base :class:`~pcapkit.protocols.schema.schema.Schema` round trips.

GitHub issue #1289: nothing on the packing path set ``__option_padding__``, so
a padding field sized from it packed nothing, and a TCP or IPv4 header rebuilt
from its schema came out shorter than its own length field said.

GitHub issue #1291: iterating a schema yielded the values its
``post_process`` stores on the instance, which ``__getitem__`` refused, so
``dict(schema)`` raised :exc:`KeyError`.

GitHub issue #1292: a :class:`~pcapkit.corekit.fields.misc.SchemaField` read
its whole declared span but packed only what its nested schema consumed, so
the octets the nested schema left unread were lost.

Every case builds its own octets in memory and reads no capture. Everything
from :mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, not at module load.

"""

import unittest

from tests._support import reimport_once_per_class

#: TCP header, Data Offset 6: NOP, EOOL, then two octets of padding.
TCP_HEADER = bytes.fromhex('0050c3500000000100000000' '6002ffff00000000' '01000000')
#: IPv4 header, IHL 6: NOP, EOOL, then two octets of padding.
IPV4_HEADER = bytes.fromhex('460000180000000040060000c0a80001c0a80002' '01000000')


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


class TestSchemaRoundTrip(unittest.TestCase):
    """Pin the base schema's packing and mapping behaviour."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_tcp_rebuild_keeps_option_padding(self) -> None:
        from pcapkit.protocols.transport.tcp import TCP

        parsed = TCP(TCP_HEADER, len(TCP_HEADER))
        rebuilt = TCP.from_schema(parsed.schema.to_dict())
        self.assertEqual(bytes(rebuilt), TCP_HEADER)

    def test_ipv4_rebuild_keeps_option_padding(self) -> None:
        from pcapkit.protocols.internet.ipv4 import IPv4

        parsed = IPv4(IPV4_HEADER, len(IPV4_HEADER))
        rebuilt = IPv4.from_schema(parsed.schema.to_dict())
        self.assertEqual(bytes(rebuilt), IPV4_HEADER)

    def test_iterated_keys_are_readable(self) -> None:
        from pcapkit.protocols.schema.internet.ipv4 import TSOption

        schema = TSOption.unpack(bytes.fromhex('4408090000000001'), 8, None)
        keys = list(schema)
        self.assertIn('timestamp', keys)
        for key in keys:
            with self.subTest(key=key):
                schema[key]  # pylint: disable=pointless-statement
        self.assertEqual(list(dict(schema)), keys)

    def test_builtin_names_are_not_items(self) -> None:
        from pcapkit.protocols.schema.internet.ipv4 import TSOption

        schema = TSOption.unpack(bytes.fromhex('4408090000000001'), 8, None)
        for name in ('__buffer__', 'pack', 'nonexistent'):
            with self.subTest(name=name), self.assertRaises(KeyError):
                schema[name]  # pylint: disable=pointless-statement

    def test_schema_field_keeps_unread_octets(self) -> None:
        _, outer = _nested_schemas()

        raw = bytes.fromhex('0302eeee04')
        self.assertEqual(outer.unpack(raw, len(raw), None).pack(), raw)

    def test_schema_field_keeps_declared_width(self) -> None:
        inner, outer = _nested_schemas()

        raw = bytes.fromhex('0302eeee04')
        rebuilt = outer.from_dict(outer.unpack(raw, len(raw), None).to_dict())
        # NOTE: The width is kept but the unread octets are zero-filled, since a
        # rebuilt schema was never unpacked; that open half is #1380, which will
        # change this expectation to ``0302eeee04``.
        self.assertEqual(rebuilt.pack(), bytes.fromhex('0302000004'))
        self.assertEqual(outer(n=3, inner=inner(x=2), tail=4).pack(), bytes.fromhex('0302000004'))


if __name__ == '__main__':
    unittest.main()
