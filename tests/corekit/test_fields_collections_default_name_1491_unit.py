# -*- coding: utf-8 -*-
"""Unnamed collection, payload and schema fields have a default name.

GitHub issue #1491: :meth:`ListField.__init__
<pcapkit.corekit.fields.collections.ListField.__init__>` set no ``_name``, so
``ListField().name`` raised :exc:`AttributeError` -- and so did every subclass
that reaches it through ``super().__init__``, :class:`OptionField` included,
whose ``unpack`` reads ``self.name``. :class:`PayloadField` and
:class:`SchemaField` had the same gap. Other fields default to
``<{class name less "Field", lower-cased}>``, as :class:`FieldBase` and
:class:`Field` do in :mod:`pcapkit.corekit.fields.field`.

Classes are imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import unittest

from tests._support import reimport_once_per_class


class TestListFieldDefaultName(unittest.TestCase):
    """Pin the default name of unnamed collection fields."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_list_field(self) -> None:
        from pcapkit.corekit.fields.collections import ListField

        self.assertEqual(ListField().name, '<list>')
        self.assertEqual(repr(ListField()), '<ListField>')

    def test_option_field_subclasses(self) -> None:
        from pcapkit.corekit.fields.collections import OptionField
        from pcapkit.protocols.schema.transport.sctp import ChunkListField, Parameter

        for cls, name in ((OptionField, '<option>'), (ChunkListField, '<chunklist>')):
            with self.subTest(cls=cls.__name__):
                field = cls(base_schema=Parameter, type_name='type',
                            registry=Parameter.registry)
                self.assertEqual(field.name, name)

    def test_copy_keeps_default_name(self) -> None:
        from pcapkit.corekit.fields.collections import ListField

        self.assertEqual(ListField()({}).name, '<list>')

    def test_schema_name_wins(self) -> None:
        from pcapkit.protocols.schema.transport.sctp import INITChunk

        self.assertEqual(INITChunk.__fields__['parameters'].name, 'parameters')


class TestMiscFieldDefaultName(unittest.TestCase):
    """Pin the default name of unnamed :mod:`~pcapkit.corekit.fields.misc` fields."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_payload_field(self) -> None:
        from pcapkit.corekit.fields.misc import PayloadField

        self.assertEqual(PayloadField().name, '<payload>')
        self.assertEqual(PayloadField()({}).name, '<payload>')

    def test_schema_field(self) -> None:
        from pcapkit.corekit.fields.misc import SchemaField
        from pcapkit.protocols.schema.transport.sctp import Parameter

        self.assertEqual(SchemaField(schema=Parameter).name, '<schema>')
        self.assertEqual(SchemaField(schema=Parameter)({}).name, '<schema>')


if __name__ == '__main__':
    unittest.main()
