# -*- coding: utf-8 -*-
"""Regression coverage for GitHub issue #730.

Every field's :meth:`~pcapkit.corekit.fields.field.FieldBase.__call__` made a
defensive copy of ``self`` once per field per packet, via
``copy.copy(self)`` at eight call sites across
:mod:`pcapkit.corekit.fields.field`, :mod:`pcapkit.corekit.fields.collections`
and :mod:`pcapkit.corekit.fields.misc`. Profiling ``extract()`` on
``examples/captures/http.pcap`` attributed 55,846 ``getattr`` calls (~1.7% of
the run) to that :func:`copy.copy` -- not to anything in this package's own
code, but to :func:`copy.copy` looking itself up: it runs
``getattr(cls, '__copy__', None)`` before it can call the very
:meth:`FieldBase.__copy__` these classes already define, and that lookup is
what a profiler credits to ``builtins.getattr``.

``copier = getattr(cls, '__copy__', None); copier(x)`` is exactly
``x.__copy__()``, so calling it directly does not change *when* a field is
copied or what the copy contains -- only the redundant lookup is removed. This
module proves that: every one of the eight call sites now reaches
:meth:`FieldBase.__copy__` without ever calling :func:`copy.copy`.

On the tree before this fix, every test below fails: each ``__call__``
listed in the issue called :func:`copy.copy` exactly once (twice for
:class:`~pcapkit.corekit.fields.misc.ConditionalField`,
:class:`~pcapkit.corekit.fields.misc.SwitchField` and
:class:`~pcapkit.corekit.fields.misc.ForwardMatchField`, whose ``__call__``
also calls a nested field's own ``__call__``).

"""
from __future__ import annotations

import copy
import unittest
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import purge_modules

if TYPE_CHECKING:
    from typing import Any

    from pcapkit.corekit.fields.field import FieldBase


class FieldCallUsesCopyDunderDirectlyTests(unittest.TestCase):
    """Every ``__call__`` in :mod:`pcapkit.corekit.fields` calls ``self.__copy__()``.

    Rather than :func:`copy.copy(self) <copy.copy>`. Each test patches
    :func:`copy.copy` and :meth:`FieldBase.__copy__` with wrappers that still do
    the real work (``side_effect=`` the original), so the field returned is
    exactly what it always was; only the call counts are new.

    """

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

        from pcapkit.corekit.fields.field import FieldBase

        self.FieldBase = FieldBase
        self.real_copy_dunder = FieldBase.__copy__

    def assertCallReachesCopyDunderOnly(self, field: 'FieldBase[Any]') -> None:
        """Call ``field({})`` once; assert it reached ``__copy__`` but not ``copy.copy``.

        Args:
            field: A field instance built with whatever a real call site would
                give it -- a real callback default, a real selector, etc. --
                rather than a bare :class:`~unittest.mock.Mock`, so this
                exercises the exact ``__call__`` bodies :func:`copy.copy(self)
                <copy.copy>` used to run through.

        """
        with mock.patch('copy.copy', side_effect=copy.copy) as copy_copy, \
                mock.patch.object(self.FieldBase, '__copy__', autospec=True,
                                   side_effect=self.real_copy_dunder) as copy_dunder:
            new_field = field({})

        self.assertEqual(
            copy_copy.call_count, 0,
            'field.__call__ still routes through copy.copy(self) instead of '
            'self.__copy__() -- see GitHub issue #730')
        self.assertGreaterEqual(copy_dunder.call_count, 1)
        self.assertIsNot(new_field, field)
        self.assertIsInstance(new_field, type(field))

    def test_field_base_call_field_py_294(self) -> None:
        """:meth:`FieldBase.__call__` (``field.py:294``), reached via :class:`NoValueField`.

        :class:`~pcapkit.corekit.fields.misc.NoValueField` is the one concrete
        class in this package that never overrides ``__call__``, so it is the
        only way to exercise the base implementation directly rather than
        through a subclass's override.

        """
        from pcapkit.corekit.fields.misc import NoValueField

        self.assertCallReachesCopyDunderOnly(NoValueField())

    def test_field_call_field_py_579(self) -> None:
        """:meth:`Field.__call__` (``field.py:579``)."""
        from pcapkit.corekit.fields.field import Field

        self.assertCallReachesCopyDunderOnly(Field(length=4))

    def test_list_field_call_collections_py_84(self) -> None:
        """:meth:`ListField.__call__` (``collections.py:84``)."""
        from pcapkit.corekit.fields.collections import ListField

        self.assertCallReachesCopyDunderOnly(ListField(length=4))

    def test_conditional_field_call_misc_py_148(self) -> None:
        """:meth:`ConditionalField.__call__` (``misc.py:148``)."""
        from pcapkit.corekit.fields.field import Field
        from pcapkit.corekit.fields.misc import ConditionalField

        field = ConditionalField(field=Field(length=1), condition=lambda packet: True)
        self.assertCallReachesCopyDunderOnly(field)

    def test_payload_field_call_misc_py_299(self) -> None:
        """:meth:`PayloadField.__call__` (``misc.py:299``)."""
        from pcapkit.corekit.fields.misc import PayloadField

        self.assertCallReachesCopyDunderOnly(PayloadField(length=4))

    def test_switch_field_call_misc_py_427(self) -> None:
        """:meth:`SwitchField.__call__` (``misc.py:427``)."""
        from pcapkit.corekit.fields.field import Field
        from pcapkit.corekit.fields.misc import SwitchField

        field = SwitchField(selector=lambda packet: Field(length=1))
        self.assertCallReachesCopyDunderOnly(field)

    def test_schema_field_call_misc_py_650(self) -> None:
        """:meth:`SchemaField.__call__` (``misc.py:650``)."""
        from pcapkit.corekit.fields.misc import SchemaField
        from pcapkit.corekit.fields.numbers import UInt8Field
        from pcapkit.protocols.schema.schema import Schema, schema_final

        @schema_final
        class OneField(Schema):
            a: 'int' = UInt8Field()

        self.assertCallReachesCopyDunderOnly(SchemaField(schema=OneField))

    def test_forward_match_field_call_misc_py_782(self) -> None:
        """:meth:`ForwardMatchField.__call__` (``misc.py:782``)."""
        from pcapkit.corekit.fields.field import Field
        from pcapkit.corekit.fields.misc import ForwardMatchField

        field = ForwardMatchField(field=Field(length=1))
        self.assertCallReachesCopyDunderOnly(field)


if __name__ == '__main__':
    unittest.main()
