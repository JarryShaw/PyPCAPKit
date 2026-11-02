# -*- coding: utf-8 -*-
"""The field modules' :attr:`__all__` lists keep in step with one another.

GitHub issue #2174 found :mod:`pcapkit.corekit.fields.misc` leaving
:class:`~pcapkit.corekit.fields.misc.SchemaField` and
:func:`~pcapkit.corekit.fields.misc.nested_packet_context` out of its
:attr:`__all__`, :mod:`pcapkit.corekit.fields.strings` leaving out
:class:`~pcapkit.corekit.fields.strings.BytesField`, and
:mod:`pcapkit.corekit.fields`, :mod:`pcapkit.corekit` and
:mod:`pcapkit.all` all leaving out
:class:`~pcapkit.corekit.fields.misc.SwitchField` and
:class:`~pcapkit.corekit.fields.numbers.PortEnumField`, so ``import *`` from any
of them dropped documented field classes.
:mod:`tests.project.test_all_exports_unit` checks :mod:`pcapkit.all` against
:mod:`pcapkit.corekit`; this module checks the field package against its own
submodules, and :mod:`pcapkit.corekit` against the field package it re-lists by
hand.

The same issue found :meth:`DeferredPacket.to_dict
<pcapkit.corekit.packet.DeferredPacket.to_dict>` annotated as returning a
:obj:`dict`, widening the
:class:`~pcapkit.corekit.multidict.OrderedMultiDict` of the
:meth:`Info.to_dict <pcapkit.corekit.infoclass.Info.to_dict>` it overrides.
"""

import importlib
import pkgutil
import unittest

import pcapkit.corekit
import pcapkit.corekit.fields
from pcapkit.corekit.fields import misc
from pcapkit.corekit.infoclass import Info
from pcapkit.corekit.multidict import OrderedMultiDict
from pcapkit.corekit.packet import DeferredPacket

#: Test tier (#1958): checks the names the field modules export, a question about
#: the tree rather than about the interpreter.
__tier__ = 'LATEST'

#: Names a field submodule exports and :mod:`pcapkit.corekit.fields` deliberately
#: does not, keyed by the submodule. The package's :attr:`__all__` lists concrete
#: field classes only, which :mod:`pcapkit.corekit` and :mod:`pcapkit.all` then
#: re-export:
#:
#: * ``Field`` and ``_TextField`` are abstract bases, kept out of ``import *`` as
#:   every package's base class is (see
#:   :data:`tests.project.test_public_api.DELIBERATE_NON_EXPORTS`).
#: * ``packet_byteorder``, ``byteorder_callback``, ``parse_ip_address``,
#:   ``nested_packet_context`` and ``pad_length`` are helpers for writing a field
#:   or its callbacks, reached by their module path. ``nested_packet_context``
#:   in particular builds the packet context a nested schema's callbacks
#:   receive; star-exporting it would drop a generic name into the caller's
#:   namespace (#2174).
#: * ``DecodedString`` is the value type :class:`~pcapkit.corekit.fields.strings.StringField`
#:   returns, not a field.
FIELDS_DELIBERATE_NON_EXPORTS = {
    'pcapkit.corekit.fields.byteorder': ('byteorder_callback', 'packet_byteorder'),
    'pcapkit.corekit.fields.field': ('Field',),
    'pcapkit.corekit.fields.ipaddress': ('parse_ip_address',),
    'pcapkit.corekit.fields.misc': ('nested_packet_context',),
    'pcapkit.corekit.fields.strings': ('DecodedString', '_TextField', 'pad_length'),
}


def submodules() -> 'list[str]':
    """Return the dotted names of the :mod:`pcapkit.corekit.fields` submodules."""
    return [info.name for info in pkgutil.iter_modules(pcapkit.corekit.fields.__path__,
                                                         'pcapkit.corekit.fields.')]


class FieldsExportsTests(unittest.TestCase):
    """Every field a submodule exports reaches ``import *`` of the packages above it."""

    def test_submodules_are_found(self) -> None:
        self.assertIn('pcapkit.corekit.fields.misc', submodules())
        self.assertIn('pcapkit.corekit.fields.numbers', submodules())

    def test_every_submodule_export_is_listed_or_excluded(self) -> None:
        listed = set(pcapkit.corekit.fields.__all__)
        for name in submodules():
            with self.subTest(module=name):
                exported = set(importlib.import_module(name).__all__)
                excluded = set(FIELDS_DELIBERATE_NON_EXPORTS.get(name, ()))
                self.assertEqual(sorted(exported - listed - excluded), [])

    def test_exclusions_are_not_stale(self) -> None:
        listed = set(pcapkit.corekit.fields.__all__)
        for name, names in FIELDS_DELIBERATE_NON_EXPORTS.items():
            with self.subTest(module=name):
                self.assertIn(name, submodules())
                exported = set(importlib.import_module(name).__all__)
                self.assertEqual(sorted(set(names) - exported), [])
                self.assertEqual(sorted(set(names) & listed), [])

    def test_each_field_is_exported_by_its_own_module(self) -> None:
        # The converse of the check above: a field the package exports is
        # also in the __all__ of the module defining it. Guards against
        # strings.__all__ dropping BytesField and misc.__all__ SchemaField (#2174).
        for name in pcapkit.corekit.fields.__all__:
            home = getattr(pcapkit.corekit.fields, name).__module__
            with self.subTest(name=name, module=home):
                self.assertIn(name, importlib.import_module(home).__all__)

    def test_corekit_relists_every_field(self) -> None:
        self.assertEqual(sorted(set(pcapkit.corekit.fields.__all__) - set(pcapkit.corekit.__all__)), [])

    def test_misc_exports_what_it_documents(self) -> None:
        for name in ('SchemaField', 'SwitchField', 'nested_packet_context'):
            with self.subTest(name=name):
                self.assertIn(name, misc.__all__)

    def test_star_import_reaches_the_new_names(self) -> None:
        for package in ('pcapkit.corekit.fields', 'pcapkit.corekit', 'pcapkit.all'):
            namespace = {}  # type: dict[str, object]
            exec(f'from {package} import *', namespace)  # pylint: disable=exec-used
            for name in ('SchemaField', 'SwitchField', 'PortEnumField'):
                with self.subTest(package=package, name=name):
                    self.assertIn(name, namespace)


class DeferredPacketToDictTests(unittest.TestCase):
    """``DeferredPacket.to_dict`` is annotated as what it returns."""

    def test_annotation_matches_the_override(self) -> None:
        mine = DeferredPacket.to_dict.__annotations__['return']
        base = Info.to_dict.__annotations__['return']
        self.assertEqual(mine.split('[', 1)[0], OrderedMultiDict.__name__)
        self.assertEqual(mine.split('[', 1)[0], base.split('[', 1)[0])


if __name__ == '__main__':
    unittest.main()
