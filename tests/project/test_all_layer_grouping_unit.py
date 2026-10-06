# -*- coding: utf-8 -*-
"""``pcapkit.all`` lists each protocol class under the group of its own layer.

The groups in ``pcapkit/all.py``'s ``__all__`` exist only as comments, so they are
read from the source with :mod:`tokenize`: the application group is every name
after the ``# Transport Layer`` comment and before ``# Protocol Schema``, and the
link group every name after ``# Raw Packet`` up to and including the line that
carries ``# Link Layer``. Each exported class's ``__layer__`` is then checked
against the group it sits in, so a protocol moved between layers (as ``OSPF``,
``RARP`` and ``DRARP`` were in #719) cannot stay listed under its old one.

"""
from __future__ import annotations

import importlib.util
import io
import os
import tokenize
import unittest

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

ALL_PY = os.path.join(os.path.dirname(__file__), os.pardir, os.pardir, 'pcapkit', 'all.py')


def read_groups() -> 'tuple[list[str], list[str]]':
    """Return the (link, application) groups of ``pcapkit/all.py``'s ``__all__``."""
    with open(ALL_PY, encoding='utf-8') as file:
        tokens = list(tokenize.generate_tokens(io.StringIO(file.read()).readline))

    # line of each group comment, and the names on each line
    marks = {}  # type: dict[str, int]
    names = []  # type: list[tuple[int, str]]
    for token in tokens:
        if token.type == tokenize.COMMENT:
            marks.setdefault(token.string.lstrip('#').strip(), token.start[0])
        elif token.type == tokenize.STRING:
            names.append((token.start[0], token.string.strip('\'"')))

    def between(after: 'int', upto: 'int') -> 'list[str]':
        return [name for line, name in names if after < line <= upto]

    def mark(label: 'str') -> 'int':
        line = marks.get(label)
        if line is None:
            raise AssertionError(f'pcapkit/all.py: group comment "# {label}" not found')
        return line

    link = between(mark('Raw Packet'), mark('Link Layer'))
    application = between(mark('Transport Layer'), mark('Protocol Schema') - 1)
    return link, application


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class AllLayerGroupingTests(unittest.TestCase):
    """Every protocol class in ``pcapkit.all.__all__`` sits under its own layer."""

    @classmethod
    def setUpClass(cls) -> None:
        import pcapkit.all
        cls.exported = {
            name: getattr(pcapkit.all, name) for name in pcapkit.all.__all__
            if isinstance(getattr(pcapkit.all, name, None), type)
        }
        cls.link, cls.application = read_groups()

    def classes_on(self, layer: 'str') -> 'set[str]':
        return {name for name, cls in self.exported.items()
                if getattr(cls, '__layer__', None) == layer}

    def foreign(self, group: 'list[str]', layer: 'str') -> 'set[str]':
        """Names in ``group`` whose class reports a layer other than ``layer``.

        A class whose ``__layer__`` is unset (``FTP_DATA`` subclasses ``Raw``) is not
        foreign.
        """
        return {name for name in group
                if (getattr(self.exported.get(name), '__layer__', None) or layer) != layer}

    def test_groups_are_found(self) -> None:
        self.assertIn('ARP', self.link)
        self.assertIn('VLAN', self.link)
        self.assertIn('FTP', self.application)
        self.assertIn('NGAP', self.application)
        self.assertNotIn('Schema', self.application)

    def test_application_classes_are_in_the_application_group(self) -> None:
        missing = self.classes_on('Application') - set(self.application)
        self.assertEqual(missing, set())

    def test_application_group_holds_only_application_classes(self) -> None:
        self.assertEqual(self.foreign(self.application, 'Application'), set())

    def test_link_group_holds_only_link_classes(self) -> None:
        self.assertEqual(self.foreign(self.link, 'Link'), set())

    def test_ospf_rarp_drarp_are_listed_once(self) -> None:
        import pcapkit.all

        for name in ('OSPF', 'RARP', 'DRARP'):
            with self.subTest(name=name):
                self.assertEqual(pcapkit.all.__all__.count(name), 1)
                self.assertNotIn(name, self.link)


if __name__ == '__main__':
    unittest.main()
