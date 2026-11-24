# -*- coding: utf-8 -*-
"""Every class files each member under the section comment its kind names (GitHub issue #2911).

``protocol-member-order.rst`` gives four section comments a meaning: every
``@property`` under ``# Properties.``, public methods under ``# Methods.``, every
dunder under ``# Data models.``, and everything else under ``# Utilities.``. The
owner ruled on #2911 that the meanings bind every class with section comments,
not only the protocol classes ``test_protocol_member_order_2490_unit`` orders.

:func:`audit` holds a class to them: a member under one of the four comments is
of that comment's kind. A member under any other comment, a topic section such
as ``# Defaults.`` or ``# Reassembly.``, keeps its place. :func:`unfiled` finds a
member above the class's first comment, which the owner ruled out on #2922. The
comments are read as :file:`util/member_sections.py` reads them for the API pages'
subtitles, and a member's kind as the #2490 guard reads it, so the three agree.

This module is unit-tier: it parses source and imports nothing it scans.

"""
from __future__ import annotations

import importlib.util
import pathlib
import tempfile
import textwrap
import unittest
from typing import TYPE_CHECKING

from tests._tiers import ROOT
from tests.project.test_protocol_member_order_2490_unit import GROUPS, classes, members

if TYPE_CHECKING:
    import ast
    from types import ModuleType

#: Test tier (#1958): parses every module under ``pcapkit/`` for a question about
#: the tree, which does not differ by interpreter.
__tier__ = 'LATEST'

#: The four section comments, each mapped to the index in :data:`GROUPS` of the
#: kind it holds.
MEANINGS = {f'{group}.': index for index, group in enumerate(GROUPS)}


def _load_fixer() -> 'ModuleType':
    """Load :file:`util/member_sections.py` by path, since :file:`util/` is not a package."""
    spec = importlib.util.spec_from_file_location('member_sections', ROOT / 'util' / 'member_sections.py')
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


member_sections = _load_fixer()


def audit(path: 'pathlib.Path', node: 'ast.ClassDef') -> 'list[tuple[str, str, str]]':
    """Each member of the class ``node``, parsed from ``path``, under one of :data:`MEANINGS` but of another kind.

    A finding is ``(member, comment, belongs)``: the comment the member is under,
    and the one its kind names.

    """
    layout = member_sections.layout(member_sections.Class(path, node))
    found = []  # type: list[tuple[str, str, str]]
    for name, group in members(node):
        section = layout[name][1]
        if section in MEANINGS and MEANINGS[section] != group:
            found.append((name, section, f'{GROUPS[group]}.'))
    return found


def unfiled(path: 'pathlib.Path', node: 'ast.ClassDef') -> 'list[str]':
    """Each member of the class ``node``, parsed from ``path``, above its first section comment.

    A class without section comments has none.

    """
    cls = member_sections.Class(path, node)
    if not member_sections.banners(cls):
        return []
    layout = member_sections.layout(cls)
    return [name for name, _ in members(node) if layout[name][1] is None]


def audit_tree(root: 'pathlib.Path' = ROOT) -> 'dict[str, tuple[list[tuple[str, str, str]], list[str]]]':
    """Every class under ``root``'s :file:`pcapkit/` with section comments, mapped to its :func:`audit` and :func:`unfiled`."""
    found = {}  # type: dict[str, tuple[list[tuple[str, str, str]], list[str]]]
    for path in sorted((root / 'pcapkit').rglob('*.py')):
        for name, node in classes(path, root):
            if member_sections.banners(member_sections.Class(path, node)):
                found[name] = audit(path, node), unfiled(path, node)
    return found


#: Fixture classes: ``Sound`` files each kind under its comment, with an
#: attribute above the first comment and a topic section; ``Misfiled`` files each
#: kind under a comment of another; ``Unfiled`` has members above its first
#: comment; ``Plain`` has no section comments.
FIXTURE = textwrap.dedent('''\
    class Sound:
        lead = None

        ##########
        # Defaults.
        ##########

        def _topic(self): ...

        def topic(self): ...

        ##########
        # Properties.
        ##########

        @property
        def name(self): ...

        @name.setter
        def name(self, value): ...

        ##########
        # Methods.
        ##########

        def read(self): ...

        ##########
        # Data models.
        ##########

        def __update__(self): ...

        __init__ = __update__

        ##########
        # Utilities.
        ##########

        @staticmethod
        def _helper(): ...


    class Misfiled:
        ##########
        # Properties.
        ##########

        def read(self): ...

        ##########
        # Methods.
        ##########

        @property
        def name(self): ...

        def _helper(self): ...

        ##########
        # Data models.
        ##########

        def _other(self): ...

        ##########
        # Utilities.
        ##########

        def __index__(self): ...


    class Unfiled:
        """A docstring is no member."""

        lead = None

        def __init__(self): ...

        @classmethod
        def check(cls): ...

        ##########
        # Methods.
        ##########

        def read(self): ...


    class Plain:
        def read(self): ...
''')


class TestAudit(unittest.TestCase):
    """The audits find each kind under another kind's comment and each member above the first, and nothing else."""

    @classmethod
    def setUpClass(cls) -> 'None':
        cls.scratch = tempfile.TemporaryDirectory(prefix='pcapkit-section-meanings-')
        cls.path = pathlib.Path(cls.scratch.name) / 'fixture.py'
        cls.path.write_text(FIXTURE, encoding='utf-8')
        found = {name.rsplit('.', 1)[-1]: node for name, node in classes(cls.path, cls.path.parent)}
        cls.findings = {name: audit(cls.path, node) for name, node in found.items()}
        cls.unfiled = {name: unfiled(cls.path, node) for name, node in found.items()}

    @classmethod
    def tearDownClass(cls) -> 'None':
        cls.scratch.cleanup()

    def test_a_sound_class_has_no_finding(self) -> 'None':
        self.assertEqual(self.findings['Sound'], [])
        self.assertEqual(self.unfiled['Sound'], [])

    def test_a_member_above_the_first_comment_is_found(self) -> 'None':
        self.assertEqual(self.unfiled['Unfiled'], ['__init__', 'check'])

    def test_a_class_without_comments_has_none_above(self) -> 'None':
        self.assertEqual(self.unfiled['Plain'], [])

    def test_each_kind_misfiled_is_found(self) -> 'None':
        self.assertEqual(self.findings['Misfiled'], [
            ('read', 'Properties.', 'Methods.'),
            ('name', 'Methods.', 'Properties.'),
            ('_helper', 'Methods.', 'Utilities.'),
            ('_other', 'Data models.', 'Utilities.'),
            ('__index__', 'Utilities.', 'Data models.'),
        ])


class TestSectionMeanings(unittest.TestCase):
    """Every class under :file:`pcapkit/` with section comments keeps the four meanings and files every member."""

    @classmethod
    def setUpClass(cls) -> 'None':
        cls.findings = audit_tree()

    def test_every_member_is_under_its_kind(self) -> 'None':
        misfiled = [f'{name}.{member} is under # {section} but belongs under # {belongs}'
                    for name, (found, _) in sorted(self.findings.items()) for member, section, belongs in found]
        self.assertEqual(misfiled, [], 'move each member under the comment its kind names (protocol-member-order.rst)')

    def test_no_member_is_above_the_first_comment(self) -> 'None':
        above = [f'{name}.{member} is above the first section comment'
                 for name, (_, found) in sorted(self.findings.items()) for member in found]
        self.assertEqual(above, [], 'move each member under the comment its kind or topic names '
                                    '(protocol-member-order.rst)')

    def test_the_scan_reaches_beyond_protocols(self) -> 'None':
        # The ruling's scope: a protocol class and one outside pcapkit.protocols.
        for name in ('pcapkit.protocols.link.arp.protocol.ARP', 'pcapkit.foundation.extraction.Extractor'):
            with self.subTest(name=name):
                self.assertIn(name, self.findings)


if __name__ == '__main__':
    unittest.main()
