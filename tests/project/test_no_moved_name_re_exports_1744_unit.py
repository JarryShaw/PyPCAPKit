# -*- coding: utf-8 -*-
"""A moved name keeps no re-export at its old path (GitHub issue #1744).

The owner ruled on #1715 and #1103 that a moved name or module keeps no
re-export at its old path, ``TLSKeyLabel`` included. Under ruling D1 on #1744
only an *explicit* re-export goes: an alias assignment, a name in a non-home
module's ``__all__``, or a name documented as importable there. A module that still uses a name it imports from
the new home keeps the import, so the old path resolving through it is expected.

These checks pin that:

* :class:`TestNotExported` -- no removed name is in its old module's
  ``__all__``;
* :class:`TestNotBound` -- a name the old module only re-exported is not bound
  there at all, and a name it still uses is the new home's own object;
* :class:`TestNoReader` -- nothing under :mod:`pcapkit`, ``examples``,
  ``util`` or ``tests`` imports a removed name from its old path, or reads it
  as an attribute of the old module imported whole;
* :class:`TestNotDocumented` -- no ``auto*`` directive under ``docs/`` documents
  a removed name at its old path;
* :class:`TestNoReExportProse` -- no docstring under :mod:`pcapkit` and no page
  under ``docs/`` says a removed name is importable, re-exported or available
  at its old path;
* :class:`TestVersionRemoved` -- the paths that shipped in a release carry
  ``versionremoved`` for the version that removed them, in the module docstring
  and on the docs page, per #1103; the beta-only ones are deleted with no
  directive.

This module is unit-tier and reads no capture.

"""
from __future__ import annotations

import ast
import importlib
import pathlib
import re
import unittest

#: Test tier (#1958): checks that each moved name's old path is gone, a question about
#: the tree.
__tier__ = 'LATEST'

#: Repository root.
ROOT = pathlib.Path(__file__).resolve().parents[2]

#: Removed paths the old module does not bind at all, as ``(old module, name)``.
PURE = (
    ('pcapkit.protocols.misc.pcapng', 'TLSKeyLabel'),
    ('pcapkit.corekit.fields.field', 'NoValueType'),
    ('pcapkit.corekit.enum', 'NoDefaultType'),
    ('pcapkit.corekit.module', 'NullType'),
    ('pcapkit.corekit.module', '_get_null'),
    ('pcapkit.protocols.protocol', 'AbsentType'),
    ('pcapkit.foundation.reassembly.data', 'DeferredPacket'),
    ('pcapkit.foundation.reassembly.data.data', 'DeferredPacket'),
    ('pcapkit.foundation.traceflow.data.data', 'DeferredPacket'),
    ('pcapkit.protocols.application.ftp', 'FTP_DATA'),
    ('pcapkit.protocols.application.rarp', 'DRARP'),
    ('pcapkit.protocols.application.ngap', 'ProcedureCode'),
    ('pcapkit.protocols.application.ngap', 'ProtocolIE'),
    ('pcapkit.protocols.internet.mh', 'NTPTimestamp'),
    ('pcapkit.protocols.internet.mh', 'PMIPv6Timestamp'),
    ('pcapkit.protocols.link.arp', 'InARP'),
    # #2529: renamed after their modules.
    ('pcapkit.protocols.application.httpv1', 'HTTP'),
    ('pcapkit.protocols.application.httpv2', 'HTTP'),
    ('pcapkit.protocols.schema.application.httpv1', 'HTTP'),
    ('pcapkit.protocols.schema.application.httpv2', 'HTTP'),
    ('pcapkit.protocols.data.application.httpv1', 'HTTP'),
    ('pcapkit.protocols.data.application.httpv2', 'HTTP'),
)

#: Removed paths the old module still uses, as ``(old module, name, new home)``.
#: D1: the import stays, the export goes.
USED = (
    ('pcapkit.corekit.fields.field', 'NO_VALUE', 'pcapkit.corekit.sentinels'),
    ('pcapkit.corekit.enum', 'NO_DEFAULT', 'pcapkit.corekit.sentinels'),
    ('pcapkit.corekit.module', 'NULL', 'pcapkit.corekit.sentinels'),
    ('pcapkit.protocols.protocol', 'ABSENT', 'pcapkit.corekit.sentinels'),
)

#: Every removed ``(old module, name)`` pair.
REMOVED = PURE + tuple((module, name) for module, name, _ in USED)

#: The paths that shipped in a release, as ``(old module, name, source file, docs page,
#: the version that removed it)``.
SHIPPED = (
    ('pcapkit.protocols.misc.pcapng', 'TLSKeyLabel',
     'pcapkit/protocols/misc/pcapng.py', 'pcapkit/protocols/misc/pcapng.rst', '1.5.0'),
    ('pcapkit.corekit.fields.field', 'NoValueType',
     'pcapkit/corekit/fields/field.py', 'pcapkit/corekit/fields/field.rst', '1.5.0'),
    ('pcapkit.protocols.internet.mh', 'NTPTimestamp',
     'pcapkit/protocols/internet/mh.py', 'pcapkit/protocols/internet/mh.rst', '1.5.0'),
    ('pcapkit.protocols.application.ftp', 'FTP_DATA',
     'pcapkit/protocols/application/ftp.py',
     'pcapkit/protocols/application/ftp.rst', '1.5.0'),
    # #2529: shipped in 1.5.x, moved to their own modules.
    ('pcapkit.protocols.application.rarp', 'DRARP',
     'pcapkit/protocols/application/rarp.py',
     'pcapkit/protocols/application/rarp.rst', '1.6.0'),
    ('pcapkit.protocols.link.arp', 'InARP',
     'pcapkit/protocols/link/arp.py',
     'pcapkit/protocols/link/arp.rst', '1.6.0'),
    # #2529: shipped in 1.5.x, renamed after their modules.
    ('pcapkit.protocols.application.httpv1', 'HTTP',
     'pcapkit/protocols/application/httpv1.py',
     'pcapkit/protocols/application/httpv1.rst', '1.6.0'),
    ('pcapkit.protocols.application.httpv2', 'HTTP',
     'pcapkit/protocols/application/httpv2.py',
     'pcapkit/protocols/application/httpv2.rst', '1.6.0'),
    ('pcapkit.protocols.schema.application.httpv1', 'HTTP',
     'pcapkit/protocols/schema/application/httpv1.py',
     'pcapkit/protocols/application/httpv1.rst', '1.6.0'),
    ('pcapkit.protocols.schema.application.httpv2', 'HTTP',
     'pcapkit/protocols/schema/application/httpv2.py',
     'pcapkit/protocols/application/httpv2.rst', '1.6.0'),
    ('pcapkit.protocols.data.application.httpv1', 'HTTP',
     'pcapkit/protocols/data/application/httpv1.py',
     'pcapkit/protocols/application/httpv1.rst', '1.6.0'),
    ('pcapkit.protocols.data.application.httpv2', 'HTTP',
     'pcapkit/protocols/data/application/httpv2.py',
     'pcapkit/protocols/application/httpv2.rst', '1.6.0'),
)


def _sources() -> 'list[pathlib.Path]':
    """Every Python file a reader could live in."""
    files = []  # type: list[pathlib.Path]
    for top in ('pcapkit', 'examples', 'util', 'tests'):
        files.extend(sorted((ROOT / top).rglob('*.py')))
    return files


def _docs_dir() -> 'pathlib.Path':
    """The Sphinx source directory."""
    return ROOT / 'docs' / 'source'


def _removed_by_module() -> 'dict[str, set[str]]':
    """The removed names, grouped by the old module they left."""
    removed = {}  # type: dict[str, set[str]]
    for module_name, name in REMOVED:
        removed.setdefault(module_name, set()).add(name)
    return removed


def _dotted(node: 'ast.expr') -> 'str | None':
    """The dotted name an attribute chain spells, or :data:`None`."""
    parts = []  # type: list[str]
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    return '.'.join(reversed(parts))


#: Wording that claims a name is still reachable somewhere.
CLAIM = re.compile(r'importable from|still importable|re-exported|available as', re.IGNORECASE)


def _sentences(text: 'str') -> 'list[str]':
    """The sentences of ``text``, each on one line."""
    sentences = []  # type: list[str]
    for paragraph in re.split(r'\n\s*\n', text):
        sentences.extend(re.split(r'(?<=[.!?])\s+', ' '.join(paragraph.split())))
    return sentences


def _claims(text: 'str', owner: 'str | None' = None) -> 'list[str]':
    """Removed paths a sentence of ``text`` claims a name is reachable at.

    A sentence counts only when it carries :data:`CLAIM` wording and names a
    removed ``(old module, name)`` pair: the dotted path itself, or the old
    module with the name -- given in the sentence, or by ``owner``, the object
    whose docstring ``text`` is.

    """
    found = []  # type: list[str]
    for sentence in _sentences(text):
        if CLAIM.search(sentence) is None:
            continue
        for module_name, name in REMOVED:
            module_re, name_re = re.escape(module_name), re.escape(name)
            if re.search(rf'(?<![\w.]){module_re}\.{name_re}(?!\w)', sentence) is not None \
                    or (re.search(rf'(?<![\w.]){module_re}(?!\w|\.\w)', sentence) is not None
                        and (owner == name
                             or re.search(rf'(?<![\w.]){name_re}(?!\w)', sentence) is not None)):
                found.append(f'{module_name}.{name}: {sentence}')
    return found


class TestNotExported(unittest.TestCase):
    """No removed name is in its old module's ``__all__``."""

    def test_removed_names_are_not_in_all(self) -> 'None':
        for module_name, name in REMOVED:
            with self.subTest(module=module_name, name=name):
                module = importlib.import_module(module_name)
                self.assertNotIn(name, module.__all__)


class TestNotBound(unittest.TestCase):
    """A pure re-export is gone; a name still used is the new home's object."""

    def test_pure_re_exports_are_not_bound(self) -> 'None':
        for module_name, name in PURE:
            with self.subTest(module=module_name, name=name):
                module = importlib.import_module(module_name)
                self.assertFalse(hasattr(module, name))

    def test_used_names_are_the_new_homes_object(self) -> 'None':
        for module_name, name, home in USED:
            with self.subTest(module=module_name, name=name):
                module = importlib.import_module(module_name)
                self.assertIs(getattr(module, name), getattr(importlib.import_module(home), name))


class TestNoReader(unittest.TestCase):
    """Every other reader imports the name from its new home."""

    def test_no_import_from_an_old_path(self) -> 'None':
        removed = _removed_by_module()
        found = []  # type: list[str]
        for path in _sources():
            tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module in removed:
                    for alias in node.names:
                        if alias.name in removed[node.module]:
                            found.append(f'{path.relative_to(ROOT)}:{node.lineno}: '
                                         f'{node.module}.{alias.name}')
        self.assertEqual(found, [])

    def test_no_attribute_read_through_an_old_module(self) -> 'None':
        removed = _removed_by_module()
        found = []  # type: list[str]
        for path in _sources():
            tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
            # An old module bound under a local name, and the top-level names a
            # plain ``import a.b.c`` binds, through which ``a.b.c.NAME`` reads.
            aliases = {}  # type: dict[str, str]
            roots = set()  # type: set[str]
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.asname is None:
                            roots.add(alias.name.partition('.')[0])
                        elif alias.name in removed:
                            aliases[alias.asname] = alias.name
                elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                    for alias in node.names:
                        if f'{node.module}.{alias.name}' in removed:
                            aliases[alias.asname or alias.name] = f'{node.module}.{alias.name}'
            for node in ast.walk(tree):
                if not isinstance(node, ast.Attribute) or not isinstance(node.ctx, ast.Load):
                    continue
                base = _dotted(node.value)
                if base in aliases:
                    module_name = aliases[base]
                elif base in removed and base.partition('.')[0] in roots:
                    module_name = base
                else:
                    continue
                if node.attr in removed[module_name]:
                    found.append(f'{path.relative_to(ROOT)}:{node.lineno}: '
                                 f'{module_name}.{node.attr}')
        self.assertEqual(found, [])


class TestNotDocumented(unittest.TestCase):
    """No ``auto*`` directive documents a removed name at its old path."""

    def test_no_directive_names_an_old_path(self) -> 'None':
        found = []  # type: list[str]
        for page in sorted(_docs_dir().rglob('*.rst')):
            text = page.read_text(encoding='utf-8')
            for module_name, name in REMOVED:
                pattern = rf'(?m)^\s*\.\. auto\w+:: {re.escape(module_name)}\.{re.escape(name)}\s*$'
                if re.search(pattern, text):
                    found.append(f'{page.relative_to(ROOT)}: {module_name}.{name}')
        self.assertEqual(found, [])


class TestNoReExportProse(unittest.TestCase):
    """No prose says a removed name is still reachable at its old path."""

    def test_no_docstring_claims_an_old_path(self) -> 'None':
        found = []  # type: list[str]
        for path in sorted((ROOT / 'pcapkit').rglob('*.py')):
            tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                    owner = None if isinstance(node, ast.Module) else node.name
                    for claim in _claims(ast.get_docstring(node) or '', owner):
                        found.append(f'{path.relative_to(ROOT)}: {claim}')
        self.assertEqual(found, [])

    def test_no_docs_page_claims_an_old_path(self) -> 'None':
        found = []  # type: list[str]
        for page in sorted(_docs_dir().rglob('*.rst')):
            for claim in _claims(page.read_text(encoding='utf-8')):
                found.append(f'{page.relative_to(ROOT)}: {claim}')
        self.assertEqual(found, [])


class TestVersionRemoved(unittest.TestCase):
    """A path that shipped in a release is recorded as removed, twice."""

    def test_docstring_and_docs_page_carry_the_directive(self) -> 'None':
        for module_name, name, source, page, version in SHIPPED:
            old_path = f'``{module_name}.{name}``'
            module = importlib.import_module(module_name)
            for label, text in (('docstring', module.__doc__ or ''),
                                ('docs page', (_docs_dir() / page).read_text(encoding='utf-8'))):
                with self.subTest(path=f'{module_name}.{name}', where=label):
                    blocks = re.findall(rf'(?ms)^\.\. versionremoved:: {re.escape(version)}\n\n(.*?)(?=^\S|\Z)',
                                        text)
                    self.assertTrue(any(old_path in block for block in blocks),
                                    f'no versionremoved:: {version} block names {old_path} in {label}')
            self.assertTrue((ROOT / source).is_file())


if __name__ == '__main__':
    unittest.main()
