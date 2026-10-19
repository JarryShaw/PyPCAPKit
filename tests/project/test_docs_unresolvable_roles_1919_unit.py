# -*- coding: utf-8 -*-
"""Pins the hand-written cross-references that cannot resolve (#1919, #1920).

Sphinx builds without ``nitpicky``, so a role whose target exists in no inventory
and on no page renders as an unlinked chip and warns about nothing. #934 part C
settled the policy for those, and :file:`docs/source/conf.py` records it next to
``intersphinx_mapping``: retarget where a real target exists, add a documented
entry where the name is contract, and otherwise demote the role to a literal.

* :class:`InventorylessPackageRoleTests` -- ``aenum``, ``pyshark``, ``pcap``
  (PyPCAP and pcap-ct), ``pcapfile`` (PyPCAPFile) and ``emoji`` publish no
  ``objects.inv`` with ``py:`` objects in it, so no role naming them can resolve.
  ``AenumRoleExclusionTests`` in :file:`test_conventions_doc_claims.py` checks
  the conventions pages; this class checks every hand-written source under
  :file:`docs/` and :file:`pcapkit/`.
* :class:`DeadTargetTests` -- targets in a package that has an inventory, but
  absent from that inventory because the role, the path or the name is wrong
  (#1919). Each is pinned in the form that fails to resolve.
* :class:`DocumentedEntryTests` -- the names #1919 decided are contract, which
  have an entry rather than a demoted role.

Scoped to hand-written sources. The class formatter in :file:`docs/source/conf.py`
covers the generated half of #1920 by writing a literal for a package outside
``intersphinx_mapping``; its output exists only at build time, so this scan reads
the file's own source like any other. ``pcapkit/const/`` and the vendor
templates that generate it are excluded, and are handled separately; the rest of
``pcapkit/vendor/`` is scanned.

"""

from __future__ import annotations

import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]

#: Paths, relative to :data:`ROOT`, that the scan does not read -- see the module
#: docstring for why each is out of scope.
EXCLUDED = (
    'pcapkit/vendor/pcapng/option_type.py',
    'pcapkit/vendor/reg/apptype/apptype.py',
    'pcapkit/const/',
)

#: Top-level packages with no ``py:`` objects in any published inventory, per the
#: note beside ``intersphinx_mapping`` in :file:`docs/source/conf.py`.
INVENTORYLESS = frozenset({'aenum', 'pyshark', 'pcap', 'pcapfile', 'emoji'})

#: A Python-domain role, in either the bare or the explicit-title form. The body
#: may wrap across lines, as an explicit title often does.
ROLE = re.compile(
    r':(?:py:)?(mod|class|meth|func|attr|exc|obj|data|const|type|property|deco):`([^`]+)`')


def _sources() -> 'list[pathlib.Path]':
    """Every hand-written ``.rst`` under :file:`docs/` and ``.py`` under :file:`pcapkit/`."""
    paths = sorted((ROOT / 'docs').rglob('*.rst')) + sorted((ROOT / 'docs').rglob('*.py')) \
        + sorted((ROOT / 'pcapkit').rglob('*.py'))
    kept = []
    for path in paths:
        rel = path.relative_to(ROOT).as_posix()
        if any(rel == ex or rel.startswith(ex) for ex in EXCLUDED):
            continue
        kept.append(path)
    return kept


def _roles() -> 'list[tuple[str, int, str, str]]':
    """``(path, line, role, target)`` for every Python-domain role in :func:`_sources`.

    The target is what Sphinx looks up: the part in angle brackets for an explicit
    title, with any ``~``/``!``/``.`` prefix and a trailing ``()`` removed.

    """
    found = []
    for path in _sources():
        text = path.read_text(encoding='utf-8')
        for match in ROLE.finditer(text):
            role, body = match.groups()
            title = re.search(r'<([^>]+)>\s*$', body)
            target = (title.group(1) if title else body).strip().lstrip('~!.')
            if target.endswith('()'):
                target = target[:-2]
            line = text.count('\n', 0, match.start()) + 1
            found.append((path.relative_to(ROOT).as_posix(), line, role, target))
    return found


class InventorylessPackageRoleTests(unittest.TestCase):
    """No role names a package that has nothing to resolve it against."""

    def test_the_scan_reads_the_pages_and_modules_it_claims_to(self) -> 'None':
        """An empty or misrooted scan would pass the next test vacuously."""
        names = {path.relative_to(ROOT).as_posix() for path in _sources()}
        for expected in ('docs/source/pcapkit/foundation/engines/3rdparty.rst',
                         'docs/source/pcapkit/toolkit/3rdparty.rst',
                         'pcapkit/corekit/fields/numbers.py',
                         'pcapkit/corekit/enum.py',
                         'pcapkit/foundation/engines/pypcap.py',
                         'pcapkit/vendor/default.py',
                         'docs/source/conf.py'):
            self.assertIn(expected, names)
        for excluded in EXCLUDED:
            self.assertFalse(any(name == excluded or name.startswith(excluded)
                                 for name in names), excluded)

    def test_the_target_parser_sees_through_an_explicit_title(self) -> 'None':
        """``:mod:`PyPCAP <pcap>``` names ``pcap`` even though its text does not."""
        body = ROLE.search(':mod:`PyPCAP\n   <pcap>`').group(2)
        title = re.search(r'<([^>]+)>\s*$', body)
        self.assertEqual(title.group(1), 'pcap')

    def test_no_role_names_an_inventoryless_package(self) -> 'None':
        """A reintroduced ``:mod:`pcap``` or ``:func:`~aenum.extend_enum``` fails here.

        Matched on the target's first dotted component, so ``pcapkit`` and
        ``pcapng`` are not mistaken for ``pcap``. The package itself is linked as
        ``|pkg|_`` (#1936, pinned in :file:`test_docs_epilog_links_1936_unit.py`),
        and a name below it is a plain double-backtick literal, the form #934
        part C prescribes for these roles.

        """
        offenders = [f'{path}:{line}: :{role}:`{target}`'
                     for path, line, role, target in _roles()
                     if target.split('.')[0] in INVENTORYLESS]
        self.assertEqual(offenders, [],
                         'these roles name a package whose objects.inv has no py: '
                         'objects, so they can never resolve; write the package as '
                         '|pkg|_ and a name below it as a double-backtick literal')


class DeadTargetTests(unittest.TestCase):
    """The targets #1919 found missing from an inventory that does exist."""

    #: ``(role, target, why)``: the exact pairing that renders as a chip. A
    #: :data:`None` role bans the target under any role.
    DEAD = (
        ('data', 'warnings.filters',
         'not in the Python inventory; write it as a literal'),
        ('func', 'warnings.catch_warnings',
         'a py:class in the Python inventory; use :class:'),
        (None, 'abc.ABCMeta.__new__',
         'not in the Python inventory; write it as a literal'),
        (None, 'collections.abc.Mapping.items',
         'not in the Python inventory; name collections.abc.Mapping'),
        (None, 'dictdumper.Dumper',
         'dictdumper documents it as dictdumper.dumper.Dumper'),
        (None, 'dictdumper.dumper.Dumper._append_dict',
         'Dumper has no _append_dict; PLIST._append_dict and JSON._append_object do'),
        ('mod', 'dpkt',
         "dpkt's inventory has no top-level module; write it as a literal"),
        (None, 'scapy.all',
         "scapy's inventory has no scapy.all; write it as a literal"),
        (None, 'scapy.layers.all',
         "scapy's inventory has no scapy.layers.all; write it as a literal"),
        ('mod', 'cryptography',
         "cryptography's inventory has no top-level module; write it as a literal"),
        ('mod', 'cryptography.exceptions',
         "cryptography's inventory has no such module; write it as a literal"),
        (None, 'pcapkit.vendor.__main__.run',
         'the CLI module documents no functions; write it as a literal'),
        (None, 'EnumMeta.registry',
         'unqualified, it does not resolve from the pages that cite it; qualify it'),
    )

    def test_no_dead_target_appears(self) -> 'None':
        """No retargeted or demoted pairing from #1919 appears."""
        roles = _roles()
        offenders = []
        for want_role, want_target, why in self.DEAD:
            for path, line, role, target in roles:
                if target == want_target and want_role in (None, role):
                    offenders.append(f'{path}:{line}: :{role}:`{target}` -- {why}')
        self.assertEqual(offenders, [])


class DocumentedEntryTests(unittest.TestCase):
    """The names cited as contract (#1919) have an entry of their own."""

    def test_compat_final_has_an_entry_under_its_module(self) -> 'None':
        """``pcapkit.utilities.compat.final`` is what ``@info_final`` tells callers to use.

        Written bare under the page's ``.. module:: pcapkit.utilities.compat``, so
        it registers as that dotted name rather than as a doubled one (#1775).

        """
        page = (ROOT / 'docs' / 'source' / 'pcapkit' / 'utilities' / 'index.rst').read_text(
            encoding='utf-8')
        module = page.index('.. module:: pcapkit.utilities.compat')
        self.assertRegex(page[module:], r'(?m)^\.\. function:: final\(')

    def test_enummeta_registry_is_documented(self) -> 'None':
        """The class-level ``registry`` that serves ``Option.registry[type]``."""
        page = (ROOT / 'docs' / 'source' / 'pcapkit' / 'protocols' / 'index.rst').read_text(
            encoding='utf-8')
        start = page.index('.. autoclass:: pcapkit.protocols.schema.schema.EnumMeta\n')
        end = page.index('\n.. ', start + 1)
        self.assertIn('.. autoproperty:: registry', page[start:end])


if __name__ == '__main__':
    unittest.main()
