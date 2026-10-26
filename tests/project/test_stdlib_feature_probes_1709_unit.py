# -*- coding: utf-8 -*-
"""The package detects interpreter features by version, never by probing for them.

The owner's ruling on GitHub pull request #1703, applied by issue #1709: where
:mod:`pcapkit` needs a name or a behaviour that only some supported interpreters
have, it asks :data:`sys.version_info`, in :mod:`pcapkit.utilities.compat` when
the answer is a name to re-export, rather than probing with :func:`getattr` or
:func:`hasattr`. Issue #1709 found these probes, each with a string literal naming
the attribute. Most ask a module or builtin class:

* ``getattr(inspect, 'get_annotations', None)``, in
  :file:`pcapkit/corekit/infoclass.py` and :file:`pcapkit/protocols/protocol.py`;
* ``getattr(types, 'UnionType', None)``, in :file:`pcapkit/corekit/infoclass.py`;
* ``hasattr(dict, '__reversed__')``, twice in :file:`pcapkit/corekit/infoclass.py`.

One asks an instance, so nothing about its receiver marks it: it is a
version probe because of the attribute it names.

* ``getattr(node, 'end_lineno', node.lineno)``, in
  :file:`pcapkit/protocols/protocol.py` -- :mod:`ast` nodes carry it from 3.8.

This scans every module of the package for both shapes: a literal attribute
probe of a module the file imports by name or of a builtin class, and a literal
probe of any object for an attribute in :data:`VERSIONED`. A computed attribute
name, as in ``getattr(hashlib, digest)``, is a lookup rather than a question
about the interpreter, and is not matched. Run against the tree without the
fixes of issue #1709, it reports exactly those and the :data:`EXEMPT` entries.

This module is unit-tier: it reads source text and never imports the package.

"""
from __future__ import annotations

import ast
import builtins
import unittest
from typing import TYPE_CHECKING

from tests._tiers import ROOT

if TYPE_CHECKING:
    from typing import Iterator

#: Package directory that is scanned.
PACKAGE = ROOT / 'pcapkit'

#: ``(path, call)`` of each match that is not a feature probe, with the reason.
EXEMPT = {
    # A third-party package's own version string, read for a warning message.
    ('pcapkit/foundation/engines/dpkt.py', "getattr(dpkt, '__version__', '(unknown version)')"),
    # Every interpreter has the attribute; it is None when there is no console.
    ('pcapkit/vendor/default.py', "getattr(sys, 'stdin', None)"),
}

#: Attributes an older interpreter lacked on its objects, and the version that
#: added them. A literal probe for one is a version probe on any receiver, which
#: is why these are matched by name alone; from the 3.8 floor (#2051) it is a
#: dead one as well.
VERSIONED = {
    'end_lineno': (3, 8),      # ast node end positions
    'end_col_offset': (3, 8),
}


def probes(source: str) -> 'Iterator[tuple[int, str]]':
    """Yield ``(lineno, call)`` for each attribute probe that asks about the interpreter.

    That is a literal probe of a module or builtin class, or a literal probe of
    any object for an attribute in :data:`VERSIONED`.

    Imports are collected from the whole file, function bodies included, since a
    probe of a module imported inside a function is a probe all the same.

    Args:
        source: Module source text.

    Yields:
        The line number and the source text of each matching call.

    """
    tree = ast.parse(source)
    modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                modules.add(alias.asname or alias.name.split('.')[0])

    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id in ('getattr', 'hasattr') and len(node.args) >= 2):
            continue
        target, attr = node.args[:2]
        if not (isinstance(attr, ast.Constant) and isinstance(attr.value, str)):
            continue
        if attr.value in VERSIONED or (isinstance(target, ast.Name) and (
                target.id in modules or isinstance(getattr(builtins, target.id, None), type))):
            yield node.lineno, ast.get_source_segment(source, node)


class StdlibFeatureProbeTests(unittest.TestCase):
    def test_no_module_detects_a_feature_by_probing_for_it(self) -> None:
        found = []
        for path in sorted(PACKAGE.rglob('*.py')):
            relative = path.relative_to(ROOT).as_posix()
            for lineno, call in probes(path.read_text(encoding='utf-8')):
                if (relative, call) not in EXEMPT:
                    found.append(f'{relative}:{lineno}: {call}')
        self.assertEqual(
            found, [],
            'gate these on sys.version_info instead, re-exported from '
            'pcapkit/utilities/compat.py where the result is a name (#1703, #1709)')

    def test_every_exemption_still_matches(self) -> None:
        """An exemption whose call has gone is a stale entry, not a pass."""
        for relative, call in sorted(EXEMPT):
            with self.subTest(path=relative):
                source = (ROOT / relative).read_text(encoding='utf-8')
                self.assertIn(call, [found for (_, found) in probes(source)])

    def test_the_issue_1709_shapes_are_matched(self) -> None:
        """The scan sees each shape issue #1709 is about, so a pass is not vacuous."""
        source = (
            'import hashlib\n'
            'import inspect\n'
            'import types\n'
            "get_annotations = getattr(inspect, 'get_annotations', None)\n"
            "union = getattr(types, 'UnionType', None)\n"
            'class Info(dict):\n'
            "    if hasattr(dict, '__reversed__'):\n"
            '        pass\n'
            'def digest(name):\n'
            '    return getattr(hashlib, name)\n'
            'def last_line(node):\n'
            "    return getattr(node, 'end_lineno', node.lineno)\n"
            'def payload(frame):\n'
            "    return getattr(frame, 'padding', b'')\n"
        )
        self.assertEqual(sorted(lineno for (lineno, _) in probes(source)), [4, 5, 7, 12])


if __name__ == '__main__':
    unittest.main()
