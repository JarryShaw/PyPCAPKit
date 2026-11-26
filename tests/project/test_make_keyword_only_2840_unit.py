# -*- coding: utf-8 -*-
"""Every ``make()`` takes its fields as keywords only (GitHub issue #2840).

The owner took the plan on #2840 that splits parsing from construction:
construction is ``Proto.from_fields(**fields)``, and each ``make()`` override takes
its fields after a bare ``*`` and ends in ``**kwargs``, so adding a field moves no
other and a positional call fails rather than filling the wrong field.

:class:`TestMakeIsKeywordOnly` parses every protocol module and fails on a
``make()`` that takes a parameter besides ``self`` positionally, takes ``*args``,
or does not end in ``**kwargs``.

This module is unit-tier and reads no capture.

"""
from __future__ import annotations

import ast
import unittest
from typing import TYPE_CHECKING

from tests._tiers import ROOT

if TYPE_CHECKING:
    from typing import Iterator

#: Test tier (#1958): parses every protocol module for a question about the tree,
#: which does not differ by interpreter.
__tier__ = 'LATEST'

#: The protocol package the audit walks.
PROTOCOLS = ROOT / 'pcapkit' / 'protocols'

#: Directory names the audit does not enter: placeholder sources and caches.
SKIPPED_DIRS = frozenset({'NotImplemented', '__pycache__'})


def _makes() -> 'Iterator[tuple[str, ast.FunctionDef]]':
    """Every ``make`` defined in a class body under :data:`PROTOCOLS`, overloads aside."""
    for path in sorted(PROTOCOLS.rglob('*.py')):
        if SKIPPED_DIRS.intersection(path.relative_to(PROTOCOLS).parts):
            continue
        tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            for item in node.body:
                if not isinstance(item, ast.FunctionDef) or item.name != 'make':
                    continue
                if any(isinstance(deco, ast.Name) and deco.id == 'overload' for deco in item.decorator_list):
                    continue
                yield f'{path.relative_to(ROOT)}:{node.name}.make', item


class TestMakeIsKeywordOnly(unittest.TestCase):
    """Each ``make`` is ``make(self, *, <fields>, **kwargs)``."""

    def test_the_audit_finds_the_base(self) -> 'None':
        """The walk reaches ``ProtocolBase.make``, so an empty result is no pass."""
        names = [name for name, _ in _makes()]
        self.assertIn('pcapkit/protocols/protocol.py:ProtocolBase.make', names)
        self.assertIn('pcapkit/protocols/transport/tcp/protocol.py:TCP.make', names)

    def test_no_make_takes_a_field_positionally(self) -> 'None':
        """``self`` is the only positional parameter, and there is no ``*args``."""
        offenders = []  # type: list[str]
        for name, func in _makes():
            positional = [arg.arg for arg in func.args.posonlyargs + func.args.args]
            if positional != ['self'] or func.args.vararg is not None:
                offenders.append(f'{name}: {positional}')
        self.assertEqual(offenders, [], 'put a bare * after self')

    def test_every_make_ends_in_kwargs(self) -> 'None':
        """The ``**kwargs`` takes the keywords the parse shares with the construction."""
        offenders = [name for name, func in _makes() if func.args.kwarg is None]
        self.assertEqual(offenders, [])


if __name__ == '__main__':
    unittest.main()
