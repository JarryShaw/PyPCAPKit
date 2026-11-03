# -*- coding: utf-8 -*-
"""No ``make()`` takes an ``X_default``/``X_namespace``/``X_reversed`` keyword, and
``_make_index`` inspects no frame (GitHub issue #2594).

The owner ruled, in review of #2593 (which closes #2489), that a ``make()`` field
holding an enumeration takes the member or an :class:`int`, resolved with the
enumeration's ``get``, and that no string is resolved inside ``make()``; #2594 holds
every maker to it, with no ``X_default``, ``X_namespace`` or ``X_reversed`` keyword
beside such a field and no name resolved against an enumeration read off the calling
method's frame.

This module holds the tree to that:

* :class:`TestNoKeywordGroups` parses every protocol module and fails on a
  ``make()`` or ``_make_*`` method taking a parameter named ``X_default``,
  ``X_namespace`` or ``X_reversed``, and on a ``_make_index`` call that passes
  ``default``, ``reversed``, ``pack`` or ``size``, or leaves out the field's ``bits``
  and ``name``;
* :class:`TestMakeIndexInspectsNoFrame` parses ``_make_index`` and ``resolve_index``
  and fails on any reference to a frame, a call stack or a caller's source;
* :class:`TestInferenceHelpersAreGone` fails on ``_make_index_calls`` or
  ``_make_index_namespace`` being defined.

:data:`PENDING` holds the methods allowed to take a group, each with what removes it.
It is checked in both directions, as ``test-coverage.rst`` asks of such tables: an
entry whose method takes no group, or does not exist, fails too, so the
change that migrates it deletes its entry.

"""
from __future__ import annotations

import ast
import importlib
import re
import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class
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

#: A parameter of an ``X_default``/``X_namespace``/``X_reversed`` group.
GROUP_PARAMETER = re.compile(r'^(?P<field>\w+)_(?:default|namespace|reversed)$')

#: Keywords no ``_make_index`` call passes.
OLD_KEYWORDS = frozenset({'default', 'reversed', 'pack', 'size', 'signed', 'lilendian'})

#: Keywords every ``_make_index`` call passes.
REQUIRED_KEYWORDS = frozenset({'bits', 'name'})

#: Names that reach a frame, a call stack or a caller's source.
FRAME_NAMES = frozenset({
    'inspect', 'sys', 'traceback',
    'currentframe', '_getframe', 'stack', 'getouterframes', 'getinnerframes',
    'getframeinfo', 'getsource', 'getsourcelines', 'signature',
    'f_back', 'f_locals', 'f_globals', 'f_code', 'f_lineno', 'tb_frame',
})

#: Methods allowed to take a group, as ``(module path, class, method)``: what removes
#: each.
PENDING = {}  # type: dict[tuple[str, str, str], str]


def _modules() -> 'Iterator[tuple[str, ast.Module]]':
    """Every protocol module, as its path from the root and its parsed source."""
    for path in sorted(PROTOCOLS.rglob('*.py')):
        if SKIPPED_DIRS.intersection(path.relative_to(PROTOCOLS).parts):
            continue
        yield path.relative_to(ROOT).as_posix(), ast.parse(path.read_text(encoding='utf-8'))


def _makers() -> 'Iterator[tuple[tuple[str, str, str], ast.FunctionDef]]':
    """Every ``make()`` and ``_make_*`` method of a class, keyed by where it is."""
    for path, tree in _modules():
        for klass in ast.walk(tree):
            if not isinstance(klass, ast.ClassDef):
                continue
            for node in klass.body:
                if isinstance(node, ast.FunctionDef) and (node.name == 'make' or node.name.startswith('_make_')):
                    yield (path, klass.name, node.name), node


def _groups(node: 'ast.FunctionDef') -> 'list[str]':
    """The group parameters ``node`` takes."""
    params = node.args.posonlyargs + node.args.args + node.args.kwonlyargs
    return sorted(param.arg for param in params if GROUP_PARAMETER.match(param.arg))


class TestNoKeywordGroups(unittest.TestCase):
    """No ``make()`` takes the ``X_default``/``X_namespace``/``X_reversed`` group."""

    def test_no_maker_takes_a_group(self) -> None:
        found = {key: _groups(node) for key, node in _makers()}
        offenders = sorted(f'{path}: {klass}.{meth}({", ".join(params)})'
                           for (path, klass, meth), params in found.items()
                           if params and (path, klass, meth) not in PENDING)
        self.assertEqual(offenders, [], 'a make() takes a keyword group; an enumeration field takes '
                                        'the member or an int, resolved with _make_index (#2594)')

    def test_pending_entries_still_take_a_group(self) -> None:
        found = {key: _groups(node) for key, node in _makers()}
        stale = sorted(f'{path}: {klass}.{meth}' for path, klass, meth in PENDING
                       if not found.get((path, klass, meth)))
        self.assertEqual(stale, [], 'a PENDING method takes no group; delete its entry')

    def test_make_index_calls_take_the_field_width(self) -> None:
        offenders = []
        for path, tree in _modules():
            for klass in ast.walk(tree):
                if not isinstance(klass, ast.ClassDef):
                    continue
                for meth in klass.body:
                    if not isinstance(meth, ast.FunctionDef) or meth.name == '_make_index':
                        continue
                    if (path, klass.name, meth.name) in PENDING:
                        continue
                    for node in ast.walk(meth):
                        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                                and node.func.attr == '_make_index'):
                            continue
                        keywords = {keyword.arg for keyword in node.keywords}
                        if (len(node.args) != 2 or keywords & OLD_KEYWORDS
                                or not REQUIRED_KEYWORDS <= keywords):
                            offenders.append(f'{path}: {klass.name}.{meth.name}')
        self.assertEqual(sorted(offenders), [],
                         '_make_index takes (value, enumeration, bits=..., name=...) (#2594)')


class TestMakeIndexInspectsNoFrame(unittest.TestCase):
    """The resolver reads its arguments and nothing of its caller."""

    @staticmethod
    def _defs(prefix: 'str') -> 'list[ast.FunctionDef]':
        """Every definition in :mod:`pcapkit.protocols.protocol` named ``prefix`` or
        ``prefix_*``, at module level or on ``ProtocolBase``, overloads included."""
        tree = ast.parse((PROTOCOLS / 'protocol.py').read_text(encoding='utf-8'))
        scopes = [tree.body] + [klass.body for klass in tree.body
                                if isinstance(klass, ast.ClassDef) and klass.name == 'ProtocolBase']
        return [node for body in scopes for node in body if isinstance(node, ast.FunctionDef)
                and (node.name == prefix or node.name.startswith(f'{prefix}_'))]

    def test_resolvers_reach_no_frame(self) -> None:
        for prefix in ('_make_index', 'resolve_index'):
            with self.subTest(method=prefix):
                defs = self._defs(prefix)
                self.assertTrue(defs, f'ProtocolBase.{prefix} is not defined')
                used = set()  # type: set[str]
                for node in defs:
                    body = ast.Module(body=node.body, type_ignores=[])
                    used |= {item.id for item in ast.walk(body) if isinstance(item, ast.Name)}
                    used |= {item.attr for item in ast.walk(body) if isinstance(item, ast.Attribute)}
                self.assertEqual(sorted(used & FRAME_NAMES), [],
                                 f'{prefix} reaches a frame or a caller; it reads only its arguments (#2594)')

    def test_make_index_takes_no_old_keyword(self) -> None:
        # the last definition is the implementation, after any overloads
        node = [node for node in self._defs('_make_index') if node.name == '_make_index'][-1]
        params = {param.arg for param in node.args.args + node.args.kwonlyargs}
        self.assertEqual(sorted(params & OLD_KEYWORDS), [])
        self.assertLessEqual(REQUIRED_KEYWORDS, params)


class TestInferenceHelpersAreGone(unittest.TestCase):
    """The helpers the frame inspection used are not defined."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_no_inference_helpers(self) -> None:
        module = importlib.import_module('pcapkit.protocols.protocol')
        self.assertFalse(hasattr(module, '_make_index_calls'))
        self.assertFalse(hasattr(module.ProtocolBase, '_make_index_namespace'))


if __name__ == '__main__':
    unittest.main()
