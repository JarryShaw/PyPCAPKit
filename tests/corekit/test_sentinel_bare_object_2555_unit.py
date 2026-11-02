# -*- coding: utf-8 -*-
"""No sentinel the package writes for itself is a bare ``object()``. C.f. #2555.

The "Naming a Sentinel" convention puts every such sentinel in
:mod:`pcapkit.corekit.sentinels` as a named class instance, public or not; its
"Why a Class and Not ``object()``" section gives the reason, a repr that is an
address. A sentinel is a singleton, so the scan flags an argument-less
``object()`` that runs when its module is imported -- in a module or class body,
a default value or a decorator -- and skips function bodies, which build a fresh
object per call. Without #2555 it flags ``_MISSING`` in
:mod:`pcapkit.foundation.registry.protocols`.

The page exempts a verbatim upstream port; the tree holds none that needs it.

"""

from __future__ import annotations

import ast
import pathlib
import textwrap
import unittest

#: Repository root.
ROOT = pathlib.Path(__file__).resolve().parents[2]


def _import_time_bare_objects(node: 'ast.AST') -> 'list[int]':
    """Line of every argument-less ``object()`` under ``node`` that runs at import.

    A function's defaults and decorators run where it is defined, and its body
    only when it is called, so the body is not walked.

    """
    lines = []  # type: list[int]
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id == 'object' and not node.args and not node.keywords):
        lines.append(node.lineno)

    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        children = [*node.args.defaults, *filter(None, node.args.kw_defaults),
                    *getattr(node, 'decorator_list', ())]  # type: list[ast.AST]
    else:
        children = list(ast.iter_child_nodes(node))
    for child in children:
        lines.extend(_import_time_bare_objects(child))
    return lines


class BareObjectSentinelTests(unittest.TestCase):
    """A sentinel is a :class:`~pcapkit.corekit.sentinels.Sentinel`, never ``object()``."""

    def test_no_module_makes_a_bare_object_at_import(self) -> 'None':
        found = []  # type: list[str]
        for path in sorted((ROOT / 'pcapkit').rglob('*.py')):
            tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
            found.extend(f'{path.relative_to(ROOT).as_posix()}:{line}'
                         for line in _import_time_bare_objects(tree))
        self.assertEqual(found, [], 'define the sentinel in pcapkit.corekit.sentinels '
                                    'and list it in sentinel-convention.rst')

    def test_the_scan_covers_import_time_and_skips_function_bodies(self) -> 'None':
        """Module, class, default and decorator ``object()`` calls; no function or lambda body."""
        source = textwrap.dedent('''\
            A = object()
            class K:
                B = object()
            def f(x=object(), *, y=object()):
                local = object()
            g = lambda z=object(): object()
            @decorate(object())
            def h(): pass
        ''')
        self.assertEqual(sorted(_import_time_bare_objects(ast.parse(source))),
                         [1, 3, 4, 4, 6, 7])


if __name__ == '__main__':
    unittest.main()
