# -*- coding: utf-8 -*-
"""The 8-octet-unit header length converts only through :mod:`pcapkit.corekit.schema.extlen`.

GitHub issue #2854 found ``(Hdr Ext Len + 1) * 8``, the length of an
IPv6-extension-style header [RFC 6564, section 4], written out inline across the
extension headers, MH, HIP, the jumbogram lookup and IPv6 reassembly, and its
inverse spelled ``length // 8 - 1`` and ``(length - 8) // 8``. Both directions
now go through :func:`~pcapkit.corekit.schema.extlen.ext_len_to_octets` and
:func:`~pcapkit.corekit.schema.extlen.octets_to_ext_len`, as
:file:`docs/source/contributing/conventions/utilities-or-corekit.rst` records.

This scans every module of the package, the helper module aside, for the
shapes below, a shift by 3 counting as a multiplication or floor division by 8:

* ``(x + 1) * 8``, either operand order;
* ``x * 8 + 8``, either operand order;
* ``x // 8 - 1``;
* ``(x - 8) // 8``.

A length that leaves out a fixed part, as ``Hdr Ext Len * 8 + 6`` sizes the
HOPOPT options, is not matched, and :data:`EXEMPT` holds the matches that count
8-octet records rather than convert a length field. Run against the tree
without the change of issue #2854, it reports every site that change converted.

``(x + 1) * 8`` split across a call is caught too, as ``4 +
ipv6_route_data_length(x)`` spelled it in IPv6-Route: :func:`linear_helpers` finds
each function of one argument that only returns ``a * x + b``, and
:func:`split_conversions` reports a sum or product reaching ``8 * x + 8`` through
a call of one. The inverse floor-divides, which no such composition reproduces,
so only the forward direction is followed through calls.

This module is unit-tier: it reads source text and never imports the package.

"""
from __future__ import annotations

import ast
import unittest
from typing import TYPE_CHECKING

from tests._tiers import ROOT

if TYPE_CHECKING:
    import pathlib
    from typing import Callable, Iterator, Optional

#: Test tier (#1958): reads source text, a question about the tree.
__tier__ = 'LATEST'

#: Package directory that is scanned.
PACKAGE = ROOT / 'pcapkit'

#: The helper module, the one place the arithmetic is written out.
HELPER = PACKAGE / 'corekit' / 'schema' / 'extlen.py'

#: ``(path, text)`` of each match that counts records rather than converting a
#: length field, with the reason.
EXEMPT = {
    # Group records, at the 8 fixed octets of each, behind the message's 8 octets.
    ('pcapkit/protocols/internet/igmpv3/schema.py', '8 + 8 * count'),
    # An I-FORWARD-TSN chunk's 8-octet stream entries behind its 8 fixed octets.
    ('pcapkit/protocols/transport/sctp/protocol.py', '8 + len(entries) * 8'),
}


def _is_const(node: 'ast.expr', value: 'int') -> 'bool':
    """Whether ``node`` is the integer literal ``value``."""
    return isinstance(node, ast.Constant) and type(node.value) is int and node.value == value


def _times_8(node: 'ast.expr') -> 'ast.expr | None':
    """The operand ``node`` multiplies by 8, as ``x * 8``, ``8 * x`` or ``x << 3``."""
    if isinstance(node, ast.BinOp):
        if isinstance(node.op, ast.Mult):
            if _is_const(node.right, 8):
                return node.left
            if _is_const(node.left, 8):
                return node.right
        if isinstance(node.op, ast.LShift) and _is_const(node.right, 3):
            return node.left
    return None


def _floor_8(node: 'ast.expr') -> 'ast.expr | None':
    """The operand ``node`` floor-divides by 8, as ``x // 8`` or ``x >> 3``."""
    if isinstance(node, ast.BinOp):
        if isinstance(node.op, ast.FloorDiv) and _is_const(node.right, 8):
            return node.left
        if isinstance(node.op, ast.RShift) and _is_const(node.right, 3):
            return node.left
    return None


def _shape(node: 'ast.BinOp') -> 'str | None':
    """Which of the module docstring's shapes ``node`` is, if any."""
    operand = _times_8(node)
    if (isinstance(operand, ast.BinOp) and isinstance(operand.op, ast.Add)
            and (_is_const(operand.left, 1) or _is_const(operand.right, 1))):
        return '(x + 1) * 8'
    if isinstance(node.op, ast.Add):
        if ((_is_const(node.right, 8) and _times_8(node.left) is not None)
                or (_is_const(node.left, 8) and _times_8(node.right) is not None)):
            return 'x * 8 + 8'
    if isinstance(node.op, ast.Sub) and _is_const(node.right, 1) and _floor_8(node.left) is not None:
        return 'x // 8 - 1'
    operand = _floor_8(node)
    if isinstance(operand, ast.BinOp) and isinstance(operand.op, ast.Sub) and _is_const(operand.right, 8):
        return '(x - 8) // 8'
    return None


def conversions(source: 'str') -> 'Iterator[tuple[int, str, str]]':
    """Yield ``(lineno, shape, text)`` for each written-out conversion in ``source``.

    Args:
        source: Module source text.

    Yields:
        The line number, the shape matched and the source text of each match.

    """
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.BinOp):
            shape = _shape(node)
            if shape is not None:
                yield node.lineno, shape, ast.get_source_segment(source, node) or ''


def _linear(node: 'ast.expr',
            resolve: 'Callable[[ast.expr], Optional[tuple[int, int]]]') -> 'tuple[int, int, Optional[str], bool]':
    """``node`` as ``(a, b, atom, inlined)``, meaning ``a * atom + b``.

    ``atom`` is the :func:`ast.dump` of the one non-constant operand, :data:`None`
    for a constant; a subexpression that is not linear in a single operand is an
    atom of its own. ``inlined`` is whether a call ``resolve`` knows was folded in.

    """
    atom = (1, 0, ast.dump(node), False)
    if isinstance(node, ast.Constant) and type(node.value) is int:
        return 0, node.value, None, False
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        a, b, var, inlined = _linear(node.operand, resolve)
        return -a, -b, var, inlined
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Sub, ast.Mult)):
        la, lb, lvar, linl = _linear(node.left, resolve)
        ra, rb, rvar, rinl = _linear(node.right, resolve)
        if isinstance(node.op, ast.Mult):
            if rvar is None:
                return la * rb, lb * rb, lvar, linl or rinl
            if lvar is None:
                return ra * lb, rb * lb, rvar, linl or rinl
        elif lvar is None or rvar is None or lvar == rvar:
            sign = 1 if isinstance(node.op, ast.Add) else -1
            return la + sign * ra, lb + sign * rb, lvar or rvar, linl or rinl
        return atom
    if isinstance(node, ast.Call) and len(node.args) == 1 and not node.keywords:
        helper = resolve(node.func)
        if helper is not None:
            a, b, var, _ = _linear(node.args[0], resolve)
            return helper[0] * a, helper[0] * b + helper[1], var, True
    return atom


def _single_return(node: 'ast.FunctionDef', *, static: 'bool') -> 'Optional[tuple[str, ast.expr]]':
    """``(parameter, value)`` of a function of one argument whose body only returns ``value``.

    ``static`` asks for a static method rather than an undecorated function.

    """
    args = node.args
    decorators = [deco.id for deco in node.decorator_list if isinstance(deco, ast.Name)]
    if (len(args.args) != 1 or args.posonlyargs or args.vararg or args.kwonlyargs or args.kwarg
            or len(decorators) != len(node.decorator_list)
            or decorators != (['staticmethod'] if static else [])):
        return None
    body = node.body
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
        body = body[1:]
    if len(body) != 1 or not isinstance(body[0], ast.Return) or body[0].value is None:
        return None
    return args.args[0].arg, body[0].value


class Module:
    """One parsed module: its functions of one argument, its classes and its imports."""

    def __init__(self, name: 'str', source: 'str') -> None:
        #: Dotted module name.
        self.name = name
        #: Source text.
        self.source = source
        #: Parsed source.
        self.tree = ast.parse(source)
        #: Module-level functions, by name, and static methods, by ``.name``.
        self.functions = {}  # type: dict[str, tuple[str, ast.expr]]
        #: Names of the module's classes.
        self.classes = set()  # type: set[str]
        #: Names bound by ``from M import n``, as ``(M, n)``.
        self.imports = {}  # type: dict[str, tuple[str, str]]
        for node in self.tree.body:
            if isinstance(node, ast.FunctionDef):
                found = _single_return(node, static=False)
                if found is not None:
                    self.functions[node.name] = found
            elif isinstance(node, ast.ClassDef):
                self.classes.add(node.name)
                for item in node.body:
                    if isinstance(item, ast.FunctionDef):
                        found = _single_return(item, static=True)
                        if found is not None:
                            self.functions[f'.{item.name}'] = found
        for node in ast.walk(self.tree):
            if isinstance(node, ast.ImportFrom) and node.module and not node.level:
                for alias in node.names:
                    self.imports[alias.asname or alias.name] = (node.module, alias.name)

    def resolver(self, table: 'dict[tuple[str, str], tuple[int, int]]'
                 ) -> 'Callable[[ast.expr], Optional[tuple[int, int]]]':
        """Resolve a callee to its ``(a, b)`` in ``table``.

        A bare name is looked up in this module or through its imports; an
        attribute of ``self``, ``cls`` or one of the module's classes, among
        its static methods.

        """
        def resolve(func: 'ast.expr') -> 'Optional[tuple[int, int]]':
            if isinstance(func, ast.Name):
                return table.get(self.imports.get(func.id, (self.name, func.id)))
            if (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)
                    and func.value.id in {'self', 'cls'} | self.classes):
                return table.get((self.name, f'.{func.attr}'))
            return None
        return resolve


def package_modules() -> 'list[tuple[pathlib.Path, Module]]':
    """Every module of the package but the helper, parsed."""
    found = []
    for path in sorted(PACKAGE.rglob('*.py')):
        if path == HELPER:
            continue
        parts = path.relative_to(ROOT).with_suffix('').parts
        name = '.'.join(parts[:-1] if parts[-1] == '__init__' else parts)
        found.append((path, Module(name, path.read_text(encoding='utf-8'))))
    return found


def linear_helpers(modules: 'list[Module]') -> 'dict[tuple[str, str], tuple[int, int]]':
    """Each function of one argument returning ``a * x + b``, as ``(module, name)`` to ``(a, b)``.

    A call of another such function folds into the form, followed to a fixed
    point. The helper module is never among ``modules``, so a call of it stays
    an atom.

    """
    table = {}  # type: dict[tuple[str, str], tuple[int, int]]
    for _ in range(10):
        changed = False
        for module in modules:
            resolve = module.resolver(table)
            for name, (param, value) in module.functions.items():
                a, b, var, _ = _linear(value, resolve)
                if var in (None, ast.dump(ast.Name(id=param, ctx=ast.Load()))) \
                        and table.get((module.name, name)) != (a, b):
                    table[module.name, name] = (a, b)
                    changed = True
        if not changed:
            break
    return table


def split_conversions(module: 'Module', table: 'dict[tuple[str, str], tuple[int, int]]'
                      ) -> 'Iterator[tuple[int, str]]':
    """Yield ``(lineno, text)`` of each sum or product reaching ``8 * x + 8`` through a call."""
    resolve = module.resolver(table)
    for node in ast.walk(module.tree):
        if isinstance(node, ast.BinOp):
            a, b, var, inlined = _linear(node, resolve)
            if inlined and var is not None and (a, b) == (8, 8):
                yield node.lineno, ast.get_source_segment(module.source, node) or ''


class ShapeTests(unittest.TestCase):
    """The matcher finds each shape, and nothing that only resembles one."""

    def test_matches_each_shape(self) -> None:
        cases = {
            '(schema.len + 1) * 8': '(x + 1) * 8',
            '8 * (1 + data[1])': '(x + 1) * 8',
            '(header[position + 1] + 1) << 3': '(x + 1) * 8',
            'schema.len * 8 + 8': 'x * 8 + 8',
            '8 + 8 * hdr_ext_len': 'x * 8 + 8',
            'data.length // 8 - 1': 'x // 8 - 1',
            '(len(data_val) + 6) // 8 - 1': 'x // 8 - 1',
            '(data.length >> 3) - 1': 'x // 8 - 1',
            '(data.length - 8) // 8': '(x - 8) // 8',
        }
        for text, shape in cases.items():
            with self.subTest(text=text):
                self.assertEqual([(found[1], found[2]) for found in conversions(text)], [(shape, text)])

    def test_leaves_other_arithmetic(self) -> None:
        for text in ('schema.len * 8 + 6', '4 + hdr_ext_len * 8', '(schema.len - 4) * 8',
                     '(schema.len + 2) * 4', '(total_length - 6) // 8', '(size + 7) // 8',
                     'index * 8 + 7', '(fraction + 1) * den', 'data.offset // 8'):
            with self.subTest(text=text):
                self.assertEqual(list(conversions(text)), [])

    @staticmethod
    def _split(source: 'str') -> 'list[str]':
        """The split conversions in a module ``m`` holding ``source``."""
        module = Module('m', source)
        return [text for _, text in split_conversions(module, linear_helpers([module]))]

    def test_matches_a_split_conversion(self) -> None:
        cases = {
            # IPv6-Route's header length before #2854's review round.
            'def data(h):\n    """Doc."""\n    return 4 + h * 8\n'
            'def header(h):\n    return 4 + data(h)\n': '4 + data(h)',
            'def units(h):\n    return h + 1\n'
            'def header(h):\n    return units(h) * 8\n': 'units(h) * 8',
            'def body(h):\n    return h * 8 + 2\n'
            'def area(h):\n    return body(h) - 4\n'
            'length = area(n) + 10\n': 'area(n) + 10',
            'class C:\n    @staticmethod\n    def body(h):\n        return h * 8 + 2\n'
            '    def read(self):\n        return self.body(self.len) + 6\n': 'self.body(self.len) + 6',
        }
        for source, text in cases.items():
            with self.subTest(text=text):
                self.assertEqual(self._split(source), [text])

    def test_leaves_other_compositions(self) -> None:
        for source in (
            'def data(h):\n    return 4 + h * 8\nlength = data(h) + 2\n',
            'def data(h):\n    return 4 + h * 8\nlength = 2 * data(h)\n',
            'def data(h):\n    return 4 + h * 8\nlength = data(h) + data(k)\n',
            'def data(h):\n    if h:\n        return 0\n    return 4 + h * 8\nlength = 4 + data(h)\n',
            'def data(h, k):\n    return 4 + h * 8\nlength = 4 + data(h, 0)\n',
            'def data(h):\n    return 4 + h * 8\nlength = 4 + other.data(h)\n',
            'from pcapkit.corekit.schema.extlen import ext_len_to_octets\nlength = ext_len_to_octets(h)\n',
        ):
            with self.subTest(source=source):
                self.assertEqual(self._split(source), [])


class TreeTests(unittest.TestCase):
    """No module but the helper writes the conversion out."""

    def test_helper_writes_both_directions(self) -> None:
        shapes = {shape for _, shape, _ in conversions(HELPER.read_text(encoding='utf-8'))}
        self.assertEqual(shapes, {'(x + 1) * 8', 'x // 8 - 1'})

    def _matches(self) -> 'list[tuple[str, int, str, str]]':
        """Every match outside the helper, as ``(path, lineno, shape, text)``."""
        found = []
        for path in sorted(PACKAGE.rglob('*.py')):
            if path == HELPER:
                continue
            rel = path.relative_to(ROOT).as_posix()
            for lineno, shape, text in conversions(path.read_text(encoding='utf-8')):
                found.append((rel, lineno, shape, text))
        return found

    def test_no_conversion_outside_the_helper(self) -> None:
        found = [f'{rel}:{lineno}: {shape}: {text}' for rel, lineno, shape, text in self._matches()
                 if (rel, text) not in EXEMPT]
        self.assertEqual(found, [], 'convert through pcapkit.corekit.schema.extlen instead (#2854):\n'
                         + '\n'.join(found))

    def test_exemptions_name_real_matches(self) -> None:
        matched = {(rel, text) for rel, _, _, text in self._matches()}
        self.assertEqual(sorted(EXEMPT - matched), [])

    def test_no_split_conversion_outside_the_helper(self) -> None:
        parsed = package_modules()
        table = linear_helpers([module for _, module in parsed])
        found = [f'{path.relative_to(ROOT).as_posix()}:{lineno}: {text}'
                 for path, module in parsed for lineno, text in split_conversions(module, table)]
        self.assertEqual(found, [], 'convert through pcapkit.corekit.schema.extlen instead (#2854):\n'
                         + '\n'.join(found))


if __name__ == '__main__':
    unittest.main()
