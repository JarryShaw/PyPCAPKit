# -*- coding: utf-8 -*-
"""Every name used in a string annotation is one the module actually binds.

The package writes its annotations as string literals and imports the names they
need inside an ``if TYPE_CHECKING:`` block. Nothing at runtime evaluates those
strings, so a name that is *never imported at all* costs nothing until a type
checker or a documentation build looks at it -- at which point it is an error in a
file that has been passing tests for months. Issue #642 found three, and mypy
2.3.1 agreed the three were the complete set:

.. code-block:: text

   pcapkit/utilities/logging.py:350:54: error: Name "Any" is not defined  [name-defined]
   pcapkit/protocols/schema/internet/ipv6_route.py:136:77: error: Name "Protocol" is not defined  [name-defined]
   pcapkit/protocols/schema/internet/ipv6_route.py:271:24: error: Name "Optional" is not defined  [name-defined]

This module is the same check without mypy: cheap enough to run on every commit,
and it does not depend on a type checker being installed or on which version of
one. Run against the tree that carried those three defects it reports exactly
those three, name for name and line for line, which is what says it is measuring
the right thing.

A deliberate non-goal: this says nothing about whether the annotations resolve at
*runtime*. They do not, and not because of anything this catches --
``TYPE_CHECKING`` is :data:`False` when the interpreter runs, so a
``TYPE_CHECKING``-only import is absent from the module namespace either way.
:func:`typing.get_type_hints` raises :exc:`NameError` on five of the six annotated
functions in :mod:`pcapkit.utilities.logging`, four of them for ``Optional`` and
``Union``, which *are* imported in its ``TYPE_CHECKING`` block. Making those
resolve is a repository-wide decision about the idiom, not a missing import, and
is out of scope here. What this module pins is the narrower and entirely
uncontroversial invariant: a name a reader sees in an annotation should be a name
the file brought into scope.

This module is unit-tier: it reads source text and never imports the package.

"""
from __future__ import annotations

import ast
import builtins
import pathlib
import sys
import unittest
from typing import TYPE_CHECKING

from tests._tiers import ROOT

if TYPE_CHECKING:
    from typing import Iterator, Optional

#: Package directory whose annotations are checked.
PACKAGE = ROOT / 'pcapkit'


def annotation_strings(tree: 'ast.AST') -> 'Iterator[tuple[str, int]]':
    """Yield every string literal ``tree`` uses as a type, with its line number.

    Four places a string is a type rather than a value, and all four are used in
    this package: a variable annotation, a parameter annotation, a return
    annotation, and the first argument of :func:`typing.cast`. The ``cast`` case
    is the one that is easiest to miss and is exactly where
    ``ipv6_route.py:271``'s ``Optional`` hid -- :func:`typing.cast` never
    evaluates that argument, so an unresolvable name there is invisible to every
    test that runs the line.

    Args:
        tree: Parsed module.

    Yields:
        ``(source, lineno)`` pairs, the source being the annotation text with its
        surrounding quotes already removed.

    """
    for node in ast.walk(tree):
        if isinstance(node, (ast.AnnAssign, ast.arg)):
            yield from _as_string(getattr(node, 'annotation', None))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield from _as_string(node.returns)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                and node.func.id == 'cast' and node.args:
            yield from _as_string(node.args[0])


def _as_string(node: 'Optional[ast.expr]') -> 'Iterator[tuple[str, int]]':
    """Yield ``(value, lineno)`` if ``node`` is a string literal, else nothing."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        yield node.value, node.lineno


#: :class:`ast.TypeAlias` where the running interpreter has it, else ``()``.
#:
#: ``ast.TypeAlias`` and ``ast.TypeVar`` are :pep:`695` nodes, new in Python 3.12,
#: and the supported range starts at 3.10 -- so naming either one directly raises
#: :exc:`AttributeError` there, and does so in *every* test in this module rather
#: than one, because :func:`bound_names` walks every node of every file. Resolving
#: them through :func:`getattr` to an empty tuple instead leaves both branches
#: fully live on 3.12+ and merely unreachable below it, since :func:`isinstance`
#: against ``()`` is always :data:`False`.
#:
#: A :data:`sys.version_info` comparison would work too, and is not chosen: it
#: writes the version down a second time, next to the attribute it guards, and the
#: two can then disagree. This form names no version at all, so when the floor
#: reaches 3.12 the whole thing collapses back to the plain attribute.
_TYPE_ALIAS = getattr(ast, 'TypeAlias', ())

#: :class:`ast.TypeVar` where the running interpreter has it, else ``()``.
#:
#: Kept separate from :data:`_TYPE_ALIAS` rather than folded into one tuple,
#: because the two spell their name differently and so cannot share a branch:
#: ``TypeAlias.name`` is an :class:`ast.Name` node, ``TypeVar.name`` a plain
#: :class:`str`.
_TYPE_VAR = getattr(ast, 'TypeVar', ())


def bound_names(tree: 'ast.AST') -> 'set[str]':
    """Every name ``tree`` binds anywhere in the module, plus the builtins.

    Deliberately generous, and scope-blind: an import nested inside
    ``if TYPE_CHECKING:``, a class defined inside a ``SPHINX_TYPE_CHECKING``
    block, a name imported or assigned inside a function body -- all count. This
    is not trying to reimplement Python's scoping rules, because the failure it
    exists to catch is a name bound *nowhere in the file at all*.

    A stricter version was tried and reverted, and the reason is worth recording
    because the strict version looks obviously better. ``get_type_hints`` resolves
    a *parameter or return* annotation against module and class scope only, never
    against a function's locals, so narrowing to those scopes catches a real
    defect: a module that binds ``Optional`` as an ordinary local somewhere and
    then writes ``'Optional[int]'`` without importing it. But the same narrowing
    false-positives on real code here, because a :func:`typing.cast` string is
    resolved *lexically*, in the function containing the call --
    ``pcapkit/toolkit/scapy.py:208`` casts to ``'IPv6ExtHdrFragment'``, imported
    six lines above it inside the same function, which is correct and which mypy
    accordingly does not flag. Distinguishing the two would mean tracking a
    binding set per scope and knowing which construct resolves in which, i.e.
    reimplementing the type checker this deliberately is not.

    So the trade is made the other way round, on purpose: **no false positives, at
    the cost of one documented false negative.** A name that is bound only as a
    local in some unrelated function will mask a genuinely missing import of that
    same name in the same file. That is the shape to know about, and it is not
    hypothetical for names like ``Any`` and ``Optional``; it is simply rarer than
    the false positives the alternative produces, and much less damaging than a
    guard that cries wolf. Matching mypy's finding set exactly is what makes this
    usable as a cheap stand-in for it, and the generous version does.

    Args:
        tree: Parsed module.

    Returns:
        The set of names considered in scope for an annotation in this module.

    """
    names = set(dir(builtins))
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                names.add(alias.asname or alias.name.split('.')[0])
        elif isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            names.add(node.name)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            names.add(node.id)
        elif isinstance(node, _TYPE_ALIAS) and isinstance(node.name, ast.Name):
            names.add(node.name.id)
        elif isinstance(node, _TYPE_VAR):
            names.add(node.name)
    return names


def referenced_names(source: str) -> 'Optional[set[str]]':
    """The names an annotation expression refers to, or :data:`None` if it is not one.

    Only the leftmost component of a dotted path matters: ``logging.Handler``
    needs ``logging`` in scope and says nothing about ``Handler``.

    A string *inside* the annotation is descended into, because a nested forward
    reference is still a type reference: ``'list["Nested"]'`` needs ``Nested`` in
    scope just as ``'list[Nested]'`` does, and the typing machinery resolves it the
    same way. Walking only the :class:`ast.Name` nodes missed that entirely -- a
    nested reference parses as an :class:`ast.Constant`, invisible to the walk --
    so an unresolvable name one level of quoting down went unreported.

    Which is why the descent below is explicit rather than :func:`ast.walk`: the
    two places a string inside an annotation is a *value* and not a type have to be
    skipped, or they become false positives. ``Literal["big", "little"]`` names no
    type ``big``, and this package writes 20-odd of those; and everything after the
    first argument of ``Annotated[T, ...]`` is metadata. Both are recognised by the
    subscripted name, which is how a type checker recognises them too.

    Args:
        source: Annotation text.

    Returns:
        The referenced names, or :data:`None` when ``source`` does not parse as an
        expression -- a docstring caught by the ``cast`` heuristic, say, rather
        than a type.

    """
    try:
        expression = ast.parse(source, mode='eval')
    except SyntaxError:
        return None

    names = set()  # type: set[str]
    _collect_references(expression.body, names)
    return names


#: Subscripted names whose slice is wholly values rather than types.
_VALUE_SLICE = frozenset({'Literal'})

#: Subscripted names whose slice is a type followed by metadata.
_TYPE_THEN_METADATA = frozenset({'Annotated'})


def _collect_references(node: 'ast.expr', names: 'set[str]') -> None:
    """Add the type names ``node`` refers to, descending into nested strings.

    Args:
        node: An annotation expression, or part of one.
        names: Accumulator, mutated in place.

    """
    if isinstance(node, ast.Constant):
        if isinstance(node.value, str):
            nested = referenced_names(node.value)
            if nested is not None:
                names |= nested
        return

    if isinstance(node, ast.Name):
        names.add(node.id)
        return

    if isinstance(node, ast.Attribute):
        root = node  # type: ast.expr
        while isinstance(root, ast.Attribute):
            root = root.value
        if isinstance(root, ast.Name):
            names.add(root.id)
        return

    if isinstance(node, ast.Subscript):
        _collect_references(node.value, names)
        head = node.value
        while isinstance(head, ast.Attribute):
            head = head.value
        label = head.id if isinstance(head, ast.Name) else ''
        elements = (list(node.slice.elts) if isinstance(node.slice, ast.Tuple)
                    else [node.slice])
        if label in _VALUE_SLICE:
            return
        if label in _TYPE_THEN_METADATA:
            elements = elements[:1]
        for element in elements:
            _collect_references(element, names)
        return

    for child in ast.iter_child_nodes(node):
        if isinstance(child, ast.expr):
            _collect_references(child, names)
    return names


def unresolved_annotation_names(package: 'pathlib.Path') -> 'list[str]':
    """Every annotation name under ``package`` that its own module never binds.

    Args:
        package: Directory to walk.

    Returns:
        ``path:lineno: name (in 'annotation')`` strings, sorted, one per finding,
        so that a failure names the file and line to edit rather than a count.

    """
    findings = []  # type: list[str]
    for path in sorted(package.rglob('*.py')):
        tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
        bound = bound_names(tree)
        for source, lineno in annotation_strings(tree):
            names = referenced_names(source)
            if names is None:
                continue
            for name in sorted(names - bound):
                findings.append(f'{_label(path)}:{lineno}: {name}  (in {source!r})')
    return sorted(findings)


def _label(path: 'pathlib.Path') -> str:
    """``path`` relative to the repository root, or absolute if it is outside it.

    The fallback is not cosmetic: the self-check below scans a temporary directory,
    and a bare :meth:`~pathlib.PurePath.relative_to` raises :exc:`ValueError` on a
    path that is not under ``ROOT``.

    """
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


class AnnotationNamesAreInScopeTests(unittest.TestCase):
    """No module uses a name in an annotation that it never brought into scope."""

    def test_every_annotation_name_is_bound_somewhere_in_its_module(self) -> None:
        unresolved = unresolved_annotation_names(PACKAGE)

        self.assertEqual(
            unresolved, [],
            'these names appear in a string annotation but are imported nowhere in '
            'their module, so a type checker cannot resolve them; add them to the '
            "module's TYPE_CHECKING block (#642):\n  " + '\n  '.join(unresolved))

    def test_the_check_itself_still_finds_a_planted_defect(self) -> None:
        """A guard that cannot fail is not a guard.

        The check is source-text analysis over a directory that is expected to be
        clean, so a bug that made it silently find nothing would look exactly like
        success. A module with a known-unresolvable name is written to a scratch
        directory and it has to be reported, with the right line and the right
        name.

        """
        import tempfile

        with tempfile.TemporaryDirectory() as scratch:
            planted = pathlib.Path(scratch) / 'planted.py'
            planted.write_text(
                'from typing import TYPE_CHECKING\n'
                '\n'
                'if TYPE_CHECKING:\n'
                '    from typing import Optional\n'
                '\n'
                '\n'
                "def f(a: 'Optional[int]', b: 'NeverImported') -> 'None': ...\n",
                encoding='utf-8',
            )

            findings = unresolved_annotation_names(pathlib.Path(scratch))

        self.assertEqual(len(findings), 1, f'expected one finding, got {findings}')
        self.assertIn('NeverImported', findings[0])
        self.assertIn(':7:', findings[0])
        # ``Optional`` is imported, if only under ``TYPE_CHECKING``, so it is not a
        # finding -- which is the distinction the whole check turns on.
        self.assertNotIn('Optional', findings[0])

    def test_a_nested_forward_reference_is_followed(self) -> None:
        """A name quoted twice is still a name that has to resolve.

        ``'list["Nested"]'`` parses to a :class:`ast.Constant` inside the
        subscript, so a walk that looks only at :class:`ast.Name` nodes never sees
        ``Nested`` at all. This was a real hole, found by review rather than by the
        self-check above, and it is the shape most likely to recur because it looks
        exactly like the annotations that *are* checked.

        """
        findings = self._findings_for(
            "def f(x: 'list[\"NeverImportedEither\"]') -> 'None': ...\n")

        self.assertEqual(len(findings), 1, f'expected one finding, got {findings}')
        self.assertIn('NeverImportedEither', findings[0])

    def test_a_literal_member_is_not_mistaken_for_a_type(self) -> None:
        """``Literal["big"]`` refers to no type called ``big``.

        The other half of following nested strings, and the reason the descent has
        to know what it is descending into: inside ``Literal`` a string is a
        *value*, and this package writes twenty-odd of them. Following those
        indiscriminately reports every literal member as an unresolvable name --
        a false positive on real code, which is worse than the missed defect it
        was meant to fix. ``Annotated``'s trailing metadata is the same case.

        """
        self.assertEqual(
            self._findings_for(
                'from typing import TYPE_CHECKING\n'
                '\n'
                'if TYPE_CHECKING:\n'
                '    from typing import Annotated, Literal\n'
                '\n'
                '\n'
                "def f(x: 'Literal[\"big\", \"little\"]') -> 'None': ...\n"
                '\n'
                '\n'
                "def g(y: 'Annotated[int, \"units=octets\"]') -> 'None': ...\n"),
            [])

    def test_a_cast_to_a_function_local_import_is_not_a_finding(self) -> None:
        """The case that keeps :func:`bound_names` scope-blind.

        ``pcapkit/toolkit/scapy.py:202-208`` imports ``IPv6ExtHdrFragment`` inside
        a function and casts to it six lines later in the same function. A
        :func:`typing.cast` string resolves lexically, so that is correct code and
        mypy does not flag it -- and a check narrowed to module and class scope
        reports it, which is how the stricter version of :func:`bound_names` was
        discovered to be wrong. Pinned here so that reintroducing the narrowing
        fails a test rather than a real module.

        """
        self.assertEqual(
            self._findings_for(
                'from typing import cast\n'
                '\n'
                '\n'
                'def f(packet: object) -> object:\n'
                '    from somewhere import Layer\n'
                "    return cast('Layer', packet)\n"),
            [])

    @unittest.skipIf(sys.version_info < (3, 12),
                     'PEP 695 syntax does not parse before Python 3.12')
    def test_a_pep695_type_parameter_is_in_scope(self) -> None:
        """A :pep:`695` type parameter binds its name, and on 3.12+ still does.

        :data:`_TYPE_ALIAS` and :data:`_TYPE_VAR` reach nodes that exist only from
        3.12 through :func:`getattr`, falling back to ``()``. The hazard in that is
        silent: a misspelt attribute name, or a fallback that somehow applied on
        3.12+ too, switches the branch off *everywhere* and nothing fails --
        because those branches only ever suppress findings, never create them. So
        both halves are asserted here, the guards and the behaviour.

        ``T`` is the load-bearing half. An :class:`ast.TypeVar` node carries its
        name as a bare :class:`str` and produces no :class:`ast.Name` node at all,
        so :data:`_TYPE_VAR` is the only thing that binds it; remove that branch
        and ``'T'`` becomes a false finding. ``Alias`` is belt and braces next to
        it: ``TypeAlias.name`` *is* an :class:`ast.Name` in :class:`ast.Store`
        context, which the preceding branch already catches.

        """
        self.assertIs(_TYPE_ALIAS, ast.TypeAlias)
        self.assertIs(_TYPE_VAR, ast.TypeVar)

        self.assertEqual(
            self._findings_for(
                'type Alias = int\n'
                '\n'
                '\n'
                "def f[T](x: 'T', y: 'Alias') -> 'None': ...\n"
                '\n'
                '\n'
                'class C[U]:\n'
                "    def m(self, v: 'U') -> 'None': ...\n"),
            [])

    def _findings_for(self, source: str) -> 'list[str]':
        """Findings for ``source`` written as a lone module in a scratch directory.

        Args:
            source: Module text.

        Returns:
            What :func:`unresolved_annotation_names` reports for it.

        """
        import tempfile

        with tempfile.TemporaryDirectory() as scratch:
            (pathlib.Path(scratch) / 'probe.py').write_text(source, encoding='utf-8')
            return unresolved_annotation_names(pathlib.Path(scratch))


if __name__ == '__main__':
    unittest.main()
