# -*- coding: utf-8 -*-
"""Every comment a crawler renders into ``_missing_`` is a ``#:`` one.

GitHub issue #2331. :meth:`pcapkit.vendor.default.Vendor.process` renders a
range-guarded :meth:`~enum.Enum._missing_` branch as three lines -- an ``if``
header, a comment naming the span, then an indented ``return``::

    miss.append(f'if {start} <= value <= {stop}:')
    miss.append(f'    #: {desc}')
    miss.append(f"    return cls._unregistered_member(value, '{self.safe_name(name)}')")

``#:`` is Sphinx's attribute-doc marker. Every crawler renders it; the
exceptions were :mod:`pcapkit.vendor.hip.group` and
:mod:`pcapkit.vendor.hip.packet`, which rendered a plain ``#``, so their
unassigned spans in :mod:`pcapkit.const.hip.group` and
:mod:`pcapkit.const.hip.packet` read ``# Unassigned`` where every other span
across :mod:`pcapkit.const` reads ``#: Unassigned``. The rendered
documentation is not what the fix is about -- autodoc reads a ``#:`` comment
where an attribute is declared, not one inside a function body, as the issue
itself notes -- it is that the generators now agree on one form rather than
two.

A comment is a comment to the interpreter either way, so no behavioural suite
catches a marker regression and nothing else checks it. Hence the two static
sweeps below, one per layer:

* :class:`VendorMissingCommentMarkerTests` reads the crawlers' own ASTs, so a
  crawler that starts emitting ``#`` is caught before anyone regenerates.
* :class:`ConstMissingCommentMarkerTests` reads the committed registries, so a
  generated file that disagrees with the generator which will overwrite it is
  caught too -- the same two-layer split
  :file:`tests/vendor/test_vendor_missing_body_unit.py` makes for #866.

Neither needs the network, a regeneration, or an importable
:mod:`pcapkit.vendor`: both read the checked-out tree as text.

"""
from __future__ import annotations

import ast
import pathlib
import re
import unittest

#: Test tier (#1958): reads the vendor templates and the committed constant modules
#: as text, a question about the tree rather than about an interpreter.
__tier__ = 'LATEST'

#: Repository root, i.e. the grandparent of the directory holding this file.
ROOT = pathlib.Path(__file__).resolve().parents[2]

#: Root of the vendor crawler package, as a path rather than an import, so this
#: module reads the same tree it is checked out in regardless of which
#: ``pcapkit`` an editable install happens to resolve.
VENDOR_ROOT = ROOT / 'pcapkit' / 'vendor'

#: Root of the generated constant package, read the same way and for the same
#: reason.
CONST_ROOT = ROOT / 'pcapkit' / 'const'

#: The range guard :meth:`~pcapkit.vendor.default.Vendor.process` opens an
#: unassigned-span branch with. Anchors :func:`_const_span_comments` to the
#: *generated* shape, so the prose ``#`` comments that
#: :mod:`pcapkit.const.ftp.command` and :mod:`pcapkit.const.http.method`
#: hand-write above their own ``_unregistered_member`` calls are not swept:
#: those are explanatory notes, not attribute docs, and ``#`` is right for them.
SPAN_GUARD = re.compile(r'^\s*if .*<= value <=.*:$')

#: The ``return`` such a branch closes on.
SPAN_RETURN = re.compile(r'^\s*return cls\._unregistered_member\(')

#: Crawlers the AST walk must reach, so a walk that silently matched nothing --
#: an ``ast`` change, a rename of the ``miss`` local -- fails loudly instead of
#: sweeping an empty set. Named rather than counted: a count of what the tree
#: holds drifts as soon as the tree does, which :ref:`documentation`'s *state no
#: count* rules against (:issue:`1103`), and the vendor cron regenerates this
#: tree on its own schedule.
REQUIRED_CRAWLERS = (
    'pcapkit/vendor/default.py',      # the shared template every crawler inherits
    'pcapkit/vendor/hip/group.py',    # #2331's pair
    'pcapkit/vendor/hip/packet.py',
    'pcapkit/vendor/hip/parameter.py',  # their already-correct HIP siblings
    'pcapkit/vendor/hip/eddsa_curve.py',
)

#: Registries the text sweep must reach, for the same reason and named the same
#: way.
REQUIRED_REGISTRIES = (
    'pcapkit/const/hip/group.py',
    'pcapkit/const/hip/packet.py',
)


def _leading_text(node: 'ast.expr') -> 'str | None':
    """Read the literal text a ``miss`` line starts with.

    A crawler renders a line either as a plain :class:`str` constant or as an
    f-string whose first segment is one -- ``f'    #: {desc}'``. Only that
    leading segment decides whether the line is a comment, so an f-string's
    interpolations are not inspected.

    Args:
        node: Expression appended to, or listed in, ``miss``.

    Returns:
        The leading literal text, or :obj:`None` when the line begins with
        something other than literal text, e.g. ``f'{prefix}...'``.

    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr) and node.values:
        head = node.values[0]
        if isinstance(head, ast.Constant) and isinstance(head.value, str):
            return head.value
    return None


def _vendor_comment_lines() -> 'list[tuple[str, str]]':
    """Collect every comment line the crawlers render into ``_missing_``.

    Walks each crawler's AST for a line added to ``miss``, whether by
    ``miss.append(...)`` or as an element of a ``miss = [...]`` literal, and
    keeps the ones whose leading literal text is a comment.

    Returns:
        Pairs of repository-relative crawler path and comment line.

    """
    found = []  # type: list[tuple[str, str]]
    for path in sorted(VENDOR_ROOT.rglob('*.py')):
        tree = ast.parse(path.read_text(encoding='utf-8'))
        lines = []  # type: list[ast.expr]
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute) and node.func.attr == 'append'
                    and isinstance(node.func.value, ast.Name) and node.func.value.id == 'miss'
                    and node.args):
                lines.append(node.args[0])
            elif (isinstance(node, ast.Assign) and isinstance(node.value, ast.List)
                    and any(isinstance(target, ast.Name) and target.id == 'miss'
                            for target in node.targets)):
                lines.extend(node.value.elts)
        for line in lines:
            text = _leading_text(line)
            if text is not None and text.lstrip().startswith('#'):
                found.append((str(path.relative_to(ROOT)), text))
    return found


def _const_span_comments() -> 'list[tuple[str, int, str]]':
    """Collect every comment inside a generated unassigned-span branch.

    A branch is recognised by its shape rather than by its text: a
    :data:`SPAN_GUARD` header, one or more comment lines, then a
    :data:`SPAN_RETURN`. A comment sitting anywhere else -- including one above
    an ``_unregistered_member`` call that no range guard opens -- is not swept.

    Returns:
        Triples of repository-relative module path, 1-based line number and
        comment line.

    """
    found = []  # type: list[tuple[str, int, str]]
    for path in sorted(CONST_ROOT.rglob('*.py')):
        lines = path.read_text(encoding='utf-8').splitlines()
        for index, line in enumerate(lines):
            if not SPAN_GUARD.match(line):
                continue
            cursor = index + 1
            comments = []  # type: list[tuple[int, str]]
            while cursor < len(lines) and lines[cursor].lstrip().startswith('#'):
                comments.append((cursor + 1, lines[cursor]))
                cursor += 1
            if comments and cursor < len(lines) and SPAN_RETURN.match(lines[cursor]):
                found.extend((str(path.relative_to(ROOT)), number, text)
                             for number, text in comments)
    return found


class VendorMissingCommentMarkerTests(unittest.TestCase):
    """The crawler layer: what the generators emit."""

    @classmethod
    def setUpClass(cls) -> 'None':
        cls.comments = _vendor_comment_lines()  # type: ignore[attr-defined]

    def test_the_sweep_reaches_the_crawlers_it_is_about(self) -> 'None':
        """A walk that matched nothing would pass every check below vacuously."""
        swept = {crawler for crawler, _ in self.comments}  # type: ignore[attr-defined]
        for crawler in REQUIRED_CRAWLERS:
            with self.subTest(crawler=crawler):
                self.assertIn(crawler, swept)

    def test_every_crawler_renders_a_sphinx_comment(self) -> 'None':
        """One form of comment across the generators, which is ``#:``."""
        for crawler, text in self.comments:  # type: ignore[attr-defined]
            with self.subTest(crawler=crawler, line=text):
                self.assertTrue(text.lstrip().startswith('#:'),
                                f'{crawler} renders {text!r} into ``_missing_``, a plain '
                                f'``#`` comment where every other crawler renders ``#:``; '
                                f'see GitHub issue #2331')

    def test_the_hip_group_and_packet_crawlers_render_sphinx_comments(self) -> 'None':
        """The specific pair from #2331, pinned by name.

        Kept alongside the general sweep because these are the crawlers the
        issue was filed against, and a named test says which file to look at
        without having to read a subTest label.

        """
        for crawler in ('pcapkit/vendor/hip/group.py', 'pcapkit/vendor/hip/packet.py'):
            with self.subTest(crawler=crawler):
                texts = [text for path, text in self.comments  # type: ignore[attr-defined]
                         if path == crawler]
                self.assertEqual(texts, ['    #: '])


class ConstMissingCommentMarkerTests(unittest.TestCase):
    """The generated layer: what the committed registries carry."""

    @classmethod
    def setUpClass(cls) -> 'None':
        cls.comments = _const_span_comments()  # type: ignore[attr-defined]

    def test_the_sweep_reaches_the_registries_it_is_about(self) -> 'None':
        """A sweep that matched nothing would pass every check below vacuously."""
        swept = {module for module, _, _ in self.comments}  # type: ignore[attr-defined]
        for module in REQUIRED_REGISTRIES:
            with self.subTest(module=module):
                self.assertIn(module, swept)

    def test_every_registry_carries_a_sphinx_comment(self) -> 'None':
        """A generated file must not disagree with the generator."""
        for module, number, text in self.comments:  # type: ignore[attr-defined]
            with self.subTest(module=module, line=number):
                self.assertTrue(text.lstrip().startswith('#:'),
                                f'{module}:{number} reads {text.strip()!r} inside an '
                                f'unassigned-span branch, a plain ``#`` comment where the '
                                f'crawlers render ``#:``; see GitHub issue #2331')

    def test_the_hip_group_and_packet_registries_carry_sphinx_comments(self) -> 'None':
        """The spans #2331 names, pinned by module rather than by tally.

        How many unassigned spans each registry has is IANA's business and
        changes with each regeneration, so this checks what every one of them
        reads instead of how many there are.

        """
        for module in REQUIRED_REGISTRIES:
            with self.subTest(module=module):
                texts = {text.strip() for path, _, text
                         in self.comments if path == module}  # type: ignore[attr-defined]
                self.assertEqual(texts, {'#: Unassigned'})

    def test_the_hip_group_and_packet_lookups_still_resolve(self) -> 'None':
        """The comment marker is the only difference; lookups behave the same."""
        from pcapkit.const.hip.group import Group
        from pcapkit.const.hip.packet import Packet

        self.assertEqual(Group(12).name, 'Unassigned')
        self.assertEqual(Packet(33).name, 'Unassigned')
        self.assertNotIn('Unassigned', Group.__members__)
        self.assertNotIn('Unassigned', Packet.__members__)


if __name__ == '__main__':
    unittest.main()
