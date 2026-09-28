# -*- coding: utf-8 -*-
"""A hard-coded ``_missing_`` body must end in a ``return``, and no emitted
line may re-enter ``_missing_`` for the same value.

GitHub issue #866. A vendor crawler renders the body of the generated
registry's :meth:`~enum.Enum._missing_` as a list of source lines, held in the
local ``miss``. Two crawlers --
:mod:`pcapkit.vendor.pcapng.record_type` and
:mod:`pcapkit.vendor.pcapng.secrets_type` -- emitted a **two**-line body whose
first line called :meth:`~pcapkit.corekit.enum.EnumRegistry._unregistered_member`
without returning it and whose second line was ``return cls(value)``::

    cls._unregistered_member(value, 'Unassigned')
    return cls(value)

That shape was harmless while the first line was ``extend_enum(...)``, which
*registers* the member, so the following ``cls(value)`` found it and returned.
#861 replaced the ``extend_enum`` call with ``_unregistered_member``, which
deliberately does **not** register -- so ``cls(value)`` missed again, re-entered
``_missing_``, and recursed until ``RecursionError``.

The invariant is deliberately not "every emitted line returns": the base
crawler itself emits legitimate non-returning lines for a range-guarded body.
:meth:`pcapkit.vendor.default.Vendor.process` (see
:file:`pcapkit/vendor/default.py:341-343`) renders such a body as three
lines -- an ``if`` header, a ``#:`` comment, then an indented ``return`` --
and only the third of the three returns::

    miss.append(f'if {start} <= value <= {stop}:')
    miss.append(f'    #: {desc}')
    miss.append(f"    return cls._unregistered_member(value, '{self.safe_name(name)}')")

Measured: 53 crawlers emit 109 such non-returning lines between them, and
three registries under :mod:`pcapkit.const` carry exactly that shape today.
A crawler hard-coding a range-guarded body as a list literal is writing
something valid, so the guard below checks only that a hard-coded body
*ends* in a ``return`` and that no emitted line re-enters ``_missing_`` for
the same value -- not that every line returns.

#861 only *half*-corrected the two generated files, and never touched the two
crawlers. It replaced the non-returning ``extend_enum(...)`` call with a
returning ``_unregistered_member(...)`` call, but the ``return cls(value)``
line that followed was left in place, now unreachable dead code::

    -        extend_enum(cls, 'Unassigned_0x%08x' % value, value)
    +        return cls._unregistered_member(value, 'Unassigned')
             return cls(value)          # <- still there, now unreachable

That is why #861's own CI was green: the first ``return`` short-circuits, so
the dead second line never ran. (A statement following a ``return`` in
generated output is itself worth noticing on its own -- it means the
generator that will overwrite the file disagrees with what the file
currently does.) Because the crawlers were never touched, a later
regeneration -- ``e58618bdf`` ("Bumped version to 1.5.0b5") -- reproduced the
original two-line body from the stale crawlers and reintroduced the
recursion, turning **12** tests red across **three** files:
:file:`tests/const/test_const_enum_lookup.py`,
:file:`tests/const/test_const_enum_no_mint.py`
(``RulingConversionDoesNotMintTests.test_converted_value_does_not_mint`` and
``test_repeated_lookup_does_not_grow_members``, two registries each), and
:file:`tests/protocols/misc/test_pcapng_unit.py` (7 of the 12) -- all twelve
``RecursionError``.

The guard here is deliberately at the **crawler** layer rather than the
generated one. ``tests/const/test_const_enum_lookup.py`` already exercises every
committed registry and is what caught the regression; what nothing covered was
the source a crawler *emits*, so a fix to a generated file could silently
disagree with the generator that will overwrite it. This module needs no network
and no regeneration: it reads the crawlers' own ASTs.

"""
from __future__ import annotations

import ast
import pathlib
import unittest

#: Root of the vendor crawler package, as a path rather than an import, so this
#: module reads the same tree it is checked out in regardless of which
#: ``pcapkit`` an editable install happens to resolve.
VENDOR_ROOT = pathlib.Path(__file__).resolve().parents[2] / 'pcapkit' / 'vendor'

#: How many crawlers emit at least one *hard-coded* line into ``miss`` as a
#: string-constant list literal. Pinned so a crawler that leaves this shape --
#: switching to ``.append()``, or dropping its unassigned range -- is visible
#: here rather than silently shrinking the sweep below. It does **not** catch
#: the opposite drift: a brand-new crawler that starts in a shape this guard
#: never covered joins invisibly, because nothing here shrinks when one is
#: added.
#:
#: Measured on ``main`` at ``946b84e83``: 96 crawler modules define
#: ``process()``. Of those, 35 assign ``miss`` as a list literal of string
#: constants -- the ones this test can see -- 53 build it by ``.append()``
#: instead, and 8 never return an ``(enum, miss)`` pair at all. That leaves
#: **61 of the 96 invisible to this guard**, not merely the two crawlers used
#: as an example in :func:`_constant_miss_lines`'s docstring below. A crawler
#: that assigns ``miss`` from a comprehension, from a variable, or under a
#: different variable name entirely is skipped by construction too, same as
#: one built by ``.append()``. All 61 are covered behaviourally, not
#: statically, by :file:`tests/const/test_const_enum_lookup.py`.
EXPECTED_CRAWLERS_WITH_CONSTANT_MISS_LINES = 35


def _constant_miss_lines() -> 'dict[str, list[str]]':
    """Collect every constant line each crawler assigns to ``miss``.

    Returns a mapping of repository-relative crawler path to the list of
    string constants in its ``miss`` list literal. A crawler that builds
    ``miss`` by ``.append()``, assigns it from a comprehension or a variable,
    or never returns an ``(enum, miss)`` pair at all, is absent from the
    returned mapping entirely -- not present with an empty list. That is
    **61 of the 96** crawler modules defining ``process()``, not just the two
    examples this docstring used to single out
    (:mod:`pcapkit.vendor.reg.ethertype`, :mod:`pcapkit.vendor.ipx.socket`);
    see :data:`EXPECTED_CRAWLERS_WITH_CONSTANT_MISS_LINES` for the full
    breakdown. All 61 are covered behaviourally, not statically, by
    :file:`tests/const/test_const_enum_lookup.py`.

    """
    found = {}  # type: dict[str, list[str]]
    for path in sorted(VENDOR_ROOT.rglob('*.py')):
        tree = ast.parse(path.read_text(encoding='utf-8'))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            if not any(isinstance(t, ast.Name) and t.id == 'miss' for t in node.targets):
                continue
            if not isinstance(node.value, ast.List):
                continue
            lines = [elt.value for elt in node.value.elts
                     if isinstance(elt, ast.Constant) and isinstance(elt.value, str)]
            if lines:
                found[str(path.relative_to(VENDOR_ROOT.parents[1]))] = lines
    return found


class VendorMissingBodyTests(unittest.TestCase):
    """Static guards over what the crawlers render into ``_missing_``."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.miss_lines = _constant_miss_lines()  # type: ignore[attr-defined]

    def test_the_sweep_size_is_pinned(self) -> None:
        """A crawler leaving or joining the sweep must be deliberate."""
        self.assertEqual(len(self.miss_lines),  # type: ignore[attr-defined]
                         EXPECTED_CRAWLERS_WITH_CONSTANT_MISS_LINES,
                         'the set of crawlers emitting a constant ``_missing_`` body '
                         'changed; update EXPECTED_CRAWLERS_WITH_CONSTANT_MISS_LINES '
                         'once you have checked the new ones still return')

    def test_the_hard_coded_body_ends_in_a_return(self) -> None:
        """The invariant #866 is about, restated to the shape that is true.

        Not every emitted line has to ``return`` -- the range-guarded shape
        in :meth:`pcapkit.vendor.default.Vendor.process` legitimately emits
        an ``if`` header and a ``#:`` comment before its ``return``, and 53
        crawlers do exactly that (see the module docstring). What has to be
        true is narrower: a hard-coded body must *end* on a ``return``, so
        control never falls off the end of ``miss`` into a fallthrough.

        This test does **not** catch #866 on its own: #866's body ended on
        ``return cls(value)``, which does return, so it passes this check
        both before and after the fix. It is
        :meth:`test_no_crawler_emits_a_self_recursive_lookup` that catches
        the cycle -- this test only guards against a body that does not
        return at all.

        """
        for crawler, lines in sorted(self.miss_lines.items()):  # type: ignore[attr-defined]
            last = lines[-1]
            with self.subTest(crawler=crawler, line=last):
                self.assertTrue(last.lstrip().startswith('return '),
                                f'{crawler} ends its hard-coded ``_missing_`` body on '
                                f'{last!r}, which does not return; a body that falls '
                                f'through does nothing observable, see GitHub issue #866')

    def test_no_crawler_emits_a_self_recursive_lookup(self) -> None:
        """``return cls(value)`` inside ``_missing_`` is unconditionally wrong.

        Named separately from :meth:`test_the_hard_coded_body_ends_in_a_return`
        because this line *does* return and so passes that check, yet re-enters
        ``_missing_`` for the same value. It was the second half of #866's
        two-line body and is the line that actually recursed.

        """
        for crawler, lines in sorted(self.miss_lines.items()):  # type: ignore[attr-defined]
            for line in lines:
                with self.subTest(crawler=crawler, line=line):
                    self.assertNotEqual(line.replace(' ', ''), 'returncls(value)',
                                        f'{crawler} emits ``return cls(value)`` inside '
                                        f'``_missing_``, which re-enters ``_missing_`` '
                                        f'for the same value; see GitHub issue #866')

    def test_the_two_regressed_crawlers_emit_a_single_returning_line(self) -> None:
        """The specific pair from #866, pinned by name.

        Kept alongside the general sweeps because a regression here is the one
        that reached ``main``, and a named test says which file to look at
        without having to read a subTest label.

        """
        for crawler in ('pcapkit/vendor/pcapng/record_type.py',
                        'pcapkit/vendor/pcapng/secrets_type.py'):
            with self.subTest(crawler=crawler):
                lines = self.miss_lines[crawler]  # type: ignore[attr-defined]
                self.assertEqual(
                    lines, ["return cls._unregistered_member(value, 'Unassigned')"],
                    f'{crawler} must emit exactly one returning line')


class RegeneratedRegistryLookupTests(unittest.TestCase):
    """The behaviour the broken body produced, pinned on the generated files.

    :file:`tests/const/test_const_enum_lookup.py` sweeps every registry and so
    already covers this; these two cases are named for #866 so the reported
    symptom is findable from the issue number.

    """

    def test_record_type_resolves_an_unassigned_value(self) -> None:
        from pcapkit.const.pcapng.record_type import RecordType

        member = RecordType(0xFFFF)
        self.assertEqual(member.name, 'Unassigned')
        self.assertEqual(int(member), 0xFFFF)
        self.assertNotIn('Unassigned', RecordType.__members__)

    def test_secrets_type_resolves_an_unassigned_value(self) -> None:
        from pcapkit.const.pcapng.secrets_type import SecretsType

        member = SecretsType(0)
        self.assertEqual(member.name, 'Unassigned')
        self.assertEqual(int(member), 0)
        self.assertNotIn('Unassigned', SecretsType.__members__)


if __name__ == '__main__':
    unittest.main()
