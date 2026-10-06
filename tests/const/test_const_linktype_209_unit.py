# -*- coding: utf-8 -*-
"""``LinkType(209)`` must resolve to the current name, not the legacy one.

GitHub issue #844: :mod:`pcapkit.const.reg.linktype` declared two members for
value ``209`` -- ``IPMB_LINUX`` first, ``I2C_LINUX`` second -- so
:class:`~aenum.IntEnum`'s "first member defined for a value is canonical" rule
made ``LinkType(209).name`` resolve to ``'IPMB_LINUX'``, the name tcpdump's own
registry (and the generated comment above it) labels "Legacy names (do not
use)". Traced to commit ``cfdf2ab5c7`` (2024-05-04): a regeneration inserted
the legacy row above the current one, because tcpdump's
``http://www.tcpdump.org/linktypes.html`` table lists them in exactly that
order -- ``LINKTYPE_IPMB_LINUX`` (209, marked legacy in its notes column)
ahead of ``LINKTYPE_I2C_LINUX`` (209, the current name). 209 is the *only*
value the table double-assigns, and that legacy note is the only occurrence of
the word "legacy" anywhere in it (measured directly against a live fetch while
fixing this).

The fix is in the generator, :mod:`pcapkit.vendor.reg.linktype`, not in the
generated file: :meth:`~pcapkit.vendor.reg.linktype.LinkType.process` now
sinks any row whose notes column mentions "legacy" into a bucket appended
*after* every other row, so the current name is always the first one defined
for a shared value regardless of the source table's own row order.

GitHub issue #852, a follow-up to the cross-review of #848, pointed out that
the original predicate tested the notes column for the word "legacy" alone,
with no check that the row's value was actually claimed by another row --
meaning a future *current* row whose notes happened to mention "legacy" about
some unrelated code would be wrongly sunk, and a single ``USER0``-style range
row would sink all sixteen expanded members at once instead of none.
:meth:`~pcapkit.vendor.reg.linktype.LinkType.process` now only sinks a
single-value row when its value is a genuine duplicate elsewhere in the same
table, and never routes a range row through the sink at all.

The cross-review of #852 itself then caught a second-order regression: the
first cut of the duplicate-value pre-scan counted only single-value rows, so a
value duplicated *across a range boundary* -- a single-value row sharing a
value with one member of a ``USER0``-style range -- was invisible to it, and
that row's legacy alias was no longer sunk even when correctly worded. The
pre-scan now expands ``a–b`` ranges the same way the main loop does
before counting, so no duplicate is missed regardless of which branch the
value comes from.

This module pins both the symptom and the root cause:

- :class:`LinkType209ConstResolutionTests` -- against the committed, generated
  :class:`pcapkit.const.reg.linktype.LinkType`, the same lookup the issue
  reported.
- :class:`LinkTypeGeneratorLegacyOrderingTests` -- against
  :meth:`~pcapkit.vendor.reg.linktype.LinkType.process` directly, fed a
  two-row fixture reproducing tcpdump's own HTML for value 209 byte-for-byte
  (captured from a live fetch while diagnosing this issue). Needs no network:
  the fixture *is* the table row, not a fetch of it, so this stays reliable in
  CI while still exercising the exact code path a real crawl runs. A
  regeneration that drops the fix reintroduces the wrong order here before it
  ever reaches the committed const file.
- :class:`LinkTypeGeneratorValueAwareTests` -- issue #852 item 1: a row whose
  value has no duplicate must never be sunk merely for mentioning "legacy",
  and the canonical member of a genuine duplicate pair must be the current
  one regardless of which table position it occupies.
- :class:`LinkTypeGeneratorRangeSinkIsolationTests` -- issue #852 item 2: a
  single range row's wording must never sink its whole expansion.
- :class:`LinkTypeGeneratorCrossRangeDuplicateTests` -- the #852 cross-review
  regression: a single-value row's legacy wording must still be honoured when
  the value it duplicates belongs to a range row, not another single-value
  one.

"""
from __future__ import annotations

import importlib.util
import unittest

from tests._support import reimport_once_per_class

#: The crawler dependencies :class:`LinkTypeGeneratorLegacyOrderingTests` needs to
#: parse its fixture. Spelled exactly as
#: :data:`tests.vendor.test_request_prompt_unit.VENDOR_DEPS` so this file reaches
#: the **existing** ``HAS_VENDOR_DEPS`` dependency gate rather than minting a new
#: one -- ``tests/_dependency_gates.py:315`` already accounts for that gate, with
#: ``dark={'test': ('html5lib',), 'gate': ('html5lib',)}``, and ``engine-tests``
#: closes it by installing the ``vendor`` extra.
#:
#: ``html5lib`` is the one that is actually missing on ``test``: ``requests`` and
#: ``bs4`` have shipped in the ``test`` extra since #507, but only
#: ``beautifulsoup4[html5lib]`` -- the ``vendor`` and ``all`` extras -- provides a
#: parser (``pyproject.toml:203``, and the note at ``:256-263`` saying so
#: deliberately).
VENDOR_DEPS = ('requests', 'bs4', 'html5lib')

#: Whether all of :data:`VENDOR_DEPS` are importable. Guarded the way
#: :file:`tests/vendor/test_request_prompt_unit.py` guards the same dependencies,
#: rather than making the whole unit tier depend on the crawlers'.
#:
#: Consequence worth knowing: :class:`LinkTypeGeneratorLegacyOrderingTests` is the
#: root-cause pin, and it runs only where the ``vendor`` extra is installed --
#: ``engine-tests`` per-PR, and locally. :class:`LinkType209ConstResolutionTests`
#: needs no parser and so still guards the reported symptom everywhere.
HAS_VENDOR_DEPS = all(importlib.util.find_spec(name) is not None for name in VENDOR_DEPS)

#: tcpdump's own two rows for value 209, captured verbatim (modulo
#: whitespace) from a live fetch of ``http://www.tcpdump.org/linktypes.html``
#: on 2026-09-27 -- legacy ``IPMB_LINUX`` first, current ``I2C_LINUX`` second,
#: exactly the order the registry itself lists them in.
LINKTYPE_209_TABLE_HTML = """
<table class="linktypedlt">
<tr><th>header row, skipped by request()</th></tr>
<tr>
<td class="symbol">LINKTYPE_IPMB_LINUX</td>
<td class="number">209</td>
<td class="symbol">DLT_IPMB_LINUX</td>
<td>
Legacy names (do not use) for Linux I2C below.
</td>
</tr>
<tr>
<td class="symbol">LINKTYPE_I2C_LINUX</td>
<td class="number">209</td>
<td class="symbol">DLT_I2C_LINUX</td>
<td>
<a href="linktypes/LINKTYPE_I2C_LINUX.html">Linux I2C packets</a>.
</td>
</tr>
</table>
"""


class LinkType209ConstResolutionTests(unittest.TestCase):
    """Against the generated, committed :class:`~pcapkit.const.reg.linktype.LinkType`."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_value_209_resolves_to_the_current_name(self) -> None:
        from pcapkit.const.reg.linktype import LinkType

        self.assertEqual(LinkType(209).name, 'I2C_LINUX',
                         "LinkType(209).name resolved to the legacy "
                         "'IPMB_LINUX' name instead of the current "
                         "'I2C_LINUX' one; see GitHub issue #844")

    def test_the_legacy_name_is_still_reachable_as_an_alias(self) -> None:
        # The fix reorders which name is canonical for 209; it does not take
        # the legacy name away -- both still name the same member by value.
        from pcapkit.const.reg.linktype import LinkType

        self.assertEqual(LinkType['IPMB_LINUX'], LinkType['I2C_LINUX'])
        self.assertEqual(LinkType['IPMB_LINUX'].value, 209)
        self.assertEqual(LinkType['IPMB_LINUX'].name, 'I2C_LINUX')


@unittest.skipUnless(HAS_VENDOR_DEPS, 'requests, bs4 and/or html5lib not installed')
class LinkTypeGeneratorLegacyOrderingTests(unittest.TestCase):
    """Against the generator's own ``process()``, root cause rather than symptom."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @staticmethod
    def _process_fixture() -> 'list[str]':
        """Run :meth:`LinkType.process` over the value-209 fixture rows.

        Builds the instance with ``object.__new__`` rather than calling
        ``LinkType()`` directly: the real constructor
        (:meth:`pcapkit.vendor.default.Vendor.__init__`) fetches the live
        registry and writes the generated const file as a side effect, and
        this test needs neither -- only the pure :meth:`process` step that
        turns registry rows into rendered enum members.
        """
        import bs4

        from pcapkit.vendor.reg.linktype import LinkType

        soup = bs4.BeautifulSoup(LINKTYPE_209_TABLE_HTML, 'html5lib')
        rows = soup.select('table.linktypedlt tr')[1:]

        inst = object.__new__(LinkType)
        enum, _miss = inst.process(rows)
        return enum

    def test_current_name_is_emitted_before_the_legacy_one(self) -> None:
        enum = self._process_fixture()

        self.assertEqual(len(enum), 2, f'expected exactly 2 rendered members, got: {enum!r}')

        first_name = enum[0].splitlines()[-1].split(' = ', 1)[0].strip()
        second_name = enum[1].splitlines()[-1].split(' = ', 1)[0].strip()

        self.assertEqual(first_name, 'I2C_LINUX',
                         f'the current name must be emitted first so it is '
                         f'canonical for value 209; got order {[first_name, second_name]!r}')
        self.assertEqual(second_name, 'IPMB_LINUX')

    def test_both_rows_still_render_with_their_own_comment(self) -> None:
        # Reordering must not lose either row or swap their bodies.
        enum = self._process_fixture()
        rendered = '\n'.join(enum)

        self.assertIn('I2C_LINUX = 209', rendered)
        self.assertIn('IPMB_LINUX = 209', rendered)
        self.assertIn('Linux I2C packets', rendered)
        self.assertIn('Legacy names (do not use) for Linux I2C below.', rendered)


#: Two rows for two *different*, otherwise-unrelated values -- neither shares
#: its value with anything else in the (2-row) table. ``FOO_LEGACY_WORDED``'s
#: notes mention "legacy" only incidentally, about a different, unnamed old
#: code -- not because ``FOO_LEGACY_WORDED`` itself is a deprecated alias of
#: ``BAR_PLAIN``. This is GitHub issue #852 item 1's own example: "a future
#: current row's notes say something like 'supersedes the legacy DLT_FOO'".
NON_DUPLICATE_LEGACY_WORDING_TABLE_HTML = """
<table class="linktypedlt">
<tr><th>header row, skipped by request()</th></tr>
<tr>
<td class="symbol">LINKTYPE_FOO_LEGACY_WORDED</td>
<td class="number">500</td>
<td class="symbol">DLT_FOO_LEGACY_WORDED</td>
<td>
Supersedes the legacy DLT_BAZ encoding used by very old capture tools.
</td>
</tr>
<tr>
<td class="symbol">LINKTYPE_BAR_PLAIN</td>
<td class="number">501</td>
<td class="symbol">DLT_BAR_PLAIN</td>
<td>
An ordinary, unrelated link type.
</td>
</tr>
</table>
"""

#: A genuine duplicate pair for a third value, worded exactly the way 209 is
#: (the legacy row's own notes say "legacy", the current row's do not).
#: ``{0}`` and ``{1}`` are substituted with the two rows' HTML in each order,
#: so the same pair can be fed through :meth:`process` current-first and
#: legacy-first without duplicating the row markup itself.
_QUX_CURRENT_ROW_HTML = """
<tr>
<td class="symbol">LINKTYPE_QUX_CURRENT</td>
<td class="number">600</td>
<td class="symbol">DLT_QUX_CURRENT</td>
<td>
The current name for this link type.
</td>
</tr>
"""

_QUX_OLD_ROW_HTML = """
<tr>
<td class="symbol">LINKTYPE_QUX_OLD</td>
<td class="number">600</td>
<td class="symbol">DLT_QUX_OLD</td>
<td>
Legacy name (do not use) for the same link type.
</td>
</tr>
"""


def _duplicate_pair_table_html(first: str, second: str) -> str:
    """Wrap two already-built rows in the table markup :meth:`process` expects."""
    return f"""
<table class="linktypedlt">
<tr><th>header row, skipped by request()</th></tr>
{first}
{second}
</table>
"""


@unittest.skipUnless(HAS_VENDOR_DEPS, 'requests, bs4 and/or html5lib not installed')
class LinkTypeGeneratorValueAwareTests(unittest.TestCase):
    """Item 1 of GitHub issue #852: the sink predicate must be value-aware.

    :meth:`~pcapkit.vendor.reg.linktype.LinkType.process`'s sink rule
    (added by #848) tested a row's notes for the word "legacy" alone, with no
    check that the row's value is actually claimed by another row. Issue
    #852 pointed out this can invert in the *other* direction: a future
    *current* row whose notes happen to mention "legacy" about some unrelated
    code gets sunk even though nothing else shares its value -- silently
    reordering the generated file's *emission order* for a value that was
    never ambiguous in the first place. (It also cannot, by itself, save a
    row from being wrongly sunk when tcpdump's wording is attached to the
    wrong member of a *genuine* duplicate pair; that residual risk is
    documented at the ``dup_values`` computation in
    :meth:`~pcapkit.vendor.reg.linktype.LinkType.process` rather than
    claimed as solved here.)
    """

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @staticmethod
    def _process(html: str) -> 'list[str]':
        import bs4

        from pcapkit.vendor.reg.linktype import LinkType

        soup = bs4.BeautifulSoup(html, 'html5lib')
        rows = soup.select('table.linktypedlt tr')[1:]

        inst = object.__new__(LinkType)
        enum, _miss = inst.process(rows)
        return enum

    def test_non_duplicated_legacy_wording_does_not_reorder(self) -> None:
        """A row cannot be sunk unless another row actually shares its value.

        Fails against the value-blind, word-only predicate on ``main``: that
        predicate sinks ``FOO_LEGACY_WORDED`` purely because its notes
        contain "legacy", swapping it after ``BAR_PLAIN`` in the returned
        list even though value 500 has no duplicate anywhere in this table.
        The value-aware predicate leaves both rows in table order, because
        neither of their values is duplicated.
        """
        enum = self._process(NON_DUPLICATE_LEGACY_WORDING_TABLE_HTML)

        self.assertEqual(len(enum), 2, f'expected exactly 2 rendered members, got: {enum!r}')

        first_name = enum[0].splitlines()[-1].split(' = ', 1)[0].strip()
        second_name = enum[1].splitlines()[-1].split(' = ', 1)[0].strip()

        self.assertEqual(
            [first_name, second_name], ['FOO_LEGACY_WORDED', 'BAR_PLAIN'],
            f'a row whose value has no duplicate must never be sunk, regardless '
            f'of its own wording; got order {[first_name, second_name]!r} -- see '
            f'GitHub issue #852 item 1'
        )

    def test_duplicate_pair_canonical_member_is_order_independent(self) -> None:
        """The *current* row must win regardless of which table position it is in.

        Unlike an earlier version of this test, which fed only the
        current-first ordering and left order-independence resting entirely
        on :class:`LinkTypeGeneratorLegacyOrderingTests`'s separate,
        legacy-first 209 fixture, this drives the *same* duplicate pair
        through :meth:`process` in **both** orders in one test -- so the name
        is earned here rather than borrowed from a sibling class. A predicate
        that regressed to counting only a positional prefix (e.g. "has this
        value already been appended to ``enum``") would still pass a
        single-order test like the old one, because that predicate is only
        wrong for the *first* occurrence of a value it has not seen yet --
        exactly what running the reversed order below would catch.
        """
        current_first = self._process(_duplicate_pair_table_html(_QUX_CURRENT_ROW_HTML, _QUX_OLD_ROW_HTML))
        legacy_first = self._process(_duplicate_pair_table_html(_QUX_OLD_ROW_HTML, _QUX_CURRENT_ROW_HTML))

        for label, enum in (('current-first', current_first), ('legacy-first', legacy_first)):
            self.assertEqual(len(enum), 2, f'[{label}] expected exactly 2 rendered members, got: {enum!r}')

            first_name = enum[0].splitlines()[-1].split(' = ', 1)[0].strip()
            second_name = enum[1].splitlines()[-1].split(' = ', 1)[0].strip()

            self.assertEqual(
                [first_name, second_name], ['QUX_CURRENT', 'QUX_OLD'],
                f'[{label}] the current member of a duplicated value must be '
                f'canonical regardless of table order; got {[first_name, second_name]!r}'
            )


#: A range row (``USER0``..``USER3``, values 900-903) whose notes mention
#: "legacy", followed by an unrelated plain row. The plain row is what makes
#: mis-sinking the range *observable* through ordering: if the range branch
#: shared the per-row ``sink`` the single-value branch computes, this single
#: row's wording would route all four expanded members through ``legacy``
#: at once, and they would come out *after* ``PLAIN_ROW`` instead of before
#: it (table order).
LEGACY_WORDED_RANGE_TABLE_HTML = """
<table class="linktypedlt">
<tr><th>header row, skipped by request()</th></tr>
<tr>
<td class="symbol">LINKTYPE_USER0</td>
<td class="number">900–903</td>
<td class="symbol">DLT_USER0</td>
<td>
Legacy user-defined range, retained for compatibility.
</td>
</tr>
<tr>
<td class="symbol">LINKTYPE_PLAIN_ROW</td>
<td class="number">999</td>
<td class="symbol">DLT_PLAIN_ROW</td>
<td>
An ordinary, unrelated link type.
</td>
</tr>
</table>
"""


@unittest.skipUnless(HAS_VENDOR_DEPS, 'requests, bs4 and/or html5lib not installed')
class LinkTypeGeneratorRangeSinkIsolationTests(unittest.TestCase):
    """Item 2 of GitHub issue #852: a range row must never sink its whole expansion.

    The ``ValueError`` branch that expands a ``USER0``-style range used to
    reuse the same per-row ``sink`` the single-value branch computed, so one
    range row whose notes mentioned "legacy" would have sunk every expanded
    member at once. :meth:`~pcapkit.vendor.reg.linktype.LinkType.process`
    now always appends range-expanded members straight into ``enum``,
    unconditionally, and this pins that deliberately.
    """

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_legacy_worded_range_row_still_lands_entirely_in_enum(self) -> None:
        import bs4

        from pcapkit.vendor.reg.linktype import LinkType

        soup = bs4.BeautifulSoup(LEGACY_WORDED_RANGE_TABLE_HTML, 'html5lib')
        rows = soup.select('table.linktypedlt tr')[1:]

        inst = object.__new__(LinkType)
        enum, _miss = inst.process(rows)

        self.assertEqual(len(enum), 5, f'expected 4 expanded USER0..USER3 members plus PLAIN_ROW, got: {enum!r}')

        names = [element.splitlines()[-1].split(' = ', 1)[0].strip() for element in enum]
        self.assertEqual(
            names, ['USER0', 'USER1', 'USER2', 'USER3', 'PLAIN_ROW'],
            f'a range row whose notes mention "legacy" must emit every expanded '
            f'member into `enum`, in table order, never sunk into `legacy` as a '
            f'block after a later row -- got {names!r}'
        )


#: A single-value legacy row for 900, followed by a range row that expands to
#: include 900 among its members (``USER0``..``USER3`` == 900-903). This is
#: the #852 cross-review's own repro: value 900 is a genuine duplicate, but
#: only because one of its two occurrences comes from a *range* expansion --
#: a duplicate-value pre-scan that counts only single-value rows never sees
#: it, so ``OLDUSER``'s "legacy" wording is silently ignored and the
#: deprecated name stays canonical for 900.
CROSS_RANGE_DUPLICATE_TABLE_HTML = """
<table class="linktypedlt">
<tr><th>header row, skipped by request()</th></tr>
<tr>
<td class="symbol">LINKTYPE_OLDUSER</td>
<td class="number">900</td>
<td class="symbol">DLT_OLDUSER</td>
<td>
Legacy name (do not use) for the range below.
</td>
</tr>
<tr>
<td class="symbol">LINKTYPE_USER0</td>
<td class="number">900–903</td>
<td class="symbol">DLT_USER0</td>
<td>
An ordinary user-defined range.
</td>
</tr>
</table>
"""


@unittest.skipUnless(HAS_VENDOR_DEPS, 'requests, bs4 and/or html5lib not installed')
class LinkTypeGeneratorCrossRangeDuplicateTests(unittest.TestCase):
    """The #852 cross-review's regression: a value duplicated *across* a range boundary.

    The first cut of the duplicate-value pre-scan built ``dup_values`` from
    only the single-value rows (filtering the notes column's number on
    ``str.isdigit()``), so a range row's expanded values never entered the
    count. A single-value row sharing one of *those* values -- ``900``,
    shared here with the first member of a ``USER0``..``USER3`` range
    covering 900-903 -- was therefore never recognised as a duplicate, and
    its correctly-worded "legacy" notes were silently ignored: it landed in
    ``enum`` instead of ``legacy``, ahead of the range it duplicates, making
    the deprecated ``OLDUSER`` canonical for value 900 instead of ``USER0``.
    That is exactly the failure mode #844 and #852 both exist to close,
    reopened by narrowing the predicate. :meth:`process`'s pre-scan now
    expands ``a–b`` ranges the same way the main loop does before counting,
    so this duplicate is caught regardless of which branch either occurrence
    comes from.
    """

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_legacy_row_duplicating_a_range_member_is_sunk(self) -> None:
        import bs4

        from pcapkit.vendor.reg.linktype import LinkType

        soup = bs4.BeautifulSoup(CROSS_RANGE_DUPLICATE_TABLE_HTML, 'html5lib')
        rows = soup.select('table.linktypedlt tr')[1:]

        inst = object.__new__(LinkType)
        enum, _miss = inst.process(rows)

        self.assertEqual(len(enum), 5, f'expected 4 expanded USER0..USER3 members plus OLDUSER, got: {enum!r}')

        names = [element.splitlines()[-1].split(' = ', 1)[0].strip() for element in enum]
        self.assertEqual(
            names, ['USER0', 'USER1', 'USER2', 'USER3', 'OLDUSER'],
            f'OLDUSER duplicates the range\'s own USER0 (both value 900) and is '
            f'correctly worded "legacy", so it must be sunk after the range -- '
            f'making USER0, not OLDUSER, canonical for value 900. Got {names!r}'
        )

    def test_malformed_en_dash_range_still_raises_loudly(self) -> None:
        """A malformed registry row must still fail loudly -- via the pre-existing main loop.

        A number column with more than one en dash (``900–903–905``) cannot
        ``start, stop = map(int, ...)`` -- too many values to unpack. The
        pre-scan's local ``_expand`` swallows exactly that ``ValueError`` and
        contributes no counted values for the row, quietly -- but that is
        *not* what makes this test pass. This is a regression guard on the
        main loop's own, pre-existing ``start, stop = map(int,
        temp.split('–'))``, which hits the identical unpack error a few
        lines later and still raises, uncaught, out of :meth:`process`.
        That statement predates #852 entirely, so this assertion passes
        identically on ``main``, on this PR's first commit (before
        ``_expand`` existed), and here: nothing about the pre-scan is what
        is being pinned.
        """
        import bs4

        from pcapkit.vendor.reg.linktype import LinkType

        html = """
<table class="linktypedlt">
<tr><th>header row, skipped by request()</th></tr>
<tr>
<td class="symbol">LINKTYPE_MALFORMED</td>
<td class="number">900–903–905</td>
<td class="symbol">DLT_MALFORMED</td>
<td>
A malformed range with two en dashes instead of one.
</td>
</tr>
</table>
"""
        soup = bs4.BeautifulSoup(html, 'html5lib')
        rows = soup.select('table.linktypedlt tr')[1:]

        inst = object.__new__(LinkType)
        with self.assertRaises(ValueError):
            inst.process(rows)


def _signed_or_underscored_duplicate_table_html(legacy_number: str, current_number: str) -> str:
    """A legacy/current duplicate pair whose shared value is spelled ``legacy_number``
    and ``current_number`` -- both parse to the same :func:`int`, but neither need be
    a plain unsigned decimal.
    """
    return f"""
<table class="linktypedlt">
<tr><th>header row, skipped by request()</th></tr>
<tr>
<td class="symbol">LINKTYPE_OLD</td>
<td class="number">{legacy_number}</td>
<td class="symbol">DLT_OLD</td>
<td>
Legacy name (do not use) for this link type.
</td>
</tr>
<tr>
<td class="symbol">LINKTYPE_CUR</td>
<td class="number">{current_number}</td>
<td class="symbol">DLT_CUR</td>
<td>
The current name for this link type.
</td>
</tr>
</table>
"""


@unittest.skipUnless(HAS_VENDOR_DEPS, 'requests, bs4 and/or html5lib not installed')
class LinkTypeGeneratorSignedOrUnderscoredValueTests(unittest.TestCase):
    """The second #852 cross-review's regression: ``_expand``'s recognition set was too narrow.

    The pre-scan's single-value branch tested ``str.isdigit()``, which is
    narrower than the main loop's own acceptance test, ``int(temp)`` --
    ``int()`` also accepts a leading sign (``+209``, ``-5``) and PEP 515
    underscore grouping (``2_09``). A value the main loop accepts but
    ``_expand`` does not is invisible to ``dup_values``, so a correctly
    "legacy"-worded row sharing that value silently stops being sunk -- the
    same class of under-count the range-expansion fix above closes, just for
    a different reason ``_expand`` can fail to recognise a value.

    Not reachable against tcpdump's live table today: every one of the 220
    committed members matches a plain unsigned decimal, so this is a latent
    hole rather than a live defect, exactly as #844 and #852's original
    word-only rule was. :meth:`process`'s ``_expand`` now tries ``int(temp)``
    directly, before the en-dash range check, so it recognises the same
    values the main loop does.
    """

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @staticmethod
    def _process(html: str) -> 'list[str]':
        import bs4

        from pcapkit.vendor.reg.linktype import LinkType

        soup = bs4.BeautifulSoup(html, 'html5lib')
        rows = soup.select('table.linktypedlt tr')[1:]

        inst = object.__new__(LinkType)
        enum, _miss = inst.process(rows)
        return enum

    def test_signed_value_pair_resolves_to_the_current_member(self) -> None:
        enum = self._process(_signed_or_underscored_duplicate_table_html('+750', '750'))

        self.assertEqual(len(enum), 2, f'expected exactly 2 rendered members, got: {enum!r}')
        names = [element.splitlines()[-1].split(' = ', 1)[0].strip() for element in enum]
        self.assertEqual(
            names, ['CUR', 'OLD'],
            f'a signed value ("+750") must still be recognised as a duplicate of '
            f'its unsigned twin ("750"), so OLD is sunk after CUR -- got {names!r}'
        )

    def test_underscored_value_pair_resolves_to_the_current_member(self) -> None:
        enum = self._process(_signed_or_underscored_duplicate_table_html('1_000', '1000'))

        self.assertEqual(len(enum), 2, f'expected exactly 2 rendered members, got: {enum!r}')
        names = [element.splitlines()[-1].split(' = ', 1)[0].strip() for element in enum]
        self.assertEqual(
            names, ['CUR', 'OLD'],
            f'an underscore-grouped value ("1_000") must still be recognised as a '
            f'duplicate of its plain twin ("1000"), so OLD is sunk after CUR -- '
            f'got {names!r}'
        )


if __name__ == '__main__':
    unittest.main()
