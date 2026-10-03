# -*- coding: utf-8 -*-
"""``EtherType(0x0101)`` must resolve to Old Xerox, not IEEE802.3 Length Field.

GitHub issue #862: :meth:`pcapkit.const.reg.ethertype.EtherType._missing_` tested
``0x0000 <= value <= 0x05DC`` (IEEE802.3 Length Field) *before*
``0x0101 <= value <= 0x01FF`` (Old Xerox Experimental values). The second range is
wholly contained in the first, and the generated ``_missing_`` returns on the
first matching ``if``, so the Old Xerox branch was unreachable for every value
it covers -- ``EtherType(0x0101).name`` resolved to
``'IEEE802_3_Length_Field_0x0101'`` instead of the Old Xerox name.

Same shape as #844/#852 (``LinkType`` 209) and #841 (IPX socket ranges): the
generated order follows the source table's own row order, and IANA's
``ieee-802-numbers-1.csv`` lists the wide IEEE802.3 range (row 2) ahead of the
narrower Old Xerox range (row 3) that it wholly contains.

Unlike #841's IPX socket table, the range bounds here are not literals in the
crawler -- :mod:`pcapkit.vendor.reg.ethertype` fetches the live IANA CSV on
every regeneration, so there is no local data table to hand-reorder. The fix
is therefore general rather than a special case for these two constants:
:meth:`~pcapkit.vendor.reg.ethertype.EtherType.process` now collects every
range row's ``(start, stop, body)`` before rendering, and
:meth:`~pcapkit.vendor.reg.ethertype.EtherType._insert_range` places each new
range immediately ahead of the first already-placed range that fully contains
it, leaving every non-overlapping pair in the CSV's own row order. Sweeping
all 56 range tests in the committed, generated file (measured directly against
``main`` at ``70fa92010``, the #861 merge commit this issue was blocked on)
found this to be the *only* containment pair among them -- no other subsumed
range exists in :class:`~pcapkit.const.reg.ethertype.EtherType` today, so
:class:`EtherTypeGeneratorGeneralOrderingTests` below pins the algorithm
itself against synthetic nested ranges rather than a second real-world pair.

This module pins both the symptom and the root cause:

- :class:`EtherType862ConstResolutionTests` -- against the committed, generated
  :class:`pcapkit.const.reg.ethertype.EtherType`, the same lookup the issue
  reported, plus the neighbouring values the fix must leave alone.
- :class:`EtherTypeGeneratorRangeOrderingTests` -- against
  :meth:`~pcapkit.vendor.reg.ethertype.EtherType.process` directly, fed a CSV
  fixture reproducing IANA's own rows for these two ranges plus one unrelated,
  non-overlapping range, byte-for-byte (captured from a live fetch of
  ``https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers-1.csv``
  on 2026-09-27). Needs no network: the fixture *is* the table rows, not a
  fetch of them, so this stays reliable in CI while still exercising the exact
  code path a real crawl runs. A regeneration that drops the fix reintroduces
  the wrong order here before it ever reaches the committed const file.
- :class:`EtherTypeGeneratorGeneralOrderingTests` -- pins
  :meth:`~pcapkit.vendor.reg.ethertype.EtherType._insert_range` itself against
  three synthetic nested ranges, so the ordering rule is proven general rather
  than only verified against the one pair #862 happened to report.

"""
from __future__ import annotations

import unittest

from tests._support import purge_modules

#: CSV fixture reproducing IANA's own rows for the #862 pair plus one
#: unrelated, non-overlapping range, byte-for-byte (captured from a live fetch
#: of ``https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers-1.csv``
#: on 2026-09-27). Row order matches the live table: the wide IEEE802.3 range
#: first, the narrower Old Xerox range it contains second, then the
#: unrelated Xyplex range -- exactly the order that reproduces the defect
#: against unfixed code.
ETHERTYPE_862_FIXTURE_CSV = [
    'Ethertype (decimal),Ethertype (hex),Exp. Ethernet (decimal),Exp. Ethernet (octal),Description,Reference',
    '0000-1500,0000-05DC,-,-,IEEE802.3 Length Field,[IEEE Std 802.3]',
    '0257-0511,0101-01FF,-,-,Old Xerox Experimental values. Invalid as an Ethertype since 1983.,[Neil_Sembower]',
    '2184-2186,0888-088A,-,-,Xyplex,[Neil_Sembower]',
]


class EtherType862ConstResolutionTests(unittest.TestCase):
    """Against the generated, committed :class:`~pcapkit.const.reg.ethertype.EtherType`."""

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_value_0x0101_resolves_to_old_xerox_name(self) -> None:
        from pcapkit.const.reg.ethertype import EtherType

        self.assertEqual(
            EtherType(0x0101).name,
            'Old_Xerox_Experimental_values_Invalid_as_an_Ethertype_since_1983',
            "EtherType(0x0101).name resolved to the IEEE802.3 Length Field "
            "name instead of the Old Xerox one; see GitHub issue #862",
        )

    def test_value_0x01ff_the_top_of_the_range_also_resolves_to_old_xerox(self) -> None:
        from pcapkit.const.reg.ethertype import EtherType

        self.assertEqual(
            EtherType(0x01FF).name,
            'Old_Xerox_Experimental_values_Invalid_as_an_Ethertype_since_1983',
        )

    def test_ieee_802_3_values_outside_the_old_xerox_range_are_unaffected(self) -> None:
        # Nothing else in the IEEE802.3 range moved: values below, and above,
        # the Old Xerox sub-range still resolve to IEEE802.3 Length Field.
        from pcapkit.const.reg.ethertype import EtherType

        for value in (0x0000, 0x0050, 0x0300, 0x05DC):
            with self.subTest(value=hex(value)):
                self.assertEqual(
                    EtherType(value).name,
                    'IEEE802_3_Length_Field_0x%04X' % value,
                )

    def test_xerox_ns_idp_a_directly_defined_member_is_unaffected(self) -> None:
        # 0x0600 is a real, directly-defined enum member (not a _missing_
        # range at all); the reordering must not disturb ordinary lookups.
        from pcapkit.const.reg.ethertype import EtherType

        self.assertEqual(EtherType(0x0600).name, 'XEROX_NS_IDP')


class EtherTypeGeneratorRangeOrderingTests(unittest.TestCase):
    """Against the generator's own ``process()``, root cause rather than symptom."""

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    @staticmethod
    def _process_fixture() -> 'tuple[list[str], list[str]]':
        """Run :meth:`EtherType.process` over the #862 fixture rows.

        Builds the instance with ``object.__new__`` rather than calling
        ``EtherType()`` directly: the real constructor
        (:meth:`pcapkit.vendor.default.Vendor.__init__`) fetches the live
        registry and writes the generated const file as a side effect, and
        this test needs neither -- only the pure :meth:`process` step that
        turns registry rows into rendered ``_missing_`` branches.
        """
        from pcapkit.vendor.reg.ethertype import EtherType

        inst = object.__new__(EtherType)
        enum, miss = inst.process(ETHERTYPE_862_FIXTURE_CSV)
        return enum, miss

    def test_old_xerox_range_is_emitted_before_ieee_802_3(self) -> None:
        _enum, miss = self._process_fixture()
        text = '\n'.join(miss)

        xerox_pos = text.index('if 0x0101 <= value <= 0x01FF:')
        ieee_pos = text.index('if 0x0000 <= value <= 0x05DC:')

        self.assertLess(
            xerox_pos, ieee_pos,
            f'the narrower Old Xerox range must be tested before the wider '
            f'IEEE802.3 range that contains it, or it is never reached -- '
            f'see GitHub issue #862; rendered miss block:\n{text}'
        )

    def test_unrelated_non_overlapping_range_keeps_table_order(self) -> None:
        # Xyplex neither contains nor is contained by either #862 range, so
        # reordering the #862 pair must not move it: it stays after both,
        # exactly the CSV's own row order.
        _enum, miss = self._process_fixture()
        text = '\n'.join(miss)

        ieee_pos = text.index('if 0x0000 <= value <= 0x05DC:')
        xyplex_pos = text.index('if 0x0888 <= value <= 0x088A:')

        self.assertLess(ieee_pos, xyplex_pos)

    def test_both_ranges_still_render_with_their_own_body(self) -> None:
        # Reordering must not lose either range or swap their bodies.
        #
        # NOTE: the second assertion used to check for the ``extend_enum``
        # form ("IEEE802.3 Length Field" was one of the ranges GitHub issue
        # #775's original ruling left minting). #775's final round converts
        # every remaining range branch on this crawler -- see
        # tests/const/test_const_enum_no_mint.py's own docstring -- so this
        # now checks for the ``_unregistered_member`` form instead, keeping
        # the hex-suffixed name exactly as before; only the registration
        # mechanism changed, because PR #878 scoped the change as not
        # registering rather than renaming.
        _enum, miss = self._process_fixture()
        text = '\n'.join(miss)

        self.assertIn(
            "return cls._unregistered_member(value, "
            "'Old_Xerox_Experimental_values_Invalid_as_an_Ethertype_since_1983')",
            text,
        )
        self.assertIn(
            "return cls._unregistered_member(value, 'IEEE802_3_Length_Field_0x%s' "
            "% hex(value)[2:].upper().zfill(4))",
            text,
        )
        self.assertNotIn('extend_enum', text)


class EtherTypeGeneratorGeneralOrderingTests(unittest.TestCase):
    """Pins :meth:`~pcapkit.vendor.reg.ethertype.EtherType._insert_range` itself.

    #862's own pair is the only containment among the 56 ranges in today's
    committed file, so this exercises the general rule -- narrower range
    before any wider range that contains it -- against synthetic nested
    ranges the live registry does not (yet) happen to contain.
    """

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_nested_ranges_are_ordered_narrowest_first(self) -> None:
        """Regression pin against two specific wrong implementations of
        "insert ahead of a containing range" -- not a general correctness
        proof for arbitrary nesting depth or arrival order. That exhaustive
        proof (every arrival order at 3 and 4 levels, plus randomised
        fuzzing) was done separately in the review of PR #865, #862's fix,
        and does not live in this repository as a test; this method only
        pins the two specific shortcuts that review considered and rejected.

        Against these three nested ranges (OUTER contains MIDDLE contains
        INNER), the correct result is always ``[INNER, MIDDLE, OUTER]``, but
        no *single* arrival order of the six possible ones catches both of
        the following wrong implementations at once -- verified by running
        both against the real :meth:`~pcapkit.vendor.reg.ethertype.EtherType.
        _insert_range` across all six orderings:

        * ``naiveA`` -- "insert at index 0 whenever contained by anything" --
          diverges from the real result only on arrival orders ``INNER,
          OUTER, MIDDLE`` and ``OUTER, INNER, MIDDLE`` (both produce
          ``[MIDDLE, INNER, OUTER]`` instead).
        * ``naiveB`` -- "insert immediately before the *last* containing
          range" -- diverges only on ``OUTER, MIDDLE, INNER`` and ``MIDDLE,
          OUTER, INNER`` (both produce ``[MIDDLE, INNER, OUTER]`` instead).
        * The other two orderings, ``MIDDLE, INNER, OUTER`` and ``INNER,
          MIDDLE, OUTER``, catch neither -- all three implementations agree
          on them, so they are not exercised below.

        So this test drives two orders, one representative of each
        discriminating pair, rather than one order claimed (wrongly, in an
        earlier revision) to catch both.
        """
        from pcapkit.vendor.reg.ethertype import EtherType

        outer = (0x0000, 0xFFFF, ['OUTER'])
        middle = (0x1000, 0x2000, ['MIDDLE'])
        inner = (0x1500, 0x1600, ['INNER'])

        orderings = (
            ('INNER, OUTER, MIDDLE -- catches the naiveA "insert at front" mistake', (inner, outer, middle)),
            ('OUTER, MIDDLE, INNER -- catches the naiveB "insert before the last container" mistake', (outer, middle, inner)),
        )
        for label, order in orderings:
            with self.subTest(order=label):
                ranges = []  # type: list[tuple[int, int, list[str]]]
                for entry in order:
                    EtherType._insert_range(ranges, entry)

                self.assertEqual(
                    [block[0] for _, _, block in ranges],
                    ['INNER', 'MIDDLE', 'OUTER'],
                )

    def test_disjoint_ranges_keep_insertion_order(self) -> None:
        from pcapkit.vendor.reg.ethertype import EtherType

        ranges = []  # type: list[tuple[int, int, list[str]]]
        EtherType._insert_range(ranges, (0x0000, 0x00FF, ['FIRST']))
        EtherType._insert_range(ranges, (0x0200, 0x02FF, ['SECOND']))
        EtherType._insert_range(ranges, (0x0400, 0x04FF, ['THIRD']))

        self.assertEqual(
            [block[0] for _, _, block in ranges],
            ['FIRST', 'SECOND', 'THIRD'],
        )


if __name__ == '__main__':
    unittest.main()
