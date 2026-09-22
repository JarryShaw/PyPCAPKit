"""``pre_process``'s width repair sized values with floor division.

GitHub issue #599. When a :class:`~pcapkit.corekit.fields.numbers.NumberField`
is packed while ``length`` is still the ``-1`` placeholder, ``pre_process``
derives a width from the value itself. It derived it with::

    self._length = math.ceil(value.bit_length() // 8)

:func:`math.ceil` on an :obj:`int` is a no-op -- ``//`` has already floored it --
so the expression was plain floor division and the width came out one octet short
for every value whose bit length is *not* an exact multiple of eight. The
intended expression is ``math.ceil(value.bit_length() / 8)``.

Two things about this suite are deliberate.

**The boundaries are tested one method each, not one parametrised sweep.** The
defect is a pattern rather than an instance -- it fails at *every* octet boundary
-- so a single case would pass against a fix that special-cased the reported
width. Standalone methods also keep each failure individually visible: the
pytest in use has no ``pytest-subtests``, so a failing :meth:`~unittest.TestCase
.subTest` still leaves its parent reported as passed.

**Each boundary is asserted as a pair.** The value *below* the boundary already
packed correctly before the fix and must go on doing so; only the value *above*
it was broken. Asserting the pair is what distinguishes a fix from a width that
has merely been shifted by one in the other direction.

The failure was not a single exception type, and this suite deliberately does not
assert one. Since #591's fix, ``_need_process`` is recomputed from the width in
force, so a mis-sized width that lands on 1, 2 or 4 octets now comes back from
:func:`struct.pack` as ``struct.error: 'B' format requires 0 <= number <= 255``
while a mis-sized 3 octets still comes back from :meth:`int.to_bytes` as
``OverflowError: int too big to convert``. What these tests pin instead is the
width and the octets -- the thing that is actually wrong.
"""

from __future__ import annotations

import importlib.util
import math
import unittest

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: The reported table, as ``(value, octets the value needs)``. The first of each
#: pair sits on an octet boundary and packed correctly before the fix; the second
#: is one past it and did not.
BOUNDARY_PAIRS = (
    (255, 1, 256, 2),
    (65535, 2, 65536, 3),
    (16777215, 3, 16777216, 4),
)


def _unresolved_field(**kwargs: 'object'):
    """A field that reaches the repair, built the only way that does.

    ``_length`` is ``-1`` only while a callable ``length`` is unresolved, and the
    repair additionally needs ``_need_process``, which ``__init__`` raises for the
    ``-1`` placeholder only when no ``__template__`` fixes the format. So a bare
    :class:`~pcapkit.corekit.fields.numbers.NumberField` given a callable and
    **not** called is what gets there. Calling it resolves the width and the
    repair never runs -- see
    :meth:`WidthRepairReachabilityTests.test_resolving_the_field_bypasses_the_repair_entirely`.

    """
    from pcapkit.corekit.fields.numbers import NumberField

    return NumberField(length=lambda pkt: 8, **kwargs)  # type: ignore[arg-type]


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class WidthRepairBoundaryTests(unittest.TestCase):
    """One method per octet boundary, each asserting the pair across it."""

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_the_one_octet_boundary_needs_two_octets_past_255(self) -> None:
        """``255`` fits one octet; ``256`` needs two and was given one.

        ``255`` has a bit length of 8 and ``8 // 8`` is 1, so it was sized
        correctly by luck. ``256`` has a bit length of 9 and ``9 // 8`` is also 1,
        which is one octet short of what it needs.

        """
        below = _unresolved_field()
        self.assertEqual(below.pack(255, dict()), b'\xff')
        self.assertEqual(below._length, 1)

        above = _unresolved_field()
        self.assertEqual(above.pack(256, dict()), b'\x01\x00')
        self.assertEqual(above._length, 2,
                         '256 needs two octets; floor division sized it at one')

    def test_the_two_octet_boundary_needs_three_octets_past_65535(self) -> None:
        """``65535`` fits two octets; ``65536`` needs three and was given two.

        Bit lengths 16 and 17, floored to 2 and 2. The second is wrong.

        """
        below = _unresolved_field()
        self.assertEqual(below.pack(65535, dict()), b'\xff\xff')
        self.assertEqual(below._length, 2)

        above = _unresolved_field()
        self.assertEqual(above.pack(65536, dict()), b'\x01\x00\x00')
        self.assertEqual(above._length, 3,
                         '65536 needs three octets; floor division sized it at two')

    def test_the_three_octet_boundary_needs_four_octets_past_16777215(self) -> None:
        """``16777215`` fits three octets; ``16777216`` needs four and was given three.

        Bit lengths 24 and 25, floored to 3 and 3. This crossing is the one that
        still surfaced as ``OverflowError`` from :meth:`int.to_bytes` after #591,
        because 3 octets has no native :func:`struct` integer code and so is
        genuinely byte-packed.

        """
        below = _unresolved_field()
        self.assertEqual(below.pack(16777215, dict()), b'\xff\xff\xff')
        self.assertEqual(below._length, 3)

        above = _unresolved_field()
        self.assertEqual(above.pack(16777216, dict()), b'\x01\x00\x00\x00')
        self.assertEqual(above._length, 4,
                         '16777216 needs four octets; floor division sized it at three')

    def test_every_octet_boundary_up_to_eight_is_sized_correctly(self) -> None:
        """The pattern, rather than the three instances above.

        For each ``n``, ``(1 << 8n) - 1`` is the largest value fitting ``n``
        octets and ``1 << 8n`` is the smallest needing ``n + 1``. Floor division
        sized both at ``n``. Swept to eight octets so the fix cannot be a table of
        the reported cases.

        """
        for n in range(1, 9):
            largest_fitting, smallest_past = (1 << (8 * n)) - 1, 1 << (8 * n)

            with self.subTest(octets=n, value=largest_fitting):
                field = _unresolved_field()
                self.assertEqual(field.pack(largest_fitting, dict()),
                                 largest_fitting.to_bytes(n, 'big'))
                self.assertEqual(field._length, n)

            with self.subTest(octets=n + 1, value=smallest_past):
                field = _unresolved_field()
                self.assertEqual(field.pack(smallest_past, dict()),
                                 smallest_past.to_bytes(n + 1, 'big'))
                self.assertEqual(field._length, n + 1)

    def test_the_smallest_mis_sized_value_is_one_not_two_hundred_and_fifty_six(self) -> None:
        """The issue understates the reach, and this is where it shows.

        #599 frames the defect as hitting values "just past an octet boundary",
        which reads as though small values were safe. They were not: floor
        division is wrong for *every* bit length that is not a multiple of eight,
        so ``1`` -- bit length 1, floored to **zero** octets -- was mis-sized
        too, and every value from 1 to 127 with it. Measured on the unfixed tree,
        ``pack(1, {})`` raised ``OverflowError: int too big to convert`` against a
        zero-octet width.

        """
        for value in (1, 2, 42, 127):
            with self.subTest(value=value):
                field = _unresolved_field()
                self.assertEqual(field.pack(value, dict()), bytes([value]))
                self.assertEqual(field._length, 1,
                                 f'{value} needs one octet; floor division sized it at zero')

    def test_the_repaired_width_is_the_ceiling_of_the_bit_length_over_eight(self) -> None:
        """The invariant the fix establishes, stated as such.

        Every width the repair picks is ``ceil(bit_length / 8)``. Holding it over
        a spread that straddles several boundaries is what makes the property the
        subject of the test rather than the sample.

        """
        values = (1, 2, 127, 128, 255, 256, 257, 4095, 65535, 65536,
                  16777215, 16777216, 1 << 40, (1 << 64) - 1, 1 << 64)

        for value in values:
            expected = math.ceil(value.bit_length() / 8)
            with self.subTest(value=value, expected_octets=expected):
                field = _unresolved_field()

                self.assertEqual(field.pack(value, dict()), value.to_bytes(expected, 'big'))
                self.assertEqual(field._length, expected)

    def test_a_bit_length_that_is_a_multiple_of_eight_is_untouched_by_the_fix(self) -> None:
        """The control, and the reason this survived #591's test suite.

        Floor division and the ceiling agree exactly when the bit length divides
        by eight. Every value #591's own repair-path test used --  ``0xFF``,
        ``0xFFFF``, ``0xFFFFFFFF``, ``0xFFFFFFFFFFFFFFFF``, ``0x800001`` -- has a
        bit length of 8, 16, 32, 64 or 24, so all five sat precisely on the
        agreement and the defect stayed invisible. They must keep packing
        identically.

        """
        for value in (0xFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x800001):
            octets = value.bit_length() // 8
            with self.subTest(value=hex(value)):
                field = _unresolved_field()

                self.assertEqual(field.pack(value, dict()), value.to_bytes(octets, 'big'))
                self.assertEqual(field._length, octets)

    def test_a_repaired_field_can_read_back_what_it_wrote(self) -> None:
        """A width that is one octet short truncates as well as raising.

        The repair rewrites ``_template`` too, so it decides what
        :meth:`~pcapkit.corekit.fields.field.FieldBase.unpack` will read. Packing
        and unpacking through the same repaired field is what shows the width is
        right rather than merely large enough not to raise.

        """
        for value in (256, 65536, 16777216, 1 << 40):
            with self.subTest(value=value):
                field = _unresolved_field()

                buffer = field.pack(value, dict())
                self.assertEqual(len(buffer), math.ceil(value.bit_length() / 8))
                self.assertEqual(field.unpack(buffer, dict()), value)

    def test_math_ceil_of_a_floor_division_is_the_floor_division(self) -> None:
        """The root cause, pinned directly rather than only described.

        The old expression *looked* like a ceiling and was not one. Stating that
        as an assertion keeps the next reader of ``pre_process`` from
        reintroducing it: the two expressions differ for seven of every eight bit
        lengths, and coincide only on the eighth.

        """
        differing = [n for n in range(1, 65)
                     if math.ceil(n // 8) != math.ceil(n / 8)]

        self.assertEqual(differing, [n for n in range(1, 65) if n % 8],
                         'math.ceil(n // 8) is n // 8, so it differs from the real '
                         'ceiling for every n that is not a multiple of 8')
        self.assertEqual(math.ceil(9 // 8), 1)
        self.assertEqual(math.ceil(9 / 8), 2)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class WidthRepairReachabilityTests(unittest.TestCase):
    """How a caller gets to the repair at all, which bounds what this fix touches."""

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_resolving_the_field_bypasses_the_repair_entirely(self) -> None:
        """The repair is a net under the *unresolved* field, nothing more.

        ``__call__`` assigns the callable's width to ``_length``, so a resolved
        field never satisfies ``_length < 0`` and packs through the ordinary path
        at the width it was told -- zero-padded, not shrunk to fit the value. The
        schema packer resolves every field before packing it, which is why this
        path is reached through the field-level API rather than through a
        protocol.

        """
        resolved = _unresolved_field()(dict())

        self.assertEqual(resolved._length, 8)
        self.assertIs(resolved._need_process, False)
        self.assertEqual(resolved.pack(256, dict()), (256).to_bytes(8, 'big'))

    def test_an_unresolved_field_is_what_satisfies_the_guard(self) -> None:
        """Both halves of ``if self._need_process and self._length < 0``.

        Stated explicitly so that a later change which stops the placeholder
        reaching here shows up as this test failing rather than as the boundary
        tests passing vacuously.

        """
        field = _unresolved_field()

        self.assertEqual(field._length, -1)
        self.assertIs(field._need_process, True)

    def test_an_enum_field_is_affected_identically(self) -> None:
        """:class:`~pcapkit.corekit.fields.numbers.EnumField` leaves ``__template__`` unset.

        Which is the condition for ``__init__`` to call ``build_template`` on the
        placeholder and so raise ``_need_process`` -- the same reason #591 hit
        ``EnumField`` too. The ``Int``/``UInt`` subclasses fix ``__template__``,
        keep ``_need_process`` false, and never reach the repair.

        """
        from pcapkit.corekit.fields.numbers import EnumField, UInt32Field

        affected = EnumField(length=lambda pkt: 8)
        self.assertIs(affected._need_process, True)
        self.assertEqual(affected.pack(256, dict()), b'\x01\x00')
        self.assertEqual(affected._length, 2)

        unaffected = UInt32Field(length=lambda pkt: 8)
        self.assertIs(unaffected._need_process, False)
        self.assertEqual(unaffected._length, -1)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class WidthRepairSurroundingContractTests(unittest.TestCase):
    """The rest of the field's contract that the repair leans on.

    Each case here pins a statement or branch of ``numbers.py`` that the repair
    depends on and that nothing reached before, which is why they live with the
    #599 suite rather than apart from it.
    """

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_a_field_with_no_length_at_all_is_refused_outright(self) -> None:
        """Ruling out the other way the placeholder might have been thought to arise.

        ``-1`` is assigned in exactly one place -- where a non-integer ``length``
        is swapped for a placeholder and stashed as a callback -- so a field
        *omitting* ``length`` never becomes an unresolved one. It is refused at
        construction with the library's own ``IntError``, which is what bounds the
        repair's reachability to a callable that was never resolved.

        """
        from pcapkit.corekit.fields.numbers import NumberField
        from pcapkit.utilities.exceptions import IntError

        with self.assertRaises(IntError):
            NumberField()

        # ... whereas a subclass fixing ``__length__`` supplies its own default.
        from pcapkit.corekit.fields.numbers import UInt16Field

        self.assertEqual(UInt16Field()._length, 2)

    def test_an_explicit_bit_length_survives_resolution(self) -> None:
        """The branch that decides whether the mask is derived or kept.

        ``__call__`` derives ``_bit_length`` from the octet width only when it was
        not given one. A field told its bit length keeps it, mask included, which
        is the case that makes the masking in ``pre_process`` meaningful at all --
        an unresolved field's mask is ``-1`` and masks nothing.

        """
        from pcapkit.corekit.fields.numbers import NumberField

        narrow = NumberField(length=2, bit_length=12)
        self.assertEqual(narrow.bit_length, 12)
        self.assertEqual(narrow._bit_mask, 0xFFF)

        resolved = narrow(dict())
        self.assertEqual(resolved.bit_length, 12, 'a given bit length must not be overwritten')
        self.assertEqual(resolved._bit_mask, 0xFFF)
        self.assertEqual(resolved.pack(0xABCD, dict()), b'\x0b\xcd',
                         'the value is truncated to 12 bits, not to 16')

        derived = NumberField(length=2)(dict())
        self.assertEqual(derived.bit_length, 16)
        self.assertEqual(derived._bit_mask, 0xFFFF)

    def test_a_repaired_enum_field_reads_back_a_namespaced_member(self) -> None:
        """The repair decides the template ``unpack`` then reads through.

        So an :class:`~pcapkit.corekit.fields.numbers.EnumField` sized by the
        repair has to round-trip into its namespace, and into the synthetic
        ``<unknown>`` member when it has none. Both directions of that are
        exercised at a width -- two octets for ``256`` -- that the repair only
        produces once the ceiling is a ceiling.

        """
        import enum

        from pcapkit.corekit.fields.numbers import EnumField

        class Width(enum.IntEnum):
            TWO_OCTETS = 256

        namespaced = EnumField(length=lambda pkt: 8, namespace=Width)
        buffer = namespaced.pack(256, dict())
        self.assertEqual(buffer, b'\x01\x00')
        self.assertIs(namespaced.unpack(buffer, dict()), Width.TWO_OCTETS)

        anonymous = EnumField(length=lambda pkt: 8)
        buffer = anonymous.pack(256, dict())
        self.assertEqual(buffer, b'\x01\x00')

        unknown = anonymous.unpack(buffer, dict())
        self.assertEqual(int(unknown), 256)
        self.assertEqual(unknown.name, '<unassigned>')


if __name__ == '__main__':
    unittest.main()
