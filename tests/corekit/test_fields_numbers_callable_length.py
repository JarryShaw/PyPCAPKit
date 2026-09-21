"""A :class:`~pcapkit.corekit.fields.numbers.NumberField` whose ``length`` is a callable.

GitHub issue #591. ``_need_process`` used to be a *latch*: ``build_template``
raised it :data:`True` in its fall-through branch and nothing ever put it back.
A callable ``length`` is a placeholder of ``-1`` until
:meth:`~pcapkit.corekit.fields.numbers.NumberField.__call__` resolves it, ``-1``
takes that fall-through branch, and the flag then outlived the very rebuild that
installed the real width. ``pre_process`` consequently handed :obj:`bytes` to a
template that had become ``>Q``, and :func:`struct.pack` refused it with
``required argument is not an integer``.

Every test here is written as a **comparison against the same width supplied
statically**, because that is what makes the defect legible: the resolved length
and the struct template are identical either way, so the only difference left is
how the length arrived. A test that merely asserted ``pack`` succeeds would pass
on a fix that quietly changed the encoding.
"""

from __future__ import annotations

import importlib.util
import struct
import unittest

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: Widths :func:`struct` has a native integer code for, paired with the
#: unsigned and signed format characters they build. These are the widths the
#: defect hit, and -- established by :meth:`CallableLengthTests
#: .test_every_native_width_was_affected_not_only_the_reported_eight` rather
#: than assumed -- *all four* were hit, not only the 8 that #591 reproduces.
NATIVE_WIDTHS = {1: ('B', 'b'), 2: ('H', 'h'), 4: ('I', 'i'), 8: ('Q', 'q')}

#: Widths with no native :func:`struct` integer code, which therefore
#: legitimately still need byte packing. ``build_template`` takes the same
#: fall-through branch for these as it does for the ``-1`` placeholder, which is
#: why clearing the flag unconditionally would have been the wrong fix.
BYTE_PACKED_WIDTHS = (3, 5, 6, 7, 9, 16)


def _high_bit_value(width: 'int') -> 'int':
    """A value whose top bit is set, so silent truncation cannot hide."""
    return (1 << (width * 8 - 1)) | 1


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class CallableLengthTests(unittest.TestCase):
    """The reported defect, and the widths either side of it."""

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_the_reported_case_a_callable_resolving_to_eight_packs(self) -> None:
        """``NumberField(length=lambda pkt: 8)`` could not pack at all.

        The reproduction in #591 verbatim: ``_make_mptcp_dss(DSS, ack=1 << 40)``
        raised ``struct.error: required argument is not an integer`` because
        this field did.

        """
        from pcapkit.corekit.fields.numbers import NumberField

        field = NumberField(length=lambda pkt: 8)(dict())

        self.assertEqual(field._length, 8)
        self.assertEqual(field.template, '>Q')
        self.assertIs(field._need_process, False,
                      'the -1 placeholder latched _need_process and #591 is back')
        self.assertEqual(field.pack(1 << 40, dict()).hex(), '0000010000000000')

    def test_a_callable_length_packs_exactly_as_the_same_static_length_does(self) -> None:
        """The comparison that is the whole proof.

        Identical resolved length, identical template; the *only* difference is
        whether ``length`` arrived as an :obj:`int` or as a callable returning
        that same :obj:`int`. Before the fix the static column packed and the
        callable column raised, for all four native widths.

        """
        from pcapkit.corekit.fields.numbers import NumberField

        for width in (*NATIVE_WIDTHS, *BYTE_PACKED_WIDTHS):
            value = _high_bit_value(width)
            with self.subTest(width=width):
                dynamic = NumberField(length=lambda pkt, w=width: w)(dict())
                static = NumberField(length=width)(dict())

                self.assertEqual(dynamic._length, static._length)
                self.assertEqual(dynamic.template, static.template)
                self.assertIs(dynamic._need_process, static._need_process)
                self.assertEqual(dynamic.pack(value, dict()), static.pack(value, dict()))

    def test_every_native_width_was_affected_not_only_the_reported_eight(self) -> None:
        """#591 left this open; it is established here rather than assumed.

        The issue reproduces the 8-octet case only and says explicitly that
        whether ``1``/``2``/``4`` are equally affected was not checked. They
        are: the latch has nothing to do with the width it latches *into*, so a
        callable resolving to 1, 2 or 4 failed with the same
        ``required argument is not an integer`` as one resolving to 8. Pinned
        per width so a fix that only repaired the reported one fails here.

        """
        from pcapkit.corekit.fields.numbers import NumberField

        for width, (unsigned_fmt, signed_fmt) in NATIVE_WIDTHS.items():
            for signed, fmt in ((False, unsigned_fmt), (True, signed_fmt)):
                with self.subTest(width=width, signed=signed):
                    field = NumberField(length=lambda pkt, w=width: w, signed=signed)(dict())

                    self.assertEqual(field.template, f'>{fmt}')
                    self.assertIs(field._need_process, False)

                    value = -1 if signed else _high_bit_value(width)
                    self.assertEqual(field.pack(value, dict()),
                                     struct.pack(f'>{fmt}', value))

    def test_a_callable_resolving_to_a_byte_packed_width_still_needs_processing(self) -> None:
        """The subtlety that makes this more than a one-line fix.

        ``build_template`` takes the same fall-through branch for any width
        outside ``{1, 2, 4, 8}`` as it does for the ``-1`` placeholder. So
        clearing the flag whenever a callable is resolved -- rather than
        recomputing it from the width now in force -- would have broken every
        one of these, which genuinely do need :meth:`int.to_bytes`.

        """
        from pcapkit.corekit.fields.numbers import NumberField

        for width in BYTE_PACKED_WIDTHS:
            value = _high_bit_value(width)
            with self.subTest(width=width):
                field = NumberField(length=lambda pkt, w=width: w)(dict())

                self.assertEqual(field.template, f'>{width}s')
                self.assertIs(field._need_process, True,
                              f'width {width} has no native struct code and must be '
                              f'byte-packed')
                self.assertEqual(field.pack(value, dict()),
                                 value.to_bytes(width, 'big'))

    def test_the_flag_always_agrees_with_the_template(self) -> None:
        """The invariant the fix establishes, stated directly.

        ``_need_process`` says "this template wants :obj:`bytes`", which is true
        exactly when the template is an ``s`` format. Holding that for every
        width, reached both ways, is what stops the two drifting apart again --
        by any route, not just the one #591 came in through.

        """
        from pcapkit.corekit.fields.numbers import NumberField

        for width in range(1, 17):
            for supply in ('static', 'callable'):
                with self.subTest(width=width, supply=supply):
                    length = width if supply == 'static' else (lambda pkt, w=width: w)
                    field = NumberField(length=length)(dict())

                    self.assertIs(field._need_process, field.template.endswith('s'),
                                  f'template {field.template} and '
                                  f'_need_process={field._need_process} disagree')

    def test_the_placeholder_itself_still_needs_processing(self) -> None:
        """The flag is recomputed, not blanket-cleared.

        While ``length`` is still the ``-1`` placeholder there is no width to
        pack to, so :data:`True` is the correct answer for it -- and it is the
        answer the unresolved field keeps. What changed is that the answer is
        no longer *sticky*.

        """
        from pcapkit.corekit.fields.numbers import NumberField

        field = NumberField(length=lambda pkt: 8)  # deliberately not resolved

        self.assertEqual(field._length, -1)
        self.assertIs(field._need_process, True)

    def test_an_unresolved_field_repairs_its_length_and_honours_the_new_template(self) -> None:
        """``pre_process``'s ``_length < 0`` safety net, kept consistent.

        A field packed without having been resolved falls into the repair at
        ``numbers.py``, which recomputes the length from the value and rebuilds
        the template. That rebuild can land on a native width, and before the
        fix the method went on to return :obj:`bytes` anyway -- the same
        mismatch as #591, one branch further down. Widths with no native code
        still come back as :obj:`bytes`.

        """
        from pcapkit.corekit.fields.numbers import NumberField

        for value, width, fmt in ((0xFF, 1, '>B'), (0xFFFF, 2, '>H'),
                                  (0xFFFFFFFF, 4, '>I'), (0xFFFFFFFFFFFFFFFF, 8, '>Q'),
                                  (0x800001, 3, '>3s')):
            with self.subTest(value=hex(value)):
                field = NumberField(length=lambda pkt: 8)  # deliberately not resolved

                self.assertEqual(field.pack(value, dict()), value.to_bytes(width, 'big'))
                self.assertEqual(field._length, width)
                self.assertEqual(field.template, fmt)
                self.assertIs(field._need_process, fmt.endswith('s'))

    def test_a_callable_length_roundtrips_through_pack_and_unpack(self) -> None:
        """Parsing was broken by the same latch, in the mirror direction.

        With the flag stuck :data:`True`, ``post_process`` called
        :meth:`int.from_bytes` on the :obj:`int` that ``struct.unpack`` had
        already produced from a ``>Q`` template. So the 8-octet callable field
        could not read what it could not write.

        """
        from pcapkit.corekit.fields.numbers import NumberField

        for width in (*NATIVE_WIDTHS, *BYTE_PACKED_WIDTHS):
            value = _high_bit_value(width)
            with self.subTest(width=width):
                field = NumberField(length=lambda pkt, w=width: w)(dict())

                buffer = field.pack(value, dict())
                self.assertEqual(len(buffer), width)
                self.assertEqual(field.unpack(buffer, dict()), value)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class SubclassCallableLengthTests(unittest.TestCase):
    """The same field classes as they are actually used in the schemas."""

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_an_enum_field_with_a_callable_length_packs(self) -> None:
        """:class:`~pcapkit.corekit.fields.numbers.EnumField` leaves ``__template__`` unset.

        Which is what exposes it: ``__init__`` only calls ``build_template`` --
        and so only latches the flag -- when no ``__template__`` fixes the
        format. :class:`EnumField` inherits :data:`None` for both, so it was
        affected exactly as the bare base class was.

        """
        from pcapkit.corekit.fields.numbers import EnumField

        for width in (1, 2, 4, 8):
            with self.subTest(width=width):
                field = EnumField(length=lambda pkt, w=width: w)(dict())

                self.assertIs(field._need_process, False)
                self.assertEqual(field.pack(1 << 4, dict()),
                                 (1 << 4).to_bytes(width, 'big'))

    def test_a_subclass_fixing_a_template_keeps_working_either_way(self) -> None:
        """The control on the other side: these were never broken, and still are not.

        ``UInt32Field`` and friends fix ``__template__``, so ``__init__`` skips
        ``build_template`` entirely and the placeholder never latched anything.
        A callable resolving to a *different* width than the class fixes is
        still honoured, and still gets the right flag for that width -- which
        is the case #585's ``SwitchField`` workaround was built out of.

        """
        from pcapkit.corekit.fields.numbers import UInt32Field, UInt64Field

        wide = UInt64Field(length=lambda pkt: 8)(dict())
        self.assertEqual(wide.template, '>Q')
        self.assertIs(wide._need_process, False)
        self.assertEqual(wide.pack(1 << 40, dict()).hex(), '0000010000000000')

        # a callable overriding the class's own fixed width, in both directions
        widened = UInt32Field(length=lambda pkt: 8)(dict())
        self.assertEqual(widened.template, '>Q')
        self.assertIs(widened._need_process, False)
        self.assertEqual(widened.pack(1 << 40, dict()).hex(), '0000010000000000')

        odd = UInt32Field(length=lambda pkt: 3)(dict())
        self.assertEqual(odd.template, '>3s')
        self.assertIs(odd._need_process, True)
        self.assertEqual(odd.pack(0x800001, dict()).hex(), '800001')


if __name__ == '__main__':
    unittest.main()
