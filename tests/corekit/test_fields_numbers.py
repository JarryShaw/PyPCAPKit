from __future__ import annotations

import importlib.util
import inspect
import unittest

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: The eight :class:`~pcapkit.corekit.fields.numbers.NumberField` subclasses that
#: fix their sign through ``__signed__``, each paired with the sign it fixes.
#: Derived by introspection in :meth:`FixedSignTests.test_the_census_is_complete`
#: rather than only written down here, so a ninth subclass added tomorrow fails
#: that test instead of quietly escaping every other test in this module.
FIXED_SIGN = {
    'Int8Field': True, 'Int16Field': True, 'Int32Field': True, 'Int64Field': True,
    'UInt8Field': False, 'UInt16Field': False, 'UInt32Field': False, 'UInt64Field': False,
}


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class FixedSignTests(unittest.TestCase):
    """``signed=`` on a subclass whose ``__signed__`` fixes the sign.

    GitHub issue #545. The argument was accepted, documented on every one of
    these eight classes, and then discarded -- in *both* directions, so
    ``UInt8Field(signed=True)._signed`` was :data:`False` and
    ``Int8Field(signed=False)._signed`` was :data:`True`. A caller who asked for
    a signed field got unsigned parsing with no warning, and the values only
    look wrong once the high bit is set, which for a length or an identifier may
    never happen in testing.

    Both directions are asserted separately because the defect was symmetrical:
    a fix that only guarded one of them would pass a test that only checked one.

    """

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_the_census_is_complete(self) -> None:
        """:data:`FIXED_SIGN` is every subclass that fixes a sign, by introspection."""
        from pcapkit.corekit.fields import numbers

        found = {
            name: obj.__signed__
            for name, obj in vars(numbers).items()
            if inspect.isclass(obj) and issubclass(obj, numbers.NumberField)
            and obj is not numbers.NumberField and obj.__signed__ is not None
        }
        self.assertEqual(found, FIXED_SIGN)

    def test_an_unsigned_field_rejects_a_contradicting_signed_true(self) -> None:
        from pcapkit.corekit.fields import numbers
        from pcapkit.utilities.exceptions import FieldValueError

        for name, fixed in FIXED_SIGN.items():
            if fixed:
                continue
            with self.assertRaises(FieldValueError, msg=f'{name}(signed=True) was accepted'):
                getattr(numbers, name)(signed=True)

    def test_a_signed_field_rejects_a_contradicting_signed_false(self) -> None:
        from pcapkit.corekit.fields import numbers
        from pcapkit.utilities.exceptions import FieldValueError

        for name, fixed in FIXED_SIGN.items():
            if not fixed:
                continue
            with self.assertRaises(FieldValueError, msg=f'{name}(signed=False) was accepted'):
                getattr(numbers, name)(signed=False)

    def test_a_signed_agreeing_with_the_class_is_accepted(self) -> None:
        """Redundant is not wrong: only a *contradiction* is rejected."""
        from pcapkit.corekit.fields import numbers

        for name, fixed in FIXED_SIGN.items():
            field = getattr(numbers, name)(signed=fixed)
            self.assertIs(field._signed, fixed, f'{name}(signed={fixed})')

    def test_omitting_signed_keeps_the_class_sign(self) -> None:
        from pcapkit.corekit.fields import numbers

        for name, fixed in FIXED_SIGN.items():
            self.assertIs(getattr(numbers, name)()._signed, fixed, name)

    def test_the_rejection_names_the_class_and_the_sign_it_fixes(self) -> None:
        """An error a caller cannot act on is barely better than silence."""
        from pcapkit.corekit.fields.numbers import Int16Field, UInt32Field
        from pcapkit.utilities.exceptions import FieldValueError

        with self.assertRaisesRegex(FieldValueError, r'UInt32Field: field is fixed as unsigned'):
            UInt32Field(signed=True)
        with self.assertRaisesRegex(FieldValueError, r'Int16Field: field is fixed as signed'):
            Int16Field(signed=False)

    def test_a_contradiction_is_judged_by_truth_value(self) -> None:
        """``signed`` is documented as a :obj:`bool` and is read as one.

        ``signed=1`` contradicts an unsigned field exactly as ``signed=True``
        does, and ``signed=0`` agrees with it exactly as ``signed=False`` does.
        Pinned because the check could as easily have been an identity test,
        which would let ``UInt8Field(signed=1)`` through.

        """
        from pcapkit.corekit.fields.numbers import UInt8Field
        from pcapkit.utilities.exceptions import FieldValueError

        with self.assertRaises(FieldValueError):
            UInt8Field(signed=1)
        self.assertIs(UInt8Field(signed=0)._signed, False)

    def test_the_fixed_classes_still_parse_as_they_always_did(self) -> None:
        """The rejection must not have moved the sign of a default construction."""
        from pcapkit.corekit.fields.numbers import Int8Field, UInt8Field

        self.assertEqual(Int8Field().unpack(b'\xff', {}), -1)
        self.assertEqual(UInt8Field().unpack(b'\xff', {}), 255)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class DeferredSignTests(unittest.TestCase):
    """``signed=`` where no ``__signed__`` fixes it, which is where it works."""

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_the_base_class_still_honours_signed(self) -> None:
        from pcapkit.corekit.fields.numbers import NumberField

        self.assertIs(NumberField(length=4, signed=True)._signed, True)
        self.assertEqual(NumberField(length=4, signed=True).template, '>i')
        self.assertIs(NumberField(length=4, signed=False)._signed, False)
        self.assertEqual(NumberField(length=4, signed=False).template, '>I')

    def test_the_base_class_defaults_to_unsigned(self) -> None:
        """:data:`None` is the new default and has to mean what ``False`` meant."""
        from pcapkit.corekit.fields.numbers import NumberField

        self.assertIs(NumberField(length=4)._signed, False)
        self.assertEqual(NumberField(length=4).template, '>I')
        self.assertEqual(NumberField(length=4).unpack(b'\xff\xff\xff\xff', {}), 0xffffffff)

    def test_an_enum_field_still_honours_signed(self) -> None:
        """:class:`EnumField` fixes no sign, so its own ``signed`` is real."""
        from pcapkit.corekit.fields.numbers import EnumField

        self.assertIs(EnumField(length=4, signed=True)._signed, True)
        self.assertIs(EnumField(length=4, signed=False)._signed, False)
        self.assertIs(EnumField(length=4)._signed, False)

    def test_a_class_fixing_a_sign_without_a_template_parses_with_that_sign(self) -> None:
        """The second instance of the same defect, one level down.

        ``__signed__`` was resolved into :attr:`_signed`, but the struct
        template was built from the raw ``signed`` *argument*. A subclass that
        fixes ``__signed__`` and leaves ``__template__`` unset -- which the
        base class explicitly allows, and which nothing in ``pcapkit`` happens
        to do today -- therefore declared itself signed and then unpacked
        unsigned: ``>I`` for a class saying ``__signed__ = True``, so
        ``b'\\xff\\xff\\xff\\xff'`` parsed as ``4294967295`` instead of ``-1``.

        """
        from pcapkit.corekit.fields.numbers import NumberField

        class SignedNoTemplate(NumberField):
            __length__ = 4
            __signed__ = True

        field = SignedNoTemplate()
        self.assertIs(field._signed, True)
        self.assertEqual(field.template, '>i')
        self.assertEqual(field.unpack(b'\xff\xff\xff\xff', {}), -1)
