# -*- coding: utf-8 -*-
"""Phase 1 of GitHub issue #877: the bare lookup base under :class:`EnumRegistry`.

The owner's ruling on #877: the helper enumerations are to be immutable unless
the RFC or IANA says otherwise, so they may subclass a bare base enumeration
defined in :mod:`pcapkit.corekit.enum`, which :class:`EnumRegistry` itself then
subclasses for the mutable ones. :class:`~pcapkit.corekit.enum.EnumLookup` is
that base, and it carries :meth:`~pcapkit.corekit.enum.EnumLookup.get`,
:meth:`~pcapkit.corekit.enum.EnumLookup.get_all` and the overridable
:meth:`~pcapkit.corekit.enum.EnumLookup._validate_value` hook -- not ``register``,
because the owner's own second thought on the same thread settled that: a base
that carried ``register`` would raise the question of why it should not carry
``register_alias`` too, and he thought a bad ruling might be created that way.
He then went with the recommendation to keep both on :class:`EnumRegistry`.

What this module pins, and why each part is worth pinning:

* the split is where it was ruled to be -- three methods on the base, the five
  mutating ones still on :class:`~pcapkit.corekit.enum.EnumRegistry`, asserted as
  an **exact** partition rather than as mere presence, so that a later change
  cannot quietly migrate one across (:class:`TwoTierSplitTests`);
* the base works as a base, for an :class:`int`-valued and a :class:`str`-valued
  enumeration alike, without either being a registry (:class:`BareLookupTests`);
* the extra tier does not become the member data type, which is the one way a
  mix-in like this breaks all three enumeration shapes at once
  (:class:`MemberTypeTests`);
* :meth:`~pcapkit.corekit.enum.EnumLookup._validate_value` accepts everything by
  default, is honoured on both the paths that call it, and is *not* called on the
  ``str``-key path -- that last one is a documented omission, so it is asserted
  rather than left to be rediscovered (:class:`ValidateValueTests`);
* the declared-but-unassigned asymmetry :meth:`get`'s own docstring describes
  survives on the new base (:class:`UnassignedAsymmetryTests`);
* members still pickle, on every protocol, for all three shapes
  (:class:`PickleTests`) -- flagged unverified while the change was being
  designed, since inserting a class into the MRO is exactly the kind of thing
  that can disturb :meth:`~object.__reduce_ex__`.

On the tree before this change every test below fails at **import**::

    ImportError: cannot import name 'EnumLookup' from 'pcapkit.corekit.enum'

That is not an artefact of how the module is written: the classes these tests
exercise inherit from the base being introduced, so there is nothing to exercise
until it exists. Two of the tests fail pre-change for a second, independent
reason as well -- :meth:`TwoTierSplitTests.test_the_split_is_an_exact_partition`
and :meth:`TwoTierSplitTests.test_enum_registry_subclasses_the_lookup_base`
both contradict the single-tier shape even when rewritten against
:class:`~pcapkit.corekit.enum.EnumRegistry` alone, because ``get`` and
``get_all`` live in ``EnumRegistry.__dict__`` there.

"""
from __future__ import annotations

import pickle
import unittest
from typing import TYPE_CHECKING

from aenum import IntEnum, IntFlag, StrEnum

from pcapkit.corekit.enum import NO_DEFAULT, EnumLookup, EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

#: The mutating half, which must stay on :class:`~pcapkit.corekit.enum.EnumRegistry`.
MUTATING = ('register', 'register_alias', 'register_aliases', '_extend',
            '_unregistered_member')

#: The lookup half, which must move to :class:`~pcapkit.corekit.enum.EnumLookup`.
LOOKUP = ('get', 'get_all', '_validate_value')


class _Int(EnumLookup, IntEnum):
    """A closed ``int``-valued set on the bare base -- no registry anywhere."""

    one = 1
    two = 2


class _Str(EnumLookup, StrEnum):
    """A closed ``str``-valued set on the bare base.

    ``angled`` deliberately carries a value that is not also a member name, which
    is what makes the value-fallback path in
    :meth:`~pcapkit.corekit.enum.EnumLookup.get` observable -- the same shape as
    :class:`~pcapkit.const.ftp.command.FEATCode`'s own ``base = '<base>'``.

    """

    plain = 'plain'
    angled = '<angled>'


class _Flag(EnumLookup, IntFlag):
    """A closed flag set on the bare base."""

    first = 1
    second = 2


class _Ranged(EnumLookup, IntEnum):
    """Hooks a range in, the way the generated registries spell it in ``_missing_``."""

    low = 1
    high = 8

    @classmethod
    def _validate_value(cls, value: 'Any') -> 'None':
        """Reject anything outside ``0 <= value <= 8``."""
        if not (isinstance(value, int) and 0 <= value <= 8):
            raise EnumValueError(f'{value!r} is not a valid {cls.__name__}')


#: 'list[Any]': Values :class:`_Counting`'s hook was handed, in order. Module
#: level rather than a class attribute because any non-descriptor assigned in an
#: enumeration body becomes a *member* -- ``seen = []`` inside the class below
#: raises ``TypeError: values must be str``, which is how this was found.
COUNTING_SEEN = []  # type: list[Any]


class _Counting(EnumLookup, StrEnum):
    """Records every :meth:`_validate_value` call, to pin the ``str``-path omission."""

    plain = 'plain'
    angled = '<angled>'

    @classmethod
    def _validate_value(cls, value: 'Any') -> 'None':
        """Record ``value`` and accept it."""
        COUNTING_SEEN.append(value)


class _PickleInt(EnumRegistry, IntEnum):
    """Registry shape ``int``, for the pickle round-trip."""

    solo = 7


class _PickleStr(EnumRegistry, StrEnum):
    """Registry shape ``str``, for the pickle round-trip."""

    solo = 'solo'


class _PickleFlag(EnumRegistry, IntFlag):
    """Registry shape flag, for the pickle round-trip."""

    solo = 4


class TwoTierSplitTests(unittest.TestCase):
    """The partition between the two tiers, asserted exactly."""

    def test_enum_registry_subclasses_the_lookup_base(self) -> 'None':
        """:class:`EnumRegistry` is a child of :class:`EnumLookup`, not a sibling.

        A sibling could not share ``get``; a *subclass* is the shape the ruling
        names, and it is also what keeps ``_member_type_`` alone -- both tiers are
        plain classes, so neither becomes the member data type.

        """
        self.assertTrue(issubclass(EnumRegistry, EnumLookup))
        self.assertIsNot(EnumRegistry, EnumLookup)
        self.assertEqual(EnumRegistry.__mro__, (EnumRegistry, EnumLookup, object))

    def test_the_split_is_an_exact_partition(self) -> 'None':
        """Each method is defined on exactly one tier, and on the right one.

        Asserted against ``__dict__`` rather than with :func:`hasattr`, which
        cannot tell "defined here" from "inherited": the mutating five are
        reachable from :class:`EnumLookup`'s subclasses either way, so presence
        alone would pass on the single-tier tree this change replaces.

        """
        for name in LOOKUP:
            with self.subTest(method=name, tier='EnumLookup'):
                self.assertIn(name, EnumLookup.__dict__)
                self.assertNotIn(name, EnumRegistry.__dict__)
        for name in MUTATING:
            with self.subTest(method=name, tier='EnumRegistry'):
                self.assertIn(name, EnumRegistry.__dict__)
                self.assertNotIn(name, EnumLookup.__dict__)

    def test_the_bare_base_offers_no_way_to_mutate(self) -> 'None':
        """A closed set on the base cannot be grown, which is the whole point."""
        for name in MUTATING:
            with self.subTest(method=name):
                self.assertFalse(hasattr(_Int, name))
                self.assertFalse(hasattr(EnumLookup, name))

    def test_registries_still_reach_every_mutating_method(self) -> 'None':
        """And the registry tier keeps all five, inherited or not."""
        for name in MUTATING:
            with self.subTest(method=name):
                self.assertTrue(callable(getattr(_PickleInt, name)))

    def test_lookup_methods_resolve_to_the_base_on_a_registry(self) -> 'None':
        """A registry's ``get`` is now the base's, not a copy of it."""
        for name in ('get', 'get_all'):
            with self.subTest(method=name):
                self.assertIs(getattr(_PickleInt, name).__func__,
                              getattr(EnumLookup, name).__func__)


class BareLookupTests(unittest.TestCase):
    """:meth:`get` and :meth:`get_all` on closed sets that are not registries."""

    def test_int_lookup_by_name_and_by_value(self) -> 'None':
        """Both keys resolve to the one canonical member."""
        self.assertIs(_Int.get('one'), _Int.one)
        self.assertIs(_Int.get(1), _Int.one)
        self.assertIs(_Int.get(2), _Int.two)

    def test_str_lookup_by_name_and_by_value(self) -> 'None':
        """Including a value that is not also a member name.

        ``_Str.get('<angled>')`` is the measurement
        :file:`docs/source/contributing/conventions/registry-protocol.rst`
        records on :class:`~pcapkit.const.ftp.command.FEATCode`, made here on a
        class that cannot be overriding ``get``, since it defines none.

        """
        self.assertIs(_Str.get('plain'), _Str.plain)
        self.assertNotIn('<angled>', _Str._member_map_)
        self.assertIs(_Str.get('<angled>'), _Str.angled)

    def test_get_is_case_sensitive(self) -> 'None':
        """The ruled default: case-sensitive, unless the RFC states that the values
        are case-insensitive (ruled on #877).

        Case-insensitivity is a per-class override needing an RFC behind it, so
        the base must not fold case itself. Auditing the existing overrides
        against their specifications is GitHub issue #903.

        """
        with self.assertRaises(KeyError):
            _Str.get('PLAIN')
        with self.assertRaises(KeyError):
            _Int.get('ONE')

    def test_get_all_returns_the_canonical_member_alone(self) -> 'None':
        """One key, one member, for a set with no duplicate values."""
        self.assertEqual(_Int.get_all('one'), (_Int.one,))
        self.assertEqual(_Int.get_all(1), (_Int.one,))
        self.assertEqual(_Str.get_all('plain'), (_Str.plain,))

    def test_default_resolves_only_through_registered_values(self) -> 'None':
        """A usable ``default`` is returned; an unusable one re-raises."""
        self.assertIs(_Int.get(99, default=1), _Int.one)
        self.assertIs(_Str.get('nope', default='plain'), _Str.plain)
        with self.assertRaises(ValueError):
            _Int.get(99, default=98)

    def test_omitted_default_propagates_the_lookup_error(self) -> 'None':
        """:data:`NO_DEFAULT` means *no default*, not a default of its own."""
        with self.assertRaises(ValueError):
            _Int.get(99)
        with self.assertRaises(ValueError):
            _Int.get(99, default=NO_DEFAULT)
        with self.assertRaises(KeyError):
            _Str.get('nope')

    def test_lookups_do_not_grow_a_closed_set(self) -> 'None':
        """No path through the base registers anything.

        ``Flag`` is excluded deliberately and gets its own test below: its
        composite caching is the owner's one ruled exception, not a leak here.

        """
        for cls in (_Int, _Str):
            with self.subTest(cls=cls.__name__):
                before = (list(cls._member_names_), dict(cls.__members__),
                          dict(cls._value2member_map_))
                for probe in ('nope', 99, -1):
                    try:
                        cls.get(probe)
                    except (KeyError, ValueError):
                        pass
                self.assertEqual(list(cls._member_names_), before[0])
                self.assertEqual(dict(cls.__members__), before[1])
                self.assertEqual(dict(cls._value2member_map_), before[2])

    def test_flag_composites_remain_the_ruled_exception(self) -> 'None':
        """A ``Flag`` still caches composites, and that is sanctioned.

        The owner's ruling on this issue is that :class:`~aenum.Flag` subclasses
        are the one exception to enumerations staying immutable: their values are
        expected to grow and fill in through combinations. So ``_Flag.get(99)``
        composing ``first|second|96`` into ``_value2member_map_`` is
        :class:`~aenum.Flag`'s own machinery behaving as expected, and the base
        does not -- and must not -- suppress it.

        The distinction worth pinning is *which* table moves: no real member is
        added, so ``_member_names_`` and ``__members__`` are untouched while the
        value cache grows. That is what separates a composite from a mint.

        """
        names_before = list(_Flag._member_names_)
        members_before = dict(_Flag.__members__)

        composite = _Flag.get(3)
        self.assertEqual(composite, _Flag.first | _Flag.second)

        self.assertEqual(list(_Flag._member_names_), names_before)
        self.assertEqual(dict(_Flag.__members__), members_before)
        self.assertIn(3, _Flag._value2member_map_)


class MemberTypeTests(unittest.TestCase):
    """The extra tier must not become the member data type."""

    def test_member_type_survives_the_extra_tier(self) -> 'None':
        """``int`` for ``IntEnum``/``IntFlag``, ``str`` for ``StrEnum``."""
        self.assertIs(_Int._member_type_, int)
        self.assertIs(_Flag._member_type_, int)
        self.assertIs(_Str._member_type_, str)

    def test_member_type_survives_it_under_a_registry_too(self) -> 'None':
        """The case that would regress: two plain tiers ahead of the enum base."""
        self.assertIs(_PickleInt._member_type_, int)
        self.assertIs(_PickleFlag._member_type_, int)
        self.assertIs(_PickleStr._member_type_, str)

    def test_members_still_behave_as_their_data_type(self) -> 'None':
        """Not merely annotated as ``int``/``str`` -- actually usable as one."""
        self.assertEqual(int(_Int.one), 1)
        self.assertEqual(str(_Str.plain), 'plain')
        self.assertEqual(int(_PickleFlag.solo), 4)
        self.assertEqual(_Int.one + 1, 2)

    def test_neither_tier_is_an_enumeration(self) -> 'None':
        """Both are plain mix-ins, which is what lets one base serve all shapes."""
        for tier in (EnumLookup, EnumRegistry):
            with self.subTest(tier=tier.__name__):
                self.assertFalse(hasattr(tier, '__members__'))


class ValidateValueTests(unittest.TestCase):
    """The hook the owner asked for on #877: some range validation that
    inheriting classes can plug into."""

    def test_the_default_hook_accepts_everything(self) -> 'None':
        """A base cannot know any subclass's range, so it forbids nothing."""
        for probe in (0, -1, 2 ** 64, 'anything', None, object()):
            with self.subTest(probe=type(probe).__name__):
                self.assertIsNone(EnumLookup._validate_value(probe))
                self.assertIsNone(_Int._validate_value(probe))

    def test_an_override_is_honoured_on_the_value_path(self) -> 'None':
        """An out-of-range value is refused before the constructor sees it."""
        self.assertIs(_Ranged.get(1), _Ranged.low)
        with self.assertRaises(EnumValueError):
            _Ranged.get(99)
        with self.assertRaises(EnumValueError):
            _Ranged.get(-1)

    def test_a_rejection_still_honours_default(self) -> 'None':
        """Because :exc:`EnumValueError` is a :exc:`ValueError`.

        Documented on the hook, and worth an assertion: an override raising
        outside that hierarchy would propagate past ``default`` instead, which is
        a behavioural difference rather than a stylistic one.

        """
        self.assertTrue(issubclass(EnumValueError, ValueError))
        self.assertIs(_Ranged.get(99, default=1), _Ranged.low)

    def test_an_in_range_but_unassigned_value_still_fails_to_resolve(self) -> 'None':
        """The hook grants legality, not membership.

        ``4`` is inside ``_Ranged``'s declared range and carries no member, so it
        passes validation and is then refused by the enumeration itself -- the
        hook is a guard in front of the lookup, not a substitute for it.

        """
        self.assertIsNone(_Ranged._validate_value(4))
        with self.assertRaises(ValueError):
            _Ranged.get(4)

    def test_the_str_key_path_does_not_call_the_hook(self) -> 'None':
        """A documented omission, so pinned rather than left to be rediscovered.

        That path resolves against the already-populated lookup tables only, where
        every value present is legal by construction.

        """
        COUNTING_SEEN.clear()
        self.assertIs(_Counting.get('plain'), _Counting.plain)
        self.assertIs(_Counting.get('<angled>'), _Counting.angled)
        with self.assertRaises(KeyError):
            _Counting.get('nope')
        self.assertEqual(COUNTING_SEEN, [])

        # Not vacuous: the same hook on the same class *is* reached from the
        # non-str path, so the empty list above is the omission and not a hook
        # that never fires.
        with self.assertRaises(ValueError):
            _Counting.get(99)
        self.assertEqual(COUNTING_SEEN, [99])

    def test_register_routes_through_the_hook(self) -> 'None':
        """The mutating path validates too, and nothing is minted when it refuses."""
        class _Registry(EnumRegistry, IntEnum):
            low = 1

            @classmethod
            def _validate_value(cls, value: 'Any') -> 'None':
                if not (isinstance(value, int) and 0 <= value <= 8):
                    raise EnumValueError(f'{value!r} is not a valid {cls.__name__}')

        before = list(_Registry._member_names_)
        with self.assertRaises(EnumValueError):
            _Registry.register(99, 'rejected')
        self.assertEqual(list(_Registry._member_names_), before)
        self.assertNotIn('rejected', _Registry.__members__)

        minted = _Registry.register(5, 'accepted')
        self.assertEqual(minted.value, 5)
        self.assertEqual(minted.name, 'accepted')
        self.assertIn('accepted', _Registry.__members__)

    def test_the_duplicate_check_runs_before_validation(self) -> 'None':
        """So the actionable message wins over a range complaint.

        ``declared`` sits outside the class's own validated range, which is how
        the ordering becomes observable at all: validate-first would answer an
        already-taken value with :exc:`EnumValueError`, losing the *"use
        register_alias()"* hint that is the useful answer.

        """
        class _Narrow(EnumRegistry, IntEnum):
            declared = 100

            @classmethod
            def _validate_value(cls, value: 'Any') -> 'None':
                if not (isinstance(value, int) and 0 <= value <= 8):
                    raise EnumValueError(f'{value!r} is not a valid {cls.__name__}')

        with self.assertRaises(ValueError) as caught:
            _Narrow.register(100, 'again')
        self.assertNotIsInstance(caught.exception, EnumValueError)
        self.assertIn('register_alias', str(caught.exception))

    def test_register_alias_does_not_need_the_hook(self) -> 'None':
        """An aliased value is already registered, so it already passed."""
        class _Aliased(EnumRegistry, IntEnum):
            declared = 100

            @classmethod
            def _validate_value(cls, value: 'Any') -> 'None':
                raise EnumValueError('this hook refuses everything')

        aliased = _Aliased.register_alias(100, 'nickname')
        self.assertIs(aliased, _Aliased.declared)
        self.assertIn('nickname', _Aliased.__members__)


class UnassignedAsymmetryTests(unittest.TestCase):
    """The declared-but-unassigned ``str`` gap, unchanged on the new base.

    :meth:`~pcapkit.corekit.enum.EnumLookup.get`'s own docstring calls this
    deliberate: closing it would mean calling ``cls(key)`` for a ``str`` value,
    which reopens the minting hazard the ``str`` path exists to avoid. Pinned
    here so that a later "fix" has to argue with a test.

    """

    def test_a_str_value_reached_only_through_missing_does_not_resolve(self) -> 'None':
        """``cls(value)`` yields it; ``get(value)`` does not."""
        class _Unassigned(EnumRegistry, StrEnum):
            plain = 'plain'

            @classmethod
            def _missing_(cls, value: 'Any') -> 'Any':
                return cls._unregistered_member(value, 'unassigned')

        member = _Unassigned('ZZ-NOT-REAL')
        self.assertEqual(member.value, 'ZZ-NOT-REAL')
        self.assertEqual(member.name, 'unassigned')

        with self.assertRaises(KeyError):
            _Unassigned.get('ZZ-NOT-REAL')

    def test_neither_path_grows_the_lookup_tables(self) -> 'None':
        """Which is why the value stays invisible to ``get`` in the first place."""
        class _Untouched(EnumRegistry, StrEnum):
            plain = 'plain'

            @classmethod
            def _missing_(cls, value: 'Any') -> 'Any':
                return cls._unregistered_member(value, 'unassigned')

        before = (len(_Untouched._member_names_), len(_Untouched._value2member_map_),
                  len(_Untouched._member_map_))
        _Untouched('ZZ-NOT-REAL')
        try:
            _Untouched.get('ZZ-ALSO-NOT-REAL')
        except KeyError:
            pass
        after = (len(_Untouched._member_names_), len(_Untouched._value2member_map_),
                 len(_Untouched._member_map_))
        self.assertEqual(before, after)


class PickleTests(unittest.TestCase):
    """Members survive the round trip on every protocol, for all three shapes.

    Inserting a class into the MRO is exactly the sort of change that can disturb
    :meth:`~object.__reduce_ex__`, and this was flagged unverified while the
    change was being designed. Each case also asserts that the class really does
    reach the new base, so the test cannot pass vacuously on the single-tier tree
    this change replaces.

    """

    def assertRoundTrips(self, member: 'Any') -> 'None':
        """Pickle and unpickle ``member`` on every protocol."""
        self.assertIn(EnumLookup, type(member).__mro__)
        for protocol in range(pickle.HIGHEST_PROTOCOL + 1):
            with self.subTest(protocol=protocol):
                back = pickle.loads(pickle.dumps(member, protocol=protocol))
                self.assertIs(back, member)
                self.assertEqual(back.name, member.name)
                self.assertEqual(back.value, member.value)
                self.assertIs(type(back), type(member))

    def test_int_registry_member_round_trips(self) -> 'None':
        """``EnumRegistry`` + ``IntEnum``."""
        self.assertRoundTrips(_PickleInt.solo)

    def test_str_registry_member_round_trips(self) -> 'None':
        """``EnumRegistry`` + ``StrEnum``."""
        self.assertRoundTrips(_PickleStr.solo)

    def test_flag_registry_member_round_trips(self) -> 'None':
        """``EnumRegistry`` + ``IntFlag``."""
        self.assertRoundTrips(_PickleFlag.solo)

    def test_bare_base_members_round_trip_too(self) -> 'None':
        """And a closed set on the base alone, which is what phase 2 will create."""
        self.assertRoundTrips(_Int.one)
        self.assertRoundTrips(_Str.plain)
        self.assertRoundTrips(_Flag.first)


if __name__ == '__main__':
    unittest.main()
