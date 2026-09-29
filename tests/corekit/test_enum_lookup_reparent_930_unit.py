# -*- coding: utf-8 -*-
"""GitHub issue #930, the blocked half of #877's phase 2: re-parenting the last
seven non-registry enumerations onto :class:`~pcapkit.corekit.enum.EnumLookup`.

GitHub issue #921 re-parented 17 of the 24 non-registry enumerations and deliberately
left seven alone, because the files holding them were still open under other pull
requests at the time: :mod:`pcapkit.const.ftp.command` (``CommandType``,
``ConformanceRequirement``) under #913, and :mod:`pcapkit.protocols.internet.esp`
(``ESPStatus``) plus :mod:`pcapkit.protocols.internet.mh`
(``FastBindingAcknowledgmentStatus``, ``IPv6AddressPrefixCode``, ``LMAAddressCode``,
``LocalizedRoutingStatus``) under #904. Both blockers have since merged, and this
module pins that the remainder actually took the base -- finishing phase 2 at 24 of 24
non-registry enumerations, with zero still outside the hierarchy.

Two of the seven, :class:`FastBindingAcknowledgmentStatus` and
:class:`IPv6AddressPrefixCode`, already defined their own ``get`` -- both as a
:class:`staticmethod`, the exact shape GitHub issue #908 found dangerous once a base
``get`` becomes a :class:`classmethod`: calling ``super().get(...)`` from a
``staticmethod`` raises :exc:`RuntimeError: super(): no arguments`. Neither override
calls ``super()`` at all, so the trap does not fire, and per this issue's own brief they
are left **untouched** -- their ``except KeyError: raise EnumKeyError(...)`` conversions
were put there by GitHub issue #923 and already answer a name miss in exactly the shape
the base now uses. Keeping the plain ``@staticmethod`` does cost something, though:
``mypy``'s ``[override]`` check and ``pylint``'s ``arguments-differ`` both flag the
resulting shape mismatch against the base's ``classmethod`` (``cls, key, default``)
signature, and both are silenced rather than resolved by widening the signature --
:class:`ReparentedBasesTests` pins, alongside each class's own base-tuple change,
that the decorator itself survived the re-parenting, which is what makes those
suppressions still apply to the right thing.

Re-parenting also makes both kept overrides reachable through a door that
did not exist before: :meth:`~pcapkit.corekit.enum.EnumLookup.get_all`,
inherited from the base for the first time, calls ``get`` internally. Before
this issue, that mattered because ``get`` itself raised **loud**: both
overrides used to log once at :data:`logging.CRITICAL` and set
:data:`sys.tracebacklimit` to ``0`` process-wide on a name miss, unlike the
base's own quiet raise. GitHub issue #930 converges both onto the base's
quiet shape instead -- a real behaviour change, not merely a re-parent --
settled on GitHub issue #933's follow-up ruling, verbatim: *"Oh wait. I
meant, they should follow house convention and not to be loud."*
:class:`KeptOverrideQuietnessTests` pins both halves of that: the ``get``
half, which genuinely changes (loud on the tree before this issue, quiet
here), and the ``get_all`` half, which is new outright (the attribute does
not exist on that tree at all).

The other five -- :class:`CommandType`, :class:`ConformanceRequirement`,
:class:`ESPStatus`, :class:`LocalizedRoutingStatus` and :class:`LMAAddressCode` -- are
pure re-parents: none defines a ``get`` of its own to reconcile with the base, so each
gains ``get``/``get_all`` for the first time. :class:`CommandType`,
:class:`LocalizedRoutingStatus` and :class:`LMAAddressCode` do carry their own
``_missing_`` range guards, which are untouched -- :class:`EnumLookup` does not
override that hook, so a re-parent cannot change what it does.

On the tree before this change, every ``.get(...)`` call below fails with
``AttributeError: type object '<Name>' has no attribute 'get'`` for the five pure
re-parents, and every base-tuple assertion in :class:`ReparentedBasesTests` fails since
:class:`~pcapkit.corekit.enum.EnumLookup` is not yet in any of these seven classes'
``__bases__`` or MRO. Quoted verbatim from an actual run of
:meth:`ReparentedBasesTests.test_command_type` with the three source files reverted to
``af2324522`` (origin/main immediately before this change; structurally identical to
``4f3d43df7`` for these seven classes) while this module itself stayed as written::

    AssertionError: Tuples differ: (<aenum 'IntFlag'>,) != (<class 'pcapkit.corekit.enum.EnumLookup'>, <aenum 'IntFlag'>)

    First differing element 0:
    <aenum 'IntFlag'>
    <class 'pcapkit.corekit.enum.EnumLookup'>

    Second tuple contains 1 additional elements.
    First extra element 1:
    <aenum 'IntFlag'>

    - (<aenum 'IntFlag'>,)
    + (<class 'pcapkit.corekit.enum.EnumLookup'>, <aenum 'IntFlag'>)

Measured against that reverted tree (plain :mod:`unittest`, 27 test methods,
each ``subTest`` resolved back to its parent method via
``getattr(test, 'test_case', test)`` rather than counted on its own --
without that resolution a ``subTest``-only failure is recorded against
``unittest.case._SubTest`` and its parent method misreads as passing):
**22 of the 27 fail or error, and five hold** --

* ``ZeroRemainOutsideEnumLookupTests.test_the_walk_found_something_to_count`` --
  a guard that keeps the census assertion from passing vacuously on an empty
  discovery, not itself a claim about this change, so it is expected to hold
  either way.
* ``FailedLookupTests.test_fast_binding_acknowledgment_status``,
  ``FailedLookupTests.test_ipv6_address_prefix_code``,
  ``GetByNameAndValueTests.test_fast_binding_acknowledgment_status`` and
  ``GetByNameAndValueTests.test_ipv6_address_prefix_code`` hold for the most
  interesting reason in this file: :class:`FastBindingAcknowledgmentStatus`
  and :class:`IPv6AddressPrefixCode` already had a working ``get`` before this
  change -- their own kept :class:`staticmethod`, described above -- so their
  lookup and failed-lookup behaviour is unaffected by the re-parent and these
  four assertions hold on both trees. What *does* fail for both classes on the
  reverted tree is their own :class:`ReparentedBasesTests` method, since the
  base-tuple/MRO change is real for all seven regardless of whether ``get``
  itself was already working.

Neither method of :class:`KeptOverrideQuietnessTests` holds, and deliberately
so -- both are pinning the one thing this issue actually changes about the two
kept overrides. ``test_get_is_now_quiet_on_both_classes`` fails against the
reverted tree because ``get`` really was loud there (see that class's own
docstring): this is not a scaffolding failure, it is the behaviour change
itself, caught in the act. ``test_get_all_is_new_and_quiet_too`` fails with
``AttributeError`` instead, since ``get_all`` does not exist on the reverted
tree at all.

"""
from __future__ import annotations

import importlib
import inspect
import pkgutil
import sys
import unittest

from pcapkit.corekit.enum import EnumLookup
from pcapkit.utilities.exceptions import EnumKeyError, EnumValueError
from pcapkit.utilities.logging import logger
from tests.utilities._harness import capture

__all__ = [
    'ReparentedBasesTests', 'GetByNameAndValueTests', 'FailedLookupTests',
    'KeptOverrideQuietnessTests', 'NoMintingTests', 'PureReparentClassmethodTests',
    'ZeroRemainOutsideEnumLookupTests',
]


class ReparentedBasesTests(unittest.TestCase):
    """Every one of the seven gained :class:`EnumLookup` as a base, mixed in
    *ahead of* its enum base so ``_member_type_`` still resolves to
    :class:`int`, and none grew a member in the process -- this issue's own
    brief is explicit that a re-parent minting one silently is exactly the
    defect this programme exists to prevent, so each test below pins both in
    one place rather than trusting that a passing base-tuple assertion says
    anything about the member table. ``__members__`` (which counts aliases)
    and ``list(cls)`` (which does not) are pinned separately, since the two
    diverge on :class:`CommandType`: its ``undefined = 0`` member is a real,
    named member -- not an alias -- but :class:`~aenum.Flag` iteration omits
    the zero value by convention, the same way it always has.
    """

    def test_command_type(self) -> None:
        from aenum import IntFlag

        from pcapkit.const.ftp.command import CommandType

        self.assertEqual(CommandType.__bases__, (EnumLookup, IntFlag))
        self.assertIn(EnumLookup, CommandType.__mro__)
        self.assertEqual(len(CommandType.__members__), 4)
        self.assertEqual(len(list(CommandType)), 3)

    def test_conformance_requirement(self) -> None:
        from aenum import IntEnum

        from pcapkit.const.ftp.command import ConformanceRequirement

        self.assertEqual(ConformanceRequirement.__bases__, (EnumLookup, IntEnum))
        self.assertIn(EnumLookup, ConformanceRequirement.__mro__)
        self.assertEqual(len(ConformanceRequirement.__members__), 3)
        self.assertEqual(len(list(ConformanceRequirement)), 3)

    def test_esp_status(self) -> None:
        import enum

        from pcapkit.protocols.internet.esp import ESPStatus

        self.assertEqual(ESPStatus.__bases__, (EnumLookup, enum.IntEnum))
        self.assertIn(EnumLookup, ESPStatus.__mro__)
        self.assertEqual(len(ESPStatus.__members__), 6)
        self.assertEqual(len(list(ESPStatus)), 6)

    def test_fast_binding_acknowledgment_status(self) -> None:
        """Also pins that its kept ``get`` override is still a
        :class:`staticmethod` -- unlike ``TransportProtocol.get`` and
        ``Criticality.get`` in GitHub issue #921, it never calls
        ``super().get(...)``, so there is no delegation to convert it for."""
        from aenum import IntEnum

        from pcapkit.protocols.internet.mh import FastBindingAcknowledgmentStatus

        self.assertEqual(FastBindingAcknowledgmentStatus.__bases__, (EnumLookup, IntEnum))
        self.assertIn(EnumLookup, FastBindingAcknowledgmentStatus.__mro__)
        self.assertEqual(len(FastBindingAcknowledgmentStatus.__members__), 6)
        self.assertEqual(len(list(FastBindingAcknowledgmentStatus)), 6)
        self.assertIsInstance(
            inspect.getattr_static(FastBindingAcknowledgmentStatus, 'get'), staticmethod)

    def test_ipv6_address_prefix_code(self) -> None:
        """Also pins that its kept ``get`` override is still a
        :class:`staticmethod`, for the same reason as
        :class:`FastBindingAcknowledgmentStatus`."""
        from aenum import IntEnum

        from pcapkit.protocols.internet.mh import IPv6AddressPrefixCode

        self.assertEqual(IPv6AddressPrefixCode.__bases__, (EnumLookup, IntEnum))
        self.assertIn(EnumLookup, IPv6AddressPrefixCode.__mro__)
        self.assertEqual(len(IPv6AddressPrefixCode.__members__), 4)
        self.assertEqual(len(list(IPv6AddressPrefixCode)), 4)
        self.assertIsInstance(
            inspect.getattr_static(IPv6AddressPrefixCode, 'get'), staticmethod)

    def test_localized_routing_status(self) -> None:
        from aenum import IntEnum

        from pcapkit.protocols.internet.mh import LocalizedRoutingStatus

        self.assertEqual(LocalizedRoutingStatus.__bases__, (EnumLookup, IntEnum))
        self.assertIn(EnumLookup, LocalizedRoutingStatus.__mro__)
        self.assertEqual(len(LocalizedRoutingStatus.__members__), 3)
        self.assertEqual(len(list(LocalizedRoutingStatus)), 3)

    def test_lma_address_code(self) -> None:
        from aenum import IntEnum

        from pcapkit.protocols.internet.mh import LMAAddressCode

        self.assertEqual(LMAAddressCode.__bases__, (EnumLookup, IntEnum))
        self.assertIn(EnumLookup, LMAAddressCode.__mro__)
        self.assertEqual(len(LMAAddressCode.__members__), 3)
        self.assertEqual(len(list(LMAAddressCode)), 3)


class NoMintingTests(unittest.TestCase):
    """None of the seven mints on a miss, exercised through ``get`` itself
    rather than only through the static counts above."""

    def test_a_battery_of_lookups_does_not_grow_any_of_the_seven(self) -> None:
        """None of the seven mints on a miss -- each is a closed set on the
        bare lookup tier, not the mutating
        :class:`~pcapkit.corekit.enum.EnumRegistry` one. Exercises every
        ``get`` (name hit, value hit, name miss, value miss) and then
        re-checks every size against the values pinned above, in the same
        process and without subprocess isolation: unlike a registry whose
        ``_missing_`` mints a placeholder, every one of these seven either
        resolves an existing member or raises, so there is nothing for an
        earlier assertion in this method to leave behind for a later one to
        mistake for growth.
        """
        from pcapkit.const.ftp.command import CommandType, ConformanceRequirement
        from pcapkit.protocols.internet.esp import ESPStatus
        from pcapkit.protocols.internet.mh import (FastBindingAcknowledgmentStatus,
                                                   IPv6AddressPrefixCode, LMAAddressCode,
                                                   LocalizedRoutingStatus)

        before = {
            CommandType: (4, 3), ConformanceRequirement: (3, 3), ESPStatus: (6, 6),
            FastBindingAcknowledgmentStatus: (6, 6), IPv6AddressPrefixCode: (4, 4),
            LocalizedRoutingStatus: (3, 3), LMAAddressCode: (3, 3),
        }
        for cls, (members, count) in before.items():
            with self.subTest(cls=cls.__name__):
                self.assertEqual(len(cls.__members__), members)
                self.assertEqual(len(list(cls)), count)

                member = next(iter(cls))
                self.assertIs(cls.get(member.name), member)
                self.assertIs(cls.get(member.value), member)
                with self.assertRaises(KeyError):
                    cls.get('NOT_A_REAL_MEMBER_930')
                with self.assertRaises(ValueError):
                    cls.get(1 << 70)

                self.assertEqual(len(cls.__members__), members)
                self.assertEqual(len(list(cls)), count)


class GetByNameAndValueTests(unittest.TestCase):
    """``get`` resolves by name and by value on each of the seven, whether
    the ``get`` reached is the base's own or one of the two kept overrides."""

    def test_command_type(self) -> None:
        from pcapkit.const.ftp.command import CommandType

        self.assertIs(CommandType.get('A'), CommandType.A)
        self.assertIs(CommandType.get(1), CommandType.A)

    def test_conformance_requirement(self) -> None:
        from pcapkit.const.ftp.command import ConformanceRequirement

        self.assertIs(ConformanceRequirement.get('M'), ConformanceRequirement.M)
        self.assertIs(ConformanceRequirement.get(1), ConformanceRequirement.M)

    def test_esp_status(self) -> None:
        from pcapkit.protocols.internet.esp import ESPStatus

        self.assertIs(ESPStatus.get('DECRYPTED'), ESPStatus.DECRYPTED)
        self.assertIs(ESPStatus.get(0), ESPStatus.DECRYPTED)
        self.assertIs(ESPStatus.get('UNSUPPORTED'), ESPStatus.UNSUPPORTED)
        self.assertIs(ESPStatus.get(5), ESPStatus.UNSUPPORTED)

    def test_fast_binding_acknowledgment_status(self) -> None:
        from pcapkit.protocols.internet.mh import FastBindingAcknowledgmentStatus

        self.assertIs(
            FastBindingAcknowledgmentStatus.get('Fast_Binding_Update_accepted'),
            FastBindingAcknowledgmentStatus.Fast_Binding_Update_accepted)
        self.assertIs(FastBindingAcknowledgmentStatus.get(0),
                      FastBindingAcknowledgmentStatus.Fast_Binding_Update_accepted)

    def test_ipv6_address_prefix_code(self) -> None:
        from pcapkit.protocols.internet.mh import IPv6AddressPrefixCode

        self.assertIs(IPv6AddressPrefixCode.get('Old_Care_of_Address'),
                      IPv6AddressPrefixCode.Old_Care_of_Address)
        self.assertIs(IPv6AddressPrefixCode.get(1), IPv6AddressPrefixCode.Old_Care_of_Address)

    def test_localized_routing_status(self) -> None:
        from pcapkit.protocols.internet.mh import LocalizedRoutingStatus

        self.assertIs(LocalizedRoutingStatus.get('Success'), LocalizedRoutingStatus.Success)
        self.assertIs(LocalizedRoutingStatus.get(0), LocalizedRoutingStatus.Success)

    def test_lma_address_code(self) -> None:
        from pcapkit.protocols.internet.mh import LMAAddressCode

        self.assertIs(LMAAddressCode.get('Reserved'), LMAAddressCode.Reserved)
        self.assertIs(LMAAddressCode.get(0), LMAAddressCode.Reserved)


class FailedLookupTests(unittest.TestCase):
    """What a miss raises on each of the seven -- a name miss is
    :exc:`KeyError`-derived and a value miss :exc:`ValueError`-derived,
    matching stdlib :class:`~enum.Enum`'s own shape (GitHub issue #923) on
    every one of the seven regardless of whether its ``get`` is the base's
    own or a kept :class:`staticmethod` override.
    """

    def test_command_type(self) -> None:
        from pcapkit.const.ftp.command import CommandType

        with self.assertRaises(KeyError) as name_miss:
            CommandType.get('NOT_A_REAL_MEMBER')
        self.assertIsInstance(name_miss.exception, EnumKeyError)

        with self.assertRaises(ValueError) as value_miss:
            CommandType.get(1 << 70)
        self.assertIsInstance(value_miss.exception, EnumValueError)

    def test_conformance_requirement(self) -> None:
        from pcapkit.const.ftp.command import ConformanceRequirement

        with self.assertRaises(KeyError) as name_miss:
            ConformanceRequirement.get('NOT_A_REAL_MEMBER')
        self.assertIsInstance(name_miss.exception, EnumKeyError)

        with self.assertRaises(ValueError) as value_miss:
            ConformanceRequirement.get(1 << 70)
        self.assertIsInstance(value_miss.exception, EnumValueError)

    def test_esp_status(self) -> None:
        from pcapkit.protocols.internet.esp import ESPStatus

        with self.assertRaises(KeyError) as name_miss:
            ESPStatus.get('NOT_A_REAL_MEMBER')
        self.assertIsInstance(name_miss.exception, EnumKeyError)

        with self.assertRaises(ValueError) as value_miss:
            ESPStatus.get(1 << 70)
        self.assertIsInstance(value_miss.exception, EnumValueError)

    def test_fast_binding_acknowledgment_status(self) -> None:
        """Its own kept ``get`` raises :exc:`EnumKeyError` directly for a
        name miss (GitHub issue #923's conversion, left untouched by this
        change) and delegates to :meth:`_missing_` for a value miss, which
        always raises :exc:`EnumValueError`."""
        from pcapkit.protocols.internet.mh import FastBindingAcknowledgmentStatus

        with self.assertRaises(KeyError) as name_miss:
            FastBindingAcknowledgmentStatus.get('NOT_A_REAL_MEMBER')
        self.assertIsInstance(name_miss.exception, EnumKeyError)

        with self.assertRaises(ValueError) as value_miss:
            FastBindingAcknowledgmentStatus.get(1 << 70)
        self.assertIsInstance(value_miss.exception, EnumValueError)

    def test_ipv6_address_prefix_code(self) -> None:
        from pcapkit.protocols.internet.mh import IPv6AddressPrefixCode

        with self.assertRaises(KeyError) as name_miss:
            IPv6AddressPrefixCode.get('NOT_A_REAL_MEMBER')
        self.assertIsInstance(name_miss.exception, EnumKeyError)

        with self.assertRaises(ValueError) as value_miss:
            IPv6AddressPrefixCode.get(1 << 70)
        self.assertIsInstance(value_miss.exception, EnumValueError)

    def test_localized_routing_status(self) -> None:
        """A pure re-parent whose own :meth:`_missing_` always raises
        :exc:`EnumValueError` directly -- the base's ``get`` re-raises it
        unchanged rather than wrapping it, since it is already a
        :exc:`~pcapkit.utilities.exceptions.BaseError`."""
        from pcapkit.protocols.internet.mh import LocalizedRoutingStatus

        with self.assertRaises(KeyError) as name_miss:
            LocalizedRoutingStatus.get('NOT_A_REAL_MEMBER')
        self.assertIsInstance(name_miss.exception, EnumKeyError)

        with self.assertRaises(ValueError) as value_miss:
            LocalizedRoutingStatus.get(1 << 70)
        self.assertIsInstance(value_miss.exception, EnumValueError)

    def test_lma_address_code(self) -> None:
        from pcapkit.protocols.internet.mh import LMAAddressCode

        with self.assertRaises(KeyError) as name_miss:
            LMAAddressCode.get('NOT_A_REAL_MEMBER')
        self.assertIsInstance(name_miss.exception, EnumKeyError)

        with self.assertRaises(ValueError) as value_miss:
            LMAAddressCode.get(1 << 70)
        self.assertIsInstance(value_miss.exception, EnumValueError)


class KeptOverrideQuietnessTests(unittest.TestCase):
    """The now-quiet raise of the two kept ``get`` overrides, and the new
    way this re-parenting opens to reach it.

    :meth:`FastBindingAcknowledgmentStatus.get` and
    :meth:`IPv6AddressPrefixCode.get` used to raise **loud** on a name
    miss -- logging once at :data:`logging.CRITICAL` and setting
    :data:`sys.tracebacklimit` to ``0`` process-wide, unlike the base's own
    quiet raise at :meth:`~pcapkit.corekit.enum.EnumLookup.get`
    (:mod:`pcapkit.corekit.enum`). GitHub issue #930 converges both onto
    that quiet shape instead, settled on GitHub issue #933's follow-up
    ruling, verbatim: *"Oh wait. I meant, they should follow house
    convention and not to be loud."* (An earlier message on the same issue
    said the opposite -- plain *"No."* -- and an earlier revision of this
    file briefly pinned loud as the settled answer on the strength of that
    message; the follow-up four minutes later superseded it, and what
    follows is the corrected version.)

    Both halves are pinned quiet, and for two different reasons against the
    reverted tree. :meth:`test_get_is_now_quiet_on_both_classes` covers
    ``get`` itself, which existed and was already loud on the tree before
    this issue -- so this test fails against that reverted tree not because
    ``get`` is structurally different there, but because its behaviour
    genuinely changes: reverted, it is loud; here, it is quiet.
    :meth:`test_get_all_is_new_and_quiet_too` covers
    :meth:`~pcapkit.corekit.enum.EnumLookup.get_all`, which did not exist
    on either class before #930 at all and is now inherited from the base,
    calling this same ``get`` internally -- so a miss reached through
    ``get_all`` is quiet for the same reason ``get`` itself is, and this
    test fails against the reverted tree with ``AttributeError`` before it
    ever reaches the quietness assertion.
    """

    def setUp(self) -> None:
        self._saved_tracebacklimit = getattr(sys, 'tracebacklimit', None)

    def tearDown(self) -> None:
        if self._saved_tracebacklimit is None:
            if hasattr(sys, 'tracebacklimit'):
                del sys.tracebacklimit
        else:
            sys.tracebacklimit = self._saved_tracebacklimit

    def test_get_is_now_quiet_on_both_classes(self) -> None:
        """The behaviour GitHub issue #930 actually changes: ``get`` was
        loud on the tree before this issue (see the class docstring) and
        is quiet now, matching the base."""
        from pcapkit.protocols.internet.mh import (FastBindingAcknowledgmentStatus,
                                                   IPv6AddressPrefixCode)

        for cls in (FastBindingAcknowledgmentStatus, IPv6AddressPrefixCode):
            with self.subTest(cls=cls.__name__):
                if hasattr(sys, 'tracebacklimit'):
                    del sys.tracebacklimit
                with capture(logger) as recorder:
                    with self.assertRaises(EnumKeyError):
                        cls.get('NOT_A_REAL_MEMBER')
                self.assertFalse(hasattr(sys, 'tracebacklimit'))
                self.assertEqual(recorder.messages, [])

    def test_get_all_is_new_and_quiet_too(self) -> None:
        """The half this issue adds outright: ``get_all`` did not exist on
        either class before, and the miss it now reaches through this same
        ``get`` is quiet for the same reason ``get`` itself is."""
        from pcapkit.protocols.internet.mh import (FastBindingAcknowledgmentStatus,
                                                   IPv6AddressPrefixCode)

        for cls in (FastBindingAcknowledgmentStatus, IPv6AddressPrefixCode):
            with self.subTest(cls=cls.__name__):
                # Not merely present: it resolves through this class's own
                # kept ``get`` rather than some other path -- ``get_all``
                # calls ``cls.get(key)`` and wraps the canonical member in a
                # one-item tuple (see ``EnumLookup.get_all``).
                member = next(iter(cls))
                self.assertEqual(cls.get_all(member.name), (member,))

                if hasattr(sys, 'tracebacklimit'):
                    del sys.tracebacklimit
                with capture(logger) as recorder:
                    with self.assertRaises(EnumKeyError):
                        cls.get_all('NOT_A_REAL_MEMBER')
                self.assertFalse(hasattr(sys, 'tracebacklimit'))
                self.assertEqual(recorder.messages, [])


class PureReparentClassmethodTests(unittest.TestCase):
    """The five pure re-parents inherit the base's ``classmethod`` outright,
    having defined no ``get`` of their own to begin with -- unlike
    :class:`FastBindingAcknowledgmentStatus` and
    :class:`IPv6AddressPrefixCode`, whose kept ``get`` overrides stay
    :class:`staticmethod` and are pinned alongside their base-tuple change in
    :class:`ReparentedBasesTests` instead, since a test that only checked the
    decorator would pass identically before and after this change and pin
    nothing about it.
    """

    def test_the_five_pure_reparents_inherit_the_bare_classmethod(self) -> None:
        from pcapkit.const.ftp.command import CommandType, ConformanceRequirement
        from pcapkit.protocols.internet.esp import ESPStatus
        from pcapkit.protocols.internet.mh import LMAAddressCode, LocalizedRoutingStatus

        for cls in (CommandType, ConformanceRequirement, ESPStatus,
                    LocalizedRoutingStatus, LMAAddressCode):
            with self.subTest(cls=cls.__name__):
                self.assertIsInstance(inspect.getattr_static(cls, 'get'), classmethod)
                # Inherited, not redeclared: the class's own ``__dict__`` carries no
                # ``get`` of its own, which is the difference between a pure
                # re-parent and a kept-and-converted override.
                self.assertNotIn('get', vars(cls))


class ZeroRemainOutsideEnumLookupTests(unittest.TestCase):
    """The census this issue exists to finish: a runtime walk over every
    importable :mod:`pcapkit.*` module (vendor templates excluded), filtering
    on ``issubclass(cls, EnumLookup)``, must now find **zero** enumerations
    outside the hierarchy -- the assertion that stops this recurring a
    fourth time. Nested classes are walked too, since GitHub issue #877's own
    count of 24 non-registry enumerations includes the seven ``httpv2``
    ``Flags`` classes nested inside schema classes.
    """

    def test_the_walk_found_something_to_count(self) -> None:
        """Guards the assertion below from passing on an empty discovery."""
        self.assertGreater(len(self._every_enum()), 100)

    def test_zero_enumerations_remain_outside_the_hierarchy(self) -> None:
        outside = [name for cls, name in self._every_enum().items()
                  if not issubclass(cls, EnumLookup)]
        self.assertEqual(outside, [], f'still outside EnumLookup: {sorted(outside)}')

    @staticmethod
    def _every_enum() -> 'dict[type, str]':
        """Every :class:`~enum.Enum`/:class:`~aenum.Enum` :mod:`pcapkit` defines,
        nested ones included, skipping :mod:`pcapkit.vendor`.

        Returns:
            Each enumeration mapped to its dotted qualified name.

        """
        import enum

        import aenum

        import pcapkit

        for module_info in pkgutil.walk_packages(pcapkit.__path__, 'pcapkit.'):
            if module_info.name.startswith('pcapkit.vendor'):
                continue
            importlib.import_module(module_info.name)

        found = {}  # type: dict[type, str]
        visited = set()  # type: set[type]

        def walk(container: 'type') -> None:
            if container in visited:
                return
            visited.add(container)
            for value in vars(container).values():
                if not isinstance(value, type):
                    continue
                if not getattr(value, '__module__', '').startswith('pcapkit'):
                    continue
                if value.__module__.startswith('pcapkit.vendor'):
                    continue
                if issubclass(value, (enum.Enum, aenum.Enum)):
                    found.setdefault(value, f'{value.__module__}.{value.__qualname__}')
                walk(value)

        import sys

        for name, module in list(sys.modules.items()):
            if not name.startswith('pcapkit') or name.startswith('pcapkit.vendor'):
                continue
            for value in vars(module).values():
                if not isinstance(value, type):
                    continue
                if not getattr(value, '__module__', '').startswith('pcapkit'):
                    continue
                if issubclass(value, (enum.Enum, aenum.Enum)):
                    found.setdefault(value, f'{value.__module__}.{value.__qualname__}')
                walk(value)
        return found


if __name__ == '__main__':
    unittest.main()
