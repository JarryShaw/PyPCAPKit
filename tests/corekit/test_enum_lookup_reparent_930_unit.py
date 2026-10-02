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
:class:`IPv6AddressPrefixCode`, defined their own ``get`` at #930's own revision -- both as
a :class:`staticmethod`, the exact shape GitHub issue #908 found dangerous once a base
``get`` becomes a :class:`classmethod`: calling ``super().get(...)`` from a
``staticmethod`` raises :exc:`RuntimeError: super(): no arguments`. Neither override
called ``super()`` at all, so the trap never fired, and per this issue's own brief they
were left **untouched** there -- their ``except KeyError: raise EnumKeyError(...)``
conversions were put there by GitHub issue #923 and already answered a name miss in
exactly the shape the base now uses. Keeping the plain ``@staticmethod`` cost something at
that revision, though: re-parenting made both **advertise** the base's two-argument
``get(key, default)`` through inheritance while still only accepting one, so a ``default``
argument raised :exc:`TypeError` instead of resolving through the base's own fallback, and
``mypy``'s ``[override]`` check plus ``pylint``'s ``arguments-differ`` both flagged the
resulting shape mismatch, silenced with a suppression. GitHub issue #935 first answered
that on the owner's ruling, verbatim: *"I lean on 1"* -- widen both signatures to accept
``default`` and delete the suppression. Asked, on GitHub pull request #940 -- which was
implementing that widening -- *"why must we have the two overrides tho? cant they directly
fall back to the base class's?"*, the owner's final ruling went further, verbatim: *"I
prefer (2) directly"* -- deleting both overrides outright rather than widening them.

Measured before acting on that final ruling: neither override ever minted an alias --
``__members__`` and ``list(cls)`` agree at 6 and 4 -- so what each docstring called
"Backport support for original codes" was the int-or-name dual resolution
:meth:`~pcapkit.corekit.enum.EnumLookup.get` already provides for every other
:class:`int`-valued registry in this tree, and none of the 20 call sites either override
had (all in tests, none in :mod:`pcapkit`) passed a key the base would have resolved
differently. There was nothing left to backport, so ``get``/``get_all`` on both now come
from the base alone, the same as the five classes below that were pure re-parents from the
start. :class:`ReparentedBasesTests` used to pin, alongside each class's own base-tuple
change, that the ``@staticmethod`` decorator survived re-parenting and then the signature
widening; now that the method is deleted rather than converted, there is nothing left to
decorate, and :class:`AllSevenInheritTheBareClassmethodTests` covers these two the same way
it always covered the other five.

Deleting the overrides is a real behaviour change, deliberately so: each branched on
``isinstance(key, int)`` and routed every other type -- ``None``, a :class:`float`, ... --
through its own *name* path, so ``get(None)`` and ``get(1.5)`` used to answer with a quiet
:exc:`~pcapkit.utilities.exceptions.EnumKeyError` on these two while the base -- branching
on ``isinstance(key, str)`` instead -- answers every other
:class:`~pcapkit.corekit.enum.EnumLookup` subclass with a loud
:exc:`~pcapkit.utilities.exceptions.EnumValueError`.
:class:`NonCanonicalKeyConvergenceTests` pins the convergence this deletion produces: all
seven now answer such a key alike, for the first time.

Re-parenting separately made both former overrides reachable through a door that did not
exist before: :meth:`~pcapkit.corekit.enum.EnumLookup.get_all`, inherited from the base for
the first time, calls ``get`` internally. Before this issue, that mattered because ``get``
itself raised **loud**: both overrides used to log once at :data:`logging.CRITICAL` and set
:data:`sys.tracebacklimit` to ``0`` process-wide on a name miss, unlike the base's own quiet
raise. GitHub issue #930 converged both onto the base's quiet shape instead -- a real
behaviour change, not merely a re-parent -- settled on GitHub issue #933's follow-up ruling,
verbatim: *"Oh wait. I meant, they should follow house convention and not to be loud."*
:class:`InheritedQuietnessTests` (renamed from ``KeptOverrideQuietnessTests`` once GitHub
issue #935 deleted the overrides that name described) pins that the quiet shape survived
the deletion too -- purely inherited now, rather than reconciled by hand on each class.

The other five -- :class:`CommandType`, :class:`ConformanceRequirement`,
:class:`ESPStatus`, :class:`LocalizedRoutingStatus` and :class:`LMAAddressCode` -- were
pure re-parents from the start: none defines a ``get`` of its own to reconcile with the
base, so each gained ``get``/``get_all`` for the first time in #930. :class:`CommandType`,
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

Neither of the first two methods of :class:`InheritedQuietnessTests` (called
``KeptOverrideQuietnessTests`` at the time this measurement was taken, before GitHub issue
#935 deleted the overrides that name described) holds against the reverted tree, and
deliberately so -- both pin the one thing this issue actually changes about the two
classes' ``get``. ``test_get_is_now_quiet_on_both_classes`` fails against the reverted tree
because ``get`` really was loud there (see that class's own docstring): this is not a
scaffolding failure, it is the behaviour change itself, caught in the act.
``test_get_all_is_new_and_quiet_too`` fails with ``AttributeError`` instead, since
``get_all`` does not exist on the reverted tree at all.

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
    'InheritedQuietnessTests', 'NoMintingTests', 'AllSevenInheritTheBareClassmethodTests',
    'NonCanonicalKeyConvergenceTests', 'ZeroRemainOutsideEnumLookupTests',
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
        """GitHub pull request #940 later deleted its kept ``get`` override
        outright (the owner preferred deleting it to widening it to accept
        ``default``), so the decorator this once pinned no longer exists to
        pin -- :class:`AllSevenInheritTheBareClassmethodTests` now covers this
        class alongside the other six."""
        from aenum import IntEnum

        from pcapkit.protocols.internet.mh import FastBindingAcknowledgmentStatus

        self.assertEqual(FastBindingAcknowledgmentStatus.__bases__, (EnumLookup, IntEnum))
        self.assertIn(EnumLookup, FastBindingAcknowledgmentStatus.__mro__)
        self.assertEqual(len(FastBindingAcknowledgmentStatus.__members__), 6)
        self.assertEqual(len(list(FastBindingAcknowledgmentStatus)), 6)

    def test_ipv6_address_prefix_code(self) -> None:
        """Same history as :class:`FastBindingAcknowledgmentStatus`."""
        from aenum import IntEnum

        from pcapkit.protocols.internet.mh import IPv6AddressPrefixCode

        self.assertEqual(IPv6AddressPrefixCode.__bases__, (EnumLookup, IntEnum))
        self.assertIn(EnumLookup, IPv6AddressPrefixCode.__mro__)
        self.assertEqual(len(IPv6AddressPrefixCode.__members__), 4)
        self.assertEqual(len(list(IPv6AddressPrefixCode)), 4)

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
    """``get`` resolves by name and by value on each of the seven, now
    uniformly through the base's own inherited implementation -- GitHub
    issue #935 deleted the two hand-rolled overrides that used to answer
    this for :class:`FastBindingAcknowledgmentStatus` and
    :class:`IPv6AddressPrefixCode`."""

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
    every one of the seven, now uniformly through the base's own ``get``
    since GitHub issue #935 deleted the two hand-rolled overrides that used
    to answer this for :class:`FastBindingAcknowledgmentStatus` and
    :class:`IPv6AddressPrefixCode`.
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
        """Since GitHub issue #935 deleted its kept override, this now
        resolves through the base's own ``get`` -- the same mechanism
        :meth:`test_localized_routing_status` below exercises."""
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


class InheritedQuietnessTests(unittest.TestCase):
    """The quiet raise :class:`FastBindingAcknowledgmentStatus` and
    :class:`IPv6AddressPrefixCode` answer a name miss with, and the door
    this re-parenting opened to reach it -- both now purely inherited from
    the base rather than reconciled by a hand-rolled override.

    Named for what survives rather than for what used to sit here: this
    class was ``KeptOverrideQuietnessTests`` while both classes still
    carried their own ``get``, first through #930's re-parenting and
    briefly again through GitHub issue #935's first attempt, which widened
    that override to accept ``default`` rather than delete it. The owner's
    final ruling, given on GitHub pull request #940, went the other way: an
    earlier lean on GitHub issue #935 had favoured widening, but on
    reviewing that attempt the owner preferred deleting both overrides
    outright. What this class pins did not change with that deletion -- the
    quiet raise -- only *how* it is produced through
    :meth:`~pcapkit.corekit.enum.EnumLookup.get`
    (:mod:`pcapkit.corekit.enum`) directly now, rather than through an
    override that reconciled itself onto the base's shape.

    Before either override existed, ``get`` on both classes raised
    **loud** -- logging once at :data:`logging.CRITICAL` and setting
    :data:`sys.tracebacklimit` to ``0`` process-wide on a name miss, unlike
    the base's own quiet raise. GitHub issue #930 converged both onto that
    quiet shape instead, settled on GitHub issue #933's follow-up ruling,
    verbatim: *"Oh wait. I meant, they should follow house convention and
    not to be loud."* (An earlier message on the same issue said the
    opposite -- plain *"No."* -- and an earlier revision of this file
    briefly pinned loud as the settled answer on the strength of that
    message; the follow-up four minutes later superseded it, and what
    follows is the corrected version.)

    The first two methods are pinned quiet, and for two different reasons
    against the tree reverted to before #930.
    :meth:`test_get_is_now_quiet_on_both_classes` covers ``get`` itself,
    which existed and was already loud on the tree before that issue -- so
    this test fails against that reverted tree not because ``get`` is
    structurally different there, but because its behaviour genuinely
    changes: reverted, it is loud; here, it is quiet.
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

    def test_get_with_unusable_default_is_quiet_too(self) -> None:
        """The base's own ``get`` (:mod:`pcapkit.corekit.enum`) has always
        accepted ``default``; a name miss whose ``default`` does not itself
        resolve falls through to the same quiet
        :exc:`~pcapkit.utilities.exceptions.EnumKeyError` a bare miss would
        have raised -- not a new, louder path. Before GitHub issue #935
        deleted the two hand-rolled overrides, this same call raised
        ``TypeError`` on a second positional argument instead; between
        #935's first attempt and its final ruling, the overrides answered
        it themselves rather than through this inherited path.
        """
        from pcapkit.protocols.internet.mh import (FastBindingAcknowledgmentStatus,
                                                   IPv6AddressPrefixCode)

        for cls in (FastBindingAcknowledgmentStatus, IPv6AddressPrefixCode):
            with self.subTest(cls=cls.__name__):
                if hasattr(sys, 'tracebacklimit'):
                    del sys.tracebacklimit
                with capture(logger) as recorder:
                    with self.assertRaises(EnumKeyError):
                        cls.get('NOT_A_REAL_MEMBER', 'ALSO_NOT_A_REAL_MEMBER')
                self.assertFalse(hasattr(sys, 'tracebacklimit'))
                self.assertEqual(recorder.messages, [])

                # A default that *does* resolve returns it without raising
                # at all.
                member = next(iter(cls))
                self.assertIs(cls.get('NOT_A_REAL_MEMBER', member), member)


class AllSevenInheritTheBareClassmethodTests(unittest.TestCase):
    """All seven now inherit the base's ``classmethod`` outright, none
    declaring a ``get`` of its own.

    Five were always this way -- pure re-parents, having defined no
    ``get`` of their own to begin with. The other two,
    :class:`FastBindingAcknowledgmentStatus` and
    :class:`IPv6AddressPrefixCode`, joined them only at GitHub pull request #940's
    final revision: their own kept ``get`` stayed a :class:`staticmethod`
    through #930's re-parenting and briefly again through #935's first attempt
    (which widened it to accept ``default`` rather than delete it), and only
    the owner's final ruling on #940 -- outright deletion over widening the
    signature -- removed it, collapsing the seven-way split this
    class used to test as five-plus-two into one uniform case. This class
    was named for the five alone before that ruling, and
    :class:`ReparentedBasesTests` pinned the other two's surviving
    ``@staticmethod`` separately, since a test that only checked the
    decorator would have passed identically whether ``get`` were kept or
    converted, and pinned nothing about which.
    """

    def test_all_seven_inherit_the_bare_classmethod(self) -> None:
        from pcapkit.const.ftp.command import CommandType, ConformanceRequirement
        from pcapkit.protocols.internet.esp import ESPStatus
        from pcapkit.protocols.internet.mh import (FastBindingAcknowledgmentStatus,
                                                   IPv6AddressPrefixCode, LMAAddressCode,
                                                   LocalizedRoutingStatus)

        for cls in (CommandType, ConformanceRequirement, ESPStatus,
                    LocalizedRoutingStatus, LMAAddressCode,
                    FastBindingAcknowledgmentStatus, IPv6AddressPrefixCode):
            with self.subTest(cls=cls.__name__):
                self.assertIsInstance(inspect.getattr_static(cls, 'get'), classmethod)
                # Inherited, not redeclared: the class's own ``__dict__`` carries
                # no ``get`` of its own -- the fact that used to distinguish a
                # pure re-parent from a kept-and-converted override, and now
                # holds for all seven alike.
                self.assertNotIn('get', vars(cls))


class NonCanonicalKeyConvergenceTests(unittest.TestCase):
    """The point of GitHub issue #935's final ruling, made literally true:
    ``get(None)`` and ``get(1.5)`` now answer alike on all seven.

    Before the two overrides were deleted, each branched on
    ``isinstance(key, int)`` and routed every other type through its own
    *name* path -- so a key that is neither an :class:`int` nor a
    :class:`str` fell through to a subscript lookup that always misses,
    answering with a quiet
    :exc:`~pcapkit.utilities.exceptions.EnumKeyError`. The base
    (:mod:`pcapkit.corekit.enum`) branches on ``isinstance(key, str)``
    instead, so the same key falls through to
    :meth:`~pcapkit.corekit.enum.EnumLookup._validate_value` and the
    constructor, reaching :meth:`_missing_` and answering with a loud
    :exc:`~pcapkit.utilities.exceptions.EnumValueError`. Deleting the
    overrides removes the branch that disagreed, so all seven now answer
    both keys the same way -- measured here rather than assumed, since
    "all seven behave alike" is exactly the claim GitHub issue #935 set
    out to make true, and the two overrides are exactly what kept it from
    being true before this.

    Verified before writing this test: no call site in this tree -- tests
    included -- ever passed ``get`` a key that is neither an :class:`int`
    nor a :class:`str`, so this divergence was live on the two overrides
    but never actually reached; its removal changes no behaviour any
    caller in this tree observed, only what a caller passing such a key
    would see.
    """

    def test_none_and_float_keys_all_raise_enumvalueerror(self) -> None:
        from pcapkit.const.ftp.command import CommandType, ConformanceRequirement
        from pcapkit.protocols.internet.esp import ESPStatus
        from pcapkit.protocols.internet.mh import (FastBindingAcknowledgmentStatus,
                                                   IPv6AddressPrefixCode, LMAAddressCode,
                                                   LocalizedRoutingStatus)

        for cls in (CommandType, ConformanceRequirement, ESPStatus,
                    LocalizedRoutingStatus, LMAAddressCode,
                    FastBindingAcknowledgmentStatus, IPv6AddressPrefixCode):
            with self.subTest(cls=cls.__name__, key=None):
                with self.assertRaises(EnumValueError):
                    cls.get(None)
            with self.subTest(cls=cls.__name__, key=1.5):
                with self.assertRaises(EnumValueError):
                    cls.get(1.5)


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
