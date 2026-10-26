# -*- coding: utf-8 -*-
"""GitHub issue #930, the blocked half of #877's phase 2: re-parenting the last
non-registry enumerations onto :class:`~pcapkit.corekit.enum.EnumLookup`.

GitHub pull request #921 re-parented every other non-registry enumeration and left these
alone, because the files holding them were open under other pull requests:
:mod:`pcapkit.const.ftp.command` (``CommandType``, ``ConformanceRequirement``) under #913,
and :mod:`pcapkit.protocols.internet.esp` (``ESPStatus``) plus
:mod:`pcapkit.protocols.internet.mh` (``FastBindingAcknowledgmentStatus``,
``IPv6AddressPrefixCode``, ``LMAAddressCode``, ``LocalizedRoutingStatus``) under #904. This
module pins that they derive from the base, so that every non-registry enumeration is
inside the hierarchy and none is outside it.

None of these declares a ``get`` of its own: ``get`` and ``get_all`` come from the base
alone. For :class:`FastBindingAcknowledgmentStatus` and :class:`IPv6AddressPrefixCode` that
is GitHub issue #935's ruling, given on GitHub pull request #940: a hand-rolled override
there resolves by :class:`int` or by name exactly as
:meth:`~pcapkit.corekit.enum.EnumLookup.get` does -- neither class mints an alias, and
``__members__`` and ``list(cls)`` agree -- so the owner preferred no override to one widened
to accept ``default``. A one-argument :class:`staticmethod` override is a poor fit for the
base in two ways: it advertises the base's ``get(key, default)`` through inheritance while
raising :exc:`TypeError` on a ``default``, and calling ``super().get(...)`` from it raises
:exc:`RuntimeError: super(): no arguments` -- the shape GitHub issue #908 found dangerous
once a base ``get`` is a :class:`classmethod`.

Inheriting the base's ``get`` also settles how a key of a third type is answered. An
override branching on ``isinstance(key, int)`` routes every other type -- ``None``, a
:class:`float`, ... -- through its own *name* path and answers with an
:exc:`~pcapkit.utilities.exceptions.EnumKeyError`, while the base, branching on
``isinstance(key, str)`` instead, answers with an
:exc:`~pcapkit.utilities.exceptions.EnumValueError`.
:class:`NonCanonicalKeyConvergenceTests` pins that they all answer such a key alike.

:meth:`~pcapkit.corekit.enum.EnumLookup.get_all`, inherited from the base, calls ``get``
internally, so a name miss reached through it is as quiet as one reached through ``get``.
GitHub issue #933 settled that these classes follow the library's house convention for a
name miss -- the base's quiet raise -- rather than logging at :data:`logging.CRITICAL` as a
special case; :class:`InheritedQuietnessTests` pins it.

:class:`CommandType`, :class:`LocalizedRoutingStatus` and :class:`LMAAddressCode` carry
their own ``_missing_`` range guards, which :class:`EnumLookup` does not override, so the
re-parent cannot change what they do.

Without the re-parenting, every ``.get(...)`` call below fails with
``AttributeError: type object '<Name>' has no attribute 'get'`` on the classes that declare
no ``get``, and every base-tuple assertion in :class:`ReparentedBasesTests` fails since
:class:`~pcapkit.corekit.enum.EnumLookup` is in none of these classes' ``__bases__`` or
MRO -- :meth:`ReparentedBasesTests.test_command_type`, for one::

    AssertionError: Tuples differ: (<aenum 'IntFlag'>,) != (<class 'pcapkit.corekit.enum.EnumLookup'>, <aenum 'IntFlag'>)

    First differing element 0:
    <aenum 'IntFlag'>
    <class 'pcapkit.corekit.enum.EnumLookup'>

    Second tuple contains 1 additional elements.
    First extra element 1:
    <aenum 'IntFlag'>

    - (<aenum 'IntFlag'>,)
    + (<class 'pcapkit.corekit.enum.EnumLookup'>, <aenum 'IntFlag'>)

:meth:`ZeroRemainOutsideEnumLookupTests.test_the_walk_found_something_to_count` holds either
way: it keeps the census assertion from passing vacuously on an empty discovery.

"""
from __future__ import annotations

import importlib
import inspect
import pkgutil
import sys
import unittest

from pcapkit.utilities.logging import logger
from tests.utilities._harness import capture

# EnumLookup and the enum exceptions are imported in each test, not here
# (#2115): an earlier module in the same process may re-import pcapkit, and they
# have to come from the same import as the class under test. ``logger`` is a
# named logging.getLogger() logger, the same object in every import.

#: Test tier (#1958): exercises threading, locking or warning and exception hooks, which
#: differ by interpreter.
__tier__ = 'ALL'

__all__ = [
    'ReparentedBasesTests', 'GetByNameAndValueTests', 'FailedLookupTests',
    'InheritedQuietnessTests', 'NoMintingTests', 'EachInheritsTheBareClassmethodTests',
    'NonCanonicalKeyConvergenceTests', 'ZeroRemainOutsideEnumLookupTests',
]


class ReparentedBasesTests(unittest.TestCase):
    """Each of these has :class:`EnumLookup` as a base, mixed in *ahead of*
    its enum base so ``_member_type_`` still resolves to :class:`int`, and
    none has a member the re-parent minted -- this issue's own brief is
    explicit that a re-parent minting one silently is exactly the defect
    this programme exists to prevent, so each test below pins both in one
    place rather than trusting that a passing base-tuple assertion says
    anything about the member table. ``__members__`` (which counts aliases)
    and ``list(cls)`` (which does not) are pinned separately, since the two
    diverge on :class:`CommandType`: its ``undefined = 0`` member is a real,
    named member -- not an alias -- but :class:`~aenum.Flag` iteration omits
    the zero value by convention, the same way it always has.
    """

    def test_command_type(self) -> None:
        from aenum import IntFlag

        from pcapkit.const.ftp.command import CommandType
        from pcapkit.corekit.enum import EnumLookup

        self.assertEqual(CommandType.__bases__, (EnumLookup, IntFlag))
        self.assertIn(EnumLookup, CommandType.__mro__)
        self.assertEqual(len(CommandType.__members__), 4)
        self.assertEqual(len(list(CommandType)), 3)

    def test_conformance_requirement(self) -> None:
        from aenum import IntEnum

        from pcapkit.const.ftp.command import ConformanceRequirement
        from pcapkit.corekit.enum import EnumLookup

        self.assertEqual(ConformanceRequirement.__bases__, (EnumLookup, IntEnum))
        self.assertIn(EnumLookup, ConformanceRequirement.__mro__)
        self.assertEqual(len(ConformanceRequirement.__members__), 3)
        self.assertEqual(len(list(ConformanceRequirement)), 3)

    def test_esp_status(self) -> None:
        import enum

        from pcapkit.corekit.enum import EnumLookup
        from pcapkit.protocols.internet.esp import ESPStatus

        self.assertEqual(ESPStatus.__bases__, (EnumLookup, enum.IntEnum))
        self.assertIn(EnumLookup, ESPStatus.__mro__)
        self.assertEqual(len(ESPStatus.__members__), 6)
        self.assertEqual(len(list(ESPStatus)), 6)

    def test_fast_binding_acknowledgment_status(self) -> None:
        """No ``get`` override to pin here (GitHub pull request #940) --
        :class:`EachInheritsTheBareClassmethodTests` covers this class
        alongside the others."""
        from aenum import IntEnum

        from pcapkit.corekit.enum import EnumLookup
        from pcapkit.protocols.internet.mh import FastBindingAcknowledgmentStatus

        self.assertEqual(FastBindingAcknowledgmentStatus.__bases__, (EnumLookup, IntEnum))
        self.assertIn(EnumLookup, FastBindingAcknowledgmentStatus.__mro__)
        self.assertEqual(len(FastBindingAcknowledgmentStatus.__members__), 6)
        self.assertEqual(len(list(FastBindingAcknowledgmentStatus)), 6)

    def test_ipv6_address_prefix_code(self) -> None:
        """Same as for :class:`FastBindingAcknowledgmentStatus`."""
        from aenum import IntEnum

        from pcapkit.corekit.enum import EnumLookup
        from pcapkit.protocols.internet.mh import IPv6AddressPrefixCode

        self.assertEqual(IPv6AddressPrefixCode.__bases__, (EnumLookup, IntEnum))
        self.assertIn(EnumLookup, IPv6AddressPrefixCode.__mro__)
        self.assertEqual(len(IPv6AddressPrefixCode.__members__), 4)
        self.assertEqual(len(list(IPv6AddressPrefixCode)), 4)

    def test_localized_routing_status(self) -> None:
        from aenum import IntEnum

        from pcapkit.corekit.enum import EnumLookup
        from pcapkit.protocols.internet.mh import LocalizedRoutingStatus

        self.assertEqual(LocalizedRoutingStatus.__bases__, (EnumLookup, IntEnum))
        self.assertIn(EnumLookup, LocalizedRoutingStatus.__mro__)
        self.assertEqual(len(LocalizedRoutingStatus.__members__), 3)
        self.assertEqual(len(list(LocalizedRoutingStatus)), 3)

    def test_lma_address_code(self) -> None:
        from aenum import IntEnum

        from pcapkit.corekit.enum import EnumLookup
        from pcapkit.protocols.internet.mh import LMAAddressCode

        self.assertEqual(LMAAddressCode.__bases__, (EnumLookup, IntEnum))
        self.assertIn(EnumLookup, LMAAddressCode.__mro__)
        self.assertEqual(len(LMAAddressCode.__members__), 3)
        self.assertEqual(len(list(LMAAddressCode)), 3)


class NoMintingTests(unittest.TestCase):
    """None of these mints on a miss, exercised through ``get`` itself
    rather than only through the static counts above."""

    def test_a_battery_of_lookups_grows_no_registry(self) -> None:
        """None of these mints on a miss -- each is a closed set on the
        bare lookup tier, not the mutating
        :class:`~pcapkit.corekit.enum.EnumRegistry` one. Exercises every
        ``get`` (name hit, value hit, name miss, value miss) and then
        re-checks every size against the values pinned above, in the same
        process and without subprocess isolation: unlike a registry whose
        ``_missing_`` mints a placeholder, every one of these either
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
    """``get`` resolves by name and by value on each of these, uniformly
    through the base's own inherited implementation -- none of them carries
    an override (GitHub issue #935)."""

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
    """What a miss raises on each of these -- a name miss is
    :exc:`KeyError`-derived and a value miss :exc:`ValueError`-derived,
    matching stdlib :class:`~enum.Enum`'s own shape (GitHub issue #923) on
    every one of them, uniformly through the base's own ``get`` (GitHub
    issue #935).
    """

    def test_command_type(self) -> None:
        from pcapkit.const.ftp.command import CommandType
        from pcapkit.utilities.exceptions import EnumKeyError, EnumValueError

        with self.assertRaises(KeyError) as name_miss:
            CommandType.get('NOT_A_REAL_MEMBER')
        self.assertIsInstance(name_miss.exception, EnumKeyError)

        with self.assertRaises(ValueError) as value_miss:
            CommandType.get(1 << 70)
        self.assertIsInstance(value_miss.exception, EnumValueError)

    def test_conformance_requirement(self) -> None:
        from pcapkit.const.ftp.command import ConformanceRequirement
        from pcapkit.utilities.exceptions import EnumKeyError, EnumValueError

        with self.assertRaises(KeyError) as name_miss:
            ConformanceRequirement.get('NOT_A_REAL_MEMBER')
        self.assertIsInstance(name_miss.exception, EnumKeyError)

        with self.assertRaises(ValueError) as value_miss:
            ConformanceRequirement.get(1 << 70)
        self.assertIsInstance(value_miss.exception, EnumValueError)

    def test_esp_status(self) -> None:
        from pcapkit.protocols.internet.esp import ESPStatus
        from pcapkit.utilities.exceptions import EnumKeyError, EnumValueError

        with self.assertRaises(KeyError) as name_miss:
            ESPStatus.get('NOT_A_REAL_MEMBER')
        self.assertIsInstance(name_miss.exception, EnumKeyError)

        with self.assertRaises(ValueError) as value_miss:
            ESPStatus.get(1 << 70)
        self.assertIsInstance(value_miss.exception, EnumValueError)

    def test_fast_binding_acknowledgment_status(self) -> None:
        """Resolves through the base's own ``get`` (GitHub issue #935) -- the
        same mechanism :meth:`test_localized_routing_status` below
        exercises."""
        from pcapkit.protocols.internet.mh import FastBindingAcknowledgmentStatus
        from pcapkit.utilities.exceptions import EnumKeyError, EnumValueError

        with self.assertRaises(KeyError) as name_miss:
            FastBindingAcknowledgmentStatus.get('NOT_A_REAL_MEMBER')
        self.assertIsInstance(name_miss.exception, EnumKeyError)

        with self.assertRaises(ValueError) as value_miss:
            FastBindingAcknowledgmentStatus.get(1 << 70)
        self.assertIsInstance(value_miss.exception, EnumValueError)

    def test_ipv6_address_prefix_code(self) -> None:
        from pcapkit.protocols.internet.mh import IPv6AddressPrefixCode
        from pcapkit.utilities.exceptions import EnumKeyError, EnumValueError

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
        from pcapkit.utilities.exceptions import EnumKeyError, EnumValueError

        with self.assertRaises(KeyError) as name_miss:
            LocalizedRoutingStatus.get('NOT_A_REAL_MEMBER')
        self.assertIsInstance(name_miss.exception, EnumKeyError)

        with self.assertRaises(ValueError) as value_miss:
            LocalizedRoutingStatus.get(1 << 70)
        self.assertIsInstance(value_miss.exception, EnumValueError)

    def test_lma_address_code(self) -> None:
        from pcapkit.protocols.internet.mh import LMAAddressCode
        from pcapkit.utilities.exceptions import EnumKeyError, EnumValueError

        with self.assertRaises(KeyError) as name_miss:
            LMAAddressCode.get('NOT_A_REAL_MEMBER')
        self.assertIsInstance(name_miss.exception, EnumKeyError)

        with self.assertRaises(ValueError) as value_miss:
            LMAAddressCode.get(1 << 70)
        self.assertIsInstance(value_miss.exception, EnumValueError)


class InheritedQuietnessTests(unittest.TestCase):
    """The quiet raise :class:`FastBindingAcknowledgmentStatus` and
    :class:`IPv6AddressPrefixCode` answer a name miss with, and
    :meth:`~pcapkit.corekit.enum.EnumLookup.get_all`, the path the
    re-parenting opens to reach it -- both inherited from the base
    (:mod:`pcapkit.corekit.enum`) rather than reconciled by a hand-rolled
    override.

    Without the fix, ``get`` on both classes raises **loud** -- logging once
    at :data:`logging.CRITICAL` and setting :data:`sys.tracebacklimit` to
    ``0`` process-wide on a name miss, unlike the base's own quiet raise.
    GitHub issue #933 settled that the two follow house convention and are
    not loud.

    :meth:`test_get_is_quiet_on_both_classes` covers ``get`` itself, and
    :meth:`test_get_all_is_new_and_quiet_too` covers ``get_all``, which calls
    this same ``get`` internally -- so a miss reached through ``get_all`` is
    quiet for the same reason ``get`` itself is.
    """

    def setUp(self) -> None:
        self._saved_tracebacklimit = getattr(sys, 'tracebacklimit', None)

    def tearDown(self) -> None:
        if self._saved_tracebacklimit is None:
            if hasattr(sys, 'tracebacklimit'):
                del sys.tracebacklimit
        else:
            sys.tracebacklimit = self._saved_tracebacklimit

    def test_get_is_quiet_on_both_classes(self) -> None:
        """The behaviour GitHub issue #930 pins: ``get`` is quiet, matching
        the base, where without the fix it is loud (see the class
        docstring)."""
        from pcapkit.protocols.internet.mh import (FastBindingAcknowledgmentStatus,
                                                   IPv6AddressPrefixCode)
        from pcapkit.utilities.exceptions import EnumKeyError

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
        """``get_all`` exists on both classes, and the miss it reaches through
        this same ``get`` is quiet for the same reason ``get`` itself is."""
        from pcapkit.protocols.internet.mh import (FastBindingAcknowledgmentStatus,
                                                   IPv6AddressPrefixCode)
        from pcapkit.utilities.exceptions import EnumKeyError

        for cls in (FastBindingAcknowledgmentStatus, IPv6AddressPrefixCode):
            with self.subTest(cls=cls.__name__):
                # Not merely present: it resolves through ``get`` rather than
                # some other path -- ``get_all``
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
        """The base's own ``get`` (:mod:`pcapkit.corekit.enum`) accepts
        ``default``; a name miss whose ``default`` does not itself resolve
        falls through to the same quiet
        :exc:`~pcapkit.utilities.exceptions.EnumKeyError` a bare miss
        raises -- not a new, louder path. A one-argument override raises
        ``TypeError`` on the second positional argument instead (GitHub
        issue #935).
        """
        from pcapkit.protocols.internet.mh import (FastBindingAcknowledgmentStatus,
                                                   IPv6AddressPrefixCode)
        from pcapkit.utilities.exceptions import EnumKeyError

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


class EachInheritsTheBareClassmethodTests(unittest.TestCase):
    """Each inherits the base's ``classmethod`` outright, none
    declaring a ``get`` of its own.

    For :class:`FastBindingAcknowledgmentStatus` and
    :class:`IPv6AddressPrefixCode` that is the owner's ruling on GitHub pull
    request #940 -- no override rather than one widened to accept
    ``default`` -- so they are one uniform case. A test that only checked
    the decorator would pass identically whether an override were kept or
    converted, so this also asserts that ``get`` is absent from each class's
    own ``__dict__``.
    """

    def test_each_inherits_the_bare_classmethod(self) -> None:
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
                # no ``get`` of its own -- which holds for each of them alike.
                self.assertNotIn('get', vars(cls))


class NonCanonicalKeyConvergenceTests(unittest.TestCase):
    """The point of GitHub issue #935's final ruling, made literally true:
    ``get(None)`` and ``get(1.5)`` answer alike on every one of them.

    An override branching on ``isinstance(key, int)`` routes every other
    type through its own *name* path -- so a key that is neither an
    :class:`int` nor a :class:`str` falls through to a subscript lookup that
    always misses, answering with a quiet
    :exc:`~pcapkit.utilities.exceptions.EnumKeyError`. The base
    (:mod:`pcapkit.corekit.enum`) branches on ``isinstance(key, str)``
    instead, so the same key falls through to
    :meth:`~pcapkit.corekit.enum.EnumLookup._validate_value` and the
    constructor, reaching :meth:`_missing_` and answering with an
    :exc:`~pcapkit.utilities.exceptions.EnumValueError`. With no override,
    they all answer both keys the same way -- measured here rather than
    assumed, since "they all behave alike" is exactly the claim GitHub issue
    #935 set out to make true.

    Scope, stated as narrowly as the evidence supports: what this settles is
    the exception a key of some third type raises. Whether any caller passes
    one is not established -- a key reaching ``get`` through a variable
    cannot be read off a search of the tree -- so this test pins the
    converged behaviour directly rather than resting on the divergence being
    unreachable.
    """

    def test_none_and_float_keys_all_raise_enumvalueerror(self) -> None:
        from pcapkit.const.ftp.command import CommandType, ConformanceRequirement
        from pcapkit.protocols.internet.esp import ESPStatus
        from pcapkit.protocols.internet.mh import (FastBindingAcknowledgmentStatus,
                                                   IPv6AddressPrefixCode, LMAAddressCode,
                                                   LocalizedRoutingStatus)
        from pcapkit.utilities.exceptions import EnumValueError

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
    on ``issubclass(cls, EnumLookup)``, must find **zero** enumerations
    outside the hierarchy -- the assertion that stops this recurring yet
    again. Nested classes are walked too, since GitHub issue #877's own
    census of non-registry enumerations includes the ``httpv2`` ``Flags``
    classes nested inside schema classes.
    """

    def test_the_walk_found_something_to_count(self) -> None:
        """Guards the assertion below from passing on an empty discovery."""
        self.assertGreater(len(self._every_enum()), 100)

    def test_zero_enumerations_remain_outside_the_hierarchy(self) -> None:
        from pcapkit.corekit.enum import EnumLookup

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
