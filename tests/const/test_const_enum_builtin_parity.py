# -*- coding: utf-8 -*-
"""Every :mod:`pcapkit.const` registry must reject an invalid value the way the built-in does.

GitHub issue #647 counted the generated range guards under :mod:`pcapkit.const`
and found that 113 of the 117 modules raise a bare :exc:`ValueError`. The issue
proposed replacing them with :class:`~pcapkit.utilities.exceptions.EnumError`;
the decision went the other way. A bare :exc:`ValueError` is exactly what
:class:`enum.IntEnum` raises for a value it does not define, mirroring the
built-in is the intent, and
:class:`~pcapkit.utilities.exceptions.EnumError` is ``(BaseError, TypeError)`` --
not a :exc:`ValueError` at all -- so swapping it in would have diverged from the
built-in *and* walked past the ``except ValueError`` in all 113 generated
``get()`` bodies, silently undoing GitHub issue #584.

What was left was the inconsistency. Six registries across four modules did
something other than raise:

* three :class:`~aenum.IntFlag` registries defined no ``_missing_`` at all, so
  ``aenum``'s :class:`~aenum.Flag` machinery composed a pseudo-member for any
  integer whatsoever. ``Flags(-1)`` returned ``65520`` -- the OR of every
  declared TCP header flag -- so a value no 16-bit wire field can hold read back
  as *every flag set at once*, and ``Flags(-65536)`` as *none set*.
* three :class:`~aenum.StrEnum` registries reached ``value.upper()`` in their
  ``_missing_`` before checking the type, so an integer raised
  :exc:`AttributeError` (``'int' object has no attribute 'upper'``) rather than
  :exc:`ValueError`.

All six now carry a guard raising a bare :exc:`ValueError`, emitted by their
templates under :mod:`pcapkit.vendor` rather than hand-written -- the tree is
generated, so a fix that is not in the template is reverted by the next crawl.

The one deliberate divergence from the built-in is preserved and pinned here:
the *mutable* registries look a value up, miss, and then **register** it with
:func:`~aenum.extend_enum` instead of raising. That is the exception the owner
named, and :class:`ConstEnumRegisterFallbackTests` exists so a future guard
cannot quietly turn a registration into a rejection -- the failure mode GitHub
issues #584 and #623 are both about.

The guard for the three flag registries delegates in-range composites to
``super()._missing_`` rather than resolving them itself, because GitHub issue
#623 established that an :class:`~aenum.IntFlag` whose ``_missing_`` re-enters
its own constructor recurses without bound.

"""
from __future__ import annotations

import enum
import importlib
import importlib.util
import inspect
import pkgutil
import re
import sys
import unittest
from typing import TYPE_CHECKING

import aenum

from tests._support import ISOLATED_PREFIXES, purge_modules, restore_modules, snapshot_modules

if TYPE_CHECKING:
    from typing import Optional

#: An integer no wire field in the library is wide enough to carry. Shared with
#: :mod:`tests.const.test_const_enum_get`, which uses the same value for the
#: same reason.
UNRESOLVABLE = 1 << 70

#: The six registries GitHub issue #647 converged, as ``(module, class name,
#: what the pre-fix lookup did with an invalid value)``. Named individually as
#: well as swept, so a regression reports *which* registry came apart rather
#: than only that the sweep shrank.
ISSUE_647_OUTLIERS = (
    ('pcapkit.const.tcp.flags', 'Flags',
     'returned 65520, the OR of every declared TCP header flag'),
    ('pcapkit.const.ftp.command', 'CommandType',
     'returned 7, the OR of A|P|S'),
    ('pcapkit.const.reg.apptype.apptype', 'TransportProtocol',
     'returned 15, the OR of tcp|udp|sctp|dccp'),
    ('pcapkit.const.ftp.command', 'Command',
     "raised AttributeError: 'int' object has no attribute 'upper'"),
    ('pcapkit.const.ftp.command', 'FEATCode',
     "raised AttributeError: 'int' object has no attribute 'upper'"),
    ('pcapkit.const.http.method', 'Method',
     "raised AttributeError: 'int' object has no attribute 'upper'"),
)

#: The registries whose ``_missing_`` ends in :func:`~aenum.extend_enum`, so an
#: unassigned value in their span is *registered* rather than rejected. This is
#: the deliberate divergence from the built-in, not an oversight: their backing
#: registries carry open "Unassigned" spans that a capture can legitimately
#: contain. They still reject a *negative* value, which no span covers.
EXPECTED_TO_REGISTER = frozenset({
    'pcapkit.const.ipv4.protection_authority.ProtectionAuthority',
    'pcapkit.const.mh.cga_type.CGAType',
})

#: The bespoke templates under :mod:`pcapkit.vendor` that carry their own copy of
#: the guard, rather than inheriting the one in :mod:`pcapkit.vendor.default`.
#: Each was rendering a registry that GitHub issue #647 found unguarded.
#:
#: Keyed to each template's own guard text rather than one literal shared by
#: all four: GitHub issue #792 moved ``pcapkit.vendor.reg.apptype.apptype``'s
#: copy to an f-string, following the library-wide convention GitHub issue
#: #783 settled, while the other three still raise with ``%`` -- #792
#: deliberately left them alone so the ``const`` diff stayed reviewable, and
#: #798 tracks sweeping them, along with the ``%``-formatted dunders and
#: dropping the f-string disable. One shared literal can no longer pin all four;
#: what #647 actually needs pinned is that each template still carries *a*
#: guard rejecting an invalid value, in whatever form that template's own
#: raise takes, not that the four agree on a formatting style the library is
#: moving away from.
BESPOKE_TEMPLATES = {
    'pcapkit.vendor.tcp.flags': "raise ValueError('%r is not a valid %s' % (value, cls.__name__))",
    'pcapkit.vendor.ftp.command': "raise ValueError('%r is not a valid %s' % (value, cls.__name__))",
    'pcapkit.vendor.http.method': "raise ValueError('%r is not a valid %s' % (value, cls.__name__))",
    'pcapkit.vendor.reg.apptype.apptype': "raise ValueError(f'{{value!r}} is not a valid {{cls.__name__}}')",
}


class _StdIntEnum(enum.IntEnum):
    """A built-in :class:`enum.IntEnum`, as the reference for what rejection looks like."""

    A = 0


class _StdStrEnum(str, enum.Enum):
    """A built-in string enumeration.

    Spelled ``(str, enum.Enum)`` rather than :class:`enum.StrEnum`, which is
    3.11+, because the CI matrix starts at 3.10.
    """

    A = 'a'


def _iter_const_registries() -> 'list[type]':
    """Every :class:`~aenum.Enum` subclass defined under :mod:`pcapkit.const`.

    Wider than either sweep in :mod:`tests.const.test_const_enum_lookup` --
    which walks the non-flag :class:`~aenum.IntEnum` classes and the
    :class:`~aenum.IntFlag` classes in two separate passes -- and wider than the
    one in :mod:`tests.const.test_const_enum_get`, which takes both but not the
    :class:`~aenum.StrEnum` registries. Rejecting an invalid value is a contract
    all three kinds share, so all three are swept here.

    Keyed on :class:`~aenum.Enum` deliberately: ``issubclass(aenum.IntFlag,
    aenum.IntEnum)`` is :data:`False`, because an
    :class:`~aenum.IntFlag`'s MRO runs through :class:`~aenum.Flag` rather than
    :class:`~aenum.IntEnum`, so a sweep written against
    :class:`~aenum.IntEnum` silently skips every flag registry -- which is how
    GitHub issue #623 survived the sweep in
    :mod:`tests.const.test_const_enum_lookup` and how three of issue #647's six
    outliers survived the one in :mod:`tests.const.test_const_enum_get`.

    Collects only classes *defined* in the module being walked, so a
    re-exported registry is counted once.

    Returns:
        The discovered enum classes, in walk order.

    """
    import pcapkit.const as const_pkg

    classes = []  # type: list[type]
    for module_info in pkgutil.walk_packages(const_pkg.__path__, const_pkg.__name__ + '.'):
        module = importlib.import_module(module_info.name)
        for _, obj in vars(module).items():
            if (inspect.isclass(obj) and issubclass(obj, aenum.Enum)
                    and obj.__module__ == module_info.name):
                classes.append(obj)
    return classes


def _qualname(obj: 'type') -> 'str':
    """The fully qualified name used as a sweep key."""
    return f'{obj.__module__}.{obj.__qualname__}'


def _raised_by(obj: 'type', value: 'object') -> 'Optional[type]':
    """The exception type ``obj(value)`` raises, or :data:`None` if it returns.

    Args:
        obj: Enumeration class to look a value up in.
        value: Value to look up.

    Returns:
        The exception's type, or :data:`None` when the lookup resolved.

    """
    try:
        obj(value)
    except BaseException as error:  # pylint: disable=broad-except
        return type(error)
    return None


class ConstEnumBuiltinParityTests(unittest.TestCase):
    """An invalid value must be rejected with the built-in's own exception."""

    if TYPE_CHECKING:
        enums: 'list[type]'

    @classmethod
    def setUpClass(cls) -> None:
        snapshot = snapshot_modules(ISOLATED_PREFIXES)
        purge_modules(['pcapkit'])
        cls.enums = _iter_const_registries()
        # The out-of-range probe below registers a junk member on the two
        # auto-extending registries, which are module-global classes. Restore
        # the region to what it held before this class purged it, rather than
        # purging again (as this used to do, GitHub issue #720): a second purge
        # cannot achieve "pollution cannot reach another module" -- it just
        # leaves the region empty for whoever runs next, exactly the gap #720
        # reports, whereas restoring rebinds it straight back to the pristine,
        # pre-purge modules so the polluted ones are unreachable.
        cls.addClassCleanup(restore_modules, snapshot, ISOLATED_PREFIXES)

    def test_the_sweep_size_is_pinned(self) -> None:
        """A registry added or removed needs a fresh look, not a silent pass."""
        flags = [obj for obj in self.enums if issubclass(obj, aenum.Flag)]
        strs = [obj for obj in self.enums
                if issubclass(obj, str) and not issubclass(obj, aenum.Flag)]
        ints = [obj for obj in self.enums
                if issubclass(obj, int) and not issubclass(obj, aenum.Flag)]

        # The decomposition is asserted, not just the total, so this sweep stays
        # in step with the three narrower ones it overlaps: 111 non-flag IntEnum
        # and 7 IntFlag in tests.const.test_const_enum_lookup, and 118 -- their
        # sum -- in tests.const.test_const_enum_get.
        #
        # Five of the nine string registries are the application layer one, which
        # GitHub issue #732 split into a package: the memberless
        # pcapkit.const.reg.apptype.apptype.AppType base plus one registry per
        # transport protocol. It is discovered exactly like a member-bearing
        # registry, since this sweep is structural and never looks at members.
        self.assertEqual(len(ints), 111)
        self.assertEqual(len(flags), 7)
        self.assertEqual(len(strs), 9)
        self.assertEqual(len(self.enums), 127)
        self.assertEqual(len({obj.__module__ for obj in self.enums}), 121)

    def test_every_registry_rejects_a_negative_value(self) -> None:
        """The registry-wide form of GitHub issue #647.

        No wire field the library parses is signed, so ``-1`` is invalid for
        every registry in the tree -- including the mutable ones, whose
        "Unassigned" spans are non-negative.
        """
        for obj in self.enums:
            with self.subTest(enum=_qualname(obj)):
                raised = _raised_by(obj, -1)
                self.assertIsNotNone(
                    raised, f'{_qualname(obj)}(-1) resolved instead of raising; '
                            f'see GitHub issue #647')
                self.assertIs(
                    raised, ValueError,
                    f'{_qualname(obj)}(-1) raised {raised.__name__ if raised else None} '
                    f'rather than the built-in ValueError; see GitHub issue #647')

    def test_the_exception_type_matches_the_built_in_enum(self) -> None:
        """The property GitHub issue #647 settled on, asserted directly.

        A :mod:`pcapkit.const` registry and a built-in :class:`enum.IntEnum`
        must raise the *same* exception type for the same invalid value. This is
        what rules out the in-library
        :class:`~pcapkit.utilities.exceptions.EnumError`, which is
        ``(BaseError, TypeError)``: substituting it would leave this assertion
        failing on every registry in the tree.
        """
        self.assertIs(_raised_by(_StdIntEnum, -1), ValueError)
        self.assertIs(_raised_by(_StdStrEnum, -1), ValueError)

        for obj in self.enums:
            with self.subTest(enum=_qualname(obj)):
                builtin = _StdStrEnum if issubclass(obj, str) else _StdIntEnum
                self.assertIs(_raised_by(obj, -1), _raised_by(builtin, -1))

    def test_the_exception_is_not_an_in_library_one(self) -> None:
        """Explicitly *not* ``EnumError``, and explicitly not loud.

        :class:`~pcapkit.utilities.exceptions.BaseError` logs at CRITICAL from
        its constructor, so it fires even for an exception that is caught and
        discarded -- which the ``except ValueError`` fallback in every generated
        ``get()`` does on purpose. A guard raising a
        :class:`~pcapkit.utilities.exceptions.BaseError` subclass would log once
        per discarded default.
        """
        from pcapkit.utilities.exceptions import BaseError, EnumError

        # The reason EnumError is wrong here, asserted rather than asserted-in-prose.
        self.assertTrue(issubclass(EnumError, TypeError))
        self.assertFalse(issubclass(EnumError, ValueError))

        for obj in self.enums:
            with self.subTest(enum=_qualname(obj)):
                with self.assertRaises(ValueError) as caught:
                    obj(-1)
                self.assertNotIsInstance(caught.exception, BaseError)

    def test_an_out_of_range_value_is_rejected_unless_the_registry_registers_it(self) -> None:
        """A value past the registry's own width, which the guards bound."""
        for obj in self.enums:
            qualname = _qualname(obj)
            with self.subTest(enum=qualname):
                raised = _raised_by(obj, UNRESOLVABLE)
                if qualname in EXPECTED_TO_REGISTER:
                    self.assertIsNone(
                        raised, f'{qualname} no longer registers an unassigned value; '
                                f'see GitHub issues #584 and #647')
                else:
                    self.assertIs(raised, ValueError, f'{qualname}({UNRESOLVABLE}) raised '
                                                      f'{raised.__name__ if raised else None}')

    def test_the_registries_named_in_issue_647(self) -> None:
        """The six outliers, by name, with what each used to do."""
        for module_name, class_name, before in ISSUE_647_OUTLIERS:
            with self.subTest(enum=f'{module_name}.{class_name}', before=before):
                obj = getattr(importlib.import_module(module_name), class_name)

                with self.assertRaises(ValueError) as caught:
                    obj(-1)
                self.assertIn(class_name, str(caught.exception))
                self.assertIs(type(caught.exception), ValueError)

    def test_every_new_guard_is_a_classmethod(self) -> None:
        """``_missing_`` without ``@classmethod`` raises :exc:`TypeError` for everything.

        ``aenum`` invokes a failed lookup as ``cls._missing_(value)``, so a plain
        function binds ``value`` to ``cls`` and leaves ``value`` unfilled. GitHub
        issue #492 found two registries like that and
        ``ConstMissingClassmethodTests`` in
        :mod:`tests.const.test_const_enum_lookup` pins the fix -- but its sweep
        is ``_iter_const_int_enums``, which excludes :class:`~aenum.IntFlag`, and
        it never sees a :class:`~aenum.StrEnum` either. Every guard GitHub issue
        #647 added is on one of those two kinds, so all six would have been
        outside it.
        """
        checked = 0
        offenders = []  # type: list[str]
        for obj in self.enums:
            if '_missing_' not in vars(obj):
                continue
            checked += 1
            if not isinstance(vars(obj)['_missing_'], classmethod):
                offenders.append(_qualname(obj))

        self.assertGreater(checked, 0, 'sweep found no _missing_ overrides at all')
        self.assertEqual(offenders, [],
                         f'_missing_ without @classmethod (GitHub issue #492): {offenders}')

        # The six of issue #647 specifically, since the sweep above would still
        # pass if they had no ``_missing_`` at all -- which was the defect.
        for module_name, class_name, _ in ISSUE_647_OUTLIERS:
            obj = getattr(importlib.import_module(module_name), class_name)
            with self.subTest(enum=f'{module_name}.{class_name}'):
                self.assertIn('_missing_', vars(obj),
                              f'{module_name}.{class_name} defines no _missing_; '
                              f'see GitHub issue #647')
                self.assertIsInstance(vars(obj)['_missing_'], classmethod)

    def test_a_string_registry_rejects_a_non_string_rather_than_crashing(self) -> None:
        """The three ``StrEnum`` outliers reached ``value.upper()`` unguarded."""
        from pcapkit.const.ftp.command import Command, FEATCode
        from pcapkit.const.http.method import Method

        for obj in (Command, FEATCode, Method):
            for value in (-1, 0, 1.5, b'GET', None):
                with self.subTest(enum=_qualname(obj), value=value):
                    raised = _raised_by(obj, value)
                    self.assertIs(raised, ValueError,
                                  f'{_qualname(obj)}({value!r}) raised '
                                  f'{raised.__name__ if raised else None}')


class ConstFlagCompositeTests(unittest.TestCase):
    """A bounded flag registry must still compose the values it does define.

    The guard rejects out-of-range values and hands everything else to
    ``super()._missing_``. Getting that wrong in the other direction -- a guard
    narrow enough to reject a legitimate composite -- would break parsing for
    every packet with more than one flag set, and is exactly what the
    ``FLAG = 'isinstance(value, int) and 4 <= value <= 15'`` checker in
    :mod:`pcapkit.vendor.tcp.flags` would have done had the template ever
    interpolated it: those are *bit offsets*, and the values they generate are
    ``1 << offset``.
    """

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_tcp_flag_composites_resolve(self) -> None:
        from pcapkit.const.tcp.flags import Flags

        self.assertEqual(int(Flags(0)), 0)
        for first, second in (('PSH', 'ACK'), ('SYN', 'FIN'), ('RST', 'URG')):
            composite = int(Flags[first]) | int(Flags[second])
            with self.subTest(composite=hex(composite)):
                self.assertNotIn(composite, {member.value for member in Flags})
                self.assertEqual(int(Flags(composite)), composite)
                self.assertEqual(Flags(composite), Flags[first] | Flags[second])

        # Every declared bit at once is the widest legitimate value, and it is
        # what Flags(-1) used to return.
        every = 0
        for member in Flags:
            every |= int(member)
        self.assertEqual(every, 0xFFF0)
        self.assertEqual(int(Flags(every)), every)

        # One past the 16-bit field the registry indexes bits of.
        for beyond in (0x10000, -1, -0x10000, UNRESOLVABLE):
            with self.subTest(value=beyond):
                with self.assertRaises(ValueError):
                    Flags(beyond)

        # An unassigned low bit is in range and still composes, rather than
        # being rejected: bits 0-3 of that field are the data offset.
        self.assertEqual(int(Flags(1)), 1)

    def test_the_other_two_flag_registries_compose(self) -> None:
        from pcapkit.const.ftp.command import CommandType
        from pcapkit.const.reg.apptype import TransportProtocol

        self.assertEqual(int(CommandType(0)), 0)
        self.assertEqual(CommandType(0x07), CommandType.A | CommandType.P | CommandType.S)
        with self.assertRaises(ValueError):
            CommandType(0x08)

        self.assertEqual(int(TransportProtocol(0)), 0)
        self.assertEqual(TransportProtocol(0x0F),
                         TransportProtocol.tcp | TransportProtocol.udp
                         | TransportProtocol.sctp | TransportProtocol.dccp)
        with self.assertRaises(ValueError):
            TransportProtocol(0x10)

    @unittest.skipIf(sys.version_info < (3, 11), 'enum.STRICT is 3.11+')
    def test_a_bounded_flag_matches_the_built_in_under_its_strict_boundary(self) -> None:
        """Where the built-in flag parity claim actually lands.

        :class:`enum.IntFlag` defaults to ``boundary=KEEP`` and *composes* an
        out-of-range value rather than raising, so the parity being asserted for
        the flag registries is against the built-in's own reject mode,
        ``boundary=STRICT``. The exception type is the same either way, which is
        the property GitHub issue #647 is about; this test records that the
        choice to bound the domain at all is the built-in's ``STRICT``
        behaviour and not an invention.
        """
        from pcapkit.const.tcp.flags import Flags

        strict = enum.IntFlag('strict', {'FIN': 1 << 15}, boundary=enum.STRICT)  # type: ignore[misc]
        keep = enum.IntFlag('keep', {'FIN': 1 << 15}, boundary=enum.KEEP)  # type: ignore[misc]

        self.assertIs(_raised_by(strict, -1), ValueError)
        self.assertIs(_raised_by(Flags, -1), _raised_by(strict, -1))

        # And the default the library deliberately does not follow.
        self.assertIsNone(_raised_by(keep, -1))


class ConstEnumRegisterFallbackTests(unittest.TestCase):
    """The one sanctioned divergence: look up, miss, then register.

    In the owner's words, the const enums mirror the built-in "with one
    exception: they contain the missing then register fallback (mutable enums)".
    A guard that turned a registration into a rejection would be the regression
    GitHub issues #584 and #623 are both about, so it is pinned here rather than
    left to the guard tests above to imply.
    """

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def tearDown(self) -> None:
        # Every test here registers members on module-global classes.
        purge_modules(['pcapkit'])

    def test_a_string_registry_still_registers_an_unknown_name(self) -> None:
        from pcapkit.const.ftp.command import Command, FEATCode
        from pcapkit.const.http.method import Method

        for obj, unknown in ((Method, 'FROBNICATE'), (Command, 'XYZZY'), (FEATCode, '<zzzz>')):
            with self.subTest(enum=_qualname(obj), value=unknown):
                before = len(obj.__members__)
                registered = obj(unknown)
                self.assertGreater(len(obj.__members__), before,
                                   f'{_qualname(obj)}({unknown!r}) did not register; '
                                   f'see GitHub issue #647')
                self.assertIs(obj(unknown), registered)

    def test_a_string_registry_still_matches_case_insensitively(self) -> None:
        from pcapkit.const.ftp.command import Command
        from pcapkit.const.http.method import Method

        for obj, lowered, member in ((Method, 'get', 'GET'), (Command, 'abor', 'ABOR')):
            with self.subTest(enum=_qualname(obj), value=lowered):
                before = len(obj.__members__)
                self.assertIs(obj(lowered), obj[member])
                self.assertEqual(len(obj.__members__), before,
                                 'a case-insensitive hit must not register a new member')

    def test_the_guard_leaves_the_other_lookup_paths_alone(self) -> None:
        """``get()`` is where the guard's rejection is caught, so it is checked too.

        The string path of a generated ``get`` never reaches ``_missing_`` at all,
        and the integer path reaches it inside a ``try``. Both are exercised here
        for the four modules GitHub issue #647 touched, so a guard that had
        broken either would fail rather than merely go unmeasured.
        """
        from pcapkit.const.ftp.command import Command
        from pcapkit.const.http.method import Method
        from pcapkit.const.reg.apptype import TransportProtocol
        from pcapkit.const.tcp.flags import Flags

        # String paths, which bypass ``_missing_``.
        self.assertIs(Flags.get('SYN'), Flags.SYN)
        self.assertIs(Command.get('abor'), Command.ABOR)
        self.assertIs(Method.get('get'), Method.GET)
        self.assertIs(TransportProtocol.get('tcp'), TransportProtocol.tcp)

        # Integer paths, which do.
        self.assertIs(TransportProtocol.get(1), TransportProtocol.tcp)
        self.assertIs(Flags.get(1 << 14), Flags.SYN)

        # And the fallback the guard's ValueError is what triggers: GitHub issue
        # #584's ``get(key, default)``, which an EnumError would have walked past.
        self.assertEqual(int(Flags.get(UNRESOLVABLE, 0)), 0)
        with self.assertRaises(ValueError):
            Flags.get(UNRESOLVABLE)

    def test_the_auto_extending_integer_registries_still_extend(self) -> None:
        from pcapkit.const.ipv4.protection_authority import ProtectionAuthority
        from pcapkit.const.mh.cga_type import CGAType

        for obj in (ProtectionAuthority, CGAType):
            with self.subTest(enum=_qualname(obj)):
                before = len(obj.__members__)
                registered = obj(UNRESOLVABLE)
                self.assertGreater(len(obj.__members__), before)
                self.assertEqual(int(registered), UNRESOLVABLE)

                # ... and still reject a value no span covers.
                with self.assertRaises(ValueError):
                    obj(-1)

    def test_apptype_still_registers_an_unassigned_port(self) -> None:
        """GitHub issue #584's machinery, which runs through ``_missing_``."""
        from pcapkit.const.reg.apptype import AppType, TransportProtocol

        registered = AppType.get(65000, proto=TransportProtocol.tcp)
        self.assertEqual(int(registered), 65000)
        self.assertIs(AppType.get(65000, proto=TransportProtocol.tcp), registered)

    def test_transport_protocol_can_still_be_extended_at_runtime(self) -> None:
        """Why this registry's bound is derived rather than written down.

        ``TransportProtocol.get`` registers an unknown protocol name at
        ``max * 2``, so a literal upper bound -- the shape the Mobility Header
        flag guards use -- would reject the very member the registry had just
        grown, and every composite containing it. The guard reads the bound off
        the current members instead, and this test is what pins that: it fails
        against a hard-coded ``0x0F``.
        """
        from pcapkit.const.reg.apptype import TransportProtocol

        self.assertNotIn('quic', TransportProtocol.__members__)
        with self.assertRaises(ValueError):
            TransportProtocol(0x10)

        grown = TransportProtocol.get('quic')
        self.assertEqual(int(grown), 0x10)
        self.assertIn('quic', TransportProtocol.__members__)

        # The new member composes with the old ones, which is the assertion a
        # literal bound fails.
        self.assertEqual(int(TransportProtocol(0x11)), 0x11)
        self.assertEqual(TransportProtocol(0x11), grown | TransportProtocol.tcp)

        # And the bound moved with it rather than disappearing.
        with self.assertRaises(ValueError):
            TransportProtocol(0x20)


class ConstEnumGuardTemplateTests(unittest.TestCase):
    """A regeneration must not undo the guard.

    :mod:`pcapkit.const` is generated from :mod:`pcapkit.vendor`, so the
    committed tree passing the tests above is not evidence that the templates
    agree with it -- the next crawl would simply revert them. The four templates
    below each carry their own copy of the guard rather than inheriting the one
    in :mod:`pcapkit.vendor.default`, which is why all four had to be edited and
    why all four are checked -- each against its own guard text now that
    GitHub issue #792 moved one of them off ``%`` formatting, per
    :data:`BESPOKE_TEMPLATES`.
    """

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    @unittest.skipUnless(importlib.util.find_spec('requests') is not None,
                         'pcapkit.vendor needs requests')
    def test_every_bespoke_template_carries_the_guard(self) -> None:
        for module_name, guard in BESPOKE_TEMPLATES.items():
            with self.subTest(vendor=module_name):
                source = inspect.getsource(importlib.import_module(module_name))
                self.assertIn(
                    guard, source, f'{module_name} no longer emits its guard; '
                                   f'see GitHub issue #647')

    @unittest.skipUnless(importlib.util.find_spec('requests') is not None,
                         'pcapkit.vendor needs requests')
    def test_the_tcp_flags_template_renders_the_committed_module(self) -> None:
        """The whole file, character for character.

        Mirrors ``test_the_vendor_templates_still_emit_the_fix`` in
        :mod:`tests.const.test_const_enum_lookup`, which does this for the four
        Mobility Header templates. Needs no network: the crawl supplies only the
        enumeration block, which is read back out of the committed module.
        """
        import pathlib

        from tests.const.test_const_enum_lookup import _normalize

        vendor_module = importlib.import_module('pcapkit.vendor.tcp.flags')
        vendor_class = vendor_module.Flags

        const_module = importlib.import_module('pcapkit.const.tcp.flags')
        committed = pathlib.Path(
            const_module.__file__  # type: ignore[arg-type]
        ).read_text(encoding='utf-8')

        block = re.compile(
            r'class \w+\(IntFlag\):\n    """.*?"""\n\n    (.*?)\n\n    @staticmethod', re.S)
        enum_block = block.search(committed)
        self.assertIsNotNone(enum_block, 'no enumeration block in pcapkit.const.tcp.flags')

        rendered = _normalize(vendor_module.LINE(
            vendor_class.__name__, vendor_class.__doc__, vendor_class.FLAG,
            enum_block.group(1),  # type: ignore[union-attr]
            'pcapkit.vendor.tcp.flags',
        ))

        self.assertIn('return super()._missing_(value)', rendered)
        self.assertEqual(rendered, committed)

    @unittest.skipUnless(importlib.util.find_spec('requests') is not None,
                         'pcapkit.vendor needs requests')
    def test_the_tcp_flags_checker_covers_the_value_domain_not_the_bit_offsets(self) -> None:
        """The checker the template used to drop, and why it could not be kept.

        ``Flags.FLAG`` read ``4 <= value <= 15`` -- the *offsets* the IANA
        registry indexes -- while the members it generates are ``1 << offset``.
        The template never interpolated it, so it was never wrong in practice;
        interpolating it unchanged would have rejected every composite, every
        single member above bit 3, and ``Flags(0)``.
        """
        from pcapkit.vendor.tcp.flags import Flags as VendorFlags

        checker = VendorFlags.FLAG
        self.assertIn('0xFFFF', checker)

        from pcapkit.const.tcp.flags import Flags

        for member in Flags:
            value = int(member)
            with self.subTest(member=member.name):
                self.assertTrue(eval(checker, {'value': value}),  # pylint: disable=eval-used
                                f'the checker rejects its own member {member.name}={value}')
                self.assertFalse(eval('isinstance(value, int) and 4 <= value <= 15',
                                      {'value': value}),  # pylint: disable=eval-used
                                 f'the old checker accepted {member.name}={value}')


if __name__ == '__main__':
    unittest.main()
