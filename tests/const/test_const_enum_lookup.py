# -*- coding: utf-8 -*-
"""Registry-wide regression tests for :mod:`pcapkit.const` enum lookups.

GitHub issue #492 found three lookup defects hiding under :mod:`pcapkit.const`:
a value that a registry actually defines being rejected by the generated
:class:`~aenum.IntEnum` (:class:`~pcapkit.const.ipv4.router_alert.RouterAlert`
and :class:`~pcapkit.const.ipx.socket.Socket`, both for value ``0``), and a
``_missing_`` lookup method missing its ``@classmethod`` decorator
(:class:`~pcapkit.const.ftp.return_code.ResponseKind` and
:class:`~pcapkit.const.ftp.return_code.GroupingInformation`), which makes
``cls._missing_(value)`` bind ``value`` to ``cls`` and raise :class:`TypeError`
for *every* unregistered value rather than the intended fallback.

Both defects were found by a sweep instantiating every :class:`~aenum.IntEnum`
under :mod:`pcapkit.const` with value ``0``, and by checking every ``_missing_``
definition in that tree for the decorator. This module reuses that sweep so the
two defects -- and the fix -- stay pinned: a future regeneration of the
``pcapkit.const`` tree (see :mod:`pcapkit.vendor`) that drops either fix will
fail this suite rather than silently reintroducing GitHub issue #492.

That sweep deliberately skips :class:`~aenum.IntFlag`, on the grounds that it is
"a different value-lookup contract" -- which is exactly why it did not catch
GitHub issue #623, a third lookup defect of the same family living in the class
of enum it excluded. The four Mobility Header flag enumerations overrode
``_missing_`` with a body ending in ``return cls(value)``, the same constructor
that had just failed to find the value, so every in-range value that is not
already a member re-entered ``_missing_`` unbounded and raised
:exc:`RecursionError`. Because their members are single bits, the reachable hole
was ``0`` -- no flags set -- and every composite of two defined bits. Overriding
``_missing_`` at all is what caused it: the override shadowed the ``aenum``
:class:`~aenum.Flag` machinery that resolves precisely those values, which is why
:class:`~pcapkit.const.tcp.flags.Flags`, which at the time defined no
``_missing_``, never had the defect -- and, as GitHub issue #647 then found, had
no range guard either, so it resolved *any* integer and ``Flags(-1)`` read back
as every TCP header flag set at once. It now carries the same guard ending in
``return super()._missing_(value)``, which is what keeps issue #623 fixed while
issue #647 is too; :mod:`tests.const.test_const_enum_builtin_parity` is where
that lands. :class:`~pcapkit.const.mh.binding_ack_flag.BindingACKFlag` and its
three siblings end in that same tail, the one
:mod:`pcapkit.vendor.default` emits for every other generated enumeration. So
this module carries a companion sweep over the :class:`~aenum.IntFlag` classes,
covering the contract the :class:`~aenum.IntEnum` sweep declines to.

Every test class purges :mod:`pcapkit` from :data:`sys.modules` in ``setUp``,
matching the convention every other module in this suite uses (see
:func:`tests._support.purge_modules`). It matters more here than usual: this
module is the first thing in the whole suite to import *every* submodule
under :mod:`pcapkit.const`, including ones nothing else touches (e.g.
:mod:`pcapkit.const.reg.apptype`). ``tests/cli/test_main.py`` stubs pieces of
:mod:`pcapkit.utilities.compat` and :mod:`pcapkit.utilities.exceptions`
straight into :data:`sys.modules` for its own isolation and, depending on
suite order, that stub can still be sitting there when this module runs --
purging first forces a clean re-import instead of tripping over it.

"""
from __future__ import annotations

import importlib
import importlib.util
import inspect
import pkgutil
import re
import unittest
from typing import TYPE_CHECKING

from aenum import IntEnum, IntFlag

from tests._support import purge_modules

#: Fully qualified names of the :class:`~aenum.IntEnum` classes under
#: :mod:`pcapkit.const` for which rejecting ``0`` is *correct*, because their
#: registries simply do not define ``0`` (three-digit response codes starting
#: at 100, or registries reserving ``0`` and starting real assignments at 1).
#: Confirmed against the IANA/RFC registries backing each one; see GitHub
#: issue #492.
EXPECTED_TO_REJECT_ZERO = frozenset({
    'pcapkit.const.ftp.return_code.ReturnCode',
    'pcapkit.const.http.status_code.StatusCode',
    'pcapkit.const.ftp.command.ConformanceRequirement',
    'pcapkit.const.sctp.cause_code.CauseCode',
    'pcapkit.const.sctp.parameter.Parameter',
    'pcapkit.const.mh.mn_id_subtype.MNIDSubtype',
})

#: The four Mobility Header flag enumerations of GitHub issue #623, as
#: ``(module stem, class name, two defined single-bit member names, the value
#: ORing those two members gives)``. That composite is deliberately a value no
#: registry assigns: it is in range, it is not a member, and it is what
#: ``return cls(value)`` recursed on. The pairs are the two lowest bits each
#: registry defines -- ``BindingACKFlag`` ``D=0x02`` ``S=0x04``,
#: ``BindingUpdateFlag`` ``D=0x10`` ``S=0x20``, ``HandoverACKFlag`` ``F=0x20``
#: ``P=0x40``, ``HandoverInitiateFlag`` ``F=0x10`` ``P=0x20``.
MH_FLAG_ENUMS = (
    ('binding_ack_flag', 'BindingACKFlag', ('D', 'S'), 0x06),
    ('binding_update_flag', 'BindingUpdateFlag', ('D', 'S'), 0x30),
    ('handover_ack_flag', 'HandoverACKFlag', ('F', 'P'), 0x60),
    ('handover_initiate_flag', 'HandoverInitiateFlag', ('F', 'P'), 0x30),
)


def _normalize(context: 'str') -> 'str':
    """Whitespace-normalise a rendered template the way the writer does.

    :meth:`pcapkit.vendor.default.Vendor.__init__` rstrips every non-blank line,
    drops whitespace-only lines, joins with ``\\n`` and writes the result with
    :func:`print`, which restores the single trailing newline. Reproducing it
    here is what lets a rendered template be compared against a committed module
    character for character.

    Args:
        context: Rendered template text.

    Returns:
        The text as it would be written to ``pcapkit/const/``.

    """
    lines = []  # type: list[str]
    for line in context.splitlines():
        if line:
            if line.strip():
                lines.append(line.rstrip())
        else:
            lines.append(line)
    return '\n'.join(lines) + '\n'


def _iter_const_int_enums() -> 'list[type]':
    """Discover every :class:`~aenum.IntEnum` defined under :mod:`pcapkit.const`.

    Walks every submodule of :mod:`pcapkit.const` and collects the
    :class:`~aenum.IntEnum` subclasses (excluding :class:`~aenum.IntFlag`,
    which is a different value-lookup contract) that are actually *defined*
    in the module being walked, rather than merely imported/re-exported by
    it -- so each registry enum is counted exactly once.

    Returns:
        The discovered enum classes, in walk order.

    """
    import pcapkit.const as const_pkg

    classes = []  # type: list[type]
    for module_info in pkgutil.walk_packages(const_pkg.__path__, const_pkg.__name__ + '.'):
        module = importlib.import_module(module_info.name)
        for _, obj in vars(module).items():
            if (inspect.isclass(obj) and issubclass(obj, IntEnum)
                    and obj.__module__ == module_info.name
                    and not issubclass(obj, IntFlag)):
                classes.append(obj)
    return classes


def _iter_const_int_flags() -> 'list[type]':
    """Discover every :class:`~aenum.IntFlag` defined under :mod:`pcapkit.const`.

    The mirror image of :func:`_iter_const_int_enums`: same walk, same
    defined-here test, but keeping exactly the classes that one discards. This
    is the sweep GitHub issue #492 declined to run, and GitHub issue #623 is
    what was hiding in it.

    Returns:
        The discovered flag classes, in walk order.

    """
    import pcapkit.const as const_pkg

    classes = []  # type: list[type]
    for module_info in pkgutil.walk_packages(const_pkg.__path__, const_pkg.__name__ + '.'):
        module = importlib.import_module(module_info.name)
        for _, obj in vars(module).items():
            if (inspect.isclass(obj) and issubclass(obj, IntFlag)
                    and obj.__module__ == module_info.name):
                classes.append(obj)
    return classes


class ConstEnumZeroLookupTests(unittest.TestCase):
    """``Enum(0)`` must behave as the backing registry says it should."""

    if TYPE_CHECKING:
        enums: 'list[type]'

    @classmethod
    def setUpClass(cls) -> None:
        purge_modules(['pcapkit'])
        cls.enums = _iter_const_int_enums()

    def test_every_registry_enum_was_discovered(self) -> None:
        # Pins the size of the sweep itself: if this drifts, a const enum was
        # added, removed, or renamed, and EXPECTED_TO_REJECT_ZERO (and the
        # analysis in GitHub issue #492) needs a fresh look rather than a
        # silent pass.
        names = {f'{obj.__module__}.{obj.__qualname__}' for obj in self.enums}
        self.assertEqual(len(self.enums), 111)
        self.assertTrue(EXPECTED_TO_REJECT_ZERO.issubset(names),
                        f'expected reject-list entries missing from the sweep: '
                        f'{EXPECTED_TO_REJECT_ZERO - names}')

    def test_zero_lookup_matches_the_registry(self) -> None:
        for obj in self.enums:
            qualname = f'{obj.__module__}.{obj.__qualname__}'
            with self.subTest(enum=qualname):
                if qualname in EXPECTED_TO_REJECT_ZERO:
                    with self.assertRaises(ValueError):
                        obj(0)
                else:
                    try:
                        obj(0)
                    except Exception as error:  # pylint: disable=broad-except
                        self.fail(f'{qualname}(0) unexpectedly raised {error!r}; '
                                  f'see GitHub issue #492')

    def test_router_alert_accepts_rfc_2113_value(self) -> None:
        # The specific HIGH-severity defect: RFC 2113 defines exactly one
        # value, 0, and the generated enum did not have it.
        from pcapkit.const.ipv4.router_alert import RouterAlert

        self.assertEqual(RouterAlert(0), RouterAlert.Router_shall_examine_packet)
        self.assertEqual(RouterAlert(0).value, 0)

    def test_ipx_socket_accepts_unspecified_socket(self) -> None:
        # The specific MEDIUM-severity defect: 0x0000 is IPX's own class
        # default for the dst/src socket field.
        from pcapkit.const.ipx.socket import Socket

        self.assertEqual(Socket(0), Socket.Unspecified)
        self.assertEqual(Socket(0).value, 0)


class ConstMissingClassmethodTests(unittest.TestCase):
    """Every ``_missing_`` under :mod:`pcapkit.const` must be a classmethod.

    aenum invokes lookup failures as ``cls._missing_(value)``. Without
    ``@classmethod``, the sole positional argument binds to ``cls`` and
    ``value`` goes unfilled, so *every* call raises :class:`TypeError` instead
    of running the intended fallback body -- see GitHub issue #492 (LOW
    severity there because, at the time, nothing reachable at runtime ever
    triggered the broken path).

    """

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_every_missing_is_a_classmethod(self) -> None:
        offenders = []  # type: list[str]
        checked = 0
        for obj in _iter_const_int_enums():
            if '_missing_' not in obj.__dict__:
                continue
            checked += 1
            if not isinstance(obj.__dict__['_missing_'], classmethod):
                offenders.append(f'{obj.__module__}.{obj.__qualname__}')

        self.assertGreater(checked, 0, 'sweep found no _missing_ overrides at all')
        self.assertEqual(offenders, [],
                         f'_missing_ without @classmethod (GitHub issue #492): {offenders}')

    def test_ftp_return_code_missing_methods_are_classmethods(self) -> None:
        # The specific defect: both were plain instance methods.
        from pcapkit.const.ftp.return_code import GroupingInformation, ResponseKind

        self.assertIsInstance(ResponseKind.__dict__['_missing_'], classmethod)
        self.assertIsInstance(GroupingInformation.__dict__['_missing_'], classmethod)

        # And the actual symptom: every unknown value used to raise TypeError
        # rather than extending the enum, not merely value 0.
        self.assertEqual(int(ResponseKind(7)), 7)
        self.assertEqual(int(ResponseKind(0)), 0)
        self.assertEqual(int(GroupingInformation(9)), 9)


class ConstFlagMissingRecursionTests(unittest.TestCase):
    """An ``IntFlag`` lookup must resolve or raise, never recurse.

    GitHub issue #623. ``_missing_`` in the four Mobility Header flag
    enumerations ended in ``return cls(value)`` -- the constructor that had just
    failed to find the value -- so every in-range non-member re-entered
    ``_missing_`` unbounded and raised :exc:`RecursionError`. The tests below
    assert the *resolved* value rather than catching the recursion, so an
    unfixed tree fails on the error rather than on an assertion, and the four
    named registries are covered alongside the sweep.

    """

    if TYPE_CHECKING:
        flags: 'list[type]'

    @classmethod
    def setUpClass(cls) -> None:
        purge_modules(['pcapkit'])
        cls.flags = _iter_const_int_flags()
        cls.addClassCleanup(purge_modules, ['pcapkit'])

    def test_the_sweep_size_is_pinned(self) -> None:
        """A flag enum added or removed needs a fresh look, not a silent pass."""
        names = {f'{obj.__module__}.{obj.__qualname__}' for obj in self.flags}
        self.assertEqual(len(self.flags), 7)

        expected = {f'pcapkit.const.mh.{stem}.{name}'
                    for stem, name, _, _ in MH_FLAG_ENUMS}
        self.assertTrue(expected.issubset(names),
                        f'issue #623 registries missing from the sweep: '
                        f'{expected - names}')

    def test_zero_resolves_to_an_empty_flag(self) -> None:
        """``F(0)`` -- no flags set -- is the reachable trigger of issue #623."""
        for obj in self.flags:
            qualname = f'{obj.__module__}.{obj.__qualname__}'
            with self.subTest(enum=qualname):
                try:
                    empty = obj(0)
                except RecursionError:
                    self.fail(f'{qualname}(0) recursed through _missing_; '
                              f'see GitHub issue #623')
                self.assertEqual(int(empty), 0)
                self.assertFalse(bool(empty))

    def test_a_composite_of_defined_bits_decomposes(self) -> None:
        """An unassigned in-range value is a composite, not an error.

        Delegating to ``aenum``'s own :class:`~aenum.Flag` machinery is what
        restores this; the ``extend_enum`` idiom the integer registries use
        would have minted an opaque ``Unassigned_0x06`` member instead.
        """
        for stem, name, members, composite in MH_FLAG_ENUMS:
            qualname = f'pcapkit.const.mh.{stem}.{name}'
            with self.subTest(enum=qualname, value=hex(composite)):
                obj = getattr(importlib.import_module(f'pcapkit.const.mh.{stem}'), name)

                # The premise: the composite really is unassigned, so it is
                # _missing_ that has to resolve it.
                self.assertNotIn(composite, {member.value for member in obj})

                first, second = (obj[member] for member in members)
                self.assertEqual(int(first) | int(second), composite)

                resolved = obj(composite)
                self.assertEqual(int(resolved), composite)
                self.assertEqual(resolved, first | second)

    def test_an_unassigned_single_bit_resolves(self) -> None:
        """``0x01`` is below every bit these four define, and recursed too."""
        for stem, name, _, _ in MH_FLAG_ENUMS:
            qualname = f'pcapkit.const.mh.{stem}.{name}'
            with self.subTest(enum=qualname):
                obj = getattr(importlib.import_module(f'pcapkit.const.mh.{stem}'), name)
                self.assertNotIn(1, {member.value for member in obj})
                self.assertEqual(int(obj(1)), 1)

    def test_the_range_guard_still_rejects(self) -> None:
        """The guard above the fixed line is untouched, so it still raises."""
        for stem, name, _, _ in MH_FLAG_ENUMS:
            qualname = f'pcapkit.const.mh.{stem}.{name}'
            with self.subTest(enum=qualname):
                obj = getattr(importlib.import_module(f'pcapkit.const.mh.{stem}'), name)

                # One past the registry's own width, read off the guard rather
                # than assumed: 0xFF for three of them, 0xFFFF for the update
                # flags, whose registry runs to 0x8000.
                width = max(member.value for member in obj)
                beyond = 0x10000 if width > 0xFF else 0x100
                with self.assertRaises(ValueError):
                    obj(beyond)
                with self.assertRaises(ValueError):
                    obj(-1)
                with self.assertRaises(ValueError):
                    obj('not an integer')

    @unittest.skipUnless(importlib.util.find_spec('requests') is not None,
                         'pcapkit.vendor needs requests')
    def test_the_vendor_templates_still_emit_the_fix(self) -> None:
        """A regeneration must not undo the fix.

        ``pcapkit/const/`` is generated from ``pcapkit/vendor/``, so the
        committed tree passing the tests above is not evidence that the
        templates agree with it -- the next crawl would simply revert them.
        Renders each of the four templates with the registry data taken back out
        of the module generated from it, and compares the whole file character
        for character. Needs no network: the crawl supplies only the enumeration
        block, which is read from the committed module rather than fetched.
        """
        import pathlib

        block = re.compile(
            r'class \w+\(IntFlag\):\n    """.*?"""\n\n    (.*?)\n\n    @staticmethod',
            re.S)

        for stem, name, _, _ in MH_FLAG_ENUMS:
            with self.subTest(vendor=f'pcapkit.vendor.mh.{stem}'):
                vendor_module = importlib.import_module(f'pcapkit.vendor.mh.{stem}')
                vendor_class = getattr(vendor_module, name)

                const_module = importlib.import_module(f'pcapkit.const.mh.{stem}')
                committed = pathlib.Path(
                    const_module.__file__  # type: ignore[arg-type]
                ).read_text(encoding='utf-8')

                enum_block = block.search(committed)
                self.assertIsNotNone(
                    enum_block, f'no enumeration block in pcapkit.const.mh.{stem}')

                rendered = _normalize(vendor_module.LINE(
                    vendor_class.__name__, vendor_class.__doc__, vendor_class.FLAG,
                    enum_block.group(1),  # type: ignore[union-attr]
                    f'pcapkit.vendor.mh.{stem}',
                ))

                self.assertIn('return super()._missing_(value)', rendered)
                self.assertNotIn('        return cls(value)', rendered)
                self.assertEqual(rendered, committed)


class RouterAlertPacketParseTests(unittest.TestCase):
    """Parse an on-the-wire packet carrying RFC 2113's Router Alert value 0."""

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_parses_igmp_over_router_alert_zero(self) -> None:
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.const.ipv4.option_number import OptionNumber
        from pcapkit.const.ipv4.router_alert import RouterAlert
        from pcapkit.protocols.data.internet.ipv4 import RTRALTOption

        # IPv4 header, 28 bytes, carrying a Router Alert option (type 148,
        # length 4, value 0) ahead of an IGMP payload -- the packet from
        # GitHub issue #492.
        wire = bytes.fromhex(
            '4600001c00000000000200007f000001000000009404000011000000'
        )

        packet = IPv4(wire)
        option = packet.info.options[OptionNumber.RTRALT]  # type: ignore[index]
        self.assertIsInstance(option, RTRALTOption)

        alert = option.alert  # type: ignore[attr-defined]
        self.assertEqual(alert, RouterAlert.Router_shall_examine_packet)
        self.assertEqual(alert.value, 0)


if __name__ == '__main__':
    unittest.main()
