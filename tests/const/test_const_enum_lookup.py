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

"""
from __future__ import annotations

import importlib
import inspect
import pkgutil
import unittest
from typing import TYPE_CHECKING

from aenum import IntEnum, IntFlag

import pcapkit.const as const_pkg

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
    classes = []  # type: list[type]
    for module_info in pkgutil.walk_packages(const_pkg.__path__, const_pkg.__name__ + '.'):
        module = importlib.import_module(module_info.name)
        for _, obj in vars(module).items():
            if (inspect.isclass(obj) and issubclass(obj, IntEnum)
                    and obj.__module__ == module_info.name
                    and not issubclass(obj, IntFlag)):
                classes.append(obj)
    return classes


class ConstEnumZeroLookupTests(unittest.TestCase):
    """``Enum(0)`` must behave as the backing registry says it should."""

    if TYPE_CHECKING:
        enums: 'list[type]'

    @classmethod
    def setUpClass(cls) -> None:
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


class RouterAlertPacketParseTests(unittest.TestCase):
    """Parse an on-the-wire packet carrying RFC 2113's Router Alert value 0."""

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
