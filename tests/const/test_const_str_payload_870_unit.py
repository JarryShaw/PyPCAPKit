# -*- coding: utf-8 -*-
"""A registered ``StrEnum`` member's :class:`str` payload must be its value.

GitHub issue #870: :meth:`pcapkit.const.http.method.Method.__new__` built every
registered member with ``obj = str.__new__(cls)`` -- no second argument -- so
the underlying :class:`str` content was permanently empty regardless of the
member's own declared value. ``_value_`` was set correctly (``Method.GET.value
== 'GET'``), but the :class:`str` the member itself *is* was not:
``str(Method.GET) == ''``, ``len(str(Method.GET)) == 0`` and, most visibly,
``Method.GET == 'GET'`` was :data:`False` for every one of the 40 declared
members. True on ``main`` at ``60b85e3a4`` (measured), and true since the class
was first written -- GitHub pull request #869 fixed the same inconsistency for an
*unregistered* member's own str payload
(:meth:`~pcapkit.const.http.method.Method._unregistered_member` now calls the
base's :meth:`~pcapkit.corekit.enum.EnumRegistry._unregistered_member`, which
does pass the value along), which is what exposed this half: after #869,
``str(Method('frob')) == 'frob'`` while ``str(Method.GET) == ''`` -- a
registered member and an unregistered one disagreeing about the one thing
they are both supposed to be, a :class:`str`.

The fix is ``obj = str.__new__(cls, value)``, mirroring
:meth:`pcapkit.const.ftp.command.Command.__new__`
(``obj = str.__new__(cls, name)``), which never had this defect. Applied to
both :mod:`pcapkit.const.http.method` (the generated module) and
:mod:`pcapkit.vendor.http.method` (the generator template that produces it),
since a fix only in the former is silently reverted by the next crawl.

This is a **behaviour change to all 40 public members**: every equality
comparison of a :class:`~pcapkit.const.http.method.Method` member against its
own wire string now succeeds where it used to fail silently (no exception --
just an unexpected :data:`False`). Nothing under :mod:`pcapkit.protocols`
compared a member this way before the fix (the one caller,
:meth:`pcapkit.protocols.application.httpv1.HTTP.read_http_header`, only ever
reads ``.value`` indirectly through :meth:`~pcapkit.const.http.method.Method.
get`, never ``str()`` or ``==`` against the member itself), so the change is
observable only to external callers and to this module's own dunders
(``__repr__``, which reads ``_value_`` and was already correct).

The wider sweep below -- :class:`StrValuedRegistryPayloadTests` -- checks the
same property, ``str(member) == member.value``, for every ``EnumRegistry``
+ ``StrEnum`` registry under :mod:`pcapkit.const` with a hand-rolled
``__new__``: :class:`~pcapkit.const.ftp.command.Command`,
:class:`~pcapkit.const.ftp.command.FEATCode`,
:class:`~pcapkit.const.http.method.Method` and
:class:`~pcapkit.const.pcapng.option_type.OptionType`. ``Command`` already
passed ``name`` to ``str.__new__`` and ``FEATCode`` has no custom ``__new__``
at all (the base :class:`~aenum.StrEnum` machinery handles it), so neither
carried this defect -- only ``Method`` did. ``OptionType`` is deliberately
*not* swept the same way: its own :attr:`~pcapkit.const.pcapng.option_type.
OptionType.value` is *itself* the formatted display string
(``'%s [%d]' % (opt_name, opt_value)``, set by its own ``__new__``), not the
raw wire value (that lives in :attr:`~pcapkit.const.pcapng.option_type.
OptionType.opt_value`) -- so ``str(member) == member.value`` holds for it
trivially and proves nothing about the property the other three are being
checked for. It gets its own, separate assertion instead, pinning its actual
contract rather than silently dropping it from the sweep.

"""
from __future__ import annotations

import unittest

from tests._support import purge_modules


class MethodStrPayload870RegressionTests(unittest.TestCase):
    """The exact repro from GitHub issue #870, and the full sweep of Method's own 40 members."""

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_the_reported_case(self) -> None:
        """``Method.GET``, byte for byte, as the issue measured it.

        Fails against ``main`` at ``60b85e3a4``: ``str(Method.GET)`` there is
        ``''`` (``len`` 0) and ``Method.GET == 'GET'`` is :data:`False`.
        """
        from pcapkit.const.http.method import Method

        self.assertEqual(Method.GET.value, 'GET')
        self.assertEqual(str(Method.GET), 'GET')
        self.assertEqual(len(str(Method.GET)), 3)
        self.assertEqual(Method.GET, 'GET')
        self.assertTrue(Method.GET == 'GET')  # pylint: disable=singleton-comparison

    def test_every_one_of_the_40_registered_members_carries_its_value_as_str_payload(self) -> None:
        """Swept, not just ``GET`` -- the defect was in ``__new__``, so every
        member built through it was affected identically."""
        from pcapkit.const.http.method import Method

        members = list(Method)
        self.assertEqual(len(members), 40, 'Method no longer declares 40 members; a fresh look is needed')

        for member in members:
            with self.subTest(member=member.name):
                self.assertEqual(str(member), member.value)
                self.assertEqual(member, member.value)
                self.assertEqual(len(str(member)), len(member.value))

    def test_registered_and_unregistered_members_are_now_consistent(self) -> None:
        """The inconsistency #870 reported: #869 fixed the unregistered half
        only, so ``str(Method('frob')) == 'frob'`` while ``str(Method.GET) ==
        ''`` on ``main`` at ``60b85e3a4``. Both now carry real content."""
        from pcapkit.const.http.method import Method

        registered = Method.GET
        unregistered = Method('frob')

        self.assertEqual(str(registered), 'GET')
        self.assertEqual(str(unregistered), 'frob')
        self.assertNotEqual(str(registered), '')
        self.assertNotEqual(str(unregistered), '')

    def test_repr_and_the_extra_attributes_are_unaffected(self) -> None:
        """The fix touches only the :class:`str` payload -- ``__repr__`` (which
        reads ``_value_``, already correct) and the ``safe``/``idempotent``
        attributes :meth:`__new__` also sets must be untouched."""
        from pcapkit.const.http.method import Method

        self.assertEqual(repr(Method.GET), '<Method.GET>')
        self.assertTrue(Method.GET.safe)
        self.assertTrue(Method.GET.idempotent)
        self.assertFalse(Method.POST.safe)
        self.assertFalse(Method.POST.idempotent)


class StrValuedRegistryPayloadTests(unittest.TestCase):
    """The registry-wide form: every ``EnumRegistry`` + ``StrEnum`` member's
    :class:`str` payload must equal its own declared value.

    :class:`~pcapkit.const.pcapng.option_type.OptionType` is deliberately
    excluded from :data:`SWEPT_REGISTRIES` -- see the module docstring for why
    sweeping it the same way would prove nothing -- and gets its own
    :meth:`test_optiontype_is_exempt_but_its_own_contract_still_holds` instead.
    """

    #: The three registries this sweep actually checks. ``Command`` and
    #: ``FEATCode`` never carried GitHub issue #870's defect (see the module
    #: docstring's sibling survey); they are swept anyway so a regression in
    #: either would be caught here too, not only in ``Method``.
    SWEPT_REGISTRIES = ('Command', 'FEATCode', 'Method')

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_every_member_of_every_swept_registry_matches_its_value(self) -> None:
        from pcapkit.const.ftp.command import Command, FEATCode
        from pcapkit.const.http.method import Method

        registries = {'Command': Command, 'FEATCode': FEATCode, 'Method': Method}
        self.assertEqual(set(registries), set(self.SWEPT_REGISTRIES))

        checked = 0
        for name in self.SWEPT_REGISTRIES:
            cls = registries[name]
            for member in cls:
                checked += 1
                with self.subTest(registry=name, member=member.name):
                    self.assertEqual(
                        str(member), member.value,
                        f'{name}.{member.name}: str(member) != member.value; '
                        f'see GitHub issue #870')

        # Command (60) + FEATCode (15) + Method (40), pinned so a registry
        # gaining or losing members gets a fresh look rather than a silent pass.
        self.assertEqual(checked, 115)

    def test_optiontype_is_exempt_but_its_own_contract_still_holds(self) -> None:
        """Not swept above because ``OptionType.value`` *is* the formatted
        display string already -- ``str(member) == member.value`` would pass
        trivially and check nothing about a raw wire payload, unlike the
        other three. This pins what its ``__new__``/``__str__`` actually
        promise instead: the value equals the display string built from
        ``opt_name``/``opt_value``, and the wire-facing ``opt_value`` is
        reachable separately via :attr:`~pcapkit.const.pcapng.option_type.
        OptionType.opt_value`, not through :class:`str` at all.
        """
        from pcapkit.const.pcapng.option_type import OptionType

        for member in OptionType:
            with self.subTest(member=member.name):
                expected = '%s [%d]' % (member.opt_name, member.opt_value)  # pylint: disable=consider-using-f-string
                self.assertEqual(str(member), expected)
                self.assertEqual(member.value, expected)
                # The raw wire value is opt_value, an int -- not derivable
                # from str(member) the way it is for Command/FEATCode/Method.
                self.assertIsInstance(member.opt_value, int)


if __name__ == '__main__':
    unittest.main()
