# -*- coding: utf-8 -*-
"""A registered ``StrEnum`` member's :class:`str` payload must be its value.

GitHub issue #870: guards against :meth:`pcapkit.const.http.method.Method.__new__`
building every registered member with ``obj = str.__new__(cls)`` -- no second
argument -- under which the underlying :class:`str` content is empty regardless
of the member's own declared value. ``_value_`` is still set correctly
(``Method.GET.value == 'GET'``), but the :class:`str` the member itself *is* is
not: ``str(Method.GET) == ''``, ``len(str(Method.GET)) == 0`` and, most visibly,
``Method.GET == 'GET'`` is :data:`False` for every declared member, as
measured. An *unregistered* member carries its value as its str payload
(:meth:`~pcapkit.const.http.method.Method._unregistered_member` calls the
base's :meth:`~pcapkit.corekit.enum.EnumRegistry._unregistered_member`, which
passes the value along; GitHub pull request #869), so with the defect
``str(Method('frob')) == 'frob'`` while ``str(Method.GET) == ''`` -- a
registered member and an unregistered one disagreeing about the one thing
they are both supposed to be, a :class:`str`.

The fix is ``obj = str.__new__(cls, value)``, mirroring
:meth:`pcapkit.const.ftp.command.Command.__new__`
(``obj = str.__new__(cls, name)``), which has no such defect. Applied to
both :mod:`pcapkit.const.http.method` (the generated module) and
:mod:`pcapkit.vendor.http.method` (the generator template that produces it),
since a fix only in the former is silently reverted by the next crawl.

The defect is visible on every public member: without the fix, every equality
comparison of a :class:`~pcapkit.const.http.method.Method` member against its
own wire string fails silently (no exception -- just an unexpected
:data:`False`). Nothing under :mod:`pcapkit.protocols` compares a member this
way (the one caller of
:meth:`~pcapkit.const.http.method.Method.get`,
:meth:`pcapkit.protocols.application.httpv1.HTTP._read_start_line`, reached
through :meth:`~pcapkit.protocols.application.httpv1.HTTP._read_http_header`
and :meth:`~pcapkit.protocols.application.httpv1.HTTP.make`, only builds a
member from the wire string, and
:meth:`~pcapkit.protocols.application.httpv1.HTTP._make_start_line` reads
``.value``; neither calls ``str()`` or ``==`` on the member itself), so the fix is
observable only to external callers and to this module's own dunders
(``__repr__`` reads ``_value_`` and is unaffected).

The wider sweep below -- :class:`StrValuedRegistryPayloadTests` -- checks the
same property, ``str(member) == member.value``, for every ``EnumRegistry``
+ ``StrEnum`` registry under :mod:`pcapkit.const` with a hand-rolled
``__new__``: :class:`~pcapkit.const.ftp.command.Command`,
:class:`~pcapkit.const.ftp.command.FEATCode`,
:class:`~pcapkit.const.http.method.Method` and
:class:`~pcapkit.const.pcapng.option_type.OptionType`. ``Command`` passes
``name`` to ``str.__new__`` and ``FEATCode`` has no custom ``__new__``
at all (the base :class:`~aenum.StrEnum` machinery handles it), so the defect
is ``Method``'s alone. ``OptionType`` is deliberately
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

from tests._support import reimport_once_per_class


class MethodStrPayload870RegressionTests(unittest.TestCase):
    """The exact repro from GitHub issue #870, and the full sweep of Method's own members."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_the_reported_case(self) -> None:
        """``Method.GET``, byte for byte, as the issue measured it.

        Without the fix, ``str(Method.GET)`` is ``''`` (``len`` 0) and
        ``Method.GET == 'GET'`` is :data:`False`.
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

    def test_registered_and_unregistered_members_both_carry_their_value(self) -> None:
        """The inconsistency #870 reported: without the fix to the
        registered half, ``str(Method('frob')) == 'frob'`` while
        ``str(Method.GET) == ''``. Both carry real content."""
        from pcapkit.const.http.method import Method

        registered = Method.GET
        unregistered = Method('frob')

        self.assertEqual(str(registered), 'GET')
        self.assertEqual(str(unregistered), 'frob')
        self.assertNotEqual(str(registered), '')
        self.assertNotEqual(str(unregistered), '')

    def test_repr_and_the_extra_attributes_are_unaffected(self) -> None:
        """Only the :class:`str` payload is at stake -- ``__repr__`` (which
        reads ``_value_``) and the ``safe``/``idempotent`` attributes
        :meth:`__new__` also sets must be unaffected."""
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

    #: The registries this sweep checks. ``Command`` and
    #: ``FEATCode`` do not carry GitHub issue #870's defect (see the module
    #: docstring's sibling survey); they are swept anyway so a regression in
    #: either would be caught here too, not only in ``Method``.
    SWEPT_REGISTRIES = ('Command', 'FEATCode', 'Method')

    def setUp(self) -> None:
        reimport_once_per_class(self)

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
        others. This pins what its ``__new__``/``__str__`` actually
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
