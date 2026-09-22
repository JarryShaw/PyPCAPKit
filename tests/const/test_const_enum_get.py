# -*- coding: utf-8 -*-
"""Registry-wide regression tests for ``get()``'s ``default`` parameter.

GitHub issue #584: the ``default`` parameter that every generated ``get()``
documents was never consulted on the integer path, because ``get`` delegated the
lookup straight to the enum call and ``_missing_`` has no access to the caller's
``default``::

    >>> Hardware.get(99999, 0)
    ValueError: 99999 is not a valid Hardware

Only the ``str`` path passed ``default`` through to :func:`~aenum.extend_enum`.
The integer path -- the one every numeric lookup takes -- could not.

The sweep below is the one #584 asked for before fixing ("the real scope is
likely wider since most ``const/`` modules are generated from the same
skeleton"). Measured: of the 118 :class:`~aenum.IntEnum` and
:class:`~aenum.IntFlag` registries defined under :mod:`pcapkit.const`, the
defect was live in 110 -- not just the three the issue named. Three of the
remaining eight never raise on an out-of-range integer because they auto-extend
the whole space, and five carry no ``get(key, default)`` at all.

Two more registries are outside this sweep because they are
:class:`~aenum.StrEnum` rather than integer enums, and both were deliberately
left alone: :class:`~pcapkit.const.pcapng.option_type.OptionType` and
:class:`~pcapkit.const.reg.apptype.AppType` each carry a bespoke integer
fallback that already resolves every value, so neither drops a default by
raising. The two string-keyed registries
:class:`~pcapkit.const.ftp.command.Command` and
:class:`~pcapkit.const.http.method.Method` have no integer path at all; they are
the subject of #582 and #583 instead.

``-1`` is the placeholder the generated signature carries, and it is what
separates "no default was supplied" from "a default was supplied and should be
used". Both halves are pinned here, because a fix that made an unresolvable key
fall back *silently* when the caller asked for no fallback would be a worse
defect than the one it replaced.

These modules are generated from :mod:`pcapkit.vendor`, so
``test_the_vendor_template_still_emits_the_fix`` renders the shared template and
compares it against a generated module. Without it a regeneration would quietly
undo the fix and the rest of this suite would still pass, because the *tree* is
what is committed and the *template* is what rebuilds it.

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

#: An integer no wire field in the library is wide enough to carry, so every
#: registry that bounds its own domain rejects it. Deliberately far outside the
#: ``0..0xFF`` range the Mobility Header flag registries check, because a value
#: *inside* an unbounded-but-undefined span reaches a separate, pre-existing
#: recursion in their ``_missing_`` (``return cls(value)``) that is not what
#: this module is about.
UNRESOLVABLE = 1 << 70

#: Enums whose integer path resolves *anything* rather than raising, so there is
#: no fallback for ``default`` to supply: all three auto-extend their unassigned
#: spans across the full integer range.
EXPECTED_TO_RESOLVE_ANYTHING = frozenset({
    'pcapkit.const.ipv4.protection_authority.ProtectionAuthority',
    'pcapkit.const.mh.cga_type.CGAType',
    'pcapkit.const.tcp.flags.Flags',
})

#: Enums carrying no ``get(key, default)``, so there is no ``default`` to drop.
#: The first four are helper enums describing a registry's columns rather than
#: registries themselves and have no ``get`` at all;
#: :class:`~pcapkit.const.reg.apptype.TransportProtocol` has a ``get`` whose
#: signature takes no ``default`` -- which is why the rewrite had to check the
#: signature rather than pattern-match the body.
EXPECTED_WITHOUT_AN_INTEGER_DEFAULT = frozenset({
    'pcapkit.const.ftp.command.CommandType',
    'pcapkit.const.ftp.command.ConformanceRequirement',
    'pcapkit.const.ftp.return_code.GroupingInformation',
    'pcapkit.const.ftp.return_code.ResponseKind',
    'pcapkit.const.reg.apptype.TransportProtocol',
})


def _iter_const_enums() -> 'list[type]':
    """Every :class:`~aenum.IntEnum` and :class:`~aenum.IntFlag` under :mod:`pcapkit.const`.

    Wider than the sweep in :mod:`tests.const.test_const_enum_lookup`, which
    excludes :class:`~aenum.IntFlag` because ``Enum(0)`` is a different contract
    for a flag registry. ``get()``'s integer path is not: the flag registries
    carry the same generated ``get`` and dropped ``default`` the same way, so
    they belong in this sweep.

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
            if (inspect.isclass(obj) and issubclass(obj, (IntEnum, IntFlag))
                    and obj.__module__ == module_info.name):
                classes.append(obj)
    return classes


def _qualname(obj: 'type') -> 'str':
    """The fully qualified name used as a sweep key."""
    return f'{obj.__module__}.{obj.__qualname__}'


class ConstEnumGetDefaultTests(unittest.TestCase):
    """``get(key, default)`` must consult ``default`` on the integer path."""

    if TYPE_CHECKING:
        enums: 'list[type]'

    @classmethod
    def setUpClass(cls) -> None:
        purge_modules(['pcapkit'])
        cls.enums = _iter_const_enums()
        # ``test_the_always_resolving_registries_have_nothing_to_fall_back_to``
        # probes registries whose ``_missing_`` extends for *any* integer, which
        # permanently registers a junk member on a module-global class. Drop the
        # whole package afterwards so that pollution cannot leak into another
        # module, rather than relying on the next test's own ``setUp`` to purge
        # it -- that protection is incidental, and this class should not depend
        # on it. Class-level rather than per-test, so ``cls.enums`` stays valid
        # for every test in this class.
        cls.addClassCleanup(purge_modules, ['pcapkit'])

    def test_the_reported_case_returns_the_default(self) -> None:
        """#584's own repro, on the enum it was reported against."""
        from pcapkit.const.arp.hardware import Hardware

        # Before the fix this raised ValueError('99999 is not a valid Hardware'),
        # dropping the caller's default entirely.
        self.assertIs(Hardware.get(99999, 0), Hardware(0))
        self.assertIs(Hardware.get(99999, 1), Hardware.Ethernet)

        # The default is genuinely consulted rather than merely swallowing the
        # error: a default that is itself unresolvable is now what fails, and
        # the message names it rather than the original key. #584 passed a
        # ``str`` where the signature says ``int``, and that is still invalid.
        with self.assertRaises(ValueError) as caught:
            Hardware.get(99999, 'X')
        self.assertIn('X', str(caught.exception))
        self.assertNotIn('99999', str(caught.exception))

        # A resolvable key is untouched.
        self.assertIs(Hardware.get(1), Hardware.Ethernet)
        self.assertIs(Hardware.get(40), Hardware(40))
        self.assertIs(Hardware.get('Ethernet'), Hardware.Ethernet)

    def test_the_placeholder_still_raises(self) -> None:
        """``-1`` means *no default*, so the lookup error must still propagate."""
        from pcapkit.const.arp.hardware import Hardware
        from pcapkit.const.arp.operation import Operation

        for enum in (Hardware, Operation):
            with self.subTest(enum=_qualname(enum)):
                with self.assertRaises(ValueError) as caught:
                    enum.get(99999)
                self.assertIn('99999', str(caught.exception))
                # Explicitly passing the placeholder is the same as omitting it.
                with self.assertRaises(ValueError):
                    enum.get(99999, -1)

    def test_the_two_unverified_enums_from_the_issue(self) -> None:
        """#584 named ``Operation`` and ``LinkType`` but verified only ``Hardware``."""
        from pcapkit.const.arp.operation import Operation
        from pcapkit.const.reg.linktype import LinkType

        self.assertIs(Operation.get(99999, 1), Operation.REQUEST)
        self.assertIs(LinkType.get(-5, 1), LinkType.ETHERNET)

    def test_the_sweep_size_is_pinned(self) -> None:
        # If this drifts, a const enum was added, removed or renamed, and the
        # two exception sets below need a fresh look rather than a silent pass.
        names = {_qualname(obj) for obj in self.enums}
        self.assertEqual(len(self.enums), 118)
        for expected in (EXPECTED_TO_RESOLVE_ANYTHING, EXPECTED_WITHOUT_AN_INTEGER_DEFAULT):
            self.assertTrue(expected.issubset(names),
                            f'sweep is missing: {expected - names}')

    def test_every_integer_path_consults_the_default(self) -> None:
        """The registry-wide form of #584, across all 118 integer registries."""
        covered = 0
        for obj in self.enums:
            qualname = _qualname(obj)
            if qualname in EXPECTED_WITHOUT_AN_INTEGER_DEFAULT:
                # Assert the reason they are excused, so the set cannot quietly
                # start covering a registry that does take a ``default``.
                get = getattr(obj, 'get', None)
                self.assertTrue(
                    get is None or 'default' not in inspect.signature(get).parameters,
                    f'{qualname} does take a `default` and belongs in the sweep')
                continue
            if qualname in EXPECTED_TO_RESOLVE_ANYTHING:
                # Covered by its own test below. Probing them here would extend
                # a module-global registry as a side effect of a sweep whose
                # subject is something else, and for these three the ``try``
                # never raises, so it would assert nothing about the fix.
                continue
            with self.subTest(enum=qualname):
                with self.assertRaises(ValueError):
                    obj.get(UNRESOLVABLE)
                fallback = next(iter(obj)).value
                self.assertIs(obj.get(UNRESOLVABLE, fallback), obj(fallback))
                covered += 1
        self.assertEqual(covered, 110)

    def test_the_always_resolving_registries_have_nothing_to_fall_back_to(self) -> None:
        """The three registries excused from the sweep, and why.

        Their ``_missing_`` extends for *any* integer, so the integer path never
        raises and ``default`` has nothing to supply. Asserted rather than merely
        listed, so ``EXPECTED_TO_RESOLVE_ANYTHING`` cannot quietly grow to hide a
        registry that does raise.

        Kept out of the sweep because probing the two :class:`~aenum.IntEnum`
        ones *mutates* the registry: the call permanently registers a member on
        a module-global class. That is done deliberately here, and ``setUpClass``
        registers a class cleanup that purges :mod:`pcapkit` afterwards so the
        pollution cannot reach another module.

        Measured: ``ProtectionAuthority`` grows 8 members to 9 and ``CGAType`` 7
        to 8, because their ``_missing_`` calls ``extend_enum``. ``Flags`` does
        not grow at all -- it is an :class:`~aenum.IntFlag` and returns a
        pseudo-member instead -- which is why the shared assertion below is
        "resolves", not "extends".
        """
        for qualname in sorted(EXPECTED_TO_RESOLVE_ANYTHING):
            module_name, _, class_name = qualname.rpartition('.')
            obj = getattr(importlib.import_module(module_name), class_name)
            with self.subTest(enum=qualname):
                # Resolving an out-of-range integer at all is the property that
                # excuses them from the sweep.
                resolved = obj.get(UNRESOLVABLE)
                self.assertIsNotNone(resolved)
                self.assertEqual(int(resolved), UNRESOLVABLE)
                # It resolves with or without a default, so the sentinel branch
                # this change added is never reached for these three.
                self.assertIs(resolved, obj.get(UNRESOLVABLE, 0))

    @unittest.skipUnless(importlib.util.find_spec('requests') is not None,
                         'pcapkit.vendor needs requests')
    def test_the_vendor_template_still_emits_the_fix(self) -> None:
        """A regeneration must not undo the fix.

        :mod:`pcapkit.const` is generated from :mod:`pcapkit.vendor`, so the
        committed tree passing is not evidence that the template agrees with it.
        Renders the shared template and compares its ``get()`` block, character
        for character, against the module generated from it.
        """
        import pathlib

        from pcapkit.vendor.default import LINE

        rendered = LINE('Hardware', 'Hardware Type [:rfc:`826`]',
                        'isinstance(value, int) and 0 <= value <= 65535',
                        "PLACEHOLDER = 'enum'", '        return None',
                        'pcapkit.vendor.arp.hardware')

        import pcapkit.const.arp.hardware as generated_module
        generated = pathlib.Path(generated_module.__file__).read_text(encoding='utf-8')

        block = re.compile(r'    @staticmethod\n    def get\(.*?\n(?=    @)', re.S)
        from_template = block.search(rendered)
        from_generated = block.search(generated)

        self.assertIsNotNone(from_template, 'the template rendered no get() block')
        self.assertIsNotNone(from_generated, 'the generated module has no get() block')
        self.assertIn('except ValueError:', from_template.group(0))
        self.assertEqual(from_template.group(0), from_generated.group(0))


if __name__ == '__main__':
    unittest.main()
