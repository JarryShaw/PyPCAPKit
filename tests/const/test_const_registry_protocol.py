# -*- coding: utf-8 -*-
"""Tests for :class:`pcapkit.corekit.enum.EnumRegistry`, tier 2 of issue #775.

Tier 1 (#838) takes the mint out of the sites in
:data:`pcapkit.vendor.default.LINE` that the default-template registries
inherit, which leaves out the crawlers that replace that template with their
own.

The design ruling on #842 finalises the abstraction: ``get``, ``get_all``,
``register`` and ``register_alias`` should always exist on the const enums, so they
live on the base class and every registry answers the same calls. The
``AppType`` sub-base class keeps its own overrides and dispatching logic, and its
subclasses override further where their contracts differ.

:class:`~pcapkit.corekit.enum.EnumRegistry` is tier one of that hierarchy. This
module pins both halves of the claim: that the generated registries covered here
really do inherit the protocol rather than carry a copy of it, and that each of
the four methods honours the contract the maintainer wrote for it.

"""
from __future__ import annotations

import importlib
import pathlib
import unittest
from typing import TYPE_CHECKING

from aenum import IntEnum, IntFlag, StrEnum, extend_enum

from pcapkit.corekit.enum import EnumRegistry
from tests._support import (ISOLATED_PREFIXES, purge_modules, reimport_once_per_class,
                            restore_modules, snapshot_modules)

if TYPE_CHECKING:
    from typing import Any

#: Repository root, for reading generated sources as text.
REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]

#: The bespoke-template registries converted onto
#: :class:`~pcapkit.corekit.enum.EnumRegistry` whose members carry no extra
#: attributes, so the shared ``_unregistered_member`` -- which sets only
#: ``_name_`` and ``_value_`` -- builds a complete member for them. ``tcp/flags``
#: is one of them: ``grep -c 'def __new__'`` reports ``0`` for both
#: ``pcapkit/vendor/tcp/flags.py`` and ``pcapkit/const/tcp/flags.py``, so it is
#: the same shape as the ``mh/*_flag`` registries, not the templates below
#: that "each attach extra attributes in ``__new__``". Its own ``_missing_``
#: does its own 16-bit range check ending in ``super()._missing_(value)``,
#: whichever base it has: that call chain resolves through :mod:`aenum`'s own
#: :class:`~aenum.Flag` machinery either way, since
#: :class:`~pcapkit.corekit.enum.EnumRegistry` never defines ``_missing_``
#: itself. The remaining bespoke templates (``ftp/command``,
#: ``ftp/return_code``, ``http/method``, ``http/status_code``,
#: ``pcapng/option_type``) do each define a custom ``__new__`` attaching further
#: attributes, so an unregistered member of theirs would be missing them; they
#: need their own override and are not in this set.
CONVERTED = (
    ('pcapkit.const.mh.binding_ack_flag', 'BindingACKFlag', 'pcapkit/const/mh/binding_ack_flag.py'),
    ('pcapkit.const.mh.binding_update_flag', 'BindingUpdateFlag', 'pcapkit/const/mh/binding_update_flag.py'),
    ('pcapkit.const.mh.handover_ack_flag', 'HandoverACKFlag', 'pcapkit/const/mh/handover_ack_flag.py'),
    ('pcapkit.const.mh.handover_initiate_flag', 'HandoverInitiateFlag', 'pcapkit/const/mh/handover_initiate_flag.py'),
    ('pcapkit.const.ipv6.extension_header', 'ExtensionHeader', 'pcapkit/const/ipv6/extension_header.py'),
    ('pcapkit.const.tcp.flags', 'Flags', 'pcapkit/const/tcp/flags.py'),
)

#: The crawlers whose bespoke templates are converted, and which must therefore
#: spell no ``get()`` of their own.
CONVERTED_VENDORS = (
    'pcapkit/vendor/mh/binding_ack_flag.py',
    'pcapkit/vendor/mh/binding_update_flag.py',
    'pcapkit/vendor/mh/handover_ack_flag.py',
    'pcapkit/vendor/mh/handover_initiate_flag.py',
    'pcapkit/vendor/ipv6/extension_header.py',
    'pcapkit/vendor/tcp/flags.py',
)

#: Every method of the protocol the ruling says must always exist.
PROTOCOL = ('get', 'get_all', 'register', 'register_alias', 'register_aliases',
            '_unregistered_member')


def _unused_value(cls: 'Any') -> 'int':
    """First non-negative integer no member of ``cls`` carries.

    Read from ``_value2member_map_`` rather than by calling ``cls(value)``:
    a declared-but-unassigned value resolves to an unregistered member
    instead of raising (#775 tier 1), so a successful call proves nothing about
    membership -- the same reason ``register_alias`` itself tests that table.

    """
    for candidate in range(1 << 16):
        if candidate not in cls._value2member_map_:
            return candidate
    raise AssertionError(f'{cls.__name__} has no unused value below 65536')


def _purge_member(cls: 'Any', name: 'str') -> 'None':
    """Undo an :func:`~aenum.extend_enum` so a test's explicit ``register()`` or
    ``register_alias()`` call does not leak into the rest of the suite.

    Mirrors ``tests.const.test_const_enum_no_mint._purge_member``, but leaves
    ``_value2member_map_`` alone when the name being dropped was an *alias*:
    that entry belongs to the pre-existing member, and removing it would make
    the alias case destructive where the mint case's is not.

    """
    member = cls._member_map_.pop(name, None)
    if member is None:
        return
    if name in cls._member_names_:
        cls._member_names_.remove(name)
    if cls._value2member_map_.get(member.value) is member and member.name == name:
        cls._value2member_map_.pop(member.value, None)


class GeneratedSourceInheritsTests(unittest.TestCase):
    """The generated registries must *inherit* the protocol, not copy it."""

    def test_converted_const_modules_declare_the_base(self) -> None:
        for _, name, relpath in CONVERTED:
            with self.subTest(registry=name):
                source = (REPO_ROOT / relpath).read_text()
                self.assertIn('from pcapkit.corekit.enum import EnumRegistry', source)
                self.assertIn(f'class {name}(EnumRegistry, ', source)

    def test_converted_const_modules_carry_no_copy_of_the_protocol(self) -> None:
        """A ``def get``/``def register`` left behind would silently shadow the
        base class, which is the failure this module guards against."""
        for _, name, relpath in CONVERTED:
            source = (REPO_ROOT / relpath).read_text()
            for method in PROTOCOL:
                with self.subTest(registry=name, method=method):
                    self.assertNotIn(f'def {method}(', source)

    def test_converted_crawlers_do_not_spell_their_own_get(self) -> None:
        for relpath in CONVERTED_VENDORS:
            with self.subTest(vendor=relpath):
                source = (REPO_ROOT / relpath).read_text()
                self.assertIn('from pcapkit.corekit.enum import EnumRegistry', source)
                self.assertNotIn("def get(key: 'int | str'", source)


class ProtocolIsInheritedTests(unittest.TestCase):
    """All of the protocol must be present, and reached from the base class."""

    if TYPE_CHECKING:
        registries: 'list[Any]'
        base: 'Any'

    @classmethod
    def setUpClass(cls) -> None:
        snapshot = snapshot_modules(ISOLATED_PREFIXES)
        purge_modules(['pcapkit'])
        cls.registries = [
            getattr(importlib.import_module(module_name), class_name)
            for module_name, class_name, _ in CONVERTED
        ]
        # NOTE: resolved from the re-imported module rather than reusing the
        # module-scope import. purge_modules() above drops every ``pcapkit``
        # entry from ``sys.modules``, so the freshly imported registries inherit
        # a *new* EnumRegistry class object -- identity against the outer one
        # would fail for a reason that says nothing about the product.
        cls.base = importlib.import_module('pcapkit.corekit.enum').EnumRegistry
        cls.addClassCleanup(restore_modules, snapshot, ISOLATED_PREFIXES)

    def test_base_class_is_in_the_mro(self) -> None:
        for registry in self.registries:
            with self.subTest(registry=registry.__qualname__):
                self.assertIn(self.base, registry.__mro__)

    def test_every_method_resolves_to_the_base_implementation(self) -> None:
        for registry in self.registries:
            for method in PROTOCOL:
                with self.subTest(registry=registry.__qualname__, method=method):
                    self.assertEqual(getattr(registry, method).__func__,
                                     getattr(self.base, method).__func__)

    def test_mixing_in_the_base_leaves_the_member_type_alone(self) -> None:
        """One base for three member types is what a generated fragment could
        not do, so the mix-in must not become the member data type itself."""
        class _Int(EnumRegistry, IntEnum):
            one = 1

        class _Flag(EnumRegistry, IntFlag):
            two = 2

        class _Str(EnumRegistry, StrEnum):
            three = 'three'

        self.assertIs(_Int._member_type_, int)
        self.assertIs(_Flag._member_type_, int)
        self.assertIs(_Str._member_type_, str)
        self.assertEqual(int(_Int.one), 1)
        self.assertEqual(str(_Str.three), 'three')


class _PreConversionFlags(IntFlag):
    """A reproduction of ``pcapkit.const.tcp.flags.Flags`` without its
    conversion onto :class:`~pcapkit.corekit.enum.EnumRegistry` (see
    :data:`CONVERTED`): a plain ``class Flags(IntFlag)`` with its own
    hand-copied ``get`` (omitted here -- irrelevant to ``_missing_``) and this
    ``_missing_``, copied verbatim. Kept inline rather than fetched from git
    history so :class:`TCPFlagsConversionTests` runs offline and the
    comparison is exact rather than approximate.
    """

    Reserved_4 = 1 << 4
    Reserved_5 = 1 << 5
    Reserved_6 = 1 << 6
    AE = 1 << 7
    CWR = 1 << 8
    ECE = 1 << 9
    URG = 1 << 10
    ACK = 1 << 11
    PSH = 1 << 12
    RST = 1 << 13
    SYN = 1 << 14
    FIN = 1 << 15

    @classmethod
    def _missing_(cls, value: 'Any') -> 'Any':
        if not (isinstance(value, int) and 0 <= value <= 0xFFFF):
            raise ValueError(f'{value!r} is not a valid {cls.__name__}')
        return super()._missing_(value)


def _resolve_or_raise(cls: 'Any', value: 'Any') -> 'Any':
    """``(int value, name)`` on success, or the exception type on failure.

    The shared probe :meth:`TCPFlagsConversionTests.test_missing_resolves_identically_to_the_pre_conversion_shape`
    runs against both the reference above and the real, converted registry.

    """
    try:
        member = cls(value)
    except Exception as error:  # pylint: disable=broad-except
        return type(error)
    return (int(member), member.name)


class TCPFlagsConversionTests(unittest.TestCase):
    """GitHub issue #775's own finding: the reason for excluding a bespoke
    template from :data:`CONVERTED` -- "each attach extra attributes in
    ``__new__``" -- does not hold for ``tcp/flags``.
    ``grep -c 'def __new__'`` reports ``0`` for both
    ``pcapkit/vendor/tcp/flags.py`` and ``pcapkit/const/tcp/flags.py``, the
    same shape as the ``mh/*_flag`` registries in :data:`CONVERTED`, so
    it belongs there rather than among the templates excluded for actually
    defining one.
    """

    def setUp(self) -> None:
        reimport_once_per_class(self, restore=True)

    def test_tcp_flags_inherits_the_base(self) -> None:
        """Guards against ``Flags`` being a plain ``IntFlag``.

        Resolves ``EnumRegistry`` freshly from the just-reimported
        ``pcapkit.corekit.enum`` rather than the module-scope import above --
        ``setUp`` gave this class its own ``pcapkit`` import, so ``Flags``
        inherits a *new* ``EnumRegistry`` class object, and identity against
        the stale outer one would fail for a reason that says nothing about
        the product (see ``ProtocolIsInheritedTests.setUpClass`` above, which
        hits the same trap).
        """
        from pcapkit.const.tcp.flags import Flags

        base = importlib.import_module('pcapkit.corekit.enum').EnumRegistry
        self.assertIn(base, Flags.__mro__)

    def test_missing_resolves_identically_to_the_pre_conversion_shape(self) -> None:
        """The conversion changes *what the class inherits*, not
        ``_missing_``'s own logic -- :class:`~pcapkit.corekit.enum.EnumRegistry`
        never defines ``_missing_`` itself, so ``super()._missing_(value)``
        inside ``Flags._missing_`` resolves through :mod:`aenum`'s
        :class:`~aenum.Flag` machinery exactly as it did when ``Flags``
        inherited from ``IntFlag`` directly. Swept rather than sampled at a
        few boundary values, across every declared member, every boundary of
        the 16-bit field the range check bounds, and several composites,
        so a widened or narrowed range check would be caught here rather
        than only in the composite-specific tests in
        ``tests/const/test_const_enum_builtin_parity.py``.
        """
        from pcapkit.const.tcp.flags import Flags

        probes = [0, 1, 0xF, 0x10, 0xFFFF, 0x10000, -1, -0x10000,
                  1 << 70, 0xFFF0]
        for member in _PreConversionFlags:
            probes.append(int(member))
        for first, second in (('PSH', 'ACK'), ('SYN', 'FIN'), ('RST', 'URG')):
            probes.append(int(_PreConversionFlags[first]) | int(_PreConversionFlags[second]))

        for value in probes:
            with self.subTest(value=value):
                self.assertEqual(_resolve_or_raise(_PreConversionFlags, value),
                                 _resolve_or_raise(Flags, value))

    def test_tcp_flags_gains_the_protocol_it_never_had(self) -> None:
        """Without the conversion none of these exist on ``Flags`` -- its own
        hand-copied ``get`` is the only member of the protocol it carries,
        with no ``get_all``, ``register``, ``register_alias``,
        ``register_aliases`` or ``_unregistered_member`` -- so this raises
        :exc:`AttributeError`.
        """
        from pcapkit.const.tcp.flags import Flags

        target = list(Flags)[0]
        self.assertEqual(Flags.get_all(target.name), (target,))

        value = _unused_value(Flags)
        self.addCleanup(_purge_member, Flags, 'unit_test_tcp_flags_minted')
        member = Flags.register(value, 'unit_test_tcp_flags_minted')
        self.assertEqual(member.value, value)

        unregistered = Flags._unregistered_member(_unused_value(Flags), 'unit_test_tcp_flags_absent')
        self.assertEqual(unregistered.name, 'unit_test_tcp_flags_absent')
        self.assertNotIn('unit_test_tcp_flags_absent', Flags.__members__)


class GetContractTests(unittest.TestCase):
    """``get`` is a shortcut for the ``[]`` operation and returns the canonical enum.

    The contract set on #842.
    """

    def setUp(self) -> None:
        reimport_once_per_class(self, restore=True)

    def test_name_and_value_both_resolve_to_the_same_member(self) -> None:
        from pcapkit.const.ipv6.extension_header import ExtensionHeader

        target = list(ExtensionHeader)[0]
        self.assertIs(ExtensionHeader.get(target.name), target)
        self.assertIs(ExtensionHeader.get(target.value), target)
        self.assertIs(ExtensionHeader.get(target.name), ExtensionHeader[target.name])

    def test_an_alias_resolves_to_its_canonical_member(self) -> None:
        from pcapkit.const.ipv6.extension_header import ExtensionHeader

        target = list(ExtensionHeader)[0]
        self.addCleanup(_purge_member, ExtensionHeader, 'unit_test_canonical')
        ExtensionHeader.register_alias(target.value, 'unit_test_canonical')

        self.assertIs(ExtensionHeader.get('unit_test_canonical'), target)
        self.assertEqual(ExtensionHeader.get('unit_test_canonical').name, target.name)

    def test_string_miss_without_default_raises_and_does_not_mint(self) -> None:
        from pcapkit.const.mh.binding_update_flag import BindingUpdateFlag

        before = len(BindingUpdateFlag.__members__)
        with self.assertRaises(KeyError):
            BindingUpdateFlag.get('Definitely-Not-A-Member')
        self.assertEqual(before, len(BindingUpdateFlag.__members__))

    def test_string_miss_with_default_falls_back_by_value(self) -> None:
        """The normalisation half of the conversion: guards against a
        hand-copied ``get()`` ending in a bare ``return NAME[key]``, under
        which ``default`` silently applies to integer keys only."""
        from pcapkit.const.ipv6.extension_header import ExtensionHeader

        target = list(ExtensionHeader)[0]
        before = len(ExtensionHeader.__members__)

        self.assertIs(ExtensionHeader.get('Definitely-Not-A-Member', target.value), target)
        self.assertEqual(before, len(ExtensionHeader.__members__))

    def test_value_miss_without_default_raises(self) -> None:
        from pcapkit.const.ipv6.extension_header import ExtensionHeader

        before = len(ExtensionHeader.__members__)
        with self.assertRaises(ValueError):
            ExtensionHeader.get(_unused_value(ExtensionHeader))
        self.assertEqual(before, len(ExtensionHeader.__members__))

    def test_value_miss_with_default_falls_back(self) -> None:
        from pcapkit.const.ipv6.extension_header import ExtensionHeader

        target = list(ExtensionHeader)[0]
        before = len(ExtensionHeader.__members__)

        result = ExtensionHeader.get(_unused_value(ExtensionHeader), target.value)

        self.assertIs(result, target)
        self.assertEqual(before, len(ExtensionHeader.__members__))

    def test_get_never_mints_on_any_converted_registry(self) -> None:
        for module_name, class_name, _ in CONVERTED:
            with self.subTest(registry=class_name):
                registry = getattr(importlib.import_module(module_name), class_name)
                before = len(registry.__members__)
                with self.assertRaises(KeyError):
                    registry.get('Definitely-Not-A-Member')
                self.assertEqual(before, len(registry.__members__))


class GetAllContractTests(unittest.TestCase):
    """``get_all`` returns every matching enum, not only the canonical one.

    The contract set on #842.
    """

    def setUp(self) -> None:
        reimport_once_per_class(self, restore=True)

    def test_a_one_to_one_registry_matches_exactly_one_member(self) -> None:
        """An alias is a second *name* for the canonical member, not a second
        member, so a registry that maps one key to one member answers with one
        entry even after an alias is registered."""
        from pcapkit.const.ipv6.extension_header import ExtensionHeader

        target = list(ExtensionHeader)[0]
        self.assertEqual(ExtensionHeader.get_all(target.value), (target,))

        self.addCleanup(_purge_member, ExtensionHeader, 'unit_test_all')
        ExtensionHeader.register_alias(target.value, 'unit_test_all')

        self.assertEqual(ExtensionHeader.get_all(target.value), (target,))
        self.assertEqual(ExtensionHeader.get_all('unit_test_all'), (target,))

    def test_get_all_is_present_on_every_converted_registry(self) -> None:
        for module_name, class_name, _ in CONVERTED:
            with self.subTest(registry=class_name):
                registry = getattr(importlib.import_module(module_name), class_name)
                target = list(registry)[0]
                self.assertEqual(registry.get_all(target.name), (target,))

    def test_get_all_propagates_a_miss(self) -> None:
        from pcapkit.const.mh.handover_ack_flag import HandoverACKFlag

        with self.assertRaises(KeyError):
            HandoverACKFlag.get_all('Definitely-Not-A-Member')


class RegisterContractTests(unittest.TestCase):
    """``register`` mints a new enum on the class at runtime under the names it is given.

    The contract set on #842: the caller supplies the names, so nothing has to guess
    one blindly.
    """

    def setUp(self) -> None:
        reimport_once_per_class(self, restore=True)

    def test_register_adds_a_new_member_under_the_given_name(self) -> None:
        from pcapkit.const.ipv6.extension_header import ExtensionHeader

        value = _unused_value(ExtensionHeader)
        self.addCleanup(_purge_member, ExtensionHeader, 'unit_test_minted')
        before = len(ExtensionHeader._member_names_)

        member = ExtensionHeader.register(value, 'unit_test_minted')

        self.assertEqual(member.value, value)
        self.assertEqual(member.name, 'unit_test_minted')
        self.assertIn(value, ExtensionHeader._value2member_map_)
        self.assertEqual(before + 1, len(ExtensionHeader._member_names_))

    def test_register_on_a_flag_registry_resolves_by_name_and_value(self) -> None:
        """Measured on :class:`~aenum.IntFlag`: a value that is the bitwise
        composite of existing flags -- which the first unused integer often is --
        registers as a *composite* pseudo-member, so ``_member_names_`` does not
        grow even though the name and value both resolve. That is
        :mod:`aenum`'s own flag semantics rather than anything this base does,
        so the assertion here is what actually holds for a flag registry."""
        from pcapkit.const.mh.handover_ack_flag import HandoverACKFlag

        value = _unused_value(HandoverACKFlag)
        self.addCleanup(_purge_member, HandoverACKFlag, 'unit_test_minted')

        member = HandoverACKFlag.register(value, 'unit_test_minted')

        self.assertEqual(member.value, value)
        self.assertIn(value, HandoverACKFlag._value2member_map_)
        self.assertIn('unit_test_minted', HandoverACKFlag.__members__)

    def test_register_over_a_taken_name_raises_value_error(self) -> None:
        """:mod:`aenum` reports a name collision as :exc:`TypeError`; the base
        translates it so one call has one failure type."""
        from pcapkit.const.mh.handover_ack_flag import HandoverACKFlag

        target = list(HandoverACKFlag)[0]
        before = len(HandoverACKFlag.__members__)

        with self.assertRaises(ValueError):
            HandoverACKFlag.register(_unused_value(HandoverACKFlag), target.name)

        self.assertEqual(before, len(HandoverACKFlag.__members__))

    def test_register_over_a_taken_value_raises_value_error_and_does_not_alias(self) -> None:
        """The guard ``register`` carries: :func:`~aenum.extend_enum` does not mint
        anything for a value that already has a member -- :mod:`aenum` treats
        that as a request to *alias* the existing member under the caller's
        name instead, silently. Without a guard, ``register(existing_value,
        'TOTALLY_NEW_NAME')`` returns the *existing* member (``.name`` still
        the original), makes ``'TOTALLY_NEW_NAME'`` reachable in
        ``__members__`` pointing at it, and mints nothing -- reachable under
        the wrong method, unannounced, and contradicting the method's own
        docstring contract that ``register`` is what mints and nothing else
        does so silently. Reproduced against this exact shape, without the
        guard, on ``pcapkit.const.reg.apptype.apptype.TransportProtocol`` (a
        different, non-:class:`~pcapkit.corekit.enum.EnumRegistry` registry,
        since that one is not gated the same way):
        ``TransportProtocol.register(6, 'TOTALLY_NEW_NAME')`` returned
        ``TransportProtocol.tcp`` unchanged and minted nothing. This pins the
        fix on the base class every :data:`CONVERTED` registry actually uses.
        """
        from pcapkit.const.ipv6.extension_header import ExtensionHeader

        target = list(ExtensionHeader)[0]
        names_before = list(ExtensionHeader._member_names_)
        members_before = dict(ExtensionHeader.__members__)

        with self.assertRaises(ValueError) as caught:
            ExtensionHeader.register(target.value, 'TOTALLY_NEW_NAME')

        self.assertIn(str(target.value), str(caught.exception))
        self.assertIn(target.name, str(caught.exception))
        self.assertIn('register_alias', str(caught.exception))
        # Nothing minted, and the wrong name never became reachable at all --
        # the failure mode this guard exists to rule out.
        self.assertEqual(names_before, list(ExtensionHeader._member_names_))
        self.assertEqual(members_before, dict(ExtensionHeader.__members__))
        self.assertNotIn('TOTALLY_NEW_NAME', ExtensionHeader.__members__)
        # And the pre-existing member is exactly as it was -- not renamed, not
        # replaced.
        self.assertIs(ExtensionHeader(target.value), target)
        self.assertEqual(target.name, ExtensionHeader(target.value).name)

    def test_register_over_a_taken_value_on_a_flag_registry_also_refuses(self) -> None:
        """The same guard, on an :class:`~aenum.IntFlag` registry: value
        collision is checked the same way regardless of member type, since
        both share :meth:`~pcapkit.corekit.enum.EnumRegistry._extend`."""
        from pcapkit.const.mh.binding_ack_flag import BindingACKFlag

        target = list(BindingACKFlag)[0]
        before = len(BindingACKFlag.__members__)

        with self.assertRaises(ValueError):
            BindingACKFlag.register(target.value, 'TOTALLY_NEW_FLAG_NAME')

        self.assertEqual(before, len(BindingACKFlag.__members__))
        self.assertNotIn('TOTALLY_NEW_FLAG_NAME', BindingACKFlag.__members__)

    def test_register_alias_still_aliases_after_the_value_guard(self) -> None:
        """:meth:`register_alias` depends on :meth:`register` accepting an
        already-registered value -- a dependency carried by the shared,
        ungated :meth:`~pcapkit.corekit.enum.EnumRegistry._extend`, so this
        pins that the value guard does not also gate the path
        :meth:`register_alias` needs. A naive guard placed directly in
        the body :meth:`register` calls would make every alias registration
        raise the exact error this test's sibling above checks for, rather
        than aliasing. Deliberately on ``ExtensionHeader`` rather than
        ``Flags``: this registry inherits
        :class:`~pcapkit.corekit.enum.EnumRegistry` independently of
        ``tcp/flags``'s conversion, so this pins the internal refactor alone
        -- unlike this class's ``Flags``-based siblings above, which pin the
        guard itself and so also need ``tcp/flags`` in :data:`CONVERTED`."""
        from pcapkit.const.ipv6.extension_header import ExtensionHeader

        target = list(ExtensionHeader)[0]
        self.addCleanup(_purge_member, ExtensionHeader, 'unit_test_alias_after_guard')

        result = ExtensionHeader.register_alias(target.value, 'unit_test_alias_after_guard')

        self.assertIs(result, target)
        self.assertIs(ExtensionHeader['unit_test_alias_after_guard'], target)


class RegisterAliasContractTests(unittest.TestCase):
    """``register_alias`` adds additional alias(es) to a given enum's mapping.

    The contract set on #842, which also ruled that an alias is always for an
    existing member, unless ``AppType`` (and the concrete enums) must call it on a
    member that does not exist yet. One method name then carries one convention
    across the registries, and for the plain registries an alias is a caller-opt-in
    name that IANA does not record.

    """

    def setUp(self) -> None:
        reimport_once_per_class(self, restore=True)

    def test_alias_adds_a_name_not_a_member(self) -> None:
        from pcapkit.const.ipv6.extension_header import ExtensionHeader

        target = list(ExtensionHeader)[0]
        self.addCleanup(_purge_member, ExtensionHeader, 'unit_test_alias')
        names_before = list(ExtensionHeader._member_names_)
        members_before = len(ExtensionHeader.__members__)

        result = ExtensionHeader.register_alias(target.value, 'unit_test_alias')

        self.assertIs(result, target)
        self.assertIs(ExtensionHeader['unit_test_alias'], target)
        self.assertEqual(names_before, list(ExtensionHeader._member_names_))
        self.assertEqual(members_before + 1, len(ExtensionHeader.__members__))

    def test_alias_for_an_unregistered_value_is_refused(self) -> None:
        from pcapkit.const.mh.binding_ack_flag import BindingACKFlag

        value = _unused_value(BindingACKFlag)
        before = len(BindingACKFlag.__members__)

        with self.assertRaises(ValueError) as caught:
            BindingACKFlag.register_alias(value, 'unit_test_alias')

        self.assertIn('is not a registered BindingACKFlag', str(caught.exception))
        self.assertEqual(before, len(BindingACKFlag.__members__))
        self.assertNotIn('unit_test_alias', BindingACKFlag.__members__)

    def test_alias_over_a_taken_name_raises_value_error(self) -> None:
        from pcapkit.const.mh.binding_ack_flag import BindingACKFlag

        target = list(BindingACKFlag)[0]
        before = len(BindingACKFlag.__members__)

        with self.assertRaises(ValueError):
            BindingACKFlag.register_alias(target.value, target.name)

        self.assertEqual(before, len(BindingACKFlag.__members__))

    def test_register_aliases_adds_several(self) -> None:
        from pcapkit.const.mh.handover_initiate_flag import HandoverInitiateFlag

        target = list(HandoverInitiateFlag)[0]
        for name in ('unit_test_a', 'unit_test_b'):
            self.addCleanup(_purge_member, HandoverInitiateFlag, name)
        names_before = list(HandoverInitiateFlag._member_names_)

        result = HandoverInitiateFlag.register_aliases(
            target.value, 'unit_test_a', 'unit_test_b')

        self.assertEqual(result, (target, target))
        self.assertIs(HandoverInitiateFlag['unit_test_a'], target)
        self.assertIs(HandoverInitiateFlag['unit_test_b'], target)
        self.assertEqual(names_before, list(HandoverInitiateFlag._member_names_))


class UnregisteredMemberTests(unittest.TestCase):
    """``_unregistered_member`` must stay outside the lookup tables, for both
    member types the base serves."""

    def setUp(self) -> None:
        reimport_once_per_class(self, restore=True)

    def test_int_valued_registries(self) -> None:
        for module_name, class_name, _ in CONVERTED:
            with self.subTest(registry=class_name):
                registry = getattr(importlib.import_module(module_name), class_name)
                value = _unused_value(registry)

                member = registry._unregistered_member(value, 'unit_test_absent')

                self.assertEqual(member.value, value)
                self.assertEqual(member.name, 'unit_test_absent')
                self.assertNotIn(value, registry._value2member_map_)
                self.assertNotIn('unit_test_absent', registry.__members__)

    def test_str_valued_registries(self) -> None:
        """``cls._member_type_.__new__`` is what generalises this beyond ``int``
        -- a generated fragment hardcoding ``int.__new__`` could not serve the
        :class:`~aenum.StrEnum` registries."""
        class _Str(EnumRegistry, StrEnum):
            known = 'known'

        member = _Str._unregistered_member('absent', 'unit_test_absent')

        self.assertEqual(member.value, 'absent')
        self.assertEqual(str(member), 'absent')
        self.assertEqual(member.name, 'unit_test_absent')
        self.assertNotIn('absent', _Str._value2member_map_)
        self.assertNotIn('unit_test_absent', _Str.__members__)


#: Sample of the default-template registries on
#: :class:`~pcapkit.corekit.enum.EnumRegistry` (GitHub issue #775's tier 3),
#: chosen to cover
#: the two shapes the census turned up in ``pcapkit/vendor/default.py``'s
#: ``LINE`` template: a registry whose own ``_missing_`` mints directly via
#: :func:`~aenum.extend_enum` for an unassigned value (``TransType``,
#: ``LinkType``, ``RecordType``, ``Parameter`` -- the last two from crawlers
#: that override ``process()`` to supply that ``_missing_`` body themselves),
#: and one that resolves a bounded-but-unassigned value through the
#: inherited ``_unregistered_member`` instead (``Hardware``). The template's
#: own ``from aenum import IntEnum{, extend_enum}`` import line depends on
#: which shape a given registry's crawler produces, so the sample deliberately
#: covers both.
GENERATED_SAMPLE = (
    ('pcapkit.const.reg.transtype', 'TransType', 'pcapkit/const/reg/transtype.py'),
    ('pcapkit.const.reg.linktype', 'LinkType', 'pcapkit/const/reg/linktype.py'),
    ('pcapkit.const.arp.hardware', 'Hardware', 'pcapkit/const/arp/hardware.py'),
    ('pcapkit.const.pcapng.record_type', 'RecordType', 'pcapkit/const/pcapng/record_type.py'),
    ('pcapkit.const.hip.parameter', 'Parameter', 'pcapkit/const/hip/parameter.py'),
)

#: Const modules tier 3 deliberately leaves alone. The bespoke ones override
#: their crawler's own ``process()``/``context()`` with a bespoke ``get()``/
#: ``_missing_`` pair that does not share :mod:`pcapkit.vendor.default`'s
#: template at all -- mixing :class:`~pcapkit.corekit.enum.EnumRegistry` in
#: without further care would silently change behaviour rather than just
#: move it, since several are :class:`~aenum.StrEnum` registries whose
#: own ``__new__`` attaches further attributes the base's generic
#: ``_unregistered_member`` does not set. GitHub issue #860 fixes the base
#: ``get()``'s own str-key-never-tries-the-value-path limitation -- measured
#: on a synthetic registry in :class:`StrEnumValueFallbackTests` below -- and
#: issue #860's step 2 converts them all (``FEATCode``, ``Command``,
#: ``Method``, ``ReturnCode``/``ResponseKind``/``GroupingInformation``,
#: ``StatusCode``, ``OptionType``, and ``AppType`` and its transport
#: subclasses), each with its own ``_unregistered_member`` override where a
#: custom ``__new__`` needs one. They stay excluded from *this* file's
#: tier-3 sweep regardless, because the exclusion here is about their
#: bespoke ``process()``/``get()`` shape not sharing the generated template,
#: which conversion onto the base does not change -- unlike the
#: default-template registries :data:`GENERATED_SAMPLE` samples above, each
#: of these classes' own ``_missing_`` stays bespoke rather than sharing the
#: generated template, and several also keep a bespoke
#: ``_unregistered_member`` (``Command``, ``Method``, ``OptionType``,
#: ``ReturnCode``, ``StatusCode``) or a bespoke ``get`` of their own
#: (``Command``, ``Method``, ``OptionType``; ``AppType`` and its transport
#: subclasses keep ``get``/``get_all``/``register``/``register_alias`` of
#: their own) -- but not every one does:
#: ``FEATCode``, ``ResponseKind`` and ``GroupingInformation`` resolve every
#: protocol method to the base's generic implementation unchanged.
#: ``TransportProtocol`` alone is excluded for
#: a separate reason: it never mixes in
#: :class:`~pcapkit.corekit.enum.EnumRegistry` at all, by the owner's own
#: ruling against extending it (GitHub PR #836) -- there is no registry
#: protocol here to inherit or shadow.
#:
#: The name below is deliberately about what the set *does*, not why: it is
#: everything this file's ``IntEnum``-only census (:data:`GENERATED_SAMPLE`
#: and the ``generated`` list below) leaves out -- not a claim that every
#: entry shares one reason. At least three apply, and the
#: grouping below tags each entry with its own: (a) is a
#: :class:`~aenum.StrEnum` registry, so would miss this file's
#: ``class \w+(EnumRegistry, IntEnum):`` regex regardless of anything else;
#: (b) mixes in the base but overrides its generic protocol with a bespoke
#: one, per the paragraph above; (c) ``TransportProtocol`` alone, which never
#: mixes in the base at all. A file can carry more than one -- ``apptype.py``
#: is (a) via ``AppType`` and (c) via ``TransportProtocol`` in the same
#: module.
#:
#: ``pcapkit/const/pcapng/tls_key_label.py`` (GitHub issue #886) is reason
#: (a) too, but on narrower grounds worth spelling out, since -- unlike the
#: rest of that group -- it does not carry a bespoke ``get()``/``register()``
#: at all; its own ``get``/``get_all``/``register``/``register_alias`` are
#: exactly the base's generic implementation, same as every
#: :data:`GENERATED_SAMPLE`-shaped registry below. What excludes it is
#: simply that this whole census, and its
#: ``class \w+(EnumRegistry, IntEnum):`` regex a few lines down, is scoped to
#: the :class:`~aenum.IntEnum` batch tier 3 of #775 converted.
#: ``TLSKeyLabel`` is :class:`~aenum.StrEnum`-valued -- RFC 9850's labels are
#: strings, matched by value -- so it is outside that batch either way.
#: Excluding it here
#: is not a judgement about its own inherited-protocol cleanliness;
#: :mod:`tests.const.test_const_enum_get`,
#: :mod:`tests.const.test_const_enum_lookup` and
#: :mod:`tests.const.test_const_enum_builtin_parity`'s dynamic
#: ``pkgutil.walk_packages`` sweeps already discover and cover it
#: generically -- it is simply outside what this file's IntEnum-only census
#: counts.
EXCLUDED_FROM_INTENUM_CENSUS = frozenset({
    # (a) str-valued: not an IntEnum, so excluded from the regex census
    # regardless of override.
    'pcapkit/const/ftp/command.py',           # Command, FEATCode
    'pcapkit/const/http/method.py',           # Method
    'pcapkit/const/pcapng/option_type.py',    # OptionType
    'pcapkit/const/pcapng/tls_key_label.py',  # TLSKeyLabel -- see the paragraph above
    'pcapkit/const/reg/apptype/dccp.py',      # DCCP
    'pcapkit/const/reg/apptype/sctp.py',      # SCTP
    'pcapkit/const/reg/apptype/tcp.py',       # TCP
    'pcapkit/const/reg/apptype/udp.py',       # UDP

    # (b) int-valued and mixes in the base, but carries a custom __new__
    # plus its own _unregistered_member override, so it is not the
    # generated shape -- get()/get_all()/register()/register_alias() all
    # still resolve to the base's generic implementation.
    'pcapkit/const/ftp/return_code.py',       # ReturnCode (ResponseKind and
                                               # GroupingInformation, same file,
                                               # are clean; excluded only as
                                               # co-residents)
    'pcapkit/const/http/status_code.py',      # StatusCode

    # (a) and (c) together: AppType is str-valued like the group above (and
    # overrides get()/get_all()/register()/register_alias() more fully than
    # either (b) file above); TransportProtocol, in the same file, never
    # mixes in the base at all.
    'pcapkit/const/reg/apptype/apptype.py',   # AppType, TransportProtocol
})


class GeneratedTemplateSourceInheritsTests(unittest.TestCase):
    """The default-template registries must inherit the protocol too,
    not just the bespoke ones :class:`GeneratedSourceInheritsTests`
    above (tier 2) already covers."""

    def test_generated_sample_declares_the_base(self) -> None:
        for _, name, relpath in GENERATED_SAMPLE:
            with self.subTest(registry=name):
                source = (REPO_ROOT / relpath).read_text()
                self.assertIn('from pcapkit.corekit.enum import EnumRegistry', source)
                self.assertIn(f'class {name}(EnumRegistry, IntEnum):', source)

    def test_generated_sample_carries_no_copy_of_the_protocol(self) -> None:
        """A ``def get``/``def register``/``def _unregistered_member`` left
        behind would silently shadow the base -- the exact two-contract bug
        #775's tier 3 removes. ``_missing_`` must survive, since it
        carries each registry's own bounded ranges and was never meant to
        move."""
        for _, name, relpath in GENERATED_SAMPLE:
            source = (REPO_ROOT / relpath).read_text()
            for method in PROTOCOL:
                with self.subTest(registry=name, method=method):
                    self.assertNotIn(f'def {method}(', source)
            with self.subTest(registry=name, method='_missing_'):
                self.assertIn("def _missing_(cls, value: 'int')", source)

    def test_every_generated_const_module_is_accounted_for(self) -> None:
        """The full census, measured rather than assumed: the modules under
        :mod:`pcapkit.const` split exactly three ways -- the
        :data:`CONVERTED` bespoke ones tier 2 handled, the
        :data:`EXCLUDED_FROM_INTENUM_CENSUS` ones deliberately left alone, and
        the rest, which must all be the generated shape. A literal "Backport
        support for original codes." docstring is not proof of a shared
        template: it is hand-copied into the bespoke StrEnum/AppType files
        too.

        GitHub issue #886's ``pcapkit/const/pcapng/tls_key_label.py`` is on
        the excluded side -- see the comment directly above
        :data:`EXCLUDED_FROM_INTENUM_CENSUS` for why. GitHub issue #880's
        ``pcapkit/const/ngap/procedure_code.py`` and
        ``pcapkit/const/ngap/protocol_ie.py`` are the generated shape
        outright -- plain ``EnumRegistry`` + ``IntEnum``, no bespoke
        ``get()``/``_missing_``-carrying ``__new__`` -- so they are on the
        *generated* side.
        """
        const_root = REPO_ROOT / 'pcapkit' / 'const'
        all_files = sorted(
            path.relative_to(REPO_ROOT).as_posix()
            for path in const_root.rglob('*.py')
            if path.name != '__init__.py'
        )
        converted_relpaths = {relpath for _, _, relpath in CONVERTED}
        generated = [path for path in all_files
                     if path not in converted_relpaths and path not in EXCLUDED_FROM_INTENUM_CENSUS]

        self.assertEqual(len(all_files), 124)
        self.assertEqual(len(generated), 107)

        for relpath in generated:
            with self.subTest(module=relpath):
                source = (REPO_ROOT / relpath).read_text()
                self.assertIn('from pcapkit.corekit.enum import EnumRegistry', source)
                self.assertRegex(source, r'class \w+\(EnumRegistry, IntEnum\):')
                for method in PROTOCOL:
                    self.assertNotIn(f'def {method}(', source)


class GeneratedProtocolIsInheritedTests(unittest.TestCase):
    """The generated sample's protocol methods must resolve to the base
    class, exactly as :class:`ProtocolIsInheritedTests` above pins for the
    bespoke ones."""

    if TYPE_CHECKING:
        registries: 'list[Any]'
        base: 'Any'

    @classmethod
    def setUpClass(cls) -> None:
        snapshot = snapshot_modules(ISOLATED_PREFIXES)
        purge_modules(['pcapkit'])
        cls.registries = [
            getattr(importlib.import_module(module_name), class_name)
            for module_name, class_name, _ in GENERATED_SAMPLE
        ]
        cls.base = importlib.import_module('pcapkit.corekit.enum').EnumRegistry
        cls.addClassCleanup(restore_modules, snapshot, ISOLATED_PREFIXES)

    def test_base_class_is_in_the_mro(self) -> None:
        for registry in self.registries:
            with self.subTest(registry=registry.__qualname__):
                self.assertIn(self.base, registry.__mro__)

    def test_every_method_resolves_to_the_base_implementation(self) -> None:
        for registry in self.registries:
            for method in PROTOCOL:
                with self.subTest(registry=registry.__qualname__, method=method):
                    self.assertEqual(getattr(registry, method).__func__,
                                     getattr(self.base, method).__func__)

    def test_member_type_stays_int_not_enumregistry(self) -> None:
        """The base-class ordering rule #855 established:
        ``class {NAME}(EnumRegistry, IntEnum)`` with the non-``Enum`` mixin
        first is what keeps :mod:`aenum` resolving ``_member_type_`` from
        ``IntEnum`` rather than from the mix-in -- verified rather than
        assumed."""
        for registry in self.registries:
            with self.subTest(registry=registry.__qualname__):
                self.assertIs(registry._member_type_, int)


class GeneratedMissingRangeParityTests(unittest.TestCase):
    """``_missing_``'s own bounded ranges are deliberately outside the
    conversion onto the base, so this is a regression pin on that claim."""

    def setUp(self) -> None:
        reimport_once_per_class(self, restore=True)

    def test_hardware_still_bounds_and_resolves_its_unassigned_ranges(self) -> None:
        """:class:`~pcapkit.const.arp.hardware.Hardware` declares ``0..38``
        and ``39..255``/``258..65534`` as unassigned-but-in-range, ``65535``
        as its own reserved member, and rejects anything else -- the
        conversion concerns only the duplicate ``get``/``register``/
        ``_unregistered_member`` a generated module could carry next to it."""
        from pcapkit.const.arp.hardware import Hardware

        # In range, unassigned: resolves without minting a permanent member
        # (tier 1's fix), reachable via the inherited get() too.
        for value in (39, 255, 258, 65534):
            with self.subTest(value=value):
                self.assertEqual(Hardware(value).value, value)
                self.assertEqual(Hardware(value).name, 'Unassigned')
                self.assertNotIn(value, Hardware._value2member_map_)
                self.assertEqual(Hardware.get(value).value, value)

        # Out of the declared 0..65535 range: still raises, with or without
        # a default -- the default is only consulted once _missing_ itself
        # has already failed to resolve the key.
        with self.assertRaises(ValueError):
            Hardware(65536)
        with self.assertRaises(ValueError):
            Hardware.get(65536)
        self.assertIs(Hardware.get(65536, 1), Hardware.Ethernet)

    def test_transtype_does_not_mint_its_declared_unassigned_range(self) -> None:
        """:class:`~pcapkit.const.reg.transtype.TransType`'s own
        ``_missing_`` goes through ``_unregistered_member`` for ``148..252``,
        not a permanent :func:`~aenum.extend_enum` mint: per the #775/#847
        mint-criterion ruling, the label is a bare ``Unassigned``, which is a
        notation for the reader rather than a name IANA assigned, so it
        matches :class:`~pcapkit.const.arp.hardware.Hardware`'s shape above."""
        from pcapkit.const.reg.transtype import TransType

        before = len(TransType._member_names_)
        member = TransType(200)

        self.assertEqual(member.value, 200)
        self.assertEqual(member.name, 'Unassigned')
        self.assertNotIn(200, TransType._value2member_map_)
        self.assertEqual(before, len(TransType._member_names_))
        self.assertEqual(TransType(200), TransType.get(200))

        with self.assertRaises(ValueError):
            TransType(9999)


class RegisterAlreadyRegisteredNowRaisesOnAGeneratedRegistryTests(unittest.TestCase):
    """The residue #855 disclosed: the duplicate-value guard keeps
    ``register()`` on an already-registered value from silently aliasing
    on a generated registry. Without it, ``TransType.register(6,
    'TOTALLY_NEW_NAME')`` returns the *existing* ``TransType.TCP``, makes
    ``'TOTALLY_NEW_NAME'`` reachable in ``__members__`` pointing at it, and
    neither mints nor raises. With it, the call raises::

        ValueError: 6 is already registered on TransType as 'TCP'; use
        TransType.register_alias() to add a further name for it

    and ``'TOTALLY_NEW_NAME'`` never enters ``__members__``.

    """

    def setUp(self) -> None:
        reimport_once_per_class(self, restore=True)

    def test_register_over_a_taken_value_raises(self) -> None:
        from pcapkit.const.reg.transtype import TransType

        names_before = list(TransType._member_names_)
        members_before = dict(TransType.__members__)

        with self.assertRaises(ValueError) as caught:
            TransType.register(6, 'TOTALLY_NEW_NAME')

        self.assertIn('6', str(caught.exception))
        self.assertIn('TCP', str(caught.exception))
        self.assertIn('register_alias', str(caught.exception))
        self.assertEqual(names_before, list(TransType._member_names_))
        self.assertEqual(members_before, dict(TransType.__members__))
        self.assertNotIn('TOTALLY_NEW_NAME', TransType.__members__)
        self.assertIs(TransType(6), TransType.TCP)

    def test_register_still_mints_for_a_genuinely_new_value(self) -> None:
        from pcapkit.const.reg.transtype import TransType

        value = _unused_value(TransType)
        self.addCleanup(_purge_member, TransType, 'unit_test_generated_minted')

        member = TransType.register(value, 'unit_test_generated_minted')

        self.assertEqual(member.value, value)
        self.assertIn(value, TransType._value2member_map_)


class GetDispatchMatrixTests(unittest.TestCase):
    """The dispatch order: a generated ``get()`` checking
    ``isinstance(key, int)`` first treats anything else as a name; the
    inherited base checks ``isinstance(key, str)`` first and treats
    anything else as a value. For a key that actually is an ``int``
    or a ``str``, both orderings agree, so every probe below except the
    "neither" one is a parity pin rather than a change; the "neither" probe
    is the one documented, deliberate difference, shown on ``TransType``
    (a plain generated ``IntEnum`` registry):

    An int-first ``get()``::

        >>> TransType.get(3.5)
        KeyError: 3.5          # not int -> treated as a name -> dict miss

    The inherited base::

        >>> TransType.get(3.5)
        ValueError: 3.5 is not a valid TransType   # not str -> treated as a
        # value -> TransType(3.5) -> _missing_(3.5) -> not int -> ValueError

    Neither raised exception mints anything, and both are still exactly the
    kind of error :meth:`~pcapkit.corekit.enum.EnumRegistry.get`'s own
    docstring promises for an unresolvable key with no default.
    """

    def setUp(self) -> None:
        reimport_once_per_class(self, restore=True)

    def test_valid_int_value(self) -> None:
        from pcapkit.const.reg.transtype import TransType

        self.assertIs(TransType.get(6), TransType.TCP)

    def test_valid_name(self) -> None:
        from pcapkit.const.reg.transtype import TransType

        self.assertIs(TransType.get('TCP'), TransType.TCP)

    def test_missing_name_without_default_raises_key_error(self) -> None:
        from pcapkit.const.reg.transtype import TransType

        with self.assertRaises(KeyError):
            TransType.get('Definitely_Not_A_Member')

    def test_missing_name_with_default_falls_back(self) -> None:
        from pcapkit.const.reg.transtype import TransType

        self.assertIs(TransType.get('Definitely_Not_A_Member', 6), TransType.TCP)

    def test_missing_int_without_default_raises_value_error(self) -> None:
        """``9999`` is outside TransType's declared ``0..255`` domain
        entirely, so this is a genuine miss rather than an unassigned-but
        in-range value that ``_missing_`` would otherwise resolve."""
        from pcapkit.const.reg.transtype import TransType

        with self.assertRaises(ValueError):
            TransType.get(9999)

    def test_missing_int_with_default_falls_back(self) -> None:
        from pcapkit.const.reg.transtype import TransType

        self.assertIs(TransType.get(9999, 6), TransType.TCP)

    def test_a_key_that_is_neither_int_nor_str_flips_exception_type(self) -> None:
        """The one deliberate, documented behaviour difference of the base's
        dispatch order: a key that is neither ``int`` nor ``str`` raises
        :exc:`ValueError` (treated as a value, rejected by ``_missing_``'s own
        ``isinstance(value, int)`` guard) rather than :exc:`KeyError`
        (treated as a name, rejected by a plain dict lookup) -- measured in
        this class's own docstring above."""
        from pcapkit.const.reg.transtype import TransType

        for key in (3.5, None, b'x'):
            with self.subTest(key=key):
                with self.assertRaises(ValueError) as caught:
                    TransType.get(key)
                self.assertIn('is not a valid TransType', str(caught.exception))


class GetDispatchMatrixIntFlagTests(unittest.TestCase):
    """The same matrix as :class:`GetDispatchMatrixTests`, on an
    :class:`~aenum.IntFlag` registry rather than a plain
    :class:`~aenum.IntEnum` one -- GitHub issue #860's own instructions call
    for measuring both member types the base serves, not just one. Every
    probe here is unchanged by #860's ``str``-branch fix, since
    ``HandoverACKFlag.get`` never takes that branch for an ``int`` key or a
    key that is neither ``int`` nor ``str``; this class exists to pin that
    the ``IntFlag`` path really is untouched, not to assume it."""

    def setUp(self) -> None:
        reimport_once_per_class(self, restore=True)

    def test_valid_int_value(self) -> None:
        from pcapkit.const.mh.handover_ack_flag import HandoverACKFlag

        self.assertIs(HandoverACKFlag.get(0x80), HandoverACKFlag.U)

    def test_valid_name(self) -> None:
        from pcapkit.const.mh.handover_ack_flag import HandoverACKFlag

        self.assertIs(HandoverACKFlag.get('U'), HandoverACKFlag.U)

    def test_missing_name_without_default_raises_key_error(self) -> None:
        from pcapkit.const.mh.handover_ack_flag import HandoverACKFlag

        with self.assertRaises(KeyError):
            HandoverACKFlag.get('Definitely_Not_A_Member')

    def test_missing_name_with_default_falls_back(self) -> None:
        from pcapkit.const.mh.handover_ack_flag import HandoverACKFlag

        self.assertIs(HandoverACKFlag.get('Definitely_Not_A_Member', 0x40), HandoverACKFlag.P)

    def test_missing_int_without_default_raises_value_error(self) -> None:
        """``9999`` is outside the ``0..0xFF`` range ``HandoverACKFlag``'s own
        ``_missing_`` bounds, so this is a genuine miss."""
        from pcapkit.const.mh.handover_ack_flag import HandoverACKFlag

        with self.assertRaises(ValueError):
            HandoverACKFlag.get(9999)

    def test_missing_int_with_default_falls_back(self) -> None:
        from pcapkit.const.mh.handover_ack_flag import HandoverACKFlag

        self.assertIs(HandoverACKFlag.get(9999, 0x40), HandoverACKFlag.P)

    def test_a_key_that_is_neither_int_nor_str_raises_value_error(self) -> None:
        from pcapkit.const.mh.handover_ack_flag import HandoverACKFlag

        for key in (3.5, None, b'x'):
            with self.subTest(key=key):
                with self.assertRaises(ValueError) as caught:
                    HandoverACKFlag.get(key)
                self.assertIn('is not a valid HandoverACKFlag', str(caught.exception))


class StrEnumValueFallbackTests(unittest.TestCase):
    """GitHub issue #860, step 1: guards against the base ``get()``'s
    ``isinstance(key, str)`` branch trying only ``cls._member_map_[key]`` --
    a *name* lookup -- and never falling back to treating a ``str`` key as a
    *value*, unlike the integer path. It shows on a synthetic registry
    rather than a real one, since #855 converts no :class:`~aenum.StrEnum`
    registry to :class:`~pcapkit.corekit.enum.EnumRegistry`. The bespoke
    ``StrEnum`` const registries -- ``FEATCode``, ``Command``, ``Method``,
    and ``AppType`` with its transport subclasses -- mix in this base
    through #860's separate step 2, and
    :data:`EXCLUDED_FROM_INTENUM_CENSUS` above holds them out of *this*
    file's tier-3 sweep for a different reason: they are
    :class:`~aenum.StrEnum`, not :class:`~aenum.IntEnum`, which is reason
    (a) there regardless of whether any one of them also overrides the
    base.

    The fallback is a plain ``_value2member_map_`` lookup, not
    ``cls(key)``: routing it through the constructor would let a failed
    *name* lookup mint a permanent member on any registry whose own
    ``_missing_`` mints directly via :func:`~aenum.extend_enum` for an
    unrecognised value -- as :class:`~pcapkit.const.ftp.command.FEATCode`'s
    does without #860's step 2 (that minting call reproduced
    verbatim in
    :meth:`test_get_never_mints_on_a_registry_whose_missing_mints_directly`
    below) -- exactly the "never mints" defect
    :meth:`~pcapkit.corekit.enum.EnumRegistry.get`'s own docstring rules
    out. The fixture below is therefore a synthetic local class reproducing
    that shape rather than an import of a real one: the defect this test
    guards against is general. A raw dict lookup can never reach ``_missing_``, so it cannot
    mint regardless of what a subclass's own ``_missing_`` does.
    """

    def test_a_str_key_that_is_a_value_but_not_a_name_resolves(self) -> None:
        """The defect itself: without the fix, this raises ``KeyError``."""
        class _Str(EnumRegistry, StrEnum):
            KNOWN = 'known-value'

        # The name resolves, as it always would.
        self.assertIs(_Str.get('KNOWN'), _Str.KNOWN)

        # The *value* -- a different string from the name -- resolves too,
        # matching what the constructor does directly.
        self.assertIs(_Str('known-value'), _Str.KNOWN)
        self.assertIs(_Str.get('known-value'), _Str.KNOWN)

    def test_name_wins_over_a_different_members_value(self) -> None:
        """Ordering decision: a name match wins over a value match, so a
        string that is *both* a member's name and a different member's
        value resolves to the name's member. This holds with or without the
        fix (the fix leaves the name branch alone) -- it is the ordering the
        fix's fall-through has to preserve, and is pinned here so the
        ordering stays a decision rather than an accident."""
        class _Str(EnumRegistry, StrEnum):
            ALPHA = 'BETA'
            BETA = 'gamma'

        self.assertIs(_Str.get('BETA'), _Str.BETA)
        self.assertIsNot(_Str.get('BETA'), _Str.ALPHA)

    def test_a_str_value_match_wins_over_a_supplied_default(self) -> None:
        """A second, compounding half of the same defect: without the fix,
        the ``str`` branch's ``except KeyError`` fires for *any* non-name key,
        so a supplied ``default`` is returned even when the key itself is a
        perfectly good value -- the default silently overrides a match that
        should win, returning ``_Str('elsewhere')`` instead of
        ``_Str.KNOWN``."""
        class _Str(EnumRegistry, StrEnum):
            KNOWN = 'known-value'
            ELSEWHERE = 'elsewhere'

        self.assertIs(_Str.get('known-value', 'elsewhere'), _Str.KNOWN)

    def test_missing_value_with_no_match_and_no_default_still_raises_key_error(self) -> None:
        """A ``str`` key that resolves neither as a name nor as a value, with
        no default, still raises :exc:`KeyError` -- not :exc:`ValueError` --
        matching :meth:`~pcapkit.corekit.enum.EnumRegistry.get`'s own
        documented contract for a name miss. Holds with or without the
        fix."""
        class _Str(EnumRegistry, StrEnum):
            KNOWN = 'known-value'

        with self.assertRaises(KeyError):
            _Str.get('totally-unknown')

    def test_get_never_mints_on_a_registry_whose_missing_mints_directly(self) -> None:
        """The crux the fix has to get right: the minting half of this
        fixture's ``_missing_`` is verbatim
        :meth:`~pcapkit.const.ftp.command.FEATCode._missing_`'s body without
        GitHub issue #860 step 2's conversion onto ``_unregistered_member``
        -- ``extend_enum(cls, value.upper(), value)`` for any unrecognised
        string. The fixture is a synthetic, self-contained reproduction of
        that shape rather than an import of the real class, since the point
        of this test is the general defect class, which a converted example
        cannot demonstrate. Its non-``str`` branch differs from that shape
        (delegates to ``super()._missing_`` rather than ``FEATCode``'s own
        explicit ``ValueError``), which is immaterial to what this test proves.
        A naive ``return cls(key)`` fallback would mint a permanent member from
        a mere failed lookup; the ``_value2member_map_`` lookup the fix uses
        instead never reaches ``_missing_`` at all, so it cannot. Holds with or
        without the fix -- without it, ``get`` never attempts the value path,
        so it cannot mint either; this pins that the fix keeps that guarantee
        while closing the gap."""
        class _MintingStr(EnumRegistry, StrEnum):
            KNOWN = 'known-value'

            @classmethod
            def _missing_(cls, value: 'Any') -> 'Any':
                if not isinstance(value, str):
                    return super()._missing_(value)
                return extend_enum(cls, value.upper(), value)

        values_before = {member.value for member in _MintingStr}
        members_before = set(_MintingStr.__members__)

        with self.assertRaises(KeyError):
            _MintingStr.get('never-seen-before')

        self.assertEqual(values_before, {member.value for member in _MintingStr})
        self.assertEqual(members_before, set(_MintingStr.__members__))


class NoDefaultSentinelTests(unittest.TestCase):
    """GitHub issue #857: :data:`~pcapkit.corekit.sentinels.NO_DEFAULT` is an
    instance of the dedicated :class:`~pcapkit.corekit.sentinels.NoDefaultType`
    compared with ``is``, rather than the magic value ``-1`` compared with
    ``==``. Owner ruling on #859: a bare :class:`object` is no less safe
    under ``is``, but a dedicated class matches the
    house convention :class:`~pcapkit.corekit.sentinels.NullType` and
    :class:`~pcapkit.corekit.sentinels.NoValueType` already set, and gives
    a readable :func:`repr` in a signature, in :func:`help`, and in a
    traceback.

    Guards against ``default == NO_DEFAULT`` with a ``-1`` sentinel, which
    reads a caller-supplied ``-1`` -- or, worse, ``-1.0``, since ``-1.0 ==
    -1`` -- as if no default had been supplied at all, so the caller's own
    fallback silently never takes effect. There is no live defect in
    :mod:`pcapkit.const` (no registry's domain reaches ``-1``), so this pins
    the *clarity* fix: ``-1`` and ``-1.0`` are ordinary defaults,
    indistinguishable from any other value a caller might pass.
    """

    def setUp(self) -> None:
        reimport_once_per_class(self, restore=True)

    def test_no_default_is_not_equal_to_any_plausible_caller_value(self) -> None:
        """The sentinel's whole point: unlike ``-1``, a
        :class:`~pcapkit.corekit.sentinels.NoDefaultType` instance -- which defines
        no ``__eq__`` of its own, so it inherits identity comparison from
        :class:`object` -- cannot compare equal to anything a caller might
        legitimately pass as ``default``, not even ``-1.0``, which a ``-1``
        marker cannot tell apart from itself."""
        from pcapkit.corekit.sentinels import NO_DEFAULT

        for value in (-1, -1.0, 0, '', None, False):
            with self.subTest(value=value):
                self.assertNotEqual(NO_DEFAULT, value)
                self.assertIsNot(NO_DEFAULT, value)

    def test_repr_is_the_readable_form_not_a_bare_object_address(self) -> None:
        """The concrete reason #859 asked for a dedicated class over a bare
        ``object()``: the latter prints as ``<object object at 0x...>``
        wherever it turns up -- a signature, :func:`help`, a traceback --
        and this prints as ``NO_DEFAULT``, its own name, instead."""
        from pcapkit.corekit.sentinels import NO_DEFAULT

        rendered = repr(NO_DEFAULT)
        self.assertEqual(rendered, 'NO_DEFAULT')
        self.assertNotIn('0x', rendered)

    def test_type_is_the_dedicated_sentinel_class_and_only_the_object_is_exported(self) -> None:
        """Only the sentinel's object is exported, not its type (GitHub issue #911).

        GitHub issue #719 is where the owner settled the rule behind this: a
        module's ``__all__`` lists a sentinel's object (such as
        ``NO_DEFAULT``), and deliberately leaves its type (such as
        ``NoDefaultType``) out, because the type is not part of the public
        surface -- exposing only the final object is what keeps the published
        API to what a caller actually uses. GitHub issue #911 implements that
        ruling. The type is out of :attr:`__all__` while staying importable by
        its dotted path.

        :mod:`pcapkit.corekit.enum` re-exports neither (GitHub issue #1744;
        #1715: a moved name keeps no re-export at its old path), so the export
        rule is asserted against :mod:`pcapkit.corekit.sentinels`, the only
        import path.
        """
        import pcapkit.corekit.enum as enum_module
        import pcapkit.corekit.sentinels as sentinels

        self.assertIs(type(sentinels.NO_DEFAULT), sentinels.NoDefaultType)
        self.assertIn('NO_DEFAULT', sentinels.__all__)
        self.assertNotIn('NoDefaultType', sentinels.__all__)
        self.assertNotIn('NO_DEFAULT', enum_module.__all__)
        self.assertFalse(hasattr(enum_module, 'NoDefaultType'))

    def test_constructing_the_type_again_returns_the_same_instance(self) -> None:
        """The ``__new__`` singleton guard: a caller who does not realise
        :data:`~pcapkit.corekit.sentinels.NO_DEFAULT` already exists and writes
        ``NoDefaultType()`` themselves still gets back the one canonical
        sentinel, rather than a second, non-identical object that would
        silently fail ``is NO_DEFAULT`` inside
        :meth:`~pcapkit.corekit.enum.EnumRegistry.get` and be treated as a
        real (if useless) default instead of *no default*."""
        from pcapkit.corekit.sentinels import NO_DEFAULT, NoDefaultType

        self.assertIs(NoDefaultType(), NO_DEFAULT)
        # And repeatedly -- not merely once by coincidence.
        self.assertIs(NoDefaultType(), NoDefaultType())

    def test_identity_survives_an_ordinary_second_import(self) -> None:
        """An already-loaded module is cached in :data:`sys.modules`, so
        importing it again -- by any of the usual spellings -- must not
        construct a second sentinel. Only a genuine :func:`importlib.reload`
        would do that (see :class:`~pcapkit.corekit.sentinels.NoDefaultType`'s own
        docstring caveat, and :class:`~pcapkit.corekit.sentinels.NullType`'s
        before it), and nothing in this package reloads
        :mod:`pcapkit.corekit.sentinels` after import."""
        import importlib

        from pcapkit.corekit.sentinels import NO_DEFAULT as first_import

        module_again = importlib.import_module('pcapkit.corekit.sentinels')

        self.assertIs(module_again.NO_DEFAULT, first_import)

    def test_missing_name_with_default_negative_one_is_a_real_default(self) -> None:
        """``-1`` and ``-1.0`` are honoured as defaults by
        :meth:`~pcapkit.corekit.enum.EnumRegistry.get` itself.

        A throwaway registry holding ``-1`` is what discriminates #857. No
        shipped registry's domain reaches ``-1``, so on one of those the name
        lookup's :exc:`KeyError` propagates whether ``-1`` is read as a default
        or as a ``-1`` marker. Here it resolves to that member, while a
        ``default == -1`` check (GitHub issue #857) reads the caller's ``-1``
        (and ``-1.0``, which compares equal) as *no default* and raises.
        """
        from aenum import IntEnum

        from pcapkit.corekit.enum import EnumRegistry

        class Signed(EnumRegistry, IntEnum):
            MINUS_ONE = -1
            ZERO = 0

        for default in (-1, -1.0):
            with self.subTest(default=default):
                self.assertIs(Signed.get('Definitely-Not-A-Member', default), Signed.MINUS_ONE)
        with self.assertRaises(KeyError):
            Signed.get('Definitely-Not-A-Member')
        self.assertEqual(len(Signed.__members__), 2)

    def test_negative_one_defaults_on_a_shipped_registry_raise_and_mint_nothing(self) -> None:
        """The #864 contract for ``-1`` and ``-1.0`` on a real registry.

        Neither is a registered value of any shipped registry, whose domains
        all start at ``0``, so ``default`` does not resolve: there is no
        ``cls(default)`` fallback left to attempt, and the name lookup's own
        :exc:`KeyError` propagates, as with no default at all; without #864
        the lookup raises :exc:`ValueError` from ``cls(-1)`` instead. This does *not*
        discriminate #857, which raised the same :exc:`KeyError`;
        :meth:`test_missing_name_with_default_negative_one_is_a_real_default`
        does.
        """
        from pcapkit.const.ipv6.extension_header import ExtensionHeader

        for default in (-1, -1.0):
            with self.subTest(default=default):
                before = len(ExtensionHeader.__members__)
                with self.assertRaises(KeyError) as caught:
                    ExtensionHeader.get('Definitely-Not-A-Member', default)
                self.assertIn('Definitely-Not-A-Member', str(caught.exception))
                self.assertEqual(before, len(ExtensionHeader.__members__))

    def test_missing_name_without_default_still_raises_on_an_int_enum(self) -> None:
        """Omitting ``default`` entirely leaves it ``NO_DEFAULT`` by the
        parameter's own default value, so identity trivially holds."""
        from pcapkit.const.ipv6.extension_header import ExtensionHeader

        before = len(ExtensionHeader.__members__)
        with self.assertRaises(KeyError) as caught:
            ExtensionHeader.get('Definitely-Not-A-Member')
        self.assertIn('Definitely-Not-A-Member', str(caught.exception))
        self.assertEqual(before, len(ExtensionHeader.__members__))

    def test_missing_name_without_default_still_raises_on_an_int_flag(self) -> None:
        """As above, on an :class:`~aenum.IntFlag` registry -- the base
        ``get()`` does not branch on member type before consulting
        ``NO_DEFAULT``."""
        from pcapkit.const.mh.binding_update_flag import BindingUpdateFlag

        before = len(BindingUpdateFlag.__members__)
        with self.assertRaises(KeyError) as caught:
            BindingUpdateFlag.get('Definitely-Not-A-Member')
        self.assertIn('Definitely-Not-A-Member', str(caught.exception))
        self.assertEqual(before, len(BindingUpdateFlag.__members__))


class GetDefaultNoMintTests(unittest.TestCase):
    """GitHub issue #864. Guards against ``cls(default)`` -- in the ``str``
    branch or the value branch -- reaching ``_missing_`` for a ``default``
    inside a minting registry's own range, growing the registry as a side
    effect of resolving ``default`` rather than ``key``. The
    owner ruled on #864 that only ``register`` may mint: ``get`` mints only
    as the natural outcome of ``key`` falling through one of ``_missing_``'s
    minted ranges, never because a fallback happened to resolve. Of the
    three mechanisms offered, the owner chose the one that cannot mint by
    construction -- ``default`` resolves through a plain
    ``_value2member_map_`` lookup only, with no snapshot-and-undo and no
    per-class marker to keep in step with future crawlers -- at the price of a
    ``default`` in a declared-but-unassigned range not resolving. ``key``
    resolution -- and whatever it lets ``_missing_`` do -- is deliberately
    left alone.
    """

    def setUp(self) -> None:
        reimport_once_per_class(self, restore=True)

    def test_get_with_an_unregistered_default_raises_rather_than_mints(self) -> None:
        """The exact reproduction from #864, on the real shipped registry.
        Measured live without #864's fix::

            >>> len(EtherType.__members__)
            160
            >>> EtherType.get(0x1234, 0x0888)
            <EtherType.Xyplex_0x0888: 2184>
            >>> len(EtherType.__members__)
            161

        ``0x1234`` (4660) falls in no ``_missing_`` range, so the lookup
        falls to ``default``; ``0x0888`` (2184) falls inside the ``Xyplex``
        range, which resolves without minting when reached as a ``key``
        (#775; see
        :meth:`GetDefaultNoMintTests.test_key_path_resolves_without_minting`).
        Without #864's fix the lookup reaches ``cls(default)``; with it,
        ``default`` does not reach ``cls(default)`` at all, so ``0x0888``
        not being an *already-registered* value propagates the ``0x1234``
        lookup's own failure instead of minting anything."""
        from pcapkit.const.reg.ethertype import EtherType

        before = len(EtherType.__members__)
        self.assertEqual(before, 160)  # the issue's own measured baseline
        self.assertNotIn('Xyplex_0x0888', EtherType.__members__)

        with self.assertRaises(ValueError) as caught:
            EtherType.get(0x1234, 0x0888)
        self.assertIn('4660', str(caught.exception))  # 0x1234 -- the key
        self.assertNotIn('2184', str(caught.exception))  # 0x0888 -- the default

        self.assertEqual(before, len(EtherType.__members__))
        self.assertNotIn('Xyplex_0x0888', EtherType.__members__)

    def test_key_path_resolves_without_minting(self) -> None:
        """``EtherType.get(0x0888)`` -- no ``default`` at all -- falls through
        ``_missing_``, the one path by which #864 ruled ``get`` may mint.
        ``Xyplex`` is a real-attributed-name range, and like every other range
        on ``EtherType``/:class:`~pcapkit.const.ipx.socket.Socket` it resolves
        through :meth:`~pcapkit.corekit.enum.EnumRegistry._unregistered_member`
        (GitHub issue #775), keeping the hex-suffixed name -- so ``key``
        resolution through ``get()`` takes the same non-minting path, which
        this pins.
        #864's own point -- that ``default`` never reaches ``_missing_`` at
        all -- holds either way."""
        from pcapkit.const.reg.ethertype import EtherType

        before = len(EtherType.__members__)
        self.assertNotIn('Xyplex_0x0888', EtherType.__members__)
        self.assertNotIn(0x0888, EtherType._value2member_map_)  # type: ignore[attr-defined]

        result = EtherType.get(0x0888)

        self.assertEqual(result.name, 'Xyplex_0x0888')
        self.assertEqual(result.value, 0x0888)
        self.assertNotIn('Xyplex_0x0888', EtherType.__members__)
        self.assertNotIn(0x0888, EtherType._value2member_map_)  # type: ignore[attr-defined]
        self.assertEqual(before, len(EtherType.__members__))

        second = EtherType.get(0x0888)
        self.assertEqual(result, second)
        self.assertIsNot(result, second)

    def test_default_still_resolves_when_registered_int(self) -> None:
        """The ruling's other half: a ``default`` that *is* already a member
        resolves, on an ``int``-valued registry -- #864 restricts ``default`` to
        ``_value2member_map_``, it does not disable it."""
        from pcapkit.const.reg.ethertype import EtherType

        target = EtherType.Internet_Protocol_version_4
        before = len(EtherType.__members__)

        result = EtherType.get(0x1234, target.value)

        self.assertIs(result, target)
        self.assertEqual(before, len(EtherType.__members__))

    def test_default_still_resolves_when_registered_str(self) -> None:
        """As above, on a ``str``-valued registry. A shipped shape: shipped
        :class:`~aenum.StrEnum` registries mix in the base (``Command``,
        ``FEATCode``, ``Method``, ``OptionType``, ``TLSKeyLabel``,
        ``AppType`` and its transport subclasses --
        :data:`EXCLUDED_FROM_INTENUM_CENSUS` holds them out of *this* file's
        ``IntEnum``-only sweep, not out of existence). This case builds its
        own rather than importing one of them, so the
        assertion stays pinned to the base's fallback behaviour itself
        rather than to a shipped registry's incidental member values."""
        class _Str(EnumRegistry, StrEnum):
            KNOWN = 'known-value'
            OTHER = 'other-value'

        result = _Str.get('totally-unknown-name', 'other-value')

        self.assertIs(result, _Str.OTHER)
        self.assertEqual({'KNOWN', 'OTHER'}, set(_Str.__members__))

    def test_default_naming_no_registered_member_raises_the_original_error(self) -> None:
        """Ruling one's accepted cost, made concrete: a ``default`` inside a
        declared-but-unassigned range does not resolve -- on either branch,
        since nothing routes it through ``cls(default)`` -> ``_missing_`` --
        and the *original* lookup error -- the one ``key`` itself would have
        raised -- propagates rather than a new error about ``default``."""
        from pcapkit.const.reg.ethertype import EtherType

        before = len(EtherType.__members__)

        # Non-``str`` branch: the original error is ValueError, about ``key``.
        with self.assertRaises(ValueError) as caught_value:
            EtherType.get(0x1234, 0x0888)
        self.assertIn('4660', str(caught_value.exception))
        self.assertNotIn('2184', str(caught_value.exception))

        # ``str`` branch: the original error is KeyError, about ``key``.
        class _Str(EnumRegistry, StrEnum):
            KNOWN = 'known-value'

        with self.assertRaises(KeyError) as caught_key:
            _Str.get('totally-unknown-name', 'also-not-a-member')
        self.assertIn('totally-unknown-name', str(caught_key.exception))
        self.assertNotIn('also-not-a-member', str(caught_key.exception))

        self.assertEqual(before, len(EtherType.__members__))


if __name__ == '__main__':
    unittest.main()
