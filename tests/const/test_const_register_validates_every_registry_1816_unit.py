# -*- coding: utf-8 -*-
"""Every registry's ``register`` refuses what its ``get`` refuses.

GitHub issue #1816. :meth:`~pcapkit.corekit.enum.EnumRegistry.register` routes a
new value through :meth:`~pcapkit.corekit.enum.EnumLookup._validate_value`, but
only ``AppType`` (#1792) overrode that hook, so everywhere else ``register``
minted a value ``get`` refuses: ``Hardware.register(70000, 'x')`` minted, and
``Hardware.get(70000)`` then returned the new member. Every registry overrides
the hook. A generated one uses the check its ``_missing_`` makes; ``TLSKeyLabel``
and ``ExtensionHeader`` have no ``_missing_``, so they check the member type and
the 8-bit Next Header field respectively.

The registries are found at runtime, after importing every module under
:mod:`pcapkit.const` and :mod:`pcapkit.protocols`, so one added later is covered
without editing this file.

What counts as out of range does not come from the override under test. It is a
negative number, a number wider than any field, a float, ``None`` and ``bytes``
for every registry, plus a ``str`` for one that does not hold strings.
``ProtectionAuthority`` has no upper bound, so its ``get`` resolves the wide
number and ``register`` must mint it: the comparison runs in both directions.

The oracle is ``get`` with no default, except where ``get`` is a
:class:`staticmethod` backport that bypasses the base lookup. ``OptionType``'s
answers every integer code with an unregistered member, so there the constructor
is the oracle instead; ``OptionType``'s ``_missing_`` refusing anything above
``0xFFFF`` is what the issue cites. ``Command``'s was one too, calling
``key.upper()`` and so answering :class:`bytes`, until #1824 made it a
:class:`classmethod` that hands a non-``str`` key to the base.

Each test imports the registries after
:func:`~tests._support.reimport_once_per_class`, whose ``restore`` puts the class's
import back afterwards, so a member minted here does not leak.

"""
from __future__ import annotations

import importlib
import inspect
import itertools
import pkgutil
import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

#: Serial for probe names, so that no refusal is a name collision instead.
_SERIAL = itertools.count()

#: Out of range for every registry: below zero, wider than any field, and not
#: an integer or string at all.
OUT_OF_RANGE = (-1, 2 ** 130, 1.5, None, b'\x01')

#: Bounds of the hooks that do not copy a ``FLAG``, which nothing else here pins:
#: ``(module, registry, accepted, refused)``. ``ExtensionHeader`` and
#: ``TLSKeyLabel`` have no ``_missing_`` to compare against, and that of
#: ``ResponseKind`` and ``GroupingInformation`` falls through rather than
#: raising outside its range.
PINNED = (
    ('pcapkit.const.ipv6.extension_header', 'ExtensionHeader', (0, 255), (-1, 256, 1.5, '0')),
    ('pcapkit.const.pcapng.tls_key_label', 'TLSKeyLabel', ('PYPCAPKIT_1816_LABEL', ''),
     (0, -1, None, b'CLIENT_RANDOM')),
    ('pcapkit.const.ftp.return_code', 'ResponseKind', (0, 9), (-1, 10, '9')),
    ('pcapkit.const.ftp.return_code', 'GroupingInformation', (0, 9), (-1, 10, '9')),
)

#: The registry whose ``_missing_`` refuses every value: it has no transport.
APPTYPE = 'pcapkit.const.reg.apptype.apptype.AppType'

#: Out of range for a registry that does not hold strings.
NOT_AN_INT = 'pypcapkit-1816-probe'

#: Around the edges of the field widths and digit counts the registries use.
BOUNDARIES = tuple(sorted({
    *(2 ** k + d for k in (1, 2, 3, 4, 7, 8, 16, 32, 128) for d in (-1, 0)),
    -1, 0, 9, 10, 599, 600, 659, 660, 999, 1000,
}))


def _registries() -> 'list[type]':
    """Every :class:`~pcapkit.corekit.enum.EnumRegistry` subclass, found at runtime."""
    for name in ('pcapkit.const', 'pcapkit.protocols'):
        package = importlib.import_module(name)
        for info in pkgutil.walk_packages(package.__path__, f'{name}.'):
            importlib.import_module(info.name)

    from pcapkit.corekit.enum import EnumRegistry

    found = []  # type: list[type]
    stack = [EnumRegistry]
    while stack:
        for sub in stack.pop().__subclasses__():
            if sub not in found:
                found.append(sub)
                stack.append(sub)
    return sorted(found, key=lambda cls: (cls.__module__, cls.__qualname__))


def _members(cls: 'type') -> 'dict[str, object]':
    return dict(cls.__members__)  # type: ignore[attr-defined]


def _label(cls: 'type') -> 'str':
    return f'{cls.__module__}.{cls.__qualname__}'


def _raises(call: 'Any', *args: 'Any') -> 'BaseException | None':
    try:
        call(*args)
    except Exception as error:  # pylint: disable=broad-exception-caught
        return error
    return None


def _oracle(cls: 'type', value: 'object') -> 'BaseException | None':
    """Whether a lookup of ``value`` on ``cls`` is refused, and with what."""
    if isinstance(inspect.getattr_static(cls, 'get'), staticmethod):
        return _raises(cls, value)
    return _raises(cls.get, value)  # type: ignore[attr-defined]


def _resolves_through_missing(cls: 'type') -> 'bool':
    """Whether ``cls`` declares a ``_missing_``, on itself or a registry base."""
    from pcapkit.corekit.enum import EnumRegistry

    return any('_missing_' in vars(base) for base in cls.__mro__[:cls.__mro__.index(EnumRegistry)])


class RegisterValidatesEveryRegistry1816Tests(unittest.TestCase):
    """``register`` and ``get`` agree on every registry about what is out of range."""

    def setUp(self) -> None:
        reimport_once_per_class(self, restore=True)

    def test_the_walk_finds_the_registries(self) -> None:
        labels = {_label(cls) for cls in _registries()}
        for expected in ('pcapkit.const.arp.hardware.Hardware',
                         'pcapkit.const.pcapng.option_type.OptionType',
                         'pcapkit.const.ftp.return_code.ResponseKind',
                         'pcapkit.const.reg.apptype.tcp.TCP'):
            self.assertIn(expected, labels)

    def test_register_refuses_an_out_of_range_value_iff_get_does(self) -> None:
        for cls in _registries():
            probes = OUT_OF_RANGE if issubclass(cls, str) else (*OUT_OF_RANGE, NOT_AN_INT)
            for value in probes:
                if value in cls._value2member_map_:  # type: ignore[attr-defined]
                    continue
                with self.subTest(registry=_label(cls), value=value):
                    refused = _oracle(cls, value)
                    members = _members(cls)
                    error = _raises(cls.register,  # type: ignore[attr-defined]
                                    value, f'pypcapkit_1816_probe_{next(_SERIAL)}')
                    self.assertEqual(error is not None, refused is not None,
                                     f'get {"refused" if refused else "accepted"} {value!r} '
                                     f'but register {"refused" if error else "minted"} it')
                    if error is not None:
                        self.assertIsInstance(error, ValueError)
                        self.assertEqual(_members(cls), members)
                        self.assertIsNotNone(_oracle(cls, value))

    def test_validate_value_mirrors_the_range_check_of_missing(self) -> None:
        # NOTE: one-way checks, each direction on its own, rather than an
        # equivalence. A value inside the range that matches neither a member
        # nor an unassigned range -- ``CauseCode(0)``, ``MPTCPOption(16)`` --
        # falls through ``_missing_``, so the constructor refuses it although the
        # range check passed; such a value is ``register``'s to mint, and is not
        # out of range. ``ResponseKind`` and ``GroupingInformation`` fall through
        # the same way outside their range rather than raising, so the second
        # check never reaches them; the pinned bounds below do. ``AppType``
        # itself is skipped: with no transport, its ``_missing_`` and its
        # ``register`` both refuse every value, which the test above covers.
        from pcapkit.utilities.exceptions import EnumValueError

        for cls in _registries():
            if not _resolves_through_missing(cls) or _label(cls) == APPTYPE:
                continue
            for value in (*BOUNDARIES, NOT_AN_INT, 1.5, None, b'\x01'):
                if value in cls._value2member_map_:  # type: ignore[attr-defined]
                    continue
                with self.subTest(registry=_label(cls), value=value):
                    checked = _raises(cls._validate_value, value)  # type: ignore[attr-defined]
                    if checked is None:
                        self.assertIsNone(cls._validate_value(value))  # type: ignore[attr-defined]
                    else:
                        self.assertIs(type(checked), EnumValueError)
                        self.assertEqual(str(checked), f'{value!r} is not a valid {cls.__name__}')
                        self.assertIsNotNone(_raises(cls, value),
                                             'the hook refuses a value the constructor resolves')
                    missing = _raises(cls._missing_, value)  # type: ignore[attr-defined]
                    if missing is not None:
                        self.assertIsNotNone(checked,
                                             '_missing_ refuses a value the hook lets through')
                        self.assertEqual(str(checked), str(missing))

    def test_every_registered_value_passes_validate_value(self) -> None:
        for cls in _registries():
            for member in cls:  # type: ignore[attr-defined]
                # NOTE: ``OptionType`` and ``AppType`` hold a formatted or service
                # string as the value; what their hook guards is the option code
                # or port the member carries beside it.
                code = getattr(member, 'opt_value', getattr(member, 'port', member._value_))
                hook = cls._validate_value  # type: ignore[attr-defined]
                with self.subTest(registry=_label(cls), member=member._name_):
                    # NOTE: called directly rather than through ``_raises``, so
                    # that a hook returning anything but ``None`` fails as well.
                    self.assertIsNone(hook(code))

    def test_the_bounds_no_flag_pins(self) -> None:
        from pcapkit.utilities.exceptions import EnumValueError

        for module, name, accepted, refused in PINNED:
            cls = getattr(importlib.import_module(module), name)
            for value in accepted:
                with self.subTest(registry=name, value=value, expect='accepted'):
                    self.assertIsNone(cls._validate_value(value))
                    if value not in cls._value2member_map_:
                        member = cls.register(value, f'pypcapkit_1816_pin_{next(_SERIAL)}')
                        self.assertIs(cls.get(value), member)
            for value in refused:
                with self.subTest(registry=name, value=value, expect='refused'):
                    with self.assertRaises(EnumValueError) as caught:
                        cls._validate_value(value)
                    self.assertIs(type(caught.exception), EnumValueError)
                    self.assertEqual(str(caught.exception), f'{value!r} is not a valid {name}')
                    members = _members(cls)
                    with self.assertRaises(EnumValueError) as minted:
                        cls.register(value, f'pypcapkit_1816_pin_{next(_SERIAL)}')
                    self.assertIs(type(minted.exception), EnumValueError)
                    self.assertEqual(_members(cls), members)


if __name__ == '__main__':
    unittest.main()
