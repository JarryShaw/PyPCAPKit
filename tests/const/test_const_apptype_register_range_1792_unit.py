# -*- coding: utf-8 -*-
"""``AppType.register`` refuses a port that ``get`` refuses.

GitHub issue #1792. Without the fix,
:meth:`~pcapkit.const.reg.apptype.apptype.AppType.register` neither calls nor
overrides :meth:`~pcapkit.corekit.enum.EnumLookup._validate_value`, so
``TCP.register(70000, 'x')`` mints a member, and ``AppType.get(70000,
proto='tcp')`` then returns it although ``get`` raises :exc:`ValueError` for a
port outside ``0``-``65535`` (#758). ``AppType`` overrides the hook with
:meth:`_missing_`'s own check and ``register`` calls it after its duplicate
check, as the base ``register`` does. The override raises
:exc:`~pcapkit.utilities.exceptions.EnumValueError`, as the registry-protocol
convention asks of one, with the message ``get`` raises.

Each test imports the registries after
:func:`~tests._support.reimport_once_per_class`, whose ``restore`` puts the
class's import back afterwards, so a member minted here does not leak.

"""
from __future__ import annotations

import itertools
import unittest

from tests._support import reimport_once_per_class

#: Serial for probe names, so that no refusal is a name collision instead.
_SERIAL = itertools.count()

#: Ports outside ``0``-``65535``, on both sides of the range.
OUT_OF_RANGE = (-1, 65536, 70000)

#: Ports that are not an :class:`int` at all, and hash like no registered port.
NOT_AN_INT = ('8080', 1.5)


def _registries() -> 'tuple[type, ...]':
    from pcapkit.const.reg.apptype import DCCP, SCTP, TCP, UDP

    return TCP, UDP, SCTP, DCCP


class AppTypeRegisterRange1792Tests(unittest.TestCase):
    """``register`` and ``get`` agree on what a port number is."""

    def setUp(self) -> None:
        reimport_once_per_class(self, restore=True)

    def assertRefusedWithoutMinting(self, registry: 'type', port: 'object') -> 'str':
        """Assert ``registry.register(port, ...)`` raises and mints nothing.

        The refusal is an :exc:`~pcapkit.utilities.exceptions.EnumValueError`,
        and so still a :exc:`ValueError` to an ``except ValueError`` caller.

        Returns:
            The message the refusal carried.

        """
        from pcapkit.utilities.exceptions import EnumValueError

        members = dict(registry.__members__)  # type: ignore[attr-defined]
        with self.assertRaises(ValueError) as caught:
            registry.register(port, f'pypcapkit-1792-probe-{next(_SERIAL)}')  # type: ignore[attr-defined]
        self.assertIsInstance(caught.exception, ValueError)
        self.assertIs(type(caught.exception), EnumValueError)
        self.assertEqual(dict(registry.__members__), members)  # type: ignore[attr-defined]
        self.assertFalse(registry.__registry__.getlist(port))  # type: ignore[attr-defined]
        return str(caught.exception)

    def test_register_refuses_an_out_of_range_port_as_get_does(self) -> None:
        for registry in _registries():
            for port in OUT_OF_RANGE:
                with self.subTest(registry=registry.__name__, port=port):
                    message = self.assertRefusedWithoutMinting(registry, port)
                    with self.assertRaises(ValueError) as lookup:
                        registry.get(port)  # type: ignore[attr-defined]
                    self.assertEqual(message, str(lookup.exception))
                    self.assertEqual(message, f'{port!r} is not a valid {registry.__name__}')

    def test_register_refuses_a_non_int_port_as_the_constructor_does(self) -> None:
        for registry in _registries():
            for port in NOT_AN_INT:
                with self.subTest(registry=registry.__name__, port=port):
                    message = self.assertRefusedWithoutMinting(registry, port)
                    with self.assertRaises(ValueError) as built:
                        registry(port)
                    self.assertEqual(message, str(built.exception))

    def test_get_still_raises_after_a_refused_register(self) -> None:
        from pcapkit.const.reg.apptype import AppType

        for registry in _registries():
            for port in OUT_OF_RANGE:
                with self.subTest(registry=registry.__name__, port=port):
                    with self.assertRaises(ValueError):
                        registry.register(port, f'pypcapkit-1792-probe-{next(_SERIAL)}')  # type: ignore[attr-defined]
                    with self.assertRaises(ValueError):
                        registry.get(port)  # type: ignore[attr-defined]
                    with self.assertRaises(ValueError):
                        AppType.get(port, proto=registry.__transport__)  # type: ignore[attr-defined]

    def test_register_still_mints_the_top_port_of_the_range(self) -> None:
        from pcapkit.const.reg.apptype import AppType

        port = 65535
        for registry in _registries():
            with self.subTest(registry=registry.__name__):
                self.assertFalse(registry.__registry__.getlist(port))  # type: ignore[attr-defined]
                member = registry.register(port, 'pypcapkit-1792-top')  # type: ignore[attr-defined]
                self.assertEqual(member.port, port)
                self.assertIs(member.proto, registry.__transport__)  # type: ignore[attr-defined]
                self.assertIs(registry.get(port), member)  # type: ignore[attr-defined]
                self.assertIs(AppType.get(port, proto=registry.__transport__), member)  # type: ignore[attr-defined]

    def test_validate_value_agrees_with_missing_on_every_probe(self) -> None:
        from pcapkit.utilities.exceptions import EnumValueError

        for registry in _registries():
            for port in (0, 65535, *OUT_OF_RANGE, *NOT_AN_INT):
                with self.subTest(registry=registry.__name__, port=port):
                    try:
                        registry._missing_(port)  # type: ignore[attr-defined]
                    except ValueError as error:
                        with self.assertRaises(EnumValueError) as caught:
                            registry._validate_value(port)  # type: ignore[attr-defined]
                        self.assertEqual(str(caught.exception), str(error))
                    else:
                        self.assertIsNone(registry._validate_value(port))  # type: ignore[attr-defined]


if __name__ == '__main__':
    unittest.main()
