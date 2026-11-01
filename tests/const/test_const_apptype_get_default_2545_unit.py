# -*- coding: utf-8 -*-
"""``AppType.get`` takes the base's ``default`` and raises the base's exceptions.

GitHub issue #2545. Without the fix,
:meth:`~pcapkit.const.reg.apptype.apptype.AppType.get` is ``get(cls, key, *,
proto=...)`` under a ``# type: ignore[override]`` and ``arguments-differ``
pair, so ``TCP.get(80, 'x')`` raises :exc:`TypeError` where
:meth:`~pcapkit.corekit.enum.EnumLookup.get` takes ``(key, default)``; and a
miss raises a builtin :exc:`ValueError` where the base raises
:exc:`~pcapkit.utilities.exceptions.EnumValueError`. The registry-protocol
convention rules out both: an override honours the signature the base
advertises (#935), and a failed lookup raises from
:mod:`pcapkit.utilities.exceptions` (#923).

Each test fails without the fix: the signature test on the missing parameter,
those passing ``default`` on :exc:`TypeError`, and the miss tests on the
builtin :exc:`ValueError`.

"""
from __future__ import annotations

import inspect
import unittest

#: Ports outside ``0``-``65535``, on both sides of the range.
OUT_OF_RANGE = (-1, 65536, 99999)

#: Keys that are not a port number at all, a service name among them.
NOT_A_PORT = ('http', None, 1.5)


def _registries() -> 'tuple[type, ...]':
    from pcapkit.const.reg.apptype import DCCP, SCTP, TCP, UDP

    return TCP, UDP, SCTP, DCCP


class AppTypeGetSignature2545Tests(unittest.TestCase):
    """``get`` accepts every argument the base's ``get`` accepts."""

    def test_the_bases_parameters_lead_the_signature(self) -> None:
        from pcapkit.const.reg.apptype import AppType
        from pcapkit.corekit.enum import EnumLookup

        base = list(inspect.signature(EnumLookup.get).parameters.values())
        override = list(inspect.signature(AppType.get).parameters.values())
        self.assertEqual([(param.name, param.kind, param.default) for param in base],
                         [(param.name, param.kind, param.default)
                          for param in override[:len(base)]])
        self.assertEqual([(param.name, param.kind) for param in override[len(base):]],
                         [('proto', inspect.Parameter.KEYWORD_ONLY)])

    def test_a_two_argument_call_resolves_as_the_one_argument_call(self) -> None:
        for registry in _registries():
            member = next(iter(registry))  # type: ignore[call-overload]
            with self.subTest(registry=registry.__name__, port=member.port):
                self.assertIs(registry.get(member.port, 'x'),  # type: ignore[attr-defined]
                              registry.get(member.port))  # type: ignore[attr-defined]
                self.assertIs(registry.get(member.port, default='x'),  # type: ignore[attr-defined]
                              registry.get(member.port))  # type: ignore[attr-defined]


class AppTypeGetDefault2545Tests(unittest.TestCase):
    """A miss answers with ``default`` as the base's would."""

    def test_a_miss_falls_back_to_a_registered_value(self) -> None:
        for registry in _registries():
            member = next(iter(registry))  # type: ignore[call-overload]
            for key in OUT_OF_RANGE + NOT_A_PORT:
                with self.subTest(registry=registry.__name__, key=key):
                    self.assertIs(registry.get(key, member.value),  # type: ignore[attr-defined]
                                  member)

    def test_the_base_registry_falls_back_in_the_registry_proto_selects(self) -> None:
        from pcapkit.const.reg.apptype import AppType

        for registry in _registries():
            member = next(iter(registry))  # type: ignore[call-overload]
            with self.subTest(registry=registry.__name__):
                self.assertIs(AppType.get(99999, member.value, proto=registry.__transport__),
                              member)

    def test_an_unusable_default_raises_the_miss(self) -> None:
        """Neither a port nor a member is a value, and the base registry holds none."""
        from pcapkit.const.reg.apptype import AppType, TransportProtocol
        from pcapkit.utilities.exceptions import EnumValueError

        for registry in _registries():
            member = next(iter(registry))  # type: ignore[call-overload]
            for default in ('x', member.port, member):
                with self.subTest(registry=registry.__name__, default=default):
                    with self.assertRaises(EnumValueError) as caught:
                        registry.get(99999, default)  # type: ignore[attr-defined]
                    self.assertEqual(str(caught.exception),
                                     f'99999 is not a valid {registry.__name__}')
            with self.subTest(registry=registry.__name__, proto=None):
                with self.assertRaises(EnumValueError) as caught:
                    AppType.get(99999, member.value)
                self.assertEqual(str(caught.exception),
                                 f'{TransportProtocol.undefined!r} names no transport protocol '
                                 'registry of AppType')


class AppTypeGetMiss2545Tests(unittest.TestCase):
    """With no usable ``default``, every miss is a quiet ``EnumValueError``."""

    def assertQuietValueMiss(self, message: 'str', registry: 'type', key: 'object',
                             **kwargs: 'object') -> None:
        """Assert ``registry.get(key, **kwargs)`` raises a quiet ``EnumValueError``
        carrying ``message``, which is still a :exc:`ValueError`."""
        from pcapkit.utilities.exceptions import EnumValueError
        from pcapkit.utilities.logging import logger
        from tests.utilities._harness import capture

        with capture(logger) as recorder:
            with self.assertRaises(ValueError) as caught:
                registry.get(key, **kwargs)  # type: ignore[attr-defined]
        self.assertIs(type(caught.exception), EnumValueError)
        self.assertEqual(str(caught.exception), message)
        self.assertEqual(recorder.messages, [])

    def test_a_port_out_of_range(self) -> None:
        for registry in _registries():
            for key in OUT_OF_RANGE:
                with self.subTest(registry=registry.__name__, key=key):
                    self.assertQuietValueMiss(f'{key!r} is not a valid {registry.__name__}',
                                              registry, key)

    def test_a_key_that_is_not_a_port(self) -> None:
        for registry in _registries():
            for key in NOT_A_PORT:
                with self.subTest(registry=registry.__name__, key=key):
                    self.assertQuietValueMiss(
                        f'{key!r} is not a valid port number for {registry.__name__}',
                        registry, key)

    def test_a_proto_naming_no_registry(self) -> None:
        from pcapkit.const.reg.apptype import AppType, TransportProtocol

        for proto in (TransportProtocol.undefined, 17):
            with self.subTest(proto=proto):
                self.assertQuietValueMiss(
                    f'{proto!r} names no transport protocol registry of AppType',
                    AppType, 80, proto=proto)


if __name__ == '__main__':
    unittest.main()
