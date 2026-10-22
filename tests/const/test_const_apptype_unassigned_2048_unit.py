# -*- coding: utf-8 -*-
"""Every in-range port answers with the asking registry's own transport.

GitHub issue #2048. IANA assigned port 8011 on UDP (``bier-echo``) and marked it
Reserved on TCP, and its CSV then dropped 8011 from the unassigned span
``8011``-``8014`` while listing no DCCP or SCTP entry for it, so DCCP and SCTP
answer ``get``'s ``unknown`` fallback, which the owner kept. The spans in
``AppType._missing_`` that name no transport answer with the asking registry's
transport rather than ``TransportProtocol.undefined``, as the fallback already
did. Lookups still mint nothing (#860), and a port outside the range still
raises (#758).

"""
from __future__ import annotations

import unittest

#: Test tier (#1958): pure-Python lookups over the generated AppType registries,
#: which behave the same on every interpreter.
__tier__ = 'LATEST'

#: ``(port, {registry: (svc)})`` for each registry, in TCP, UDP, SCTP, DCCP order.
EXPECTED = (
    # IANA's rows on TCP and UDP only; nothing on SCTP or DCCP.
    (8011, ('reserved', 'bier-echo', 'unknown', 'unknown')),
    (8009, ('nvme-disc', 'reserved', 'unknown', 'unknown')),
    # An unassigned span naming no transport.
    (8012, ('unassigned', 'unassigned', 'unassigned', 'unassigned')),
    # A reserved span naming no transport.
    (226, ('reserved', 'reserved', 'reserved', 'reserved')),
    # Spans naming TCP and UDP (#760); nothing on SCTP or DCCP.
    (6010, ('x11', 'x11', 'unknown', 'unknown')),
    # No row and no span on any transport.
    (54321, ('unknown', 'unknown', 'unknown', 'unknown')),
)


def _registries() -> 'tuple[type, ...]':
    from pcapkit.const.reg.apptype import DCCP, SCTP, TCP, UDP

    return TCP, UDP, SCTP, DCCP


def _sizes(registry: 'type') -> 'tuple[int, int, int]':
    """What a minting lookup would grow on ``registry``."""
    return (len(registry.__members__),  # type: ignore[attr-defined]
            len(registry._value2member_map_),  # type: ignore[attr-defined]
            len(list(registry.__registry__.items())))  # type: ignore[attr-defined]


class AppTypeUnassigned2048Tests(unittest.TestCase):
    """Every in-range port answers with the asking registry's transport."""

    def test_each_registry_answers_with_its_own_transport(self) -> None:
        from pcapkit.const.reg.apptype import AppType

        for port, answers in EXPECTED:
            for registry, svc in zip(_registries(), answers):
                with self.subTest(registry=registry.__name__, port=port):
                    member = registry.get(port)
                    self.assertIsInstance(member, registry)
                    self.assertEqual(member.svc, svc)
                    self.assertEqual(member.port, port)
                    self.assertIs(member.proto, registry.__transport__)
                    self.assertEqual(AppType.get(port, proto=registry.__transport__), member)

    def test_the_issues_own_port(self) -> None:
        from pcapkit.const.reg.apptype import DCCP, SCTP, TCP, UDP

        self.assertEqual(repr(TCP.get(8011)), '<TCP.reserved: 8011 [tcp]>')
        self.assertEqual(repr(UDP.get(8011)), '<UDP.bier-echo: 8011 [udp]>')
        self.assertEqual(repr(SCTP.get(8011)), '<SCTP.unknown: 8011 [sctp]>')
        self.assertEqual(repr(DCCP.get(8011)), '<DCCP.unknown: 8011 [dccp]>')

    def test_lookups_mint_nothing(self) -> None:
        """#860: span and fallback members alike stay unregistered."""
        for registry in _registries():
            before = _sizes(registry)
            for port, _ in EXPECTED:
                registry.get(port)
                registry.get_all(port)
            with self.subTest(registry=registry.__name__):
                self.assertEqual(_sizes(registry), before)
                self.assertNotIn('unassigned', registry.__members__)  # type: ignore[attr-defined]
                self.assertNotIn('unknown', registry.__members__)  # type: ignore[attr-defined]

    def test_out_of_range_still_raises(self) -> None:
        """#758: the rule covers ``0``-``65535`` only."""
        from pcapkit.const.reg.apptype import AppType

        for registry in _registries():
            for port in (-1, 65536):
                with self.subTest(registry=registry.__name__, port=port):
                    with self.assertRaises(ValueError):
                        registry.get(port)
                    with self.assertRaises(ValueError):
                        AppType.get(port, proto=registry.__transport__)


if __name__ == '__main__':
    unittest.main()
