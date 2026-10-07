# -*- coding: utf-8 -*-
"""A tail shorter than 8 octets is not an ``IPv6_Ext`` header.

GitHub issue #1178. :meth:`~pcapkit.protocols.protocol.ProtocolBase._parse_next_layer`
keeps a next layer as :class:`~pcapkit.protocols.misc.raw.Raw` when fewer octets
were captured than its ``__length_hint__`` (:issue:`1170`).
:class:`~pcapkit.protocols.internet.ipv6_ext.IPv6_Ext` hinted 2, though
:rfc:`6564#section-4` and :rfc:`8200#section-4` make every extension header at
least 8 octets, so a 2--7 octet tail of a longer declared payload was parsed as
an 8-octet header built partly from octets that were never captured.

"""
from __future__ import annotations

import importlib.util
import unittest

from tests._support import reimport_once_per_class

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: ``alias`` values that reach the generic fallback: an absent alias, a number
#: IANA has not registered, ``Shim6`` (registered to ``IPv6_Ext`` directly) and
#: ``HOPOPT`` (the code ``IPv6`` substitutes the fallback for).
ALIASES = {'absent': {}, 'unregistered': {'alias': 200}, 'Shim6': {'alias': 140}, 'HOPOPT': {'alias': 0}}

#: The IPv6 payload length the caller declares, longer than any tail below.
DECLARED = 300


def tail(size: int) -> bytes:
    """``size`` octets opening with No Next Header and Hdr Ext Len 0 or 1."""
    return bytes([59, 1 if size >= 16 else 0]) + bytes(range(1, size - 1))


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class IPv6ExtLengthHintTests(unittest.TestCase):
    """The fallback's hint is the 8-octet minimum header."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def parse(self, data: bytes, **kwargs: int) -> object:
        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.protocols.internet.ipv6_ext import IPv6_Ext

        outer = bytes([0x60]) + bytes(5) + bytes([59, 64]) + bytes(32)
        return IPv6(outer, len(outer))._parse_next_layer(
            IPv6_Ext, data, DECLARED, version=6, extension=True, **kwargs)

    def test_short_tail_is_raw_and_rebuilds_exactly(self) -> None:
        from pcapkit.protocols.misc.raw import Raw

        for label, kwargs in ALIASES.items():
            for size in range(2, 8):
                with self.subTest(alias=label, size=size):
                    parsed = self.parse(tail(size), **kwargs)
                    self.assertIsInstance(parsed, Raw)
                    self.assertEqual(bytes(Raw.from_data(parsed.info)), tail(size))

    def test_complete_header_still_parses(self) -> None:
        from pcapkit.protocols.internet.ipv6_ext import IPv6_Ext

        for label, kwargs in ALIASES.items():
            for size in (8, 16):
                with self.subTest(alias=label, size=size):
                    parsed = self.parse(tail(size), **kwargs)
                    self.assertIsInstance(parsed, IPv6_Ext)
                    self.assertEqual(parsed.length, size)


if __name__ == '__main__':
    unittest.main()
