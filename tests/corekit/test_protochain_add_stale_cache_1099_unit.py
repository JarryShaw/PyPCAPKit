# -*- coding: utf-8 -*-
"""GitHub issue #1099: :meth:`ProtoChain.__add__ <pcapkit.corekit.protochain.ProtoChain.__add__>`
must not carry the left operand's cached ``protocols``/``aliases`` into the result.

Both are :func:`~functools.cached_property` values stored on the instance, so a
result built by shallow-copying the left operand kept them from before the merge.
"""
from __future__ import annotations

import unittest

from pcapkit.corekit.protochain import ProtoChain
from pcapkit.protocols.internet.ipv4 import IPv4
from pcapkit.protocols.link.ethernet import Ethernet
from pcapkit.protocols.transport.tcp import TCP


class ProtoChainAddCacheTests(unittest.TestCase):
    def _check(self, *, warm: bool) -> None:
        left = ProtoChain(Ethernet)
        right = ProtoChain(TCP, basis=ProtoChain(IPv4))  # TCP:IPv4
        if warm:
            self.assertEqual(left.protocols, (Ethernet,))
            self.assertEqual(left.aliases, ('Ethernet',))
            self.assertEqual(right.protocols, (TCP, IPv4))

        merged = left + right

        self.assertEqual(merged.protocols, (Ethernet, TCP, IPv4))
        self.assertEqual(merged.aliases, ('Ethernet', 'TCP', 'IPv4'))
        self.assertEqual(merged.chain, 'Ethernet:TCP:IPv4')
        self.assertEqual(len(merged), 3)

        # neither operand is mutated, whether or not its cache was warm
        self.assertEqual(left.protocols, (Ethernet,))
        self.assertEqual(left.aliases, ('Ethernet',))
        self.assertEqual(left.chain, 'Ethernet')
        self.assertEqual(right.chain, 'TCP:IPv4')

    def test_add_after_reading_cached_properties(self) -> None:
        self._check(warm=True)

    def test_add_without_prior_read(self) -> None:
        self._check(warm=False)

    def test_inplace_add_rebinds_without_mutating_the_original(self) -> None:
        original = ProtoChain(Ethernet)
        self.assertEqual(original.protocols, (Ethernet,))

        chain = original
        chain += ProtoChain(IPv4)

        self.assertIsNot(chain, original)
        self.assertEqual(chain.protocols, (Ethernet, IPv4))
        self.assertEqual(chain.aliases, ('Ethernet', 'IPv4'))
        self.assertEqual(original.protocols, (Ethernet,))
        self.assertEqual(original.chain, 'Ethernet')


if __name__ == '__main__':
    unittest.main()
