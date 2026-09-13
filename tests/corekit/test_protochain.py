from __future__ import annotations

import unittest

from tests._support import bootstrap_core_modules, install_fake_protocol_module, purge_modules


class ProtoChainTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])
        self.ProtocolBase = install_fake_protocol_module()
        modules = bootstrap_core_modules()
        self.protochain = modules['protochain']
        self.exceptions = modules['exceptions']

        class Ethernet(self.ProtocolBase):
            alias = 'Ethernet'

            @classmethod
            def id(cls) -> tuple[str, ...]:
                return ('ETH', 'Ethernet')

        class IPv4(self.ProtocolBase):
            alias = 'IPv4'

            @classmethod
            def id(cls) -> tuple[str, ...]:
                return ('IP', 'IPv4')

        class TCP(self.ProtocolBase):
            alias = 'TCP'

            @classmethod
            def id(cls) -> tuple[str, ...]:
                return ('TCP',)

        self.Ethernet = Ethernet
        self.IPv4 = IPv4
        self.TCP = TCP

    def test_protochain_behaves_like_a_named_sequence(self) -> None:
        chain = self.protochain.ProtoChain(self.Ethernet(), basis=self.protochain.ProtoChain(self.IPv4(), basis=self.protochain.ProtoChain(self.TCP())))

        self.assertEqual(chain.chain, 'Ethernet:IPv4:TCP')
        self.assertEqual(chain.protocols, (self.Ethernet, self.IPv4, self.TCP))
        self.assertEqual(chain.aliases, ('Ethernet', 'IPv4', 'TCP'))
        self.assertEqual(chain[0], 'Ethernet')
        self.assertEqual(chain[1:], ('IPv4', 'TCP'))
        self.assertEqual(repr(chain), 'ProtoChain(Ethernet, IPv4, TCP)')

    def test_protochain_supports_contains_count_and_index(self) -> None:
        chain = self.protochain.ProtoChain(self.Ethernet(), basis=self.protochain.ProtoChain(self.IPv4(), basis=self.protochain.ProtoChain(self.TCP())))

        self.assertIn('ip', chain)
        self.assertIn(self.TCP, chain)
        self.assertIn(self.Ethernet(), chain)
        self.assertEqual(chain.count('ethernet'), 1)
        self.assertEqual(chain.index('IPV4'), 1)
        self.assertEqual(chain.index(self.TCP), 2)

        with self.assertRaises(self.exceptions.IndexNotFound):
            chain.index('udp')

    def test_protochain_add_merges_chains(self) -> None:
        left = self.protochain.ProtoChain(self.Ethernet())
        right = self.protochain.ProtoChain(self.IPv4())

        merged = left + right

        self.assertEqual(merged.aliases, ('Ethernet', 'IPv4'))
        self.assertEqual(left.aliases, ('Ethernet',))
        self.assertEqual(right.aliases, ('IPv4',))

    def test_protochain_from_list_alias_bounds_and_negative_paths(self) -> None:
        chain = self.protochain.ProtoChain.from_list([
            self.Ethernet(),
            self.IPv4,
            self.TCP(),
        ])

        self.assertEqual(chain.aliases, ('Ethernet', 'IPv4', 'TCP'))
        self.assertEqual(chain.protocols, (self.Ethernet, self.IPv4, self.TCP))
        self.assertEqual(chain.index('TCP', start=-1), 2)
        self.assertEqual(chain.index('Ethernet', stop=-1), 0)
        self.assertNotIn('udp', chain)
        self.assertEqual(chain.count('udp'), 0)

        custom = self.protochain.ProtoChain(self.IPv4, alias='Internet Protocol')
        self.assertEqual(custom.aliases, ('Internet Protocol',))
        class_default = self.protochain.ProtoChain(self.IPv4)
        self.assertEqual(class_default.aliases, ('IPv4',))
        instance_custom = self.protochain.ProtoChain(self.Ethernet(), alias='Layer 2')
        self.assertEqual(instance_custom.aliases, ('Layer 2',))

        with self.assertRaises(self.exceptions.IndexNotFound):
            chain.index('Ethernet', start=1)


if __name__ == '__main__':
    unittest.main()
