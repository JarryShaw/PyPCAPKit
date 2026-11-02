# -*- coding: utf-8 -*-
"""Unit tests for :mod:`pcapkit.protocols.link.inarp`.

#2529: a module holds one protocol class, named after it, so ``InARP`` left
:mod:`pcapkit.protocols.link.arp` for a module of its own, with no re-export at
the old path. Every case builds its own octets.

"""
from __future__ import annotations

import importlib
import importlib.util
import unittest

from tests._support import reimport_once_per_class

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: An InARP-Request (operation 8) over Ethernet and IPv4, :rfc:`2390`.
INARP_REQUEST = bytes.fromhex('000108000604' '0008' '001122334455' '0a000001'
                              '66778899aabb' '00000000')


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class InARPModuleTests(unittest.TestCase):
    """``InARP`` lives in its own module and keeps ARP's behaviour."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_inarp_is_defined_in_its_own_module(self) -> None:
        from pcapkit.protocols.link.arp import ARP
        from pcapkit.protocols.link.inarp import InARP

        inarp = importlib.import_module('pcapkit.protocols.link.inarp')
        self.assertEqual(InARP.__module__, 'pcapkit.protocols.link.inarp')
        self.assertEqual(inarp.__all__, ['InARP'])
        self.assertEqual(InARP.__bases__, (ARP,))

    def test_arp_module_holds_arp_alone(self) -> None:
        """#2529: no re-export at the old path (#1715, #1744)."""
        arp = importlib.import_module('pcapkit.protocols.link.arp')

        self.assertEqual(arp.__all__, ['ARP'])
        self.assertFalse(hasattr(arp, 'InARP'))

    def test_id_index_and_layer(self) -> None:
        """``InARP`` narrows ``id()`` to itself and inherits ARP's ``__index__``."""
        from pcapkit.const.reg.ethertype import EtherType
        from pcapkit.protocols.link.arp import ARP
        from pcapkit.protocols.link.inarp import InARP

        self.assertEqual(InARP.id(), ('InARP',))
        self.assertEqual(ARP.id(), ('ARP',))
        self.assertNotIn('__index__', vars(InARP))
        self.assertEqual(InARP.__index__(), EtherType.Address_Resolution_Protocol)
        self.assertEqual(InARP.__layer__, 'Link')

    def test_top_level_names_are_the_new_homes_object(self) -> None:
        import pcapkit
        import pcapkit.protocols
        import pcapkit.protocols.link
        from pcapkit.protocols.link.inarp import InARP

        for package in (pcapkit, pcapkit.protocols, pcapkit.protocols.link):
            with self.subTest(package=package.__name__):
                self.assertIs(package.InARP, InARP)
                self.assertIn('InARP', package.__all__)

    def test_parsed_arp_keeps_its_dynamic_inarp_alias(self) -> None:
        """EtherType ``0x0806`` binds ARP alone; operation 8 reports ``InARP``."""
        from pcapkit.protocols.link.arp import ARP
        from pcapkit.protocols.link.inarp import InARP

        parsed = ARP(INARP_REQUEST)
        self.assertIs(type(parsed), ARP)
        self.assertEqual(parsed.alias, 'InARP')
        self.assertEqual(parsed.name, 'Inverse Address Resolution Protocol')
        self.assertEqual(InARP(INARP_REQUEST).alias, 'InARP')
        self.assertEqual(InARP.from_data(InARP(INARP_REQUEST).info).data, INARP_REQUEST)


if __name__ == '__main__':
    unittest.main()
