# -*- coding: utf-8 -*-
"""Unit tests for :mod:`pcapkit.protocols.application.drarp`.

#2529: a module holds one protocol class, named after it, so ``DRARP`` left
:mod:`pcapkit.protocols.application.rarp` for a module of its own, with no
re-export at the old path. Every case builds its own octets.

"""
from __future__ import annotations

import importlib
import importlib.util
import unittest

from tests._support import reimport_once_per_class

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: A DRARP-Request (operation 5) over Ethernet and IPv4, :rfc:`1931`.
DRARP_REQUEST = bytes.fromhex('000108000604' '0005' '001122334455' '0a000001'
                              '66778899aabb' '0a000002')


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class DRARPModuleTests(unittest.TestCase):
    """``DRARP`` lives in its own module and keeps RARP's behaviour."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_drarp_is_defined_in_its_own_module(self) -> None:
        from pcapkit.protocols.application.drarp import DRARP
        from pcapkit.protocols.application.rarp import RARP

        drarp = importlib.import_module('pcapkit.protocols.application.drarp')
        self.assertEqual(DRARP.__module__, 'pcapkit.protocols.application.drarp')
        self.assertEqual(drarp.__all__, ['DRARP'])
        self.assertEqual(DRARP.__bases__, (RARP,))

    def test_rarp_module_holds_rarp_alone(self) -> None:
        """#2529: no re-export at the old path (#1715, #1744)."""
        rarp = importlib.import_module('pcapkit.protocols.application.rarp')

        self.assertEqual(rarp.__all__, ['RARP'])
        self.assertFalse(hasattr(rarp, 'DRARP'))

    def test_id_and_index(self) -> None:
        """``DRARP`` narrows ``id()`` to itself and inherits RARP's ``__index__``."""
        from pcapkit.const.reg.ethertype import EtherType
        from pcapkit.protocols.application.drarp import DRARP
        from pcapkit.protocols.application.rarp import RARP

        self.assertEqual(DRARP.id(), ('DRARP',))
        self.assertEqual(RARP.id(), ('RARP', 'DRARP'))
        self.assertNotIn('__index__', vars(DRARP))
        self.assertEqual(DRARP.__index__(), EtherType.Reverse_Address_Resolution_Protocol)

    def test_top_level_names_are_the_new_homes_object(self) -> None:
        import pcapkit
        import pcapkit.protocols
        import pcapkit.protocols.application
        from pcapkit.protocols.application.drarp import DRARP

        for package in (pcapkit, pcapkit.protocols, pcapkit.protocols.application):
            with self.subTest(package=package.__name__):
                self.assertIs(package.DRARP, DRARP)
                self.assertIn('DRARP', package.__all__)

    def test_parsed_rarp_keeps_its_dynamic_drarp_alias(self) -> None:
        """EtherType ``0x8035`` binds RARP alone; operation 5 reports ``DRARP``."""
        from pcapkit.protocols.application.drarp import DRARP
        from pcapkit.protocols.application.rarp import RARP

        parsed = RARP(DRARP_REQUEST)
        self.assertIs(type(parsed), RARP)
        self.assertEqual(parsed.alias, 'DRARP')
        self.assertEqual(DRARP(DRARP_REQUEST).alias, 'DRARP')
        self.assertEqual(DRARP.from_data(DRARP(DRARP_REQUEST).info).data, DRARP_REQUEST)


if __name__ == '__main__':
    unittest.main()
