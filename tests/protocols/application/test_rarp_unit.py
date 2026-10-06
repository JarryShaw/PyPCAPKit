# -*- coding: utf-8 -*-
"""Unit tests for :mod:`pcapkit.protocols.application.rarp`.

Relocated from ``tests/protocols/link/test_link_unit.py`` with the module
itself, under :issue:`719`.
"""
from __future__ import annotations

import importlib.util
import unittest

from tests._support import purge_modules, reimport_once_per_class

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)



@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class RARPUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        reimport_once_per_class(self)

    def tearDown(self) -> None:
        purge_modules(['pcapkit'])

    def test_rarp_ids_and_index_are_stable(self) -> None:
        from pcapkit.const.reg.ethertype import EtherType
        from pcapkit.protocols.application.rarp import DRARP, RARP

        self.assertEqual(RARP.id(), ('RARP', 'DRARP'))
        self.assertEqual(DRARP.id(), ('DRARP',))
        self.assertEqual(RARP.__index__(), EtherType.Reverse_Address_Resolution_Protocol)

if __name__ == '__main__':
    unittest.main()
