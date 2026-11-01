# -*- coding: utf-8 -*-
"""Unit tests for :mod:`pcapkit.protocols.application.rarp`."""
from __future__ import annotations

import importlib.util
import unittest

from tests._support import reimport_once_per_class

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)



@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class RARPUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_rarp_ids_and_index_are_stable(self) -> None:
        from pcapkit.const.reg.ethertype import EtherType
        from pcapkit.protocols.application.rarp import RARP

        self.assertEqual(RARP.id(), ('RARP', 'DRARP'))
        self.assertEqual(RARP.__index__(), EtherType.Reverse_Address_Resolution_Protocol)

if __name__ == '__main__':
    unittest.main()
