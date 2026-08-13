from __future__ import annotations

import types
import unittest
from unittest import mock

from tests._support import load_module, purge_modules


class ModuleDescriptorTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])
        self.module = load_module('pcapkit.corekit.module', 'pcapkit/corekit/module.py')

    def test_klass_imports_target_attribute(self) -> None:
        target_module = types.SimpleNamespace(Target=dict)
        with mock.patch('importlib.import_module', return_value=target_module) as importer:
            descriptor = self.module.ModuleDescriptor('demo.module', 'Target')
            self.assertIs(descriptor.klass, dict)

        importer.assert_called_once_with('demo.module')


if __name__ == '__main__':
    unittest.main()
