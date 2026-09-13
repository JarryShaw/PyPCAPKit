from __future__ import annotations

import unittest

from tests._support import bootstrap_core_modules, purge_modules


class ModuleLoadingIntegrationTests(unittest.TestCase):
    def test_core_modules_bootstrap_together(self) -> None:
        purge_modules(['pcapkit'])
        modules = bootstrap_core_modules()

        self.assertIn('compat', modules)
        self.assertIn('exceptions', modules)
        self.assertIn('warnings', modules)
        self.assertIn('multidict', modules)
        self.assertIn('decorators', modules)
        self.assertIn('protochain', modules)


if __name__ == '__main__':
    unittest.main()
