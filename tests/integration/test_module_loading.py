from __future__ import annotations

import unittest

from tests._support import bootstrap_core_modules, isolate_modules


class ModuleLoadingIntegrationTests(unittest.TestCase):
    def test_core_modules_bootstrap_together(self) -> None:
        # ``isolate_modules`` rather than ``purge_modules``: ``bootstrap_core_modules``
        # leaves a stub ``pcapkit`` -- a bare module object carrying only
        # ``__path__`` -- bound in ``sys.modules``, so a later ``import pcapkit``
        # silently gets a package with none of its public names on it. See #660.
        isolate_modules(self)
        modules = bootstrap_core_modules()

        self.assertIn('compat', modules)
        self.assertIn('exceptions', modules)
        self.assertIn('warnings', modules)
        self.assertIn('multidict', modules)
        self.assertIn('decorators', modules)
        self.assertIn('protochain', modules)


if __name__ == '__main__':
    unittest.main()
