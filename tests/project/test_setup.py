from __future__ import annotations

import importlib.util
import pathlib
import sys
import types
import unittest
from unittest import mock

#: Test tier (#1958): loads setup.py under the running interpreter, as every leg's
#: install does.
__tier__ = 'ALL'

ROOT = pathlib.Path(__file__).resolve().parents[2]


class SetupModuleTests(unittest.TestCase):
    def _load_setup_module(self):
        fake_setuptools = types.ModuleType('setuptools')
        captured = {}

        def fake_setup(*args, **kwargs):
            captured['args'] = args
            captured['kwargs'] = kwargs

        fake_setuptools.setup = fake_setup
        with mock.patch.dict(sys.modules, {'setuptools': fake_setuptools}):
            spec = importlib.util.spec_from_file_location('project_setup', ROOT / 'setup.py')
            assert spec is not None and spec.loader is not None
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        return module, captured

    def test_setup_passes_no_long_description(self) -> None:
        """``pyproject.toml``'s static ``readme`` is the long description (#1968).

        Dependabot replaces this file with a stub that passes none, so a long
        description supplied here leaves ``readme`` dynamic and the stub's build
        failing.
        """
        _, captured = self._load_setup_module()
        self.assertNotIn('long_description', captured['kwargs'])
        self.assertNotIn('long_description_content_type', captured['kwargs'])

    def test_setup_overrides_no_build_command(self) -> None:
        """No ``cmdclass``: the commands only ever ran the BPC conversion (#2051).

        Nothing converts the 3.8 syntax any more, so a build command overridden
        here has nothing left to add to setuptools' own.
        """
        module, captured = self._load_setup_module()
        self.assertEqual(captured, {'args': (), 'kwargs': {}})
        self.assertFalse(hasattr(module, 'refactor'))


if __name__ == '__main__':
    unittest.main()
