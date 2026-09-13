from __future__ import annotations

import importlib.util
import pathlib
import subprocess
import sys
import types
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]


class SetupModuleTests(unittest.TestCase):
    def _load_setup_module(self):
        fake_setuptools = types.ModuleType('setuptools')
        captured = {}

        def fake_setup(*args, **kwargs):
            captured['args'] = args
            captured['kwargs'] = kwargs

        fake_setuptools.setup = fake_setup
        sys.modules['setuptools'] = fake_setuptools

        command_specs = {
            'setuptools.command.sdist': 'sdist',
            'setuptools.command.build_py': 'build_py',
            'setuptools.command.develop': 'develop',
            'setuptools.command.install': 'install',
            'setuptools.command.bdist_wheel': 'bdist_wheel',
        }

        loaded = ['setuptools']
        for module_name, class_name in command_specs.items():
            module = types.ModuleType(module_name)
            module.__dict__[class_name] = type(class_name, (), {})
            sys.modules[module_name] = module
            loaded.append(module_name)

        spec = importlib.util.spec_from_file_location('project_setup', ROOT / 'setup.py')
        module = importlib.util.module_from_spec(spec)
        assert spec is not None and spec.loader is not None
        spec.loader.exec_module(module)
        return module, captured, loaded

    def test_get_long_description_reads_readme(self) -> None:
        module, _, loaded = self._load_setup_module()
        try:
            description = module.get_long_description()
        finally:
            for name in loaded + ['project_setup']:
                sys.modules.pop(name, None)

        self.assertIn('PyPCAPKit', description)

    def test_refactor_runs_no_backports_on_modern_python(self) -> None:
        module, _, loaded = self._load_setup_module()
        try:
            with mock.patch('subprocess.check_call', autospec=True) as check_call:
                module.refactor('pcapkit')
        finally:
            for name in loaded + ['project_setup']:
                sys.modules.pop(name, None)

        check_call.assert_not_called()

    def test_refactor_runs_required_backports_for_old_python(self) -> None:
        module, _, loaded = self._load_setup_module()
        try:
            with mock.patch.object(module, 'sys') as fake_sys, \
                 mock.patch('subprocess.check_call', autospec=True) as check_call:
                fake_sys.executable = sys.executable
                fake_sys.version_info = (3, 5)
                fake_sys.exit.side_effect = AssertionError('should not exit')

                module.refactor('pcapkit')
        finally:
            for name in loaded + ['project_setup']:
                sys.modules.pop(name, None)

        commands = [call.args[0][2] for call in check_call.call_args_list]
        self.assertEqual(commands, ['f2format', 'walrus', 'poseur'])

    def test_refactor_exits_when_backport_command_fails(self) -> None:
        module, _, loaded = self._load_setup_module()
        try:
            with mock.patch.object(module, 'sys') as fake_sys, \
                 mock.patch('subprocess.check_call', autospec=True, side_effect=subprocess.CalledProcessError(3, 'f2format')):
                fake_sys.executable = sys.executable
                fake_sys.version_info = (3, 5)
                fake_sys.exit.side_effect = SystemExit(3)

                with self.assertRaises(SystemExit) as error:
                    module.refactor('pcapkit')
        finally:
            for name in loaded + ['project_setup']:
                sys.modules.pop(name, None)

        self.assertEqual(error.exception.code, 3)


if __name__ == '__main__':
    unittest.main()
