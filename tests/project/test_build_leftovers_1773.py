# -*- coding: utf-8 -*-
"""Pins for the build and packaging leftovers fixed in #1773.

* Every PyBPC conversion in :file:`setup.py` lands in a package tree before a
  wheel exists, so none of them is a no-op on ``dist_dir``. Measured by building
  a real wheel of a stub package with :file:`setup.py`'s own ``cmdclass``.
* Each backport's failure message names the feature that tool back-ports.
* ``make profile`` reaches a Makefile that exists, and every ``prune`` in
  :file:`MANIFEST.in` names a directory the repository tracks or ignores. Every
  other line there changes what the template selects (#1794).
* No reStructuredText is tracked outside ``docs/`` (the #719 ruling), the
  examples' Markdown READMEs still ship in the sdist, and nothing points at a
  README path that no longer exists.

"""

from __future__ import annotations

import importlib.util
import json
import logging
import pathlib
import re
import shutil
import subprocess  # nosec: B404
import sys
import tempfile
import textwrap
import types
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]


def tracked() -> 'list[str]':
    """Every path git tracks, or skip when this is not a checkout."""
    if shutil.which('git') is None or not (ROOT / '.git').exists():
        raise unittest.SkipTest('not a git checkout')
    result = subprocess.run(['git', 'ls-files', '-z'], cwd=ROOT,  # nosec
                            capture_output=True, check=True)
    return [name for name in result.stdout.decode('utf-8').split('\0') if name]


def is_history(path: 'str') -> 'bool':
    """The changelogs record old filenames on purpose."""
    return any(part.lower().startswith('changelog') for part in pathlib.PurePosixPath(path).parts)


#: Builds a wheel of a one-module stub package with setup.py's ``cmdclass``,
#: ``refactor`` replaced by a recorder, and writes what it saw as JSON.
WHEEL_DRIVER = textwrap.dedent('''
    import importlib.util, json, os, sys, zipfile
    from unittest import mock

    import setuptools
    from setuptools.dist import Distribution

    root, work, report = sys.argv[1:4]
    captured = {}
    with mock.patch.object(setuptools, 'setup', lambda **kwargs: captured.update(kwargs)):
        spec = importlib.util.spec_from_file_location('project_setup', os.path.join(root, 'setup.py'))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

    os.chdir(work)
    os.makedirs('pcapkit')
    with open(os.path.join('pcapkit', '__init__.py'), 'w') as file:
        file.write('VALUE = 1\\n')
    dist_dir = os.path.join(work, 'dist')
    calls = []

    def record(path):
        init = os.path.join(path, '__init__.py')
        wheels = os.path.isdir(dist_dir) and [n for n in os.listdir(dist_dir) if n.endswith('.whl')]
        calls.append({'path': os.path.relpath(os.path.abspath(path), work),
                      'package': os.path.isfile(init), 'after_wheel': bool(wheels)})
        if os.path.isfile(init):
            with open(init, 'a') as file:
                file.write('CONVERTED = True\\n')

    module.refactor = record
    dist = Distribution({'name': 'probe', 'version': '0', 'packages': ['pcapkit'],
                         'cmdclass': captured['cmdclass']})
    dist.script_name = 'setup.py'
    dist.script_args = ['-q', 'bdist_wheel', '--dist-dir', dist_dir]
    dist.parse_command_line()
    dist.run_commands()
    wheels = [n for n in os.listdir(dist_dir) if n.endswith('.whl')]
    with zipfile.ZipFile(os.path.join(dist_dir, wheels[0])) as archive:
        shipped = archive.read('pcapkit/__init__.py').decode()
    with open(report, 'w') as file:
        json.dump({'calls': calls, 'shipped': shipped}, file)
''')


class WheelConversionTests(unittest.TestCase):
    """A wheel is archived from a converted tree, and nothing converts ``dist_dir``."""

    @classmethod
    def setUpClass(cls) -> None:
        with tempfile.TemporaryDirectory() as work:
            report = pathlib.Path(work) / 'report.json'
            project = pathlib.Path(work) / 'project'
            project.mkdir()
            result = subprocess.run([sys.executable, '-c', WHEEL_DRIVER,  # nosec
                                     str(ROOT), str(project), str(report)],
                                    capture_output=True, text=True, timeout=300)
            if result.returncode != 0:
                raise AssertionError(f'wheel build failed:\n{result.stdout}\n{result.stderr}')
            cls.report = json.loads(report.read_text(encoding='utf-8'))

    def test_a_conversion_runs_during_the_wheel_build(self) -> None:
        self.assertTrue(self.report['calls'])

    def test_every_conversion_targets_an_existing_package_tree(self) -> None:
        for call in self.report['calls']:
            with self.subTest(path=call['path']):
                self.assertTrue(call['package'], f"refactor() pointed at {call['path']}, "
                                                 'which holds no package')

    def test_no_conversion_runs_after_the_wheel_is_written(self) -> None:
        for call in self.report['calls']:
            with self.subTest(path=call['path']):
                self.assertFalse(call['after_wheel'], f"refactor({call['path']}) ran after "
                                                      'the wheel was written, so it cannot change it')

    def test_the_wheel_ships_the_converted_tree(self) -> None:
        self.assertIn('CONVERTED = True', self.report['shipped'])


class BackportMessageTests(unittest.TestCase):
    """Each backport's failure names the feature its tool back-ports."""

    def load_setup(self) -> 'types.ModuleType':
        fakes = {'setuptools': types.ModuleType('setuptools')}
        fakes['setuptools'].setup = lambda **kwargs: None  # type: ignore[attr-defined]
        for name in ('sdist', 'build_py', 'develop', 'install'):
            module = types.ModuleType(f'setuptools.command.{name}')
            setattr(module, name, type(name, (), {}))
            fakes[module.__name__] = module
        logger = logging.getLogger('pcapkit.setup')
        handlers = logger.handlers[:]
        self.addCleanup(setattr, logger, 'handlers', handlers)
        with mock.patch.dict(sys.modules, fakes):
            spec = importlib.util.spec_from_file_location('project_setup_1773', ROOT / 'setup.py')
            assert spec is not None and spec.loader is not None
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        return module

    def failure_message(self, tool: 'str') -> 'str':
        module = self.load_setup()

        def check_call(argv: 'list[str]') -> 'int':
            if argv[2] == tool:
                raise subprocess.CalledProcessError(2, argv)
            return 0

        with mock.patch.object(module, 'sys') as fake_sys, \
                mock.patch('subprocess.check_call', side_effect=check_call), \
                self.assertLogs('pcapkit.setup', 'ERROR') as logs:
            fake_sys.executable = sys.executable
            fake_sys.version_info = (3, 5)
            fake_sys.exit.side_effect = SystemExit
            with self.assertRaises(SystemExit):
                module.refactor('pcapkit')
        self.assertEqual(len(logs.output), 1)
        return logs.output[0]

    def test_each_failure_names_its_own_feature(self) -> None:
        for tool, feature in (('f2format', 'f-string'),
                              ('walrus', 'assignment expression'),
                              ('poseur', 'positional-only parameter')):
            with self.subTest(tool=tool):
                message = self.failure_message(tool)
                self.assertIn(f'{feature} backport', message)
                self.assertIn(f'bpc-{tool}', message)


class MakefileTests(unittest.TestCase):
    """``make profile`` reaches a Makefile that exists."""

    def test_every_sub_make_directory_exists(self) -> None:
        text = (ROOT / 'Makefile').read_text(encoding='utf-8')
        directories = re.findall(r'\$\(MAKE\) -C (\S+)', text)
        self.assertIn('examples/legacy_smoke', directories)
        for directory in directories:
            with self.subTest(directory=directory):
                self.assertTrue((ROOT / directory / 'Makefile').is_file())

    @unittest.skipUnless(shutil.which('make'), 'make is not installed')
    def test_make_profile_resolves(self) -> None:
        result = subprocess.run(['make', '-n', 'profile'], cwd=ROOT,  # nosec
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('test_profile.py', result.stdout)


class ManifestTests(unittest.TestCase):
    """What :file:`MANIFEST.in` names exists, and the examples' READMEs still ship."""

    def test_every_prune_names_a_tracked_or_ignored_directory(self) -> None:
        files = tracked()
        for line in (ROOT / 'MANIFEST.in').read_text(encoding='utf-8').splitlines():
            if not line.startswith('prune '):
                continue
            directory = line.split()[1]
            with self.subTest(directory=directory):
                if any(name.startswith(f'{directory}/') for name in files):
                    continue
                ignored = subprocess.run(['git', 'check-ignore', '-q', '--no-index',  # nosec
                                          f'{directory}/'], cwd=ROOT, check=False)
                self.assertEqual(ignored.returncode, 0,
                                 f'prune {directory} names a directory git neither tracks nor ignores')

    def test_every_other_directive_changes_the_selection(self) -> None:
        """Dropping any non-``prune`` line changes which tracked files the template selects.

        An exclusion may instead guard a path git ignores, as ``prune`` may above.
        The template runs without setuptools' defaults, so ``include README.md``
        counts as effective here although a real build ships the README anyway
        (#1794).
        """
        files = tracked()
        directives = [line.strip() for line in
                      (ROOT / 'MANIFEST.in').read_text(encoding='utf-8').splitlines()
                      if line.strip() and not line.lstrip().startswith('#')]
        driver = textwrap.dedent('''
            import json, os, sys
            from setuptools.command.egg_info import FileList
            data = json.loads(sys.stdin.read())
            tracked = set(data['files'])

            def select(lines):
                listing = FileList()
                listing.allfiles = list(data['files'])
                for line in lines:
                    listing.process_template_line(line)
                return sorted({name.replace(os.sep, '/') for name in listing.files} & tracked)

            lines = data['lines']
            print(json.dumps([select(lines)] + [select(lines[:index] + lines[index + 1:])
                                                for index in range(len(lines))]))
        ''')
        result = subprocess.run([sys.executable, '-c', driver], cwd=ROOT,  # nosec
                                input=json.dumps({'files': files, 'lines': directives}),
                                capture_output=True, text=True, check=True, timeout=120)
        selected, *without = json.loads(result.stdout)
        for line, rest in zip(directives, without):
            action, *words = line.split()
            if action == 'prune':
                continue
            with self.subTest(line=line):
                if rest != selected:
                    continue
                if action.endswith('exclude'):
                    if action.startswith('recursive-'):
                        targets = [f'{words[0]}/{pattern}' for pattern in words[1:]]
                    else:
                        targets = words
                    if all(subprocess.run(['git', 'check-ignore', '-q', '--no-index',  # nosec
                                           target], cwd=ROOT, check=False).returncode == 0
                           for target in targets):
                        continue
                self.fail(f'{line!r} changes nothing the template selects from the tracked files')

    def test_no_restructuredtext_outside_docs(self) -> None:
        stray = [name for name in tracked()
                 if name.endswith('.rst') and not name.startswith('docs/')]
        self.assertEqual(stray, [])

    def test_the_examples_markdown_ships(self) -> None:
        files = tracked()
        markdown = sorted(name for name in files
                          if name.startswith('examples/') and name.endswith('.md'))
        self.assertIn('examples/benchmark/README.md', markdown)
        self.assertIn('examples/legacy_smoke/README.md', markdown)
        driver = textwrap.dedent('''
            import json, sys
            from setuptools.command.egg_info import FileList
            listing = FileList()
            listing.allfiles = json.loads(sys.stdin.read())
            with open('MANIFEST.in', encoding='utf-8') as file:
                for line in file:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        listing.process_template_line(line)
            print(json.dumps(sorted(set(listing.files))))
        ''')
        result = subprocess.run([sys.executable, '-c', driver], cwd=ROOT,  # nosec
                                input=json.dumps(files), capture_output=True, text=True,
                                check=True, timeout=120)
        shipped = set(json.loads(result.stdout))
        self.assertEqual([name for name in markdown if name not in shipped], [])

    def test_no_reference_to_a_missing_examples_readme(self) -> None:
        missing = []
        for name in tracked():
            path = ROOT / name
            if is_history(name) or path.suffix in {'.pcap', '.pcapng', '.png', '.gz'} \
                    or not path.is_file():
                continue
            text = path.read_text(encoding='utf-8', errors='ignore')
            cited = set(re.findall(r'examples/[\w/]+/README\.\w+', text))
            if name.startswith('examples/'):
                parent = pathlib.PurePosixPath(name).parent
                cited.update(str(parent / bare) for bare in
                             re.findall(r'(?<![\w/.])README\.(?:rst|md|txt)\b', text))
            missing.extend(f'{name}: {target}' for target in sorted(cited)
                           if not (ROOT / target).is_file())
        self.assertEqual(missing, [])


if __name__ == '__main__':
    unittest.main()
