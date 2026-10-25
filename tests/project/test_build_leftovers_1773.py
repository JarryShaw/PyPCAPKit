# -*- coding: utf-8 -*-
"""Pins for the build and packaging leftovers fixed in #1773.

* ``make profile`` reaches a Makefile that exists, and every ``prune`` in
  :file:`MANIFEST.in` names a directory the repository tracks or ignores. Every
  other line there changes what the template selects (#1794).
* No reStructuredText is tracked outside ``docs/`` (the #719 ruling), the
  examples' Markdown READMEs ship in the sdist, and nothing points at a
  README path that does not exist.

"""

from __future__ import annotations

import json
import pathlib
import re
import shutil
import subprocess  # nosec: B404
import sys
import textwrap
import unittest

#: Test tier (#1958): reads the Makefile and MANIFEST.in, and asks setuptools what
#: the manifest template selects.
__tier__ = 'LATEST'

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
