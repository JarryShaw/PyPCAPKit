# -*- coding: utf-8 -*-
"""#1968: every action is pinned to a commit, and Dependabot keeps the pins current.

A tag or a branch is a reference the action's owner can move, so ``uses:
owner/repo@v4`` runs whatever that reference names on the day of the run. Each
``uses:`` outside this repository therefore names a full commit and carries the
release that commit is as a trailing comment::

    uses: actions/checkout@<40-hex sha> # v7.0.1

which is the form Dependabot's ``github-actions`` ecosystem rewrites on a bump,
commit and comment together. A local ``./`` reference and a ``docker://`` image
are not actions fetched by tag, so they are left alone.

* :class:`TestEveryActionIsPinned` reads the raw text of every workflow and every
  composite action under :file:`.github`, since YAML drops the comment.
* :class:`TestDependabotUpdatesTheActions` checks :file:`.github/dependabot.yml`
  watches the ``github-actions`` ecosystem from the repository root.
* :class:`TestDependabotCoversEveryManifest` checks the owner's ruling on #1968:
  ``pip`` over the root, :file:`docs` and :file:`examples/benchmark`, and
  neither :file:`conda` nor a ``docker`` entry, as Dependabot cannot update
  either; and the root job's ``exclude-paths`` skips
  :file:`conda/requirements.txt`, which it would otherwise read.
* :class:`TestDependabotCanBuildTheEditable` checks :file:`pyproject.toml`
  declares its readme statically, as Dependabot now fetches that file in place
  of :file:`setup.py` and passes it through unstubbed.
* :class:`TestPyUpOpensNoUpdates` checks :file:`.pyup.yml` turns PyUp's update
  pull requests off, as Dependabot opens them.

"""

from __future__ import annotations

import re
import unittest
from typing import TYPE_CHECKING

try:
    import tomllib
except ImportError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]

from tests import _workflows
from tests._tiers import ROOT

if TYPE_CHECKING:
    import pathlib
    from typing import Any

#: Test tier (#1958): checks the workflow files and Dependabot's configuration, a
#: question about the tree.
__tier__ = 'LATEST'

#: Every ``uses:`` key, quoted or not, with whatever follows it on the line.
USES = re.compile(r'''(?m)^\s*(?:-\s+)?uses:\s*(?P<ref>['"]?[^\s'"#]+['"]?)(?P<rest>.*)$''')
#: What must follow a non-local reference's ``@``: a commit, then its version.
PIN = re.compile(r'[0-9a-f]{40}')
COMMENT = re.compile(r'\s+# v\d[\w.-]*\s*')
#: The Dependabot configuration.
DEPENDABOT = ROOT / '.github' / 'dependabot.yml'
#: PyUp's configuration.
PYUP = ROOT / '.pyup.yml'
#: The directories the ``pip`` entry watches, in the owner's ruling on #1968.
PIP_DIRECTORIES = ['/', '/docs', '/examples/benchmark']


def updates() -> 'dict[str, dict[str, Any]]':
    """The entries of :file:`.github/dependabot.yml`, by ecosystem."""
    document = _workflows.loads(DEPENDABOT.read_text(encoding='utf-8'))
    return {entry['package-ecosystem']: entry for entry in document['updates']}


def directories(entry: 'dict[str, Any]') -> 'list[str]':
    """What an entry watches, whichever of ``directory`` and ``directories`` it uses."""
    return list(entry['directories']) if 'directories' in entry else [entry['directory']]


def files() -> 'list[pathlib.Path]':
    """The workflows, and any composite action, under :file:`.github`."""
    found = sorted(_workflows.WORKFLOWS.glob('*.yml')) + sorted(_workflows.WORKFLOWS.glob('*.yaml'))
    for name in ('action.yml', 'action.yaml'):
        found.extend(sorted((ROOT / '.github').rglob(name)))
    return found


def unpinned(text: 'str') -> 'list[str]':
    """Each non-local ``uses:`` line of ``text`` not pinned to a commit with a version comment."""
    bad = []
    for match in USES.finditer(text):
        ref = match['ref'].strip('\'"')
        if ref.startswith(('./', 'docker://')):
            continue
        _, _, version = ref.partition('@')
        if PIN.fullmatch(version) is None or COMMENT.fullmatch(match['rest']) is None:
            bad.append(match.group(0).strip())
    return bad


class TestEveryActionIsPinned(unittest.TestCase):
    """No ``uses:`` outside this repository names a tag or a branch."""

    def test_there_are_files_to_read(self) -> None:
        self.assertTrue(files())

    def test_every_action_is_a_commit_with_its_version(self) -> None:
        for path in files():
            with self.subTest(file=path.name):
                self.assertEqual(unpinned(path.read_text(encoding='utf-8')), [])

    def test_the_parsed_reference_is_the_commit(self) -> None:
        """What GitHub runs is what YAML reads, and the comment is not part of it."""
        for path in sorted(_workflows.WORKFLOWS.glob('*.yml')):
            for job_id, job in (_workflows.load(path).get('jobs') or {}).items():
                for entry in job.get('steps') or []:
                    uses = str(entry.get('uses', ''))
                    if not uses or uses.startswith(('./', 'docker://')):
                        continue
                    with self.subTest(file=path.name, job=job_id, uses=uses):
                        action, _, sha = uses.partition('@')
                        self.assertRegex(sha, r'^[0-9a-f]{40}$')
                        self.assertTrue(_workflows.pinned(uses, action))
                        self.assertTrue(_workflows.versions(path, action))

    def test_the_check_refuses_a_tag_a_branch_and_a_missing_comment(self) -> None:
        sha = '0' * 40
        for line in ('- uses: actions/checkout@v7',
                     '  uses: pypa/gh-action-pypi-publish@release/v1',
                     f'- uses: actions/checkout@{sha}',
                     f'- uses: actions/checkout@{sha} # latest',
                     f'- uses: actions/checkout@{sha[:7]} # v7.0.1',
                     f"- uses: 'actions/checkout@v7' # v7.0.1"):
            with self.subTest(line=line):
                self.assertEqual(unpinned(line + '\n'), [line.strip()])
        for line in (f'- uses: actions/checkout@{sha} # v7.0.1',
                     f'  uses: github/codeql-action/init@{sha} # v4.39.0',
                     '  uses: ./.github/workflows/unit-tests.yml',
                     '  uses: docker://alpine:3.20',
                     '#   uses: some/action@master'):
            with self.subTest(line=line):
                self.assertEqual(unpinned(line + '\n'), [])


class TestDependabotUpdatesTheActions(unittest.TestCase):
    """Dependabot watches the workflows as well as the Python dependencies."""

    def test_the_github_actions_ecosystem_is_configured(self) -> None:
        text = DEPENDABOT.read_text(encoding='utf-8')
        ecosystems = re.findall(r'package-ecosystem:\s*"([^"]+)"', text)
        self.assertIn('github-actions', ecosystems)
        self.assertIn('pip', ecosystems)

    def test_it_reads_the_workflows_from_the_root(self) -> None:
        """``directory: "/"`` is where Dependabot looks for :file:`.github/workflows`."""
        text = DEPENDABOT.read_text(encoding='utf-8')
        entry = re.search(r'(?ms)package-ecosystem:\s*"github-actions".*?(?=^\s*-\s+package-ecosystem:|\Z)', text)
        self.assertIsNotNone(entry)
        self.assertRegex(entry.group(0), r'(?m)^\s*directory:\s*"/"')  # type: ignore[union-attr]
        self.assertRegex(entry.group(0), r'(?m)^\s*interval:\s*"\w+"')  # type: ignore[union-attr]



class TestDependabotCoversEveryManifest(unittest.TestCase):
    """Dependabot watches the docs and benchmark pins, and nothing it cannot update."""

    def test_pip_watches_the_root_docs_and_the_benchmark(self) -> None:
        self.assertEqual(directories(updates()['pip']), PIP_DIRECTORIES)

    def test_each_pip_directory_holds_a_manifest(self) -> None:
        for directory in PIP_DIRECTORIES:
            with self.subTest(directory=directory):
                here = ROOT / directory.lstrip('/')
                self.assertTrue(sorted(here.glob('*requirements*.txt')) or (here / 'pyproject.toml').is_file())

    def test_conda_is_not_watched(self) -> None:
        """Conda Update's ``Refresh the platform pins`` and ``Setup Conda Distribution`` write it."""
        for ecosystem, entry in updates().items():
            with self.subTest(ecosystem=ecosystem):
                self.assertNotIn('/conda', directories(entry))

    def test_the_root_job_skips_the_conda_requirements(self) -> None:
        """The ``/`` job reads requirements files one directory down, :file:`conda` included.

        dependabot-core's ``SharedFileFetcher.req_files_for_dir`` fetches them, and
        ``FileFetchers::Base.filter_excluded`` drops an entry whose path from the
        repository root matches ``exclude-paths``; without it the job checked
        :file:`conda/requirements.txt`'s cryptography pin.
        """
        self.assertIn('conda/requirements.txt', updates()['pip'].get('exclude-paths') or [])

    def test_there_is_no_docker_entry(self) -> None:
        """Dependabot reads a ``FROM`` that names its image; the benchmark's is an ``ARG``.

        Its digests live in :file:`examples/benchmark/python-images.txt`.
        """
        self.assertNotIn('docker', updates())

    def test_every_entry_is_weekly_and_names_one_kind_of_directory(self) -> None:
        """The schema takes ``directory`` or ``directories``, never both."""
        for ecosystem, entry in updates().items():
            with self.subTest(ecosystem=ecosystem):
                self.assertEqual(entry['schedule'], {'interval': 'weekly'})
                self.assertEqual(len({'directory', 'directories'} & set(entry)), 1)


class TestDependabotCanBuildTheEditable(unittest.TestCase):
    """The Pipfile's editable ``pypcapkit`` reads its readme from :file:`pyproject.toml`.

    There is no :file:`setup.py` (#2061), so ``fetch_project_file`` in
    Dependabot's Python file fetcher fetches :file:`pyproject.toml` in its place,
    and the Pipfile updater writes it unstubbed: ``SetupFileSanitizer`` runs only
    on a :file:`setup.py`. A static ``readme`` does not depend on what a stub
    would supply.
    """

    def setUp(self) -> None:
        if tomllib is None:  # pragma: no cover
            self.skipTest('tomllib needs Python 3.11')
        self.project = tomllib.loads((ROOT / 'pyproject.toml').read_text(encoding='utf-8'))['project']

    def test_the_readme_is_not_dynamic(self) -> None:
        self.assertNotIn('readme', self.project.get('dynamic', []))

    def test_the_readme_is_the_markdown_file(self) -> None:
        self.assertEqual(self.project['readme'], {'file': 'README.md', 'content-type': 'text/markdown'})


class TestPyUpOpensNoUpdates(unittest.TestCase):
    """PyUp's update pull requests are off, and nothing in its file turns one back on."""

    def test_the_global_update_is_off(self) -> None:
        config = _workflows.loads(PYUP.read_text(encoding='utf-8'))
        self.assertIs(config.get('update'), False)

    def test_no_requirements_file_overrides_it(self) -> None:
        """A listed file takes its own ``update``, which defaults to ``all``."""
        config = _workflows.loads(PYUP.read_text(encoding='utf-8'))
        for item in config.get('requirements') or []:
            with self.subTest(item=item):
                self.assertIsInstance(item, dict)
                (options,) = item.values()
                self.assertIs(options.get('update'), False)


if __name__ == '__main__':
    unittest.main()
