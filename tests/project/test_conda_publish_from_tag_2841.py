# -*- coding: utf-8 -*-
"""#2841: every Conda Update bump that publishes packages the ``v<version>`` tag's tree.

Conda Update built ``main``'s tip, so once a feature merged without a version
bump, a scheduled bump or #2060's ``publish`` dispatch uploaded unreleased code
under the released version. #2841's options 1, 2b and 3, taken for every
publishing bump: the bump is still committed to ``main`` and tagged
``conda-<version>+<build>``, but ``conda-dist`` builds the tree ``v<version>``
names, with only :file:`conda/` and :file:`util/` from the bump; a release whose
dependencies ``main`` has changed is not built; and the bump's message names the tag.

* :class:`TestFindTheReleaseTag`: ``Find the release tag`` runs on every
  publishing bump, before anything is bumped or pushed. Run in a scratch clone
  of ``main``, it writes the tag and the commit it names. Where ``main``'s version
  has no tag, a forced bump fails with an ``::error`` and any other bump goes on
  with a ``::notice``, writing nothing.
* :class:`TestCheckTheDependencies`: ``Check the release tag's dependencies``,
  run on scratch trees, hands the tag on where the tag's :file:`pyproject.toml`
  names what ``main``'s does. Otherwise it names both sets, and a forced bump
  fails with an ``::error`` while any other warns and hands nothing on, so the
  run stays green; :class:`TestTheReportWarns` posts that as ``warning``.
* :class:`TestTheBumpNamesTheTag`: ``Commit Changes`` records the tag's tree in
  the bump's message.
* :class:`TestTheCommitReachesCondaDist`: ``conda-update`` hands that commit on;
  without it nothing is tagged or uploaded, and with it ``conda-dist``'s
  ``Check out the release tag's tree`` runs after every checkout and before
  anything reads the tree.
* :class:`TestTheReleaseTreeIsBuilt`: that step, run on a checkout of the bump's
  tag, leaves the tag's tree with the bump's :file:`conda/` and :file:`util/`,
  and nothing a later merge added.
* :class:`TestNoForcedWarningAdvisesMain`: Push Changes' warnings name the tag
  whose tree a second dispatch would build.

"""

from __future__ import annotations

import os
import pathlib
import shlex
import subprocess  # nosec: B404
import sys
import unittest
from typing import TYPE_CHECKING

from tests import _workflows
from tests._support import scale_timeout
from tests._workflows import WORKFLOWS
from tests.project.test_cron_reports_2030 import _ReportStep
from tests.project.test_release_gates import (NULL, ROOT, CondaStepHarness, conda_context, evaluate_condition,
                                              job_blocks, job_runs)

if TYPE_CHECKING:
    from typing import Any, Optional

#: Test tier (#1958): reads the workflow file, and runs its steps' shell offline.
__tier__ = 'LATEST'

CONDA = 'cron-conda.yml'
#: The steps this change adds, by name.
FIND = 'Find the release tag'
DEPS = "Check the release tag's dependencies"
TREE = "Check out the release tag's tree"
#: Push Changes' warnings on a forced bump it does not push, which #2060 added.
FORCED_TITLES = ('Nothing published as main moved past this checkout',
                 'Nothing published as the build is already on main',
                 'Nothing published as main moved during the push')


def step(job_id: 'str', label: 'str') -> 'dict[str, Any]':
    """The one step of ``job_id`` whose name, or else id, is ``label``."""
    [found] = [entry for entry in _workflows.steps(CONDA, job_id) if label in (entry.get('name'), entry.get('id'))]
    return found


def labels(job_id: 'str') -> 'list[str]':
    return [str(entry.get('name') or entry.get('id')) for entry in _workflows.steps(CONDA, job_id)]


class _ReleaseRepository(CondaStepHarness):
    """An origin holding a release, a merge after it, and a forced bump of it on ``main``.

    The release is a lightweight ``v*`` tag, as Create Release's are, and the bump
    an annotated ``conda-*`` tag, as ``conda-tag`` pushes. ``None`` deletes a file.

    """

    VERSION = '2.0.1'
    RELEASE_TAG = f'v{VERSION}'
    CONDA_TAG = f'conda-{VERSION}+3'

    #: What the release adds on top of the harness's base commit.
    RELEASED = {
        'pcapkit/__init__.py': f"__version__ = '{VERSION}'\n",
        'pcapkit/released.py': 'released\n',
        'pyproject.toml': 'as released\n',
        'conda/pypcapkit/meta.yaml': 'the recipe at the tag\n',
        'conda/only-at-the-tag.txt': 'gone by the bump\n',
        'util/release_conda.py': 'the script at the tag\n',
    }  # type: dict[str, Optional[str]]
    #: A feature merged after the release, without a version bump.
    MERGED = {
        'pcapkit/released.py': 'changed since\n',
        'pcapkit/unreleased.py': 'merged since\n',
        'pyproject.toml': 'changed since\n',
    }  # type: dict[str, Optional[str]]
    #: The forced bump, all of it under conda/ and util/.
    BUMPED = {
        'conda/build': '3\n',
        'conda/pypcapkit/meta.yaml': 'the recipe fixed on main\n',
        'conda/only-at-the-tag.txt': None,
        'util/release_conda.py': 'the script fixed on main\n',
        'util/added_on_main.py': 'a script main added\n',
    }  # type: dict[str, Optional[str]]

    def setUp(self) -> None:
        super().setUp()
        # The steps run `python`, setup-python's interpreter; this one stands for it.
        python = self.root / 'bin' / 'python'
        python.write_text(f'#!/bin/sh\nexec {shlex.quote(sys.executable)} "$@"\n', encoding='utf-8')
        python.chmod(0o755)
        work = self._clone('work')
        self.release = self._commit(work, self.RELEASED, 'release')
        self._git(work, 'tag', self.RELEASE_TAG)
        self._git(work, 'push', 'origin', 'HEAD:refs/heads/main', f'refs/tags/{self.RELEASE_TAG}')
        self.merge = self._commit(work, self.MERGED, 'feat: a merge', (self.HUMAN, self.GITHUB))
        self.bump = self._commit(work, self.BUMPED, 'Bumped build to 3')
        self._git(work, 'tag', '-a', self.CONDA_TAG, '-m', 'Conda Build')
        self._git(work, 'push', 'origin', 'HEAD:refs/heads/main', f'refs/tags/{self.CONDA_TAG}')

    def _commit(self, clone: 'pathlib.Path', files: 'dict[str, Optional[str]]', message: 'str',
                identity: 'Optional[tuple[tuple[str, str], tuple[str, str]]]' = None) -> 'str':
        for path, text in files.items():
            target = clone / path
            if text is None:
                target.unlink()
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding='utf-8')
        self._git(clone, 'add', '-A')
        self._git(clone, 'commit', '-m', message, identity=identity)
        return self._git(clone, 'rev-parse', 'HEAD')

    def tree(self, clone: 'pathlib.Path') -> 'dict[str, str]':
        """Every file on disk under ``clone``, ``.git`` aside, and what it holds."""
        found = {}
        for root, dirs, files in os.walk(clone):
            dirs[:] = [name for name in dirs if name != '.git']
            for name in files:
                path = pathlib.Path(root, name)
                found[path.relative_to(clone).as_posix()] = path.read_bytes().decode('utf-8')
        return found

    def committed(self, rev: 'str') -> 'dict[str, str]':
        """Every file ``rev`` holds, and what it holds, unstripped as :meth:`_git` would leave it."""
        found = {}
        for path in self._origin('ls-tree', '-r', '--name-only', rev).splitlines():
            blob = subprocess.run(['git', '--git-dir', str(self.origin), 'show', f'{rev}:{path}'],  # nosec: B603 B607
                                  env=self.env, capture_output=True, check=True, timeout=scale_timeout(30))
            found[path] = blob.stdout.decode('utf-8')
        return found


class TestFindTheReleaseTag(_ReleaseRepository, unittest.TestCase):

    def find(self, clone: 'pathlib.Path', forced: 'str' = 'true') -> 'tuple[int, dict[str, str], str]':
        """The step's exit status, its outputs, and its stdout, run in ``clone``."""
        result, outputs = self._bash(step('conda-update', FIND)['run'], clone, {'FORCED': forced})
        return result.returncode, outputs, result.stdout

    def test_it_runs_on_every_publishing_bump(self) -> None:
        """The schedule's and a ``workflow_run``'s too, and never a build-only run's, which pushes nothing."""
        condition = step('conda-update', FIND)['if']
        for publishes, bump, expected in (('true', 'true', True), ('true', 'false', False), ('false', 'true', False),
                                          (NULL, 'true', False), ('true', NULL, False)):
            with self.subTest(publishes=publishes, bump=bump):
                scope = {'needs': {'mode': {'outputs': {} if publishes is NULL else {'publishes': publishes}}},
                         'steps': {'bump': {'outputs': {} if bump is NULL else {'bump': bump}}}}
                self.assertIs(evaluate_condition(condition, scope), expected)
        self.assertEqual(step('conda-update', FIND)['id'], 'release-tag')
        self.assertEqual(step('conda-update', FIND)['env'], {'FORCED': '${{ steps.bump.outputs.forced }}'})

    def test_it_runs_before_anything_is_bumped_or_pushed(self) -> None:
        """After the install that makes ``pcapkit`` importable and the step that says ``forced``."""
        names = labels('conda-update')
        for earlier in ('Install and Setup', 'Decide whether to bump'):
            with self.subTest(earlier=earlier):
                self.assertLess(names.index(earlier), names.index(FIND))
        for later in ('Bump Version', 'Commit Changes', 'Push Changes'):
            with self.subTest(later=later):
                self.assertLess(names.index(FIND), names.index(later))

    def test_it_finds_the_tag_on_a_tip_past_it(self) -> None:
        """A merge after the release, which a recovery dispatch and a scheduled bump both meet."""
        clone = self._clone('runner')
        self._git(clone, 'checkout', '-q', '--detach', self.merge)
        for forced in ('true', 'false'):
            with self.subTest(forced=forced):
                status, outputs, stdout = self.find(clone, forced)
                self.assertEqual((status, outputs), (0, {'tag': self.RELEASE_TAG, 'commit': self.release}), stdout)
                self.assertIn(f"::notice title=Publishing {self.RELEASE_TAG}::this run builds "
                              f"{self.RELEASE_TAG}'s tree, {self.release}, under the build it bumps on main", stdout)

    def untagged(self) -> 'dict[str, pathlib.Path]':
        """A clone of ``main`` bumped to each version no tag names, a dev one included."""
        clones = {}
        for version in ('2.1.0', '2.1.0.dev1'):
            clones[version] = self._clone(f'bump-{version}')
            self._commit(clones[version], {'pcapkit/__init__.py': f"__version__ = '{version}'\n"}, 'chore: bump')
        return clones

    def test_a_forced_bump_of_a_version_with_no_tag_is_refused(self) -> None:
        """Nothing to republish: the step fails the job before the bump, so nothing is pushed."""
        for version, work in self.untagged().items():
            with self.subTest(version=version):
                status, outputs, stdout = self.find(work)
                self.assertEqual((status, outputs), (1, {}), stdout)
                self.assertIn(f"::error title=No v{version} tag::main's version is {version}, which no "
                              f'v{version} tag names', stdout)

    def test_any_other_bump_of_a_version_with_no_tag_goes_on_unbuilt(self) -> None:
        """A notice, no outputs and success: the bump is pushed, and ``conda-tag`` and ``conda-dist`` skip."""
        for version, work in self.untagged().items():
            for forced in ('false', ''):
                with self.subTest(version=version, forced=forced):
                    status, outputs, stdout = self.find(work, forced)
                    self.assertEqual((status, outputs), (0, {}), stdout)
                    self.assertEqual(stdout.splitlines(), [
                        f"::notice title=No v{version} tag::main's version is {version}, which no v{version} tag "
                        'names, so the bump is pushed but neither tagged nor uploaded: a conda build packages only '
                        "a released version's tree"])


class TestCheckTheDependencies(CondaStepHarness, unittest.TestCase):
    """``Check the release tag's dependencies``, run on ``main`` with the real util/conda_vendor.py."""

    TAG = 'v2.0.1'
    #: The tag's ``pyproject.toml``: what util/conda_vendor.py's ``direct`` reads, and an extra it does not.
    RELEASED = ('[project]\nname = "pypcapkit"\ndependencies = [ "dictdumper~=0.8.0", "chardet" ]\n\n'
                '[project.optional-dependencies]\ncli = [ "emoji" ]\n'
                'all = [ "emoji", "cryptography>=3.4; platform_python_implementation != \'PyPy\'" ]\n')
    #: Those as util/conda_vendor.py lists them.
    LISTED = 'chardet, cryptography>=3.4; platform_python_implementation != "PyPy", dictdumper~=0.8.0, emoji'
    #: Each way ``main`` can name other dependencies: its ``pyproject.toml``, and its set as listed.
    CHANGED = {
        'one added': (RELEASED.replace('"chardet" ]', '"chardet", "aenum" ]'), 'aenum, ' + LISTED),
        'a pin moved': (RELEASED.replace('~=0.8.0', '~=0.9.0'), LISTED.replace('~=0.8.0', '~=0.9.0')),
        'the all extra changed': (RELEASED.replace('all = [ "emoji", ', 'all = [ '), LISTED.replace(', emoji', '')),
    }

    def setUp(self) -> None:
        super().setUp()
        python = self.root / 'bin' / 'python'
        python.write_text(f'#!/bin/sh\nexec {shlex.quote(sys.executable)} "$@"\n', encoding='utf-8')
        python.chmod(0o755)
        self.work = self._clone('work')
        # The script reads conda/platform-pins.toml as it is imported.
        for path in ('util/conda_vendor.py', 'util/python_versions.py', 'conda/platform-pins.toml'):
            (self.work / path).parent.mkdir(parents=True, exist_ok=True)
            (self.work / path).write_bytes((ROOT / path).read_bytes())
        (self.work / 'pyproject.toml').write_text(self.RELEASED, encoding='utf-8')
        self._git(self.work, 'add', '-A')
        self._git(self.work, 'commit', '-m', 'release')
        self._git(self.work, 'tag', self.TAG)

    def check(self, pyproject: 'str', forced: 'str' = 'false',
              tag: 'str' = TAG) -> 'tuple[int, dict[str, str], str]':
        """The step's exit status, outputs and output, with ``main``'s ``pyproject.toml`` reading ``pyproject``."""
        (self.work / 'pyproject.toml').write_text(pyproject, encoding='utf-8')
        result, outputs = self._bash(step('conda-update', DEPS)['run'], self.work,
                                     {'FORCED': forced, 'RELEASE_TAG': tag, 'RELEASE_COMMIT': 'f' * 40})
        return result.returncode, outputs, result.stdout + result.stderr

    def reason(self, main: 'str') -> 'str':
        return (f"{self.TAG}'s tree would be built with main's vendored requirements, and the two name different "
                f'dependencies. {self.TAG}: {self.LISTED}. main: {main}.')

    def test_it_runs_where_a_tag_was_found(self) -> None:
        """Before the bump, so a refusal pushes and tags nothing."""
        condition = step('conda-update', DEPS)['if']
        for tag, expected in (('v2.0.1', True), ('', False), (NULL, False)):
            with self.subTest(tag=tag):
                scope = {'steps': {'release-tag': {'outputs': {} if tag is NULL else {'tag': tag}}}}
                self.assertIs(evaluate_condition(condition, scope), expected)
        self.assertEqual(step('conda-update', DEPS)['id'], 'release-deps')
        self.assertEqual(step('conda-update', DEPS)['env'],
                         {'FORCED': '${{ steps.bump.outputs.forced }}',
                          'RELEASE_TAG': '${{ steps.release-tag.outputs.tag }}',
                          'RELEASE_COMMIT': '${{ steps.release-tag.outputs.commit }}'})
        names = labels('conda-update')
        self.assertEqual(names.index(DEPS), names.index(FIND) + 1)
        self.assertLess(names.index(DEPS), names.index('Bump Version'))

    def test_the_same_dependencies_hand_the_tag_on(self) -> None:
        """Reordered, and with an extra outside ``all`` changed: what is vendored is the same, forced or not."""
        reordered = self.RELEASED.replace('"dictdumper~=0.8.0", "chardet"', '"chardet", "dictdumper~=0.8.0"')
        for label, text in (('as tagged', self.RELEASED), ('reordered', reordered),
                            ('another extra changed', reordered.replace('cli = [ "emoji" ]', 'cli = [ ]'))):
            for forced in ('true', 'false'):
                with self.subTest(label, forced=forced):
                    self.assertEqual(self.check(text, forced), (
                        0, {'same': 'true', 'tag': self.TAG, 'commit': 'f' * 40},
                        f'{self.TAG} names the dependencies main does, which conda/requirements.txt vendors\n'))

    def test_a_forced_bump_on_other_dependencies_fails_naming_both_sets(self) -> None:
        for label, (text, main) in self.CHANGED.items():
            with self.subTest(label):
                self.assertEqual(self.check(text, 'true'), (1, {'same': 'false'}, (
                    f'::error title=Dependencies differ from {self.TAG}::{self.reason(main)} A manual run with '
                    'publish therefore publishes nothing.\n')))

    def test_any_other_bump_on_other_dependencies_warns_and_hands_nothing_on(self) -> None:
        """Green, so a scheduled or ``workflow_run`` run is not red; ``conda-tag`` and ``conda-dist`` then skip."""
        for label, (text, main) in self.CHANGED.items():
            for forced in ('false', ''):
                with self.subTest(label, forced=forced):
                    self.assertEqual(self.check(text, forced), (0, {'same': 'false'}, (
                        f'::warning title=Dependencies differ from {self.TAG}::{self.reason(main)} The bump is '
                        'pushed but neither tagged nor uploaded.\n')))

    def test_a_tag_it_cannot_read_fails_either_way(self) -> None:
        for forced in ('true', 'false'):
            with self.subTest(forced=forced):
                status, outputs, output = self.check(self.RELEASED, forced, tag='v0.0.0')
                self.assertEqual((status, outputs), (1, {}), output)
                self.assertTrue(output.startswith('::error title=No pyproject.toml at v0.0.0::'), output)


class TestTheBumpNamesTheTag(CondaStepHarness, unittest.TestCase):
    """``Commit Changes``, run on a clone holding a bump: the message it commits."""

    def commit(self, release_tag: 'str') -> 'list[str]':
        clone = self._clone(f'bump-{release_tag or "untagged"}')
        (clone / 'conda' / 'build').write_text('3\n', encoding='utf-8')
        result, _ = self._bash(step('conda-update', 'Commit Changes')['run'], clone,
                               {'CHANGED_FILES': 'conda/requirements.txt', 'RELEASE_TAG': release_tag})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return self._git(clone, 'log', '-1', '--format=%B').splitlines()

    def test_a_tagged_version_is_named(self) -> None:
        message = self.commit('v2.0.1')
        self.assertEqual(message[0], 'Bumped build to 3')
        self.assertEqual(message[-3:], ['  conda/requirements.txt', '',
                                        "The build packages v2.0.1's tree, with conda/ and util/ from this commit."])

    def test_no_tag_adds_nothing(self) -> None:
        """A bump that is not built, or a build-only run's, which is never pushed."""
        self.assertEqual(self.commit('')[-1], '  conda/requirements.txt')

    def test_the_tag_is_the_one_handed_on(self) -> None:
        """From Check the release tag's dependencies, so a tag naming other dependencies is not named."""
        self.assertEqual(step('conda-update', 'Commit Changes')['env']['RELEASE_TAG'],
                         '${{ steps.release-deps.outputs.tag }}')


class TestTheCommitReachesCondaDist(unittest.TestCase):

    def test_without_it_nothing_is_tagged_or_uploaded(self) -> None:
        """A version with no ``v*`` tag: the bump is pushed, on every trigger, and goes no further."""
        jobs = job_blocks((WORKFLOWS / CONDA).read_text(encoding='utf-8'))
        for event_name, extra in (('workflow_run', {}), ('schedule', {'unit_tests': 'success', 'verdict': 'skipped',
                                                                     'verified': NULL})):
            for release, expected in ((NULL, False), ('f' * 40, True)):
                scope = conda_context(event_name=event_name, release=release, **extra)
                with self.subTest(event=event_name, release=release):
                    self.assertTrue(job_runs(jobs, 'conda-update', scope))
                    self.assertIs(job_runs(jobs, 'conda-tag', scope), expected)
                    self.assertIs(job_runs(jobs, 'conda-dist', scope), expected)

    def test_conda_update_hands_on_the_commit(self) -> None:
        """The commit only where the dependencies matched; the tag wherever it was found, for the report."""
        outputs = _workflows.job(CONDA, 'conda-update')['outputs']
        self.assertEqual(outputs['PCAPKIT_RELEASE_COMMIT'], '${{ steps.release-deps.outputs.commit }}')
        self.assertEqual(outputs['PCAPKIT_RELEASE_TAG'], '${{ steps.release-tag.outputs.tag }}')
        self.assertEqual(step('conda-dist', TREE)['env'],
                         {'PCAPKIT_RELEASE_COMMIT': '${{ needs.conda-update.outputs.PCAPKIT_RELEASE_COMMIT }}'})

    def test_the_tree_step_runs_exactly_when_the_commit_is_set(self) -> None:
        """Set on a publishing bump of a tagged version; a build-only run keeps the dispatched tree."""
        condition = step('conda-dist', TREE)['if']
        for publishes, commit, expected in (('true', 'f' * 40, True), ('true', '', False), ('true', NULL, False),
                                            ('false', 'f' * 40, False), ('false', NULL, False)):
            scope = {'needs': {'mode': {'outputs': {'publishes': publishes}},
                               'conda-update': {'outputs': {} if commit is NULL else
                                                {'PCAPKIT_RELEASE_COMMIT': commit}}}}
            with self.subTest(publishes=publishes, commit=commit):
                self.assertIs(evaluate_condition(condition, scope), expected)

    def test_it_follows_every_checkout_and_precedes_every_read(self) -> None:
        names = labels('conda-dist')
        for earlier in ('checkout', 'checkout-dispatched', "Apply conda-update's changes"):
            with self.subTest(earlier=earlier):
                self.assertLess(names.index(earlier), names.index(TREE))
        for later in ('setup-python', 'Install and Setup', 'Setup Conda Distribution', 'Build conda packages',
                      'Smoke-test the vendored packages'):
            with self.subTest(later=later):
                self.assertLess(names.index(TREE), names.index(later))
        # `bash` on every leg, Windows's included, and no expression in the script.
        self.assertEqual(step('conda-dist', TREE)['shell'], 'bash')
        self.assertNotIn('${{', step('conda-dist', TREE)['run'])

    def test_the_checkout_before_it_is_the_bump(self) -> None:
        """So the step's ``HEAD`` is the commit ``conda-tag`` tagged, whose conda/ and util/ it keeps."""
        ref = step('conda-dist', 'checkout')['with']['ref']
        self.assertEqual(ref, 'conda-${{ needs.conda-update.outputs.PCAPKIT_VERSION }}'
                              '+${{ needs.conda-update.outputs.PCAPKIT_BUILD }}')


class TestTheReleaseTreeIsBuilt(_ReleaseRepository, unittest.TestCase):
    """``Check out the release tag's tree``, run where ``checkout`` leaves a forced bump's leg."""

    def setUp(self) -> None:
        super().setUp()
        self.runner = self._clone('runner')
        self._git(self.runner, 'checkout', '-q', '--detach', self.CONDA_TAG)

    def test_the_fixture_is_not_vacuous(self) -> None:
        """Without the step, the leg would build the merge and the bump's conda/ alike."""
        self.assertEqual(self._git(self.runner, 'rev-parse', 'HEAD'), self.bump)
        self.assertIn('pcapkit/unreleased.py', self.tree(self.runner))
        self.assertNotEqual(self.committed(self.release)['pcapkit/released.py'],
                            self.tree(self.runner)['pcapkit/released.py'])

    def test_it_builds_the_tag_with_the_bumps_conda_and_util(self) -> None:
        result, outputs = self._bash(step('conda-dist', TREE)['run'], self.runner,
                                     {'PCAPKIT_RELEASE_COMMIT': self.release})
        self.assertEqual((result.returncode, outputs), (0, {}), result.stdout + result.stderr)
        self.assertEqual(self._git(self.runner, 'rev-parse', 'HEAD'), self.release)
        tooling = ('conda/', 'util/')
        expected = {path: text for path, text in self.committed(self.release).items()
                    if not path.startswith(tooling)}
        expected.update((path, text) for path, text in self.committed(self.bump).items() if path.startswith(tooling))
        self.assertEqual(self.tree(self.runner), expected)
        # What that means for this fixture, spelled out.
        built = self.tree(self.runner)
        self.assertNotIn('pcapkit/unreleased.py', built)
        self.assertEqual(built['pcapkit/released.py'], 'released\n')
        self.assertEqual(built['pyproject.toml'], 'as released\n')
        self.assertEqual(built['conda/build'], '3\n')
        self.assertEqual(built['conda/pypcapkit/meta.yaml'], 'the recipe fixed on main\n')
        self.assertNotIn('conda/only-at-the-tag.txt', built)
        self.assertEqual(built['util/added_on_main.py'], 'a script main added\n')

    def test_a_commit_it_cannot_check_out_fails_the_leg(self) -> None:
        result, _ = self._bash(step('conda-dist', TREE)['run'], self.runner, {'PCAPKIT_RELEASE_COMMIT': '0' * 40})
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self._git(self.runner, 'rev-parse', 'HEAD'), self.bump)


class TestNoForcedWarningAdvisesMain(unittest.TestCase):
    """Push Changes' forced warnings advise a dispatch that builds the tag, by name."""

    def test_push_changes_reads_the_tag(self) -> None:
        self.assertEqual(step('conda-update', 'Push Changes')['env']['RELEASE_TAG'],
                         '${{ steps.release-deps.outputs.tag }}')

    def test_every_forced_warning_names_it(self) -> None:
        script = step('conda-update', 'Push Changes')['run']
        self.assertIn('''again="dispatch Conda Update again with publish on main, which builds ${RELEASE_TAG}'s '''
                      '''tree, not main's"''', script)
        warnings = [line for line in script.splitlines() if '::warning title=Nothing published' in line]
        titles = sorted(line.strip().split('::')[1] for line in warnings)
        self.assertEqual(titles, sorted(f'warning title={title}' for title in FORCED_TITLES))
        for line in warnings:
            with self.subTest(warning=line.split('::')[1]):
                self.assertIn('$again', line)
                self.assertNotIn('dispatch Conda Update', line)


class TestTheReportWarns(_ReportStep):
    """Write the run report: a pushed bump the dependency check withheld posts as ``warning``."""

    workflow, job, file = CONDA, 'conda-update', 'conda-report.md'

    def setUp(self) -> None:
        super().setUp()
        (self.work / 'conda').mkdir()
        (self.work / 'conda' / 'build').write_text('4\n', encoding='utf-8')
        (self.temp / 'platform-pins.log').write_text('', encoding='utf-8')

    def test_other_dependencies_warn(self) -> None:
        for same, expected in (('false', 'warning'), ('true', 'success'), ('', 'success')):
            with self.subTest(same=same):
                text, status = self.report(PUBLISHES='true', FILES_CHANGED='true', CHANGED_FILES='conda/build',
                                           BUMP='true', FORCED='false', PUSH='success', COMMIT='f' * 40,
                                           SAME_DEPENDENCIES=same)
                self.assertEqual(status, expected)
                self.assertTrue(text.endswith(f'- Pushed: build 4 as {"f" * 40}\n'), text)

    def test_it_reads_the_check(self) -> None:
        self.assertEqual(step('conda-update', 'Write the run report')['env']['SAME_DEPENDENCIES'],
                         '${{ steps.release-deps.outputs.same }}')


if __name__ == '__main__':
    unittest.main()
