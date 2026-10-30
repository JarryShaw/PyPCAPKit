# -*- coding: utf-8 -*-
"""#2458: ``cron-conda.yml`` never tags or uploads a dev-release version.

#2452 (not yet merged) proposes the equivalent gate for
:file:`.github/workflows/create-release.yml`'s publishers (``github``, ``tag``,
``pypi``, ``conda``), gated on ``PCAPKIT_DEV_RELEASE`` by that PR's owner
ruling: ``__version__`` carrying a PEP 440 dev-release suffix (``X.Y.Z.devN``)
is a work-in-progress signal, and that workflow's ``workflow_run`` trigger
means a scheduled Vendor Update can reach it and publish that version with no
human in the path.

:file:`cron-conda.yml` is a separate workflow with its own independent route to
publishing: ``conda-tag`` pushes a ``conda-<version>+<build>`` tag and
``conda-dist`` uploads to anaconda.org, both whenever ``mode``'s ``publishes``
output is ``'true'`` and ``conda-update``'s ``CONDA_CHANGED`` is ``'true'`` --
reachable the same way, from its own ``schedule`` and ``workflow_run`` triggers,
and until now with no dev-release check of its own. This workflow has no
``version_check`` job to share #2452's proposed output with, so
``conda-update``'s own ``Get Version`` step computes ``PCAPKIT_DEV_RELEASE``
independently, and ``conda-tag`` and ``conda-dist`` each read it.

Deliberately ``is_devrelease``, never ``is_prerelease``: the latter is also
``true`` for a deliberately-tagged alpha/beta/rc this project has shipped for
real (e.g. ``1.5.0b14``), and gating on it would silently block one.
:meth:`TestGetVersionComputesDevRelease.test_running_the_script_disagrees_with_is_prerelease_on_a_real_release`
runs the real step script against both shapes of version string to show the
two outputs actually disagree there.

* :class:`TestGetVersionComputesDevRelease`: the ``Get Version`` step's script,
  and the job's declared ``outputs:``, by text and by running the script.
* :class:`TestTheGateIsAToplevelConjunct`: ``conda-tag`` and ``conda-dist``
  each read ``PCAPKIT_DEV_RELEASE`` exactly once, as a top-level ``&&``
  conjunct (``conda-dist``'s inside its publishing branch only, so a
  build-only run still builds and smoke-tests a dev version).
* :class:`TestTheGateBlocksPublishing`: :func:`tests.project.test_release_gates
  .job_runs` on dev-release rows built on top of
  :func:`tests.project.test_release_gates.conda_context`: tagging and
  uploading are blocked on the schedule and on a ``workflow_run``, a
  build-only manual run still builds, and the gate costs a run nothing when
  the output is absent (an older run's shape, served as ``null``).

"""

from __future__ import annotations

import os
import pathlib
import re
import shutil
import subprocess  # nosec: B404
import tempfile
import unittest

from tests import _workflows
from tests._support import bash_argv
from tests.project.test_release_gates import (NULL, UnsupportedExpression, conda_context, declared_if,
                                              evaluate_condition, job_blocks, job_runs, resolved_context,
                                              with_condition)

#: Test tier (#1958): reads the workflow file, and runs one step's shell offline.
__tier__ = 'LATEST'

CONDA = 'cron-conda.yml'
#: The ``bash`` the step runs under, by absolute path (#2103).
BASH = shutil.which('bash')
#: The one ``&&`` conjunct both publishing jobs must carry, compact (no whitespace).
CONJUNCT = "needs.conda-update.outputs.PCAPKIT_DEV_RELEASE!='true'"


def _step(job_id: 'str', label: 'str') -> 'dict[str, object]':
    [found] = [entry for entry in _workflows.steps(CONDA, job_id)
              if label in (entry.get('name'), entry.get('id'))]
    return found  # type: ignore[return-value]


def dev_context(dev_release: 'object', **kwargs: 'object') -> 'dict[str, object]':
    """:func:`tests.project.test_release_gates.conda_context`, with ``conda-update``'s
    ``Get Version`` step handed ``PCAPKIT_DEV_RELEASE`` as ``dev_release``.

    :data:`tests.project.test_release_gates.NULL` reproduces an older run's shape,
    which published no such output at all; left out of :func:`conda_context` itself
    rather than added as a parameter there, since nothing else in this module's
    sibling tests needs it.

    """
    context = conda_context(**kwargs)  # type: ignore[arg-type]
    steps = context['needs']['conda-update']['steps']  # type: ignore[index]
    assert isinstance(steps, dict)
    if dev_release is NULL:
        steps['get_version']['outputs'].pop('PCAPKIT_DEV_RELEASE', None)  # type: ignore[index]
    else:
        steps['get_version']['outputs']['PCAPKIT_DEV_RELEASE'] = dev_release  # type: ignore[index]
    return context


class TestGetVersionComputesDevRelease(unittest.TestCase):
    """The ``Get Version`` step in ``conda-update``, and what it hands downstream."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.step = _step('conda-update', 'Get Version')

    def test_the_script_reads_is_devrelease_not_is_prerelease(self) -> None:
        script = self.step['run']
        assert isinstance(script, str)
        self.assertIn('PCAPKIT_DEV_RELEASE=$(python -c ', script)
        dev_release_line = next(line for line in script.splitlines()
                                if 'PCAPKIT_DEV_RELEASE=$(python -c' in line)
        self.assertIn('Version(pcapkit.__version__).is_devrelease', dev_release_line)
        # PCAPKIT_CONDA_LABEL (pre-existing) legitimately reads is_prerelease a
        # few lines away; this narrows to the one line that must not.
        self.assertNotIn('is_prerelease', dev_release_line)

    def test_conda_update_declares_the_output(self) -> None:
        outputs = _workflows.job(CONDA, 'conda-update')['outputs']
        assert isinstance(outputs, dict)
        self.assertEqual(outputs.get('PCAPKIT_DEV_RELEASE'),
                         '${{ steps.get_version.outputs.PCAPKIT_DEV_RELEASE }}')

    def test_the_step_runs_whenever_a_bump_or_a_build_only_run_needs_the_version(self) -> None:
        """Same gate as ``PCAPKIT_VERSION`` and ``PCAPKIT_CONDA_LABEL``, which
        ``conda-tag``/``conda-dist`` already depend on this step for.

        """
        self.assertEqual(self.step['if'],
                         "steps.bump.outputs.bump == 'true' || needs.mode.outputs.publishes != 'true'")

    @unittest.skipIf(not BASH, 'needs bash on PATH')
    def test_running_the_script_disagrees_with_is_prerelease_on_a_real_release(self) -> None:
        """The semantic reason ``is_prerelease`` is wrong here, run rather than asserted.

        ``1.5.0b14`` is a real, deliberately-tagged beta this project has
        shipped (see the module docstring): ``is_prerelease`` is ``true`` for
        it, ``is_devrelease`` is not. A dev build in progress
        (``1.6.0.dev3``) is the opposite: both outputs the script writes
        today agree it is a dev build, but ``PCAPKIT_DEV_RELEASE`` is the one
        a mutation back to ``is_prerelease`` would flip silently on the beta.

        """
        for version, label, dev_release in (
            ('1.5.0b14', 'dev', 'false'),  # is_prerelease: true, is_devrelease: false
            ('1.6.0.dev3', 'dev', 'true'),  # both true
            ('1.6.0', 'main', 'false'),  # both false
            # A dev build that also carries a `pre` segment: closes a mutation
            # that would narrow the script's predicate to
            # `is_devrelease and Version(v).pre is None`, which would read
            # false here although this is still a dev release.
            ('1.6.0rc1.dev2', 'dev', 'true'),
            # A dev build that also carries a `post` segment: closes a
            # mutation that would narrow the predicate to
            # `is_devrelease and not is_postrelease`, which would read false
            # here for the same reason.
            ('1.6.0.post1.dev0', 'dev', 'true'),
        ):
            with self.subTest(version=version):
                outputs = self._run(version)
                self.assertEqual(outputs['PCAPKIT_CONDA_LABEL'], label)
                self.assertEqual(outputs['PCAPKIT_DEV_RELEASE'], dev_release)

    def _run(self, version: 'str') -> 'dict[str, str]':
        """The step's script, against a scratch ``pcapkit`` stub reporting ``version``."""
        with tempfile.TemporaryDirectory(prefix='pcapkit-2458-get-version-') as tmp:
            root = pathlib.Path(tmp)
            (root / 'pcapkit.py').write_text(f'__version__ = {version!r}\n', encoding='utf-8')
            (root / 'conda').mkdir()
            (root / 'conda' / 'build').write_text('7\n', encoding='utf-8')
            output = root / 'output'
            output.write_text('', encoding='utf-8')
            env = {'PATH': os.environ.get('PATH', ''), 'PYTHONPATH': str(root),
                  'GITHUB_OUTPUT': str(output)}
            script = self.step['run']
            assert isinstance(script, str)
            result = subprocess.run(  # nosec: B603
                bash_argv('-e', '-c', script, executable=str(BASH)),
                cwd=root, env=env, capture_output=True, text=True, check=False, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            lines = dict(line.split('=', 1) for line in output.read_text(encoding='utf-8').splitlines() if line)
            return lines


class TestTheGateIsAToplevelConjunct(unittest.TestCase):
    """The text layer: both publishing jobs read the new output exactly once,
    and reversing or dropping the comparison is what the regex has to notice.

    """

    def test_conda_tag_reads_it_as_a_toplevel_and(self) -> None:
        condition = _workflows.job(CONDA, 'conda-tag')['if']
        assert isinstance(condition, str)
        compact = re.sub(r'\s+', '', condition)
        self.assertIn(f'&&{CONJUNCT}', compact,
                      '`conda-tag` does not gate on PCAPKIT_DEV_RELEASE as a top-level '
                      '`&&` conjunct')
        self.assertTrue(compact.endswith(CONJUNCT), compact)
        self.assertEqual(compact.count('PCAPKIT_DEV_RELEASE'), 1)

    def test_conda_dist_reads_it_inside_the_publishing_branch_only(self) -> None:
        condition = _workflows.job(CONDA, 'conda-dist')['if']
        assert isinstance(condition, str)
        compact = re.sub(r'\s+', '', condition)
        escape = "&&(needs.mode.outputs.publishes!='true'||("
        self.assertEqual(compact.count(escape), 1, compact)
        self.assertTrue(compact.endswith('))'), compact)
        inner = compact.replace(escape, '', 1)[:-2]
        self.assertTrue(inner.endswith(f'&&{CONJUNCT}'), inner)
        self.assertEqual(compact.count('PCAPKIT_DEV_RELEASE'), 1)
        # Not a top-level conjunct of the whole expression -- a build-only run
        # (the `publishes != 'true'` disjunct) must reach the build regardless
        # of the version.
        self.assertFalse(compact.startswith(f'{CONJUNCT}&&'))

    def test_every_declared_if_is_evaluable(self) -> None:
        """The same bar :mod:`tests.project.test_release_gates` holds every
        condition in this file to -- :func:`tests.project.test_release_gates
        .evaluate_condition` implements a fixed subset, and
        ``test_every_declared_if_is_evaluable`` there already covers every job
        in ``cron-conda.yml``, this module's two included. Re-stated here so a
        failure names this module rather than only the shared one.

        """
        text = (_workflows.WORKFLOWS / CONDA).read_text(encoding='utf-8')
        jobs = job_blocks(text, _workflows.WORKFLOWS / CONDA)
        for name in ('conda-tag', 'conda-dist'):
            condition = declared_if(jobs[name])
            with self.subTest(job=name):
                try:
                    evaluate_condition(condition, resolved_context(jobs, conda_context()))
                except UnsupportedExpression as error:
                    self.fail(f'`{name}`\'s `if:` is outside the evaluated subset: {error}')


class TestTheGateBlocksPublishing(unittest.TestCase):
    """:func:`tests.project.test_release_gates.job_runs`, on dev-release rows
    built on top of :func:`tests.project.test_release_gates.conda_context`.

    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.jobs = job_blocks((_workflows.WORKFLOWS / CONDA).read_text(encoding='utf-8'),
                              _workflows.WORKFLOWS / CONDA)

    def test_a_dev_release_bump_is_neither_tagged_nor_uploaded(self) -> None:
        """The run 38325136710 shape (:func:`conda_context`'s defaults), but for a
        dev-release version: without the gate this is exactly #1632's chain, which
        :mod:`tests.project.test_release_gates`'s
        ``test_a_committed_bump_is_tagged_and_uploaded`` pins the other way.

        """
        context = dev_context('true')
        self.assertTrue(job_runs(self.jobs, 'conda-update', context))
        for job in ('conda-tag', 'conda-dist'):
            with self.subTest(job=job):
                self.assertFalse(
                    job_runs(self.jobs, job, context),
                    f'`{job}` runs for a dev-release bump, so it would be tagged or '
                    f'uploaded with no human in the path (#2458)')

    def test_a_dev_release_bump_on_the_schedule_is_also_blocked(self) -> None:
        context = dev_context('true', event_name='schedule', unit_tests='success', verdict='skipped',
                              verified=NULL)
        self.assertTrue(job_runs(self.jobs, 'conda-update', context))
        for job in ('conda-tag', 'conda-dist'):
            with self.subTest(job=job):
                self.assertFalse(job_runs(self.jobs, job, context))

    def test_a_non_dev_bump_still_publishes(self) -> None:
        """The gate costs a real release nothing: the bare row, with the output
        explicitly ``'false'`` rather than merely absent.

        """
        context = dev_context('false')
        for job in ('conda-update', 'conda-tag', 'conda-dist'):
            with self.subTest(job=job):
                self.assertTrue(job_runs(self.jobs, job, context))

    def test_an_older_run_with_no_such_output_still_publishes(self) -> None:
        """#2458 is additive: a row shaped like one from before this change existed
        -- ``conda-update`` published no ``PCAPKIT_DEV_RELEASE`` at all, served as
        ``null`` -- must not newly block a bump that was never a dev release.

        """
        context = dev_context(NULL)
        for job in ('conda-tag', 'conda-dist'):
            with self.subTest(job=job):
                self.assertTrue(job_runs(self.jobs, job, context))

    def test_a_build_only_dev_release_run_still_builds(self) -> None:
        """A manual run without ``publish`` builds whatever ``conda-update`` left,
        tags nothing, and must keep doing so for a dev-release version: there is
        nothing to tag or upload on this path regardless, and blocking the build
        would also lose the smoke test.

        """
        context = dev_context('true', event_name='workflow_dispatch', unit_tests='success',
                              verdict='skipped', verified=NULL, files_changed='false', pushed=NULL,
                              conda_tag='skipped')
        self.assertTrue(job_runs(self.jobs, 'conda-update', context))
        self.assertFalse(job_runs(self.jobs, 'conda-tag', context))
        self.assertTrue(
            job_runs(self.jobs, 'conda-dist', context),
            '`conda-dist` does not build a dev-release version on a build-only '
            'manual run, which uploads nothing regardless of the version')

    def test_removing_the_conjunct_reproduces_the_defect(self) -> None:
        """The headline tests above have to be able to fail: with the clause
        stripped from both jobs' ``if:``, a dev-release bump is tagged and
        uploaded again.

        """
        jobs = dict(self.jobs)
        for name in ('conda-tag', 'conda-dist'):
            condition = declared_if(jobs[name])
            mutant = re.sub(r"\s*&&\s*needs\.conda-update\.outputs\.PCAPKIT_DEV_RELEASE\s*!=\s*'true'",
                            '', condition)
            self.assertNotEqual(mutant, condition,
                                f'the mutation did not remove the clause from `{name}`, so this '
                                f'test proves nothing')
            self.assertNotIn('PCAPKIT_DEV_RELEASE', mutant,
                             f'the mutation did not remove the clause from `{name}`, so this '
                             f'test proves nothing')
            jobs[name] = with_condition(jobs[name], mutant)
        context = dev_context('true')
        for job in ('conda-tag', 'conda-dist'):
            with self.subTest(job=job):
                self.assertTrue(
                    job_runs(jobs, job, context),
                    f'`{job}` still skips with the PCAPKIT_DEV_RELEASE clause removed, so '
                    f'this test would not have caught #2458 being reverted')


if __name__ == '__main__':
    unittest.main()
