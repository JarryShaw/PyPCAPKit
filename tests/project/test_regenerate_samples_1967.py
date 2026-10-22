# -*- coding: utf-8 -*-
"""#1967: :file:`util/regenerate_samples.py`, the ``Regenerate sample captures`` step, run as the step runs it.

* :class:`TestRegenerateSamples` runs the script against a stand-in generator: a
  clean run, a run on stand-in captures, a failed run at either level, and a bad
  level.
* :class:`TestTheFormerShellAgrees` runs the shell the steps held before the
  script against the same stand-ins and requires the same output, log and status.
* :class:`TestTheStepsRunTheScript` pins the step in the ``integration``,
  ``pypcap-parity`` and ``gate`` jobs to the script, and keeps the old inline
  shell out of every workflow.

"""

from __future__ import annotations

import os
import pathlib
import shutil
import subprocess  # nosec: B404
import sys
import tempfile
import textwrap
import unittest

from tests._workflows import WORKFLOWS, job, load, steps

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'util' / 'regenerate_samples.py'
STEP = 'Regenerate sample captures'
RUN = 'python util/regenerate_samples.py'
#: The jobs whose step runs the script, and the level each takes from where.
LEVELLED_JOBS = ('integration', 'pypcap-parity')
GATE = 'gate'
#: Text only the old inline step held, which no workflow may hold now.
INLINE = ('make_samples.py', 'make-samples.log', '(download unavailable)', 'Sample fixture generation failed')

FAILED = ('title=Sample fixture generation failed::examples/generators/make_samples.py could not rebuild '
          'examples/captures/. This is a fixture-generation failure, not a test failure -- the test suite '
          'has not run.')
DEGRADED = ('::warning title=Sample fixtures degraded::The upstream Wireshark captures were unreachable, so '
            'synthesised stand-ins were used. The PCAP-NG tier ran, but not against the upstream bytes.')
UPSTREAM = 'Upstream Wireshark captures were used, matching their pinned SHA-256 digests.'

#: A stand-in generator: its output alternates streams, flushed, so the merged order is fixed.
GENERATOR = textwrap.dedent('''\
    import pathlib, sys
    pathlib.Path('ran').write_text('yes')
    for stream, text in {lines!r}:
        (sys.stderr if stream == 'err' else sys.stdout).write(text + '\\n')
        (sys.stderr if stream == 'err' else sys.stdout).flush()
    sys.exit({status})
''')
CLEAN = (('out', 'wrote examples/captures/a.pcap'), ('err', 'a warning on stderr'),
         ('out', 'wrote examples/captures/b.pcapng (upstream)'))
DEGRADED_RUN = (('out', 'wrote examples/captures/a.pcap'),
                ('out', 'test.pcapng: synthesised (download unavailable)'),
                ('err', 'urlopen failed'),
                ('out', 'other.pcapng: synthesised (download unavailable)'))

#: The ``run:`` the ``integration`` and ``pypcap-parity`` steps held before the
#: script; ``gate``'s differed only in a literal ``error`` for ``${ANNOTATION_LEVEL}``.
FORMER_SHELL = textwrap.dedent('''\
    if ! python examples/generators/make_samples.py 2>&1 | tee "$RUNNER_TEMP/make-samples.log"; then
      echo "::${ANNOTATION_LEVEL} title=Sample fixture generation failed::examples/generators/make_samples.py could not rebuild examples/captures/. This is a fixture-generation failure, not a test failure -- the test suite has not run."
      exit 1
    fi

    if grep -q '(download unavailable)' "$RUNNER_TEMP/make-samples.log"; then
      echo "::warning title=Sample fixtures degraded::The upstream Wireshark captures were unreachable, so synthesised stand-ins were used. The PCAP-NG tier ran, but not against the upstream bytes."
      grep '(download unavailable)' "$RUNNER_TEMP/make-samples.log"
    else
      echo "Upstream Wireshark captures were used, matching their pinned SHA-256 digests."
    fi
''')  # noqa: E501


def merged(lines: 'tuple[tuple[str, str], ...]') -> 'str':
    """The generator's standard output and error, merged as ``2>&1`` merges them."""
    return ''.join(text + '\n' for _, text in lines)


class _Scratch(unittest.TestCase):
    """A scratch checkout root holding a stand-in generator, and a ``RUNNER_TEMP``."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-1967-samples-')  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.tmp = pathlib.Path(tmp.name)
        (self.tmp / 'examples' / 'generators').mkdir(parents=True)
        self.runner_temp = self.tmp / 'runner-temp'
        self.runner_temp.mkdir()
        self.log = self.runner_temp / 'make-samples.log'

    def generator(self, lines: 'tuple[tuple[str, str], ...]', status: 'int' = 0) -> 'None':
        (self.tmp / 'examples' / 'generators' / 'make_samples.py').write_text(
            GENERATOR.format(lines=lines, status=status), encoding='utf-8')

    def env(self, level: 'str') -> 'dict[str, str]':
        env = {key: value for key, value in os.environ.items() if key not in ('ANNOTATION_LEVEL', 'RUNNER_TEMP')}
        env.update(ANNOTATION_LEVEL=level, RUNNER_TEMP=str(self.runner_temp), PYTHONIOENCODING='utf-8')
        return env

    def script(self, level: 'str' = 'error') -> 'subprocess.CompletedProcess[str]':
        """``python util/regenerate_samples.py`` from the scratch root, as the step runs it."""
        return subprocess.run([sys.executable, str(SCRIPT)], cwd=self.tmp, env=self.env(level),  # nosec: B603
                              capture_output=True, text=True, check=False, timeout=120)


class TestRegenerateSamples(_Scratch):
    """The generator's output on standard output and in the log, then one verdict."""

    def test_a_clean_run_says_upstream_was_used(self) -> None:
        self.generator(CLEAN)
        result = self.script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, merged(CLEAN) + UPSTREAM + '\n')
        self.assertEqual(self.log.read_text(encoding='utf-8'), merged(CLEAN))

    def test_a_run_on_stand_ins_warns_and_lists_them(self) -> None:
        self.generator(DEGRADED_RUN)
        result = self.script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, merged(DEGRADED_RUN) + DEGRADED + '\n'
                         'test.pcapng: synthesised (download unavailable)\n'
                         'other.pcapng: synthesised (download unavailable)\n')
        self.assertEqual(self.log.read_text(encoding='utf-8'), merged(DEGRADED_RUN))

    def test_a_failed_run_annotates_at_the_level_and_fails(self) -> None:
        """A failure ends the step before the degraded check, even with stand-ins in the output."""
        self.generator(DEGRADED_RUN, status=3)
        for level in ('error', 'warning'):
            with self.subTest(level=level):
                result = self.script(level)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(result.stdout, merged(DEGRADED_RUN) + f'::{level} {FAILED}\n')
                self.assertEqual(self.log.read_text(encoding='utf-8'), merged(DEGRADED_RUN))

    def test_a_ktlo_leg_writes_no_error(self) -> None:
        """At ``warning``, a KTLO leg's level, no outcome writes an ``::error``."""
        for lines, status in ((CLEAN, 0), (DEGRADED_RUN, 0), (CLEAN, 1)):
            with self.subTest(status=status, degraded=lines is DEGRADED_RUN):
                self.generator(lines, status)
                self.assertNotIn('::error', self.script('warning').stdout)

    def test_a_bad_level_fails_before_the_generator_runs(self) -> None:
        self.generator(CLEAN)
        for level in ('', 'notice', 'ERROR'):
            with self.subTest(level=level):
                result = self.script(level)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, '')
                self.assertIn('ANNOTATION_LEVEL', result.stderr)
                self.assertFalse((self.tmp / 'ran').exists())
                self.assertFalse(self.log.exists())

    def test_no_runner_temp_fails_the_step(self) -> None:
        self.generator(CLEAN)
        env = self.env('error')
        del env['RUNNER_TEMP']
        result = subprocess.run([sys.executable, str(SCRIPT)], cwd=self.tmp, env=env,  # nosec: B603
                                capture_output=True, text=True, check=False, timeout=120)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('RUNNER_TEMP', result.stderr)

    def test_it_takes_no_arguments(self) -> None:
        result = subprocess.run([sys.executable, str(SCRIPT), 'extra'], cwd=self.tmp,  # nosec: B603
                                env=self.env('error'), capture_output=True, text=True, check=False, timeout=120)
        self.assertEqual(result.returncode, 2)
        self.assertFalse((self.tmp / 'ran').exists())


@unittest.skipIf(shutil.which('bash') is None or shutil.which('tee') is None or shutil.which('grep') is None,
                 'needs bash, tee and grep')
class TestTheFormerShellAgrees(_Scratch):
    """The script prints, logs and exits as the steps' former shell did, under ``shell: bash``."""

    def former(self, level: 'str') -> 'subprocess.CompletedProcess[str]':
        # `python` is the leg's interpreter on the runner; here, this one's.
        bin_dir = self.tmp / 'bin'
        bin_dir.mkdir(exist_ok=True)
        python = bin_dir / 'python'
        if not python.exists():
            python.symlink_to(sys.executable)
        env = self.env(level)
        env['PATH'] = f'{bin_dir}{os.pathsep}{env.get("PATH", "")}'
        return subprocess.run(['bash', '--noprofile', '--norc', '-eo', 'pipefail', '-c', FORMER_SHELL],  # nosec
                              cwd=self.tmp, env=env, capture_output=True, text=True, check=False, timeout=120)

    def test_every_outcome_matches(self) -> None:
        for lines, status, level in ((CLEAN, 0, 'error'), (DEGRADED_RUN, 0, 'error'),
                                     (DEGRADED_RUN, 3, 'error'), (CLEAN, 1, 'warning')):
            with self.subTest(status=status, level=level, degraded=lines is DEGRADED_RUN):
                self.generator(lines, status)
                old = self.former(level)
                old_log = self.log.read_text(encoding='utf-8')
                self.log.unlink()
                new = self.script(level)
                self.assertEqual((new.returncode, new.stdout), (old.returncode, old.stdout))
                self.assertEqual(self.log.read_text(encoding='utf-8'), old_log)


class TestTheStepsRunTheScript(unittest.TestCase):
    """Each job's ``Regenerate sample captures`` is one call of the script."""

    def step(self, job_id: 'str') -> 'dict[str, object]':
        found = [step for step in steps('unit-tests.yml', job_id) if step.get('name') == STEP]
        self.assertEqual(len(found), 1, job_id)
        return found[0]

    def test_each_job_runs_the_script(self) -> None:
        for job_id in (*LEVELLED_JOBS, GATE):
            with self.subTest(job=job_id):
                step = self.step(job_id)
                self.assertEqual(step['run'], RUN)
                self.assertEqual(step['shell'], 'bash')

    def test_the_levelled_jobs_keep_their_guards_and_level(self) -> None:
        for job_id in LEVELLED_JOBS:
            with self.subTest(job=job_id):
                step = self.step(job_id)
                self.assertEqual(step['id'], 'samples')
                self.assertEqual(step['if'], "${{ steps.install.outcome == 'success' }}")
                self.assertEqual(step['continue-on-error'], '${{ matrix.ktlo == true }}')
                self.assertNotIn('env', step)
                self.assertEqual(job('unit-tests.yml', job_id)['env']['ANNOTATION_LEVEL'],
                                 "${{ matrix.ktlo && 'warning' || 'error' }}")

    def test_gate_keeps_its_error_level(self) -> None:
        step = self.step(GATE)
        self.assertEqual(step['env'], {'ANNOTATION_LEVEL': 'error'})
        self.assertNotIn('ANNOTATION_LEVEL', job('unit-tests.yml', GATE).get('env') or {})
        self.assertFalse({'id', 'if', 'continue-on-error'} & set(step))

    def test_no_workflow_keeps_the_inline_shell(self) -> None:
        found = []
        for path in sorted(WORKFLOWS.glob('*.yml')):
            for job_id, body in load(path).get('jobs', {}).items():
                for step in body.get('steps', []):
                    found.extend(f'{path.name} {job_id} {step.get("name")!r}: {text}'
                                 for text in INLINE if text in step.get('run', ''))
        self.assertEqual(found, [])


if __name__ == '__main__':
    unittest.main()
