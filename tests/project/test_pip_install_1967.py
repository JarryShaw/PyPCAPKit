# -*- coding: utf-8 -*-
"""#1967: :file:`util/pip_install.py`, the install step of most test jobs, run as the steps run it.

* :class:`TestPipInstall` runs the script against a stand-in ``pip``: a clean
  install, a failed one with and without an ``ERROR:`` line, a failed upgrade,
  and the arguments and levels it refuses.
* :class:`TestTheStepMatchesTheReferenceShell` runs the steps' inline shell form,
  :data:`REFERENCE_ANNOTATED` and :data:`REFERENCE_BARE`, the reference the script
  must match, against the same stand-in and requires the same output, log and
  status;
  for the steps whose shell wrote no annotation, the same except for the
  annotation the script writes for a failed install; and for an indented
  ``ERROR:`` line, the same except for the reason the shell missed (#2041).
* :class:`TestTheStepsRunTheScript` pins each covered step to the script, with
  its guards and environment, and every other ``pip install`` in
  ``unit-tests.yml`` to a listed step that keeps its shell.
* :class:`TestTheOtherWorkflowsRunTheScript` does the same for the install of
  ``experimental.yml``'s ``experimental`` and ``windows`` (#2060) and
  ``python-compatibility.yml``'s ``compatibility``.

"""

from __future__ import annotations

import json
import os
import pathlib
import re
import shutil
import signal
import subprocess  # nosec: B404
import sys
import tempfile
import textwrap
import unittest

from tests._dependency_gates import EDITABLE_INSTALL
from tests._support import bash_argv
from tests._workflows import WORKFLOWS, job, load, steps

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'util' / 'pip_install.py'
WORKFLOW = WORKFLOWS / 'unit-tests.yml'
LOG = 'pip-install.log'
SPEC = '.[test,DPKT]'

#: A leg's name holding a comma, which the title must escape, and a ``%``, which it must not.
LEG = 'Python 3.7 (KTLO, non-blocking) 100%'
TITLE = 'pcapkit did not install on Python 3.7 (KTLO%2C non-blocking) 100%'
SKIPPED = '. The rest of this leg is skipped.'
NO_REASON = "pip failed without an ERROR line; see this step's log"

#: The KTLO-capable sites' ``LEG``, and their jobs' ``ANNOTATION_LEVEL``.
MATRIX_LEG = "Python ${{ matrix.python-version }}${{ matrix.ktlo && ' (KTLO, non-blocking)' || '' }}"
MATRIX_LEVEL = "${{ matrix.ktlo && 'warning' || 'error' }}"
#: Each covered step, as ``(job, step name)``, and the extras it installs.
MATRIX_SITES = {
    ('test', 'Install package and test dependencies'): 'test,DPKT,crypto,NGAP',
    ('integration', 'Install package, test and generator dependencies'): 'test,Scapy,DPKT,cli',
    ('pypcap-parity', 'Install package, test and generator dependencies'):
        'test,Scapy,DPKT,cli,PyShark,PyPCAP,PyPCAPFile',
}
#: The jobs on ``latest`` alone, which have no KTLO leg; each step sets ``error``.
LATEST_SITES = {
    ('unittest-ordering', 'Install package and test dependencies'): 'test,DPKT,crypto,NGAP',
    ('project-tests', 'Install package and test dependencies'): 'test,Scapy,DPKT,crypto,cli,NGAP,vendor,docs,PyShark',
    ('gate', 'Install package, test and generator dependencies'): 'test,Scapy,DPKT,crypto,cli,NGAP,vendor,docs,PyShark',
}
#: The ``pip install`` steps that keep their shell: the ``latest`` leg's addition, which
#: upgrades nothing and annotates nothing, coverage, which is not the package, and
#: ``engine-tests``' cells, whose installs run in a venv and may fail by design.
LEFT_INLINE = frozenset({
    ('test', "Install the whole suite's dependencies on latest"),
    ('integration', "Install the whole suite's dependencies on latest"),
    ('test', 'Install coverage'),
    ('engine-tests', 'Write the per-cell script'),
})
#: The KTLO jobs, which run their twin's steps by alias (#1738).
TWINS = {'test-ktlo': 'test', 'integration-ktlo': 'integration', 'pypcap-parity-ktlo': 'pypcap-parity'}
#: Text only the inline install holds.
INLINE = ('pip-install.log', 'did not install on', "s/^ERROR: //p")
#: The covered steps outside ``unit-tests.yml``, as ``(workflow, job)``, each step whole,
#: and its job's ``ANNOTATION_LEVEL``. The experimental legs are never blocking, so
#: always ``warning``; Compat's KTLO legs take ``warning`` as ``test``'s do. Compat
#: installs no extra, and its step keeps the default shell.
ELSEWHERE = {
    ('experimental.yml', 'experimental'): ({
        'name': 'Install package and test dependencies',
        'id': 'install',
        'if': "${{ steps.python.outcome == 'success' }}",
        'continue-on-error': True,
        'timeout-minutes': 10,
        'shell': 'bash',
        'env': {'LEG': 'Python ${{ matrix.python-version }} (experimental, non-blocking)'},
        'run': "python util/pip_install.py -e '.[test,DPKT,crypto,NGAP]'",
    }, 'warning'),
    # #2060: the Windows leg's, the same install on `latest`.
    ('experimental.yml', 'windows'): ({
        'name': 'Install package and test dependencies',
        'id': 'install',
        'if': "${{ steps.python.outcome == 'success' }}",
        'continue-on-error': True,
        'timeout-minutes': 10,
        'shell': 'bash',
        'env': {'LEG': 'Python ${{ needs.python-versions.outputs.latest }} on Windows (experimental, non-blocking)'},
        'run': "python util/pip_install.py -e '.[test,DPKT,crypto,NGAP]'",
    }, 'warning'),
    ('python-compatibility.yml', 'compatibility'): ({
        'name': 'Install package',
        'id': 'install',
        'if': "${{ steps.python.outcome == 'success' }}",
        'continue-on-error': '${{ matrix.ktlo == true }}',
        'env': {'LEG': MATRIX_LEG},
        'run': 'python util/pip_install.py -e .',
    }, MATRIX_LEVEL),
}
#: The other ``pip install`` steps of those workflows, which install ``requests`` for
#: util/superseded.py on an interpreter of their own, never the package.
ELSEWHERE_INLINE = frozenset({
    ('experimental.yml', 'current', 'Install requests'),
    ('experimental.yml', 'experimental', "Install the watcher's requests"),
})

#: A stand-in ``pip``: it appends its arguments to ``calls``, then does what
#: ``PIP_<STEP>`` says, ``STEP`` ``UPGRADE`` or ``INSTALL``: ``OUTPUT`` lines, each
#: ``out:`` or ``err:``, flushed in turn, then exit ``STATUS``, or a signal as ``-N``.
PIP = textwrap.dedent('''\
    import json, os, signal, sys
    with open('calls', 'a', encoding='utf-8') as calls:
        calls.write(json.dumps(sys.argv[1:]) + '\\n')
    step = 'UPGRADE' if sys.argv[1:3] == ['install', '-U'] else 'INSTALL'
    for line in json.loads(os.environ.get('PIP_' + step + '_OUTPUT', '[]')):
        stream = sys.stderr if line.startswith('err:') else sys.stdout
        stream.write(line[4:] + '\\n')
        stream.flush()
    status = int(os.environ.get('PIP_' + step + '_STATUS', '0'))
    if status < 0:
        os.kill(os.getpid(), -status)
    sys.exit(status)
''')

#: ``test``'s and ``integration``'s install in its inline shell form, under
#: ``shell: bash``, the reference the script must match; ``SPEC`` stands for each
#: job's extras.
REFERENCE_ANNOTATED = textwrap.dedent('''\
    python -m pip install -U pip setuptools wheel
    if ! python -m pip install -e 'SPEC' 2>&1 | tee "$RUNNER_TEMP/pip-install.log"; then
      reason=$(sed -n 's/^ERROR: //p' "$RUNNER_TEMP/pip-install.log" | tail -n 1)
      if [ -z "$reason" ]; then reason="pip failed without an ERROR line; see this step's log"; fi
      echo "::${ANNOTATION_LEVEL} title=pcapkit did not install on ${LEG//,/%2C}::${reason//%/%25}. The rest of this leg is skipped."
      exit 1
    fi
''').replace('SPEC', SPEC)  # noqa: E501
#: The other covered steps' install in its inline shell form, under the default shell.
REFERENCE_BARE = textwrap.dedent('''\
    python -m pip install -U pip setuptools wheel
    python -m pip install -e 'SPEC'
''').replace('SPEC', SPEC)

CLEAN = ['out:Obtaining file:///checkout', 'err:a deprecation warning', 'out:Successfully installed pypcapkit-1.5.0']
FAILED = ['out:Collecting pytest>=8', 'err:ERROR: Ignored the following versions: 8.0.0 Requires-Python >=3.8',
          'out:INFO: pip is looking at multiple versions', 'err:ERROR: No matching distribution found for pytest>=8']
#: The tail of a failed wheel build, as pip printed it on ``Python pypy3.10 (KTLO)``:
#: its one ``ERROR:`` line is indented, so the inline shell finds none (#2041).
WHEEL_FAILED = ['out:  note: This error originates from a subprocess, and is likely not a problem with pip.',
                'out:  ERROR: Failed building wheel for cryptography', 'out:Successfully built pypcapkit',
                'out:Failed to build cryptography', 'out:',
                'err:[notice] A new release of pip is available: 26.2.1 -> 26.2.2',
                'err:[notice] To update, run: pip install --upgrade pip',
                'err:error: failed-wheel-build-for-install', 'err:',
                'err:× Failed to build installable wheels for some pyproject.toml based projects',
                'err:╰─> cryptography']
#: Every ``(install output, install status)`` an install step can meet.
OUTCOMES = (
    (CLEAN, 0),
    (FAILED, 1),
    (['out:Killed'], 137),
    (['err:ERROR: 100% of the index timed out'], 2),
    (['err:ERROR: the first reason', 'err:ERROR: '], 1),
    (['out:ERROR:no space after the colon'], 1),
    (FAILED, -signal.SIGTERM),
)


def text(lines: 'list[str]') -> 'str':
    """What the stand-in writes for ``lines``, its two streams merged."""
    return ''.join(line[4:] + '\n' for line in lines)


class _Scratch(unittest.TestCase):
    """A scratch checkout root, a stand-in ``pip`` on ``PYTHONPATH`` and a ``RUNNER_TEMP``."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-1967-pip-')  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.tmp = pathlib.Path(tmp.name)
        (self.tmp / 'stub' / 'pip').mkdir(parents=True)
        (self.tmp / 'stub' / 'pip' / '__init__.py').write_text('', encoding='utf-8')
        (self.tmp / 'stub' / 'pip' / '__main__.py').write_text(PIP, encoding='utf-8')
        self.runner_temp = self.tmp / 'runner-temp'
        self.runner_temp.mkdir()
        self.log = self.runner_temp / LOG

    def env(self, level: 'str' = 'warning', **pip: 'object') -> 'dict[str, str]':
        env = {key: value for key, value in os.environ.items()
               if key not in ('ANNOTATION_LEVEL', 'LEG', 'RUNNER_TEMP', 'PYTHONPATH', 'PYTHONSAFEPATH')
               and not key.startswith('PIP_')}
        env.update(ANNOTATION_LEVEL=level, LEG=LEG, RUNNER_TEMP=str(self.runner_temp),
                   PYTHONPATH=str(self.tmp / 'stub'), PYTHONIOENCODING='utf-8')
        for key, value in pip.items():
            env[f'PIP_{key.upper()}'] = json.dumps(value) if isinstance(value, list) else str(value)
        return env

    def calls(self) -> 'list[list[str]]':
        path = self.tmp / 'calls'
        if not path.exists():
            return []
        calls = [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines()]
        path.unlink()
        return calls

    def script(self, *args: 'str', env: 'dict[str, str]') -> 'subprocess.CompletedProcess[str]':
        """``python util/pip_install.py ARGS`` from the scratch root, as the step runs it."""
        return subprocess.run([sys.executable, str(SCRIPT), *args], cwd=self.tmp, env=env,  # nosec: B603
                              capture_output=True, text=True, check=False, timeout=120)


class TestPipInstall(_Scratch):
    """The upgrade, then the install on standard output and in the log, then one verdict."""

    def test_a_clean_install_writes_no_annotation(self) -> None:
        result = self.script('-e', SPEC, env=self.env(install_output=CLEAN, upgrade_output=['out:upgraded']))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'upgraded\n' + text(CLEAN))
        self.assertEqual(self.log.read_text(encoding='utf-8'), text(CLEAN))
        self.assertEqual(self.calls(), [['install', '-U', 'pip', 'setuptools', 'wheel'], ['install', '-e', SPEC]])

    def test_a_failed_install_names_pips_last_error_at_the_level(self) -> None:
        for level in ('error', 'warning'):
            with self.subTest(level=level):
                result = self.script('-e', SPEC, env=self.env(level, install_output=FAILED, install_status=1))
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(result.stdout, text(FAILED) + f'::{level} title={TITLE}::No matching '
                                 f'distribution found for pytest>=8{SKIPPED}\n')
                self.assertEqual(self.log.read_text(encoding='utf-8'), text(FAILED))

    def test_a_failure_without_a_reason_is_still_named(self) -> None:
        """No ``ERROR:`` line, or an empty last one, falls back; a ``%`` in the reason is escaped."""
        for output, reason in ((['out:Killed'], NO_REASON), (['err:ERROR: first', 'err:ERROR: '], NO_REASON),
                               (['err:ERROR: 100% of the index timed out'], '100%25 of the index timed out')):
            with self.subTest(output=output):
                result = self.script('-e', SPEC, env=self.env(install_output=output, install_status=1))
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertTrue(result.stdout.endswith(f'::warning title={TITLE}::{reason}{SKIPPED}\n'),
                                result.stdout)

    def test_an_indented_error_line_is_the_reason(self) -> None:
        """Pip indents a failed wheel build's ``ERROR:`` line; the reason drops the indent and the prefix (#2041)."""
        result = self.script('-e', SPEC, env=self.env(install_output=WHEEL_FAILED, install_status=1))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stdout, text(WHEEL_FAILED) + f'::warning title={TITLE}::Failed building wheel '
                         f'for cryptography{SKIPPED}\n')
        for output, reason in ((['out:\tERROR: a tab', 'out:  INFO: later'], 'a tab'),
                               (['err:ERROR: first', 'out:    ERROR: last'], 'last'),
                               (['out:ERROR: first', 'out:  ERROR: '], NO_REASON)):
            with self.subTest(output=output):
                result = self.script('-e', SPEC, env=self.env(install_output=output, install_status=1))
                self.assertTrue(result.stdout.endswith(f'::warning title={TITLE}::{reason}{SKIPPED}\n'),
                                result.stdout)

    def test_a_signal_is_a_failed_install(self) -> None:
        result = self.script('-e', SPEC, env=self.env(install_output=FAILED, install_status=-signal.SIGTERM))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(len([line for line in result.stdout.splitlines() if line.startswith('::')]), 1)

    def test_a_failed_upgrade_ends_with_pips_status_and_no_annotation(self) -> None:
        for status, expected in ((3, 3), (-signal.SIGTERM, 128 + signal.SIGTERM)):
            with self.subTest(status=status):
                result = self.script('-e', SPEC, env=self.env(upgrade_output=['err:no index'], upgrade_status=status))
                self.assertEqual(result.returncode, expected, result.stderr)
                self.assertEqual(result.stdout, '')
                self.assertEqual(result.stderr, 'no index\n')
                self.assertFalse(self.log.exists())
                self.assertEqual(self.calls(), [['install', '-U', 'pip', 'setuptools', 'wheel']])

    def test_a_bad_level_fails_before_pip_runs(self) -> None:
        for level in ('', 'notice', 'ERROR'):
            with self.subTest(level=level):
                result = self.script('-e', SPEC, env=self.env(level))
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, '')
                self.assertIn('ANNOTATION_LEVEL', result.stderr)
                self.assertEqual(self.calls(), [])

    def test_it_takes_one_editable_spec_and_nothing_else(self) -> None:
        for args in ((), ('-e',), (SPEC,), ('-e', SPEC, 'extra'), ('-r', 'requirements.txt')):
            with self.subTest(args=args):
                result = self.script(*args, env=self.env())
                self.assertEqual(result.returncode, 2)
                self.assertEqual(self.calls(), [])

    def test_a_missing_variable_fails_before_pip_runs(self) -> None:
        for name in ('ANNOTATION_LEVEL', 'LEG', 'RUNNER_TEMP'):
            with self.subTest(variable=name):
                env = self.env()
                del env[name]
                result = self.script('-e', SPEC, env=env)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(name, result.stderr)
                self.assertEqual(self.calls(), [])


@unittest.skipIf(any(shutil.which(tool) is None for tool in ('bash', 'tee', 'sed', 'tail')),
                 'needs bash, tee, sed and tail')
class TestTheStepMatchesTheReferenceShell(_Scratch):
    """The script prints, logs and exits as the steps' inline shell form does."""

    def reference(self, shell: 'str', env: 'dict[str, str]') -> 'subprocess.CompletedProcess[str]':
        """``shell`` as a step runs it: ``shell: bash`` for the annotated steps, ``bash -e`` for the rest."""
        bin_dir = self.tmp / 'bin'
        bin_dir.mkdir(exist_ok=True)
        python = bin_dir / 'python'
        if not python.exists():
            python.symlink_to(sys.executable)  # the leg's `python`; here, this interpreter
        env = dict(env, PATH=f'{bin_dir}{os.pathsep}{env.get("PATH", "")}')
        command = (bash_argv('-eo', 'pipefail', '-c', shell) if shell is REFERENCE_ANNOTATED
                   else bash_argv('-e', '-c', shell))
        return subprocess.run(command, cwd=self.tmp, env=env,  # nosec: B603
                              capture_output=True, text=True, check=False, timeout=120)

    def both(self, shell: 'str', level: 'str', **pip: 'object') -> 'tuple[tuple[object, ...], tuple[object, ...]]':
        """``(status, stdout, log, pip's calls)`` of the inline shell, then of the script, each with its stderr."""
        found = []
        for run in (lambda env: self.reference(shell, env), lambda env: self.script('-e', SPEC, env=env)):
            result = run(self.env(level, **pip))
            log = self.log.read_text(encoding='utf-8') if self.log.exists() else None
            if self.log.exists():
                self.log.unlink()
            found.append(((result.returncode, result.stdout, log, self.calls()), result.stderr))
        return found[0], found[1]

    def test_every_annotated_outcome_matches(self) -> None:
        for output, status in OUTCOMES:
            for level in ('error', 'warning'):
                with self.subTest(output=output, status=status, level=level):
                    (old, _), (new, _) = self.both(REFERENCE_ANNOTATED, level, install_output=output,
                                                   install_status=status)
                    self.assertEqual(new, old)

    def test_an_indented_error_line_departs_on_purpose(self) -> None:
        """The inline shell's ``^ERROR: `` misses an indented line and falls back; the script names it
        (#2041). Everything else still matches, and so does an outcome where both find the same line."""
        for level in ('error', 'warning'):
            with self.subTest(level=level):
                (old, _), (new, _) = self.both(REFERENCE_ANNOTATED, level, install_output=WHEEL_FAILED,
                                               install_status=1)
                self.assertEqual((new[0], new[2], new[3]), (old[0], old[2], old[3]))
                head = text(WHEEL_FAILED) + f'::{level} title={TITLE}::'
                self.assertEqual(old[1], f'{head}{NO_REASON}{SKIPPED}\n')
                self.assertEqual(new[1], f'{head}Failed building wheel for cryptography{SKIPPED}\n')

    def test_a_failed_upgrade_matches_on_both_forms(self) -> None:
        for shell in (REFERENCE_ANNOTATED, REFERENCE_BARE):
            for status in (1, 3, -signal.SIGTERM):
                with self.subTest(annotated=shell is REFERENCE_ANNOTATED, status=status):
                    (old, _), (new, _) = self.both(shell, 'error', upgrade_output=['err:no index'],
                                                   upgrade_status=status)
                    self.assertEqual(new, old)

    def test_the_bare_steps_gain_the_annotation(self) -> None:
        """The bare shell gives pip's status, its two streams apart and no annotation; the script
        merges its streams into standard output and the log, and on a failure gives status 1 and
        the annotation."""
        for output, status in OUTCOMES:
            with self.subTest(output=output, status=status):
                (old, old_stderr), (new, new_stderr) = self.both(REFERENCE_BARE, 'error', install_output=output,
                                                                 install_status=status)
                self.assertEqual(new[3], old[3])
                self.assertEqual((old[1], old[2]), (text([line for line in output if line.startswith('out:')]), None))
                self.assertTrue(old_stderr.startswith(text([line for line in output if line.startswith('err:')])))
                self.assertEqual((new[2], new_stderr), (text(output), ''))
                if status == 0:
                    self.assertEqual((new[0], new[1]), (0, text(output)))
                    continue
                self.assertNotEqual(old[0], 0)
                self.assertEqual(new[0], 1)
                self.assertTrue(str(new[1]).startswith(f'{text(output)}::error title={TITLE}::'), new[1])
                self.assertEqual(str(new[1]).count('\n::'), 1)


class TestTheStepsRunTheScript(unittest.TestCase):
    """Each covered step is one call of the script, with its guards; no other keeps the shell."""

    def step(self, job_id: 'str', name: 'str') -> 'dict[str, object]':
        found = [entry for entry in steps(WORKFLOW, job_id) if entry.get('name') == name]
        self.assertEqual(len(found), 1, f'{job_id} {name!r}')
        return found[0]

    def test_each_site_runs_the_script(self) -> None:
        for (job_id, name), extras in {**MATRIX_SITES, **LATEST_SITES}.items():
            with self.subTest(job=job_id):
                run = self.step(job_id, name)['run']
                self.assertEqual(run, f"python util/pip_install.py -e '.[{extras}]'")
                self.assertEqual(EDITABLE_INSTALL.findall(str(run)), [extras])

    def test_the_matrix_sites_keep_their_guards_and_level(self) -> None:
        for job_id, name in MATRIX_SITES:
            with self.subTest(job=job_id):
                step = self.step(job_id, name)
                self.assertEqual(step['id'], 'install')
                self.assertEqual(step['if'], "${{ steps.python.outcome == 'success' }}")
                self.assertEqual(step['continue-on-error'], '${{ matrix.ktlo == true }}')
                self.assertEqual(step['env'], {'LEG': MATRIX_LEG})
                self.assertEqual(step.get('shell'), None if job_id == 'pypcap-parity' else 'bash')
                self.assertNotIn('timeout-minutes', step)
                self.assertEqual(job(WORKFLOW, job_id)['env']['ANNOTATION_LEVEL'], MATRIX_LEVEL)

    def test_the_latest_sites_annotate_at_error_on_their_own_version(self) -> None:
        for job_id, name in LATEST_SITES:
            with self.subTest(job=job_id):
                step = self.step(job_id, name)
                setup = next(entry for entry in steps(WORKFLOW, job_id)
                             if str(entry.get('uses', '')).startswith('actions/setup-python@'))
                self.assertEqual(step['env'], {'ANNOTATION_LEVEL': 'error',
                                               'LEG': f"Python {setup['with']['python-version']}"})
                self.assertFalse({'id', 'if', 'continue-on-error', 'shell', 'timeout-minutes'} & set(step))
                self.assertNotIn('ANNOTATION_LEVEL', job(WORKFLOW, job_id).get('env') or {})
                self.assertFalse([leg for leg in (job(WORKFLOW, job_id).get('strategy') or {}).get('matrix', {})
                                  .get('include', []) if leg.get('ktlo')])

    def test_the_ktlo_twins_run_the_same_step(self) -> None:
        for twin, job_id in TWINS.items():
            name = next(name for site, name in MATRIX_SITES if site == job_id)
            with self.subTest(job=twin):
                self.assertEqual(self.step(twin, name), self.step(job_id, name))

    def test_every_other_pip_install_is_a_listed_one(self) -> None:
        sites = {*MATRIX_SITES, *LATEST_SITES}
        found = []
        for job_id, body in load(WORKFLOW)['jobs'].items():
            for step in body.get('steps', []):
                where = (TWINS.get(job_id, job_id), step.get('name'))
                run = str(step.get('run', ''))
                if re.search(r'pip install|pip_install\.py', run) and where not in sites | LEFT_INLINE:
                    found.append(f'{job_id} {step.get("name")!r}')
                if where not in LEFT_INLINE:
                    found.extend(f'{job_id} {step.get("name")!r}: {piece}' for piece in INLINE if piece in run)
        self.assertEqual(found, [])

    def test_the_listed_steps_still_install(self) -> None:
        """So :data:`LEFT_INLINE` names nothing stale."""
        for job_id, name in LEFT_INLINE:
            with self.subTest(job=job_id, step=name):
                self.assertIn('pip install', str(self.step(job_id, name)['run']))


class TestTheOtherWorkflowsRunTheScript(unittest.TestCase):
    """The experimental and Compat installs run the script, with their guards; nothing else there keeps the shell."""

    def test_each_site_is_the_script_with_its_guards(self) -> None:
        for (name, job_id), (expected, _) in ELSEWHERE.items():
            with self.subTest(workflow=name, job=job_id):
                found = [entry for entry in steps(WORKFLOWS / name, job_id) if entry.get('name') == expected['name']]
                self.assertEqual(found, [expected])

    def test_each_job_sets_the_level(self) -> None:
        for (name, job_id), (_, level) in ELSEWHERE.items():
            with self.subTest(workflow=name, job=job_id):
                self.assertEqual(job(WORKFLOWS / name, job_id)['env']['ANNOTATION_LEVEL'], level)

    def test_every_other_pip_install_is_a_listed_one(self) -> None:
        sites = {(name, job_id, expected['name']) for (name, job_id), (expected, _) in ELSEWHERE.items()}
        found = []
        for name in sorted({name for name, _ in ELSEWHERE}):
            for job_id, body in load(WORKFLOWS / name)['jobs'].items():
                for step in body.get('steps', []):
                    where = (name, job_id, step.get('name'))
                    run = str(step.get('run', ''))
                    if re.search(r'pip install|pip_install\.py', run) and where not in sites | ELSEWHERE_INLINE:
                        found.append(f'{name} {job_id} {step.get("name")!r}')
                    found.extend(f'{name} {job_id} {step.get("name")!r}: {piece}' for piece in INLINE if piece in run)
        self.assertEqual(found, [])

    def test_the_listed_steps_still_install(self) -> None:
        """So :data:`ELSEWHERE_INLINE` names nothing stale."""
        for name, job_id, step_name in ELSEWHERE_INLINE:
            with self.subTest(workflow=name, job=job_id, step=step_name):
                found = [entry for entry in steps(WORKFLOWS / name, job_id) if entry.get('name') == step_name]
                self.assertEqual(len(found), 1)
                self.assertIn('pip install', str(found[0]['run']))


if __name__ == '__main__':
    unittest.main()
