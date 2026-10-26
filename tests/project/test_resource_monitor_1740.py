# -*- coding: utf-8 -*-
"""#1740: the experimental legs sample their runner while the tests run.

GraalPy's leg loses its runner 18-30 minutes into ``Run unit tests``, under a
120-minute cap, so experimental.yml records what the runner has left: a sampler
started before the tests, stopped ``if: always()`` after them, whose samples
``Run unit tests`` copies into its own log, each line led by ``[monitor]``, and a
file uploaded ``if: always()`` with ``continue-on-error``. A lost runner runs no
later step, ``always()`` ones included, so the log lines are the evidence that
survives it; the upload is for a runner that survives the tests.

:class:`TestTheStepsAreInPlace` reads the steps. :class:`TestTheSamplesReachTheTestsLog`
runs them, with ``sleep`` and ``python`` stubbed on ``PATH``, so what is checked is
what bash does with them. :class:`TestItGatesNothing` holds it out of every gating
path, as #1732's split requires.

"""

from __future__ import annotations

import json
import os
import pathlib
import re
import select
import shutil
import socket
import subprocess  # nosec B404
import sys
import tempfile
import time
import unittest
from typing import TYPE_CHECKING

from tests._support import bash_argv
from tests.project.test_python_matrix_tiers_1633 import job, legs, workflow, workflow_commands
from tests.project.test_python_versions_1660 import ROOT, prose

if TYPE_CHECKING:
    from typing import Any

EXPERIMENTAL = ('experimental.yml', 'experimental')
START, TESTS, STOP = 'Start the resource monitor', 'Run unit tests', 'Stop the resource monitor'
UPLOAD = "Upload the resource monitor's log"
#: Where the sampler writes, and the pid it leaves for the stop step.
LOG = '$RUNNER_TEMP/resource-monitor.log'
PIDFILE = '$RUNNER_TEMP/resource-monitor.pid'
#: The sampler's own output, the log alone, detached from the step's.
REDIRECT = ') >> "$log" 2>&1'
PREFIX = '[monitor] '
#: What each sample holds, as the issue asked for it.
PROBES = ('free -m', 'df -h / "$GITHUB_WORKSPACE"', 'cat /proc/loadavg',
          'ps -eo pid,rss,vsz,etime,args --sort=-rss | head -6')
#: The experimental job's caps and its check name, which the monitor leaves alone.
#: The watcher's interpreter and its requests (#1938) are capped as the rest are.
CAPS = {'python': 5, 'install': 10, 'watcher-python': 1, 'watcher': 1, 'tests': 120}
CHECK_NAME = 'Python ${{ matrix.python-version }} (experimental)'
#: A sample's first line, ``[monitor] <UTC time> sample <n>``.
HEADER = re.compile(r'^\[monitor\] \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ sample (\d+)$')


def steps() -> 'list[dict[str, Any]]':
    return job(*EXPERIMENTAL)['steps']


def step(name: 'str') -> 'dict[str, Any]':
    found = [entry for entry in steps() if (entry.get('name') or entry.get('uses')) == name]
    if len(found) != 1:
        raise AssertionError(f'expected one {name!r} step in experimental.yml, found {len(found)}')
    return found[0]


def position(name: 'str') -> 'int':
    return steps().index(step(name))


class TestTheStepsAreInPlace(unittest.TestCase):
    """Started before the tests, stopped and uploaded ``if: always()`` after them."""

    def test_the_monitor_starts_before_the_tests_on_the_legs_they_run(self) -> None:
        start = step(START)
        self.assertEqual(position(START) + 1, position(TESTS))
        self.assertEqual(start.get('id'), 'monitor')
        self.assertEqual(start.get('if'), step(TESTS).get('if'))
        self.assertIs(start.get('continue-on-error'), True)
        self.assertEqual(start.get('shell'), 'bash')
        script = start['run']
        for probe in PROBES:
            with self.subTest(probe=probe):
                self.assertIn(probe, script)
        self.assertIn('sleep 30 &', script)
        self.assertTrue(script.startswith(f'log="{LOG}"\n: > "$log"\n'), script[:200])
        self.assertIn(f"sed 's/^/{PREFIX}/'", script)
        # Detached from the step's output, which the runner would end 5 s after the shell.
        self.assertIn(') >> "$log" 2>&1 < /dev/null &', script)
        self.assertIn(f'echo "$!" > "{PIDFILE}"', script)

    def test_the_tests_step_streams_the_samples_into_its_own_log(self) -> None:
        script = step(TESTS)['run']
        self.assertTrue(script.startswith(f'tail -n +1 -F "{LOG}" 2>/dev/null &\n'), script[:200])
        self.assertIn('trap \'kill "$monitor" 2>/dev/null || true\' EXIT', script)
        self.assertIn('python -m pytest "$@"', script)
        self.assertTrue(script.rstrip().endswith('exit "$status"'))

    def test_the_monitor_is_stopped_if_always(self) -> None:
        stop = step(STOP)
        self.assertEqual(position(STOP), position(TESTS) + 1)
        self.assertEqual(stop.get('if'), '${{ always() }}')
        self.assertIs(stop.get('continue-on-error'), True)
        self.assertIn(PIDFILE, stop['run'])

    def test_the_log_is_uploaded_if_always_and_cannot_fail_the_leg(self) -> None:
        upload = step(UPLOAD)
        self.assertGreater(position(UPLOAD), position(STOP))
        self.assertEqual(upload.get('if'), '${{ always() }}')
        self.assertIs(upload.get('continue-on-error'), True)
        self.assertTrue(upload['uses'].startswith('actions/upload-artifact@'))
        self.assertEqual(upload['with'], {
            'name': 'resource-monitor-${{ matrix.python-version }}',
            'path': '${{ runner.temp }}/resource-monitor.log',
            'if-no-files-found': 'ignore',
            'retention-days': 14,
        })


def sh(script: 'str', env: 'dict[str, str]', shell: 'tuple[str, ...]',
       pass_fds: 'tuple[int, ...]' = ()) -> 'subprocess.CompletedProcess[str]':
    """``script`` as the runner runs it: ``shell: bash`` or the default ``bash -e``."""
    with tempfile.NamedTemporaryFile('w', suffix='.sh', delete=False, encoding='utf-8') as file:
        file.write(script)
    try:
        return subprocess.run([*shell, file.name], env=env, capture_output=True, text=True,  # nosec B603
                              check=False, timeout=60, pass_fds=pass_fds)
    finally:
        os.unlink(file.name)


def gnu_timeout(env: 'dict[str, str]') -> 'str | None':
    """The ``timeout`` the tests step resolves on ``env``'s ``PATH``: ``gnutimeout`` first (#2020)."""
    return shutil.which('gnutimeout', path=env['PATH']) or shutil.which('timeout', path=env['PATH'])


BASH = tuple(bash_argv('-eo', 'pipefail'))
DEFAULT = tuple(bash_argv('-e'))


@unittest.skipUnless(sys.platform.startswith('linux') and all(map(shutil.which, ('bash', 'free', 'tail', 'ps'))),
                     'the sampler reads /proc and procps, as on the Ubuntu runners')
class TestTheSamplesReachTheTestsLog(unittest.TestCase):
    """The start, tests and stop scripts, run in order, with ``sleep 30`` made 0.2 s and pytest a stub."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-1740-')  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.tmp = pathlib.Path(tmp.name)
        (self.tmp / 'temp').mkdir()
        bindir = self.tmp / 'bin'
        bindir.mkdir()
        real_sleep = shutil.which('sleep')
        assert real_sleep is not None
        (bindir / 'sleep').write_text(f'#!/bin/sh\nexec {real_sleep} 0.2\n', encoding='utf-8')
        # pytest leaves its progress line unfinished, as the runner's log shows it does.
        (bindir / 'python').write_text(f'#!/bin/sh\nprintf uuu.u\n{real_sleep} 1.5\nprintf "uu [ 1%%]\\n"\nexit 3\n',
                                       encoding='utf-8')
        # No real sudo here: the probe fails, as where `sudo -n` cannot start a scope.
        (bindir / 'sudo').write_text('#!/bin/sh\necho "sudo: a password is required" >&2\nexit 1\n', encoding='utf-8')
        for stub in bindir.iterdir():
            stub.chmod(0o755)
        self.env = dict(os.environ, RUNNER_TEMP=str(self.tmp / 'temp'), GITHUB_WORKSPACE=str(ROOT),
                        PATH=str(bindir) + os.pathsep + os.environ.get('PATH', ''))

    def pid(self) -> 'int':
        return int((self.tmp / 'temp' / 'resource-monitor.pid').read_text(encoding='utf-8'))

    def test_samples_stream_into_the_tests_log_and_the_stop_step_ends_the_sampler(self) -> None:
        start = sh(step(START)['run'], self.env, BASH)
        self.assertEqual(start.returncode, 0, start.stderr)
        pid = self.pid()
        self.addCleanup(lambda: subprocess.run(['kill', str(pid)], capture_output=True, check=False))
        self.assertTrue(pathlib.Path(f'/proc/{pid}').exists(), 'the sampler did not outlive its step')

        tests = sh(step(TESTS)['run'], self.env, DEFAULT)
        # The tests' own status, not the trap's or tail's.
        self.assertEqual(tests.returncode, 3, tests.stderr)
        lines = tests.stdout.splitlines()
        samples = [int(match.group(1)) for match in map(HEADER.match, lines) if match]
        self.assertGreaterEqual(len(samples), 2, tests.stdout)
        self.assertEqual(samples, list(range(1, len(samples) + 1)))
        # Each starts its own line, even after pytest's unfinished one.
        self.assertEqual([line for line in lines if PREFIX.strip() in line and not line.startswith(PREFIX)], [])
        for needle in ('Mem:', 'Filesystem', '[monitor] loadavg ', 'RSS'):
            with self.subTest(holds=needle):
                self.assertTrue(any(needle in line for line in lines if line.startswith(PREFIX)), tests.stdout)

        stop = sh(step(STOP)['run'], self.env, BASH)
        self.assertEqual(stop.returncode, 0, stop.stderr)
        self.assertRegex(stop.stdout, r'^\d+ samples taken\.$')
        for _ in range(50):
            if not pathlib.Path(f'/proc/{pid}').exists():
                break
            time.sleep(0.1)
        self.assertFalse(pathlib.Path(f'/proc/{pid}').exists(), 'the stop step left the sampler running')

    def test_each_sample_is_one_write_so_no_output_lands_inside_it(self) -> None:
        """#1888: ``tail -F`` relays each write as it lands, so pytest's output can come between two.

        The log is a ``SOCK_SEQPACKET`` socket here, which keeps every write apart, the most a relay
        could split a sample, and pytest's unfinished line goes between each two.
        """
        script = step(START)['run']
        self.assertIn(REDIRECT, script)
        ours, theirs = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(ours.close)
        with theirs:
            start = sh(script.replace(REDIRECT, f') >&{theirs.fileno()} 2>&1'), self.env, BASH,
                       pass_fds=(theirs.fileno(),))
        self.assertEqual(start.returncode, 0, start.stderr)
        pid = self.pid()
        self.addCleanup(lambda: subprocess.run(['kill', str(pid)], capture_output=True, check=False))
        ours.settimeout(30)
        writes: 'list[str]' = []
        while sum(bool(HEADER.match(line)) for write in writes for line in write.splitlines()) < 3:
            data = ours.recv(1 << 16)
            self.assertTrue(data, f'the sampler stopped after {writes!r}')
            writes.append(data.decode())
        lines = ''.join('uuu.u' + write for write in writes).splitlines()
        self.assertEqual([line for line in lines if PREFIX.strip() in line and not line.startswith(PREFIX)], [])
        for write in writes:
            with self.subTest(write=write[:60]):
                self.assertEqual(sum(bool(HEADER.match(line)) for line in write.splitlines()), 1)
                self.assertTrue(write.endswith('\n'))
                # No larger, and the relay's write of it to the step's pipe is atomic too.
                self.assertLessEqual(len(write.encode()), select.PIPE_BUF)

    def test_the_stop_step_passes_on_a_leg_the_monitor_never_started(self) -> None:
        stop = sh(step(STOP)['run'], self.env, BASH)
        self.assertEqual(stop.returncode, 0, stop.stderr)
        self.assertEqual(stop.stdout, 'The resource monitor did not start on this leg.\n')


#: The containment, as the issue's research sized it (estimates); the exit
#: on a spent heap is #1753's, which
#: tests/project/test_graalpy_worker_heap_1753.py pins.
HEAP, GRAAL_WORKERS, SCOPE_MEMORY = '--vm.Xmx2g --vm.XX:+ExitOnOutOfMemoryError', '3', '12G'
#: A ``LATEST``-tier module, as ``List the LATEST tier`` would hand the tests step (#1958):
#: a stand-in naming no real module, so this pin runs no test module by path.
SWEEP = 'tests/protocols/test_a_latest_sweep_unit.py'
FSIZE = 2 * 1024 ** 3
#: The probe is the scope itself, every flag included, under a throwaway unit.
PROBE = 'if probe=$(scoped "pcapkit-probe-$$.scope" true 2>&1); then'
SCOPE_FLAGS = ('sudo -n --preserve-env systemd-run --scope --quiet --unit="$unit"',
               f'-p MemoryMax={SCOPE_MEMORY}', '-p MemorySwapMax=0', '-p CPUWeight=20',
               '--uid="$(id -u)"', '--gid="$(id -g)"',
               '-- env PATH="$PATH" HOME="$HOME" LD_LIBRARY_PATH="${LD_LIBRARY_PATH-}" \\\n',
               'GRAAL_PYTHON_VM_ARGS="$GRAAL_PYTHON_VM_ARGS" "$@"')
#: What ``sudo`` receives, past ``-n``, for the probe and for the tests, ``{unit}`` aside.
SUDO_ARGV = ('-n --preserve-env systemd-run --scope --quiet --unit={unit} '
             '-p MemoryMax=12G -p MemorySwapMax=0 -p CPUWeight=20 --uid={uid} --gid={gid} -- env PATH=')
SUMMARY = 'Containment summary'
#: ``${{ startsWith(matrix.python-version, 'graalpy') && 'a' || 'b' }}``, the one expression form the step's env uses.
BY_IMPL = re.compile(r"^\$\{\{ startsWith\(matrix\.python-version, 'graalpy'\) && '([^']*)' \|\| '([^']*)' \}\}$")


def by_impl(expression: 'str', version: 'str') -> 'str':
    """``expression`` as GitHub evaluates it on the leg of ``version``."""
    match = BY_IMPL.match(expression)
    if match is None:
        raise AssertionError(f'not keyed on the GraalPy leg: {expression!r}')
    # `a && 'x' || 'y'` is 'y' where 'x' is empty, as in GitHub's expressions.
    return match.group(1) if version.lower().startswith('graalpy') and match.group(1) else match.group(2)


class TestTheTestsAreContained(unittest.TestCase):
    """The tests are held to what leaves the runner alive, so a breach fails the step."""

    def legs(self) -> 'list[str]':
        found = [leg['python-version'] for leg in legs(*EXPERIMENTAL)]
        self.assertTrue(any(version.startswith('graalpy') for version in found), found)
        self.assertTrue(any(not version.startswith('graalpy') for version in found), found)
        return found

    def test_graalpy_alone_gets_a_2g_heap_and_3_workers(self) -> None:
        env = step(TESTS).get('env', {})
        for version in self.legs():
            graalpy = version.startswith('graalpy')
            with self.subTest(version=version):
                self.assertEqual(by_impl(env['GRAAL_PYTHON_VM_ARGS'], version), HEAP if graalpy else '')
                self.assertEqual(by_impl(env['WORKERS'], version), GRAAL_WORKERS if graalpy else 'auto')
        script = step(TESTS)['run']
        self.assertIn('set -- -q -n "$WORKERS" --dist load', script)
        self.assertNotIn('-n auto', script)

    def test_the_timeout_ends_the_tests_before_the_step_cap(self) -> None:
        script = step(TESTS)['run']
        # #1963: the command the timeout runs, pytest or GraalPy's shards of it, is set just before.
        self.assertIn('set -- python -m pytest "$@"\n', script)
        match = re.search(r'"\$gnu_timeout" --signal=INT --kill-after=(\d+)m (\d+)m "\$@"\n', script)
        self.assertIsNotNone(match, script)
        assert match is not None
        kill_after, duration = map(int, match.groups())
        self.assertEqual((duration, kill_after), (110, 3))
        self.assertLess(duration + kill_after, step(TESTS)['timeout-minutes'])

    def test_no_file_grows_past_2_gib(self) -> None:
        self.assertIn(f'set -- prlimit --fsize={FSIZE} "$gnu_timeout" ', step(TESTS)['run'])

    def test_the_scope_is_probed_and_falls_back_with_a_warning(self) -> None:
        script = step(TESTS)['run']
        self.assertIn(PROBE, script)
        # One definition of the scope, so the probe cannot drift from the tests' flags.
        self.assertEqual(script.count('systemd-run'), 1)
        self.assertEqual(script.count('sudo '), 1)
        for flag in SCOPE_FLAGS:
            with self.subTest(flag=flag):
                self.assertIn(flag, script)
        self.assertIn('set -- scoped pcapkit-tests.scope "$@"', script)
        fallback = script[script.index('else\n', script.index(PROBE)):]
        self.assertIn('scope=none', fallback)
        # The tests step writes no annotation and needs no `LEG`; `Containment summary` warns.
        self.assertNotIn('::', script)
        self.assertNotIn('LEG', step(TESTS).get('env', {}))
        self.assertIn('title=${1} on ${LEG//,/%2C}', step(SUMMARY)['run'])
        self.assertIn('warn "No memory cap"', step(SUMMARY)['run'])
        # The probe, the scope and the fallback all come before the one run of the tests.
        self.assertLess(script.index('scope=none'), script.index('"$@" 2>&1 | tee "$RUNNER_TEMP/pytest.log"'))

    def test_the_sampler_runs_outside_the_scope(self) -> None:
        start, tests = step(START)['run'], step(TESTS)['run']
        for word in ('systemd-run', 'sudo', 'prlimit', 'timeout '):
            with self.subTest(word=word):
                self.assertNotIn(word, start)
        self.assertLess(tests.index('tail -n +1 -F'), tests.index('systemd-run'))
        # The scope runs the tests alone: its command line, after `--`, holds no `tail`.
        self.assertNotIn('tail', tests[tests.index('-- env PATH='):].splitlines()[0])
        self.assertIn('/sys/fs/cgroup/system.slice/pcapkit-tests.scope', start)
        self.assertIn('oom_kill', start)


@unittest.skipUnless(sys.platform.startswith('linux') and all(map(shutil.which, ('bash', 'timeout', 'prlimit', 'jq'))),
                     'the tests step runs coreutils timeout and util-linux prlimit, as on the Ubuntu runners')
class TestTheContainmentRuns(unittest.TestCase):
    """The tests step and ``Containment summary``, run with ``sudo``, ``python`` and /proc/vmstat stubbed."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-1740-')  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.tmp = pathlib.Path(tmp.name)
        self.temp = self.tmp / 'temp'
        self.temp.mkdir()
        self.bindir = self.tmp / 'bin'
        self.bindir.mkdir()
        (self.temp / 'resource-monitor.log').write_text('', encoding='utf-8')
        self.vmstat = self.tmp / 'vmstat'
        self.vmstat.write_text('oom_kill 7\n', encoding='utf-8')
        self.argv = self.tmp / 'argv'
        self.env = dict(os.environ, RUNNER_TEMP=str(self.temp), GITHUB_WORKSPACE=str(ROOT), WORKERS='3',
                        GRAAL_PYTHON_VM_ARGS=HEAP, LATEST_TIER=SWEEP,
                        LEG='Python graalpy-25.4 (experimental, non-blocking)',
                        GITHUB_STEP_SUMMARY=str(self.tmp / 'summary.md'),
                        PATH=str(self.bindir) + os.pathsep + os.environ.get('PATH', ''))

    def stub(self, name: 'str', body: 'str') -> 'None':
        path = self.bindir / name
        path.write_text('#!/bin/sh\n' + body, encoding='utf-8')
        path.chmod(0o755)

    def scope(self) -> 'None':
        """A ``sudo`` whose probe passes and whose scope runs what follows ``--``, recording each call."""
        self.stub('sudo', f'printf "%s\\n" "$*" >> {self.argv}\n'
                          'while [ "$#" -gt 0 ] && [ "$1" != -- ]; do shift; done\n'
                          '[ "$#" -gt 0 ] || exit 0\nshift\nexec "$@"\n')

    def run_step(self, script: 'str | None' = None) -> 'subprocess.CompletedProcess[str]':
        script = step(TESTS)['run'] if script is None else script
        return sh(script.replace('/proc/vmstat', str(self.vmstat)), self.env, DEFAULT)

    def status(self) -> 'dict[str, str]':
        text = (self.temp / 'tests-status').read_text(encoding='utf-8')
        return dict(line.split('=', 1) for line in text.splitlines())

    def summary(self, status: 'str') -> 'list[str]':
        """``Containment summary``'s workflow commands, given ``tests-status``."""
        (self.temp / 'tests-status').write_text(status, encoding='utf-8')
        result = sh(step(SUMMARY)['run'], self.env, BASH)
        self.assertEqual(result.returncode, 0, result.stderr)
        return workflow_commands(result.stdout)

    def no_real_sudo(self) -> 'None':
        """Every run here resolves ``sudo`` to a stub in ``self.bindir``, never the real one."""
        found = shutil.which('sudo', path=self.env['PATH'])
        self.assertEqual(found, str(self.bindir / 'sudo'))

    def test_the_scope_runs_the_tests_under_the_timeout_and_fsize_cap(self) -> None:
        self.scope()
        self.stub('python', 'echo "args: $*"\necho "heap $GRAAL_PYTHON_VM_ARGS"\n'
                            'grep "^Max file size" /proc/$$/limits\nexit 1\n')
        self.no_real_sudo()
        result = self.run_step()
        self.assertEqual(result.returncode, 1, result.stderr)
        probe, run = self.argv.read_text(encoding='utf-8').splitlines()
        # The probe passes sudo every flag the tests' scope does, under a throwaway unit.
        unit = re.match(r'-n --preserve-env systemd-run --scope --quiet --unit=(pcapkit-probe-\d+\.scope) ', probe)
        self.assertIsNotNone(unit, probe)
        assert unit is not None
        ids = {'uid': os.getuid(), 'gid': os.getgid()}
        self.assertTrue(probe.startswith(SUDO_ARGV.format(unit=unit.group(1), **ids)), probe)
        self.assertTrue(probe.endswith(f' GRAAL_PYTHON_VM_ARGS={HEAP} true'), probe)
        self.assertTrue(run.startswith(SUDO_ARGV.format(unit='pcapkit-tests.scope', **ids)), run)
        # #2020: GNU's timeout, `gnutimeout` where the image has one, by its path.
        self.assertIn(f' prlimit --fsize={FSIZE} {gnu_timeout(self.env)} --signal=INT --kill-after=3m 110m '
                      'python -m pytest -q -n 3 ', run)
        self.assertIn('args: -m pytest -q -n 3 --dist load', result.stdout)
        self.assertIn(f'heap {HEAP}\n', result.stdout)
        self.assertIn(f' GRAAL_PYTHON_VM_ARGS={HEAP} prlimit ', run)
        self.assertRegex(result.stdout, rf'Max file size +{FSIZE} +{FSIZE} +bytes')
        self.assertEqual(workflow_commands(result.stdout), [])
        status = self.status()
        self.assertRegex(status.pop('elapsed'), r'^\d+$')
        self.assertEqual(status, {'exit': '1', 'scope': '12G', 'probe': '', 'oom_kills': '0', 'memory_errors': '0',
                                  'crashed_workers': '0'})

    def test_without_a_scope_the_tests_run_uncapped_with_a_warning(self) -> None:
        self.stub('sudo', 'echo "sudo: a password is required" >&2\nexit 1\n')
        self.stub('python', 'exit 0\n')
        self.no_real_sudo()
        result = self.run_step()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(workflow_commands(result.stdout), [])
        self.assertIn('No 12G scope: the probe failed (sudo: a password is required), so the tests run uncapped.\n',
                      result.stdout)
        self.assertEqual(self.status()['scope'], 'none')
        self.assertEqual(self.status()['probe'], 'sudo: a password is required')
        self.assertEqual(self.summary((self.temp / 'tests-status').read_text(encoding='utf-8')), [
            '::warning title=No memory cap on Python graalpy-25.4 (experimental%2C non-blocking)::The probe, sudo -n '
            "systemd-run --scope with the tests' flags, failed (sudo: a password is required), so the tests ran "
            'without the 12G scope. Experimental legs never block (#1660), so this job still succeeds.'])

    def test_the_uncapped_tests_run_the_capped_argv(self) -> None:
        """The fallback drops the scope and nothing else, so the two paths run one pytest."""
        argvs = {}
        for path, sudo in (('capped', None), ('uncapped', 'echo "sudo: a password is required" >&2\nexit 1\n')):
            if sudo is None:
                self.scope()
            else:
                self.stub('sudo', sudo)
            self.stub('python', f'printf "%s\\n" "$@" > {self.tmp / path}\nexit 0\n')
            self.no_real_sudo()
            result = self.run_step()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(self.status()['scope'], '12G' if sudo is None else 'none')
            argvs[path] = (self.tmp / path).read_text(encoding='utf-8').splitlines()
        self.assertEqual(argvs['capped'], argvs['uncapped'])
        argv = argvs['capped']
        self.assertEqual(argv[:6], ['-m', 'pytest', '-q', '-n', '3', '--dist'])
        for arg in (f'--junitxml={self.temp}/junit.xml', '--ignore=tests/integration', '--ignore-glob=*_runtime.py',
                    '--ignore-glob=*_regression.py', f'--ignore={SWEEP}', '--durations=30'):
            with self.subTest(arg=arg):
                self.assertIn(arg, argv)
        # Only the capped path took the tests through sudo: the probe and the run.
        self.assertEqual(len(self.argv.read_text(encoding='utf-8').splitlines()), 2)

    def test_a_timeout_exits_124(self) -> None:
        self.scope()
        self.stub('python', 'exec sleep 30\n')
        script = step(TESTS)['run'].replace('--kill-after=3m 110m', '--kill-after=3s 1s')
        self.assertNotEqual(script, step(TESTS)['run'])
        result = self.run_step(script)
        self.assertEqual(result.returncode, 124, result.stderr)
        self.assertEqual(self.status()['exit'], '124')

    def test_oom_kills_and_memory_errors_are_counted(self) -> None:
        self.scope()
        self.stub('python', f'echo "oom_kill 9" > {self.vmstat}\necho "E   MemoryError"\nexit 1\n')
        result = self.run_step()
        self.assertEqual(result.returncode, 1, result.stderr)
        status = self.status()
        self.assertEqual({key: status[key] for key in ('exit', 'scope', 'oom_kills', 'memory_errors')},
                         {'exit': '1', 'scope': '12G', 'oom_kills': '2', 'memory_errors': '1'})

    def titles(self, status: 'str') -> 'list[str]':
        return [re.sub(r'^::warning title=(.*?) on Python .*$', r'\1', line) for line in self.summary(status)]

    def test_the_summary_reports_each_cause_distinctly(self) -> None:
        (self.temp / 'resource-monitor.log').write_text(
            '\n[monitor] 2026-10-14T20:00:00Z sample 1\n[monitor] Mem:  15990  9000  1000  10  6000  6990\n'
            '\n[monitor] 2026-10-14T20:00:30Z sample 2\n[monitor] Mem:  15990  15000  100  10  890  990\n',
            encoding='utf-8')
        base = 'scope=12G\n'
        self.assertEqual(self.titles(base + 'exit=124\noom_kills=0\nmemory_errors=0\n'),
                         ['tests timed out at 110 minutes'])
        self.assertEqual(self.titles(base + 'exit=137\noom_kills=1\nmemory_errors=0\n'),
                         ['tests lost a process to the OOM killer'])
        self.assertEqual(self.titles(base + 'exit=1\noom_kills=0\nmemory_errors=3\n'), ['tests raised MemoryError'])
        # A failure with no cause of its own is `Experimental summary`'s to report, as any step's.
        self.assertEqual(self.titles(base + 'exit=1\noom_kills=0\nmemory_errors=0\n'), [])
        oom = self.summary(base + 'exit=137\noom_kills=1\nmemory_errors=0\n')[0]
        self.assertIn('last sample 2 at 2026-10-14T20:00:30Z: used 15000 MiB of 15990, 990 available', oom)
        self.assertIn('scope 12G', oom)

    def test_a_hung_teardown_killed_after_the_timeout_is_a_timeout(self) -> None:
        """``--kill-after`` ends a teardown SIGINT did not with SIGKILL, exit 137, as an OOM kill does."""
        base = 'scope=12G\nmemory_errors=0\n'
        timeout = ['tests timed out at 110 minutes']
        self.assertEqual(self.titles(base + 'exit=137\noom_kills=0\nelapsed=6781\n'), timeout)
        self.assertEqual(self.titles(base + 'exit=137\noom_kills=0\nelapsed=6600\n'), timeout)
        # Before 110 minutes, or with an OOM kill, 137 is not the timeout's.
        self.assertEqual(self.titles(base + 'exit=137\noom_kills=0\nelapsed=6599\n'), [])
        self.assertEqual(self.titles(base + 'exit=137\noom_kills=1\nelapsed=6781\n'),
                         ['tests lost a process to the OOM killer'])
        self.assertEqual(self.titles(base + 'exit=137\noom_kills=0\n'), [])
        killed = self.summary(base + 'exit=137\noom_kills=0\nelapsed=6781\n')[0]
        self.assertIn('timeout sent SIGKILL 3 minutes on (exit 137, no OOM kill), scope 12G, 6781 s', killed)

    def test_a_tests_step_killed_after_the_timeout_records_137_and_its_time(self) -> None:
        self.scope()
        self.stub('python', "trap '' INT\nsleep 5\n")
        script = step(TESTS)['run'].replace('--kill-after=3m 110m', '--kill-after=1s 1s')
        self.assertNotEqual(script, step(TESTS)['run'])
        self.no_real_sudo()
        result = self.run_step(script)
        self.assertEqual(result.returncode, 137, result.stderr)
        self.assertEqual(self.status()['exit'], '137')
        self.assertIn(self.status()['elapsed'], {'2', '3'})

    def test_the_summary_is_quiet_without_a_status(self) -> None:
        result = sh(step(SUMMARY)['run'], self.env, BASH)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(workflow_commands(result.stdout), [])
        self.assertIn('the tests step wrote no tests-status', result.stdout)

    def test_experimental_summary_is_mains_and_runs_last(self) -> None:
        """The causes are a step of their own, so ``Experimental summary`` stays the KTLO summary's."""
        self.assertEqual(position(SUMMARY) + 1, position('Experimental summary'))
        self.assertEqual(step(SUMMARY).get('if'), '${{ !cancelled() }}')
        self.assertIs(step(SUMMARY).get('continue-on-error'), True)
        # #2077: and the watcher's `stopped`, so a superseded stop reads as one.
        self.assertEqual(step(SUMMARY).get('env'),
                         {'LEG': 'Python ${{ matrix.python-version }} (experimental, non-blocking)',
                          'STOPPED': '${{ steps.tests.outputs.stopped }}'})
        self.assertNotIn('tests-status', step('Experimental summary')['run'])


class TestItGatesNothing(unittest.TestCase):
    """In experimental.yml alone, inside its caps and check names, and read by nothing."""

    def test_only_the_experimental_job_runs_it(self) -> None:
        for path in sorted((ROOT / '.github' / 'workflows').glob('*.yml')):
            if path.name == EXPERIMENTAL[0]:
                continue
            with self.subTest(workflow=path.name):
                self.assertNotIn('resource-monitor', path.read_text(encoding='utf-8'))
        self.assertIs(job(*EXPERIMENTAL).get('continue-on-error'), True)
        # #2030: last but the steps that name and upload the job's summary.
        self.assertEqual([entry['name'] for entry in steps()[-3:]],
                         ['Experimental summary', 'Name the job summary', 'Upload the job summary'])

    def test_the_caps_and_check_name_are_unchanged(self) -> None:
        spec = job(*EXPERIMENTAL)
        self.assertEqual(spec['name'], CHECK_NAME)
        self.assertEqual(spec['timeout-minutes'], 140)
        self.assertEqual({entry.get('id'): entry['timeout-minutes'] for entry in spec['steps']
                          if 'timeout-minutes' in entry}, CAPS)

    def test_no_reader_takes_the_artifact_for_a_junit_one(self) -> None:
        """CI Timing reads ``junit-*`` artifacts by name; nothing else reads this one."""
        from util import ci_timing  # pylint: disable=import-outside-toplevel
        name = step(UPLOAD)['with']['name']
        self.assertFalse(name.startswith('junit-'))
        self.assertTrue(ci_timing.JUNIT_ARTIFACT.startswith('junit-'))
        self.assertEqual([path.name for path in sorted((ROOT / 'util').glob('*.py'))
                          if 'resource-monitor' in path.read_text(encoding='utf-8')], [])
        # #2060's `windows` runs no monitor and downloads nothing.
        jobs = workflow(EXPERIMENTAL[0])['jobs']
        self.assertEqual(list(jobs), ['current', 'python-versions', 'changes', 'experimental', 'windows'])
        self.assertNotIn('resource-monitor', json.dumps(jobs['windows']))


class TestTheDocsSayIt(unittest.TestCase):

    def test_the_workflows_page_describes_the_monitor(self) -> None:
        page = prose(ROOT / 'docs' / 'source' / 'contributing' / 'workflows.rst')
        for phrase in ('``Start the resource monitor``', '``[monitor]``', '``resource-monitor-<version>``',
                       '``Stop the resource monitor``',
                       # #2165: the runner's shutdown check, cited by its method rather than by line.
                       "actions/runner's ``StepsRunner.RunAsync``, at ``796cc18ff``"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, page)

    def test_the_workflows_page_describes_the_containment(self) -> None:
        page = prose(ROOT / 'docs' / 'source' / 'contributing' / 'workflows.rst')
        for phrase in (f'``GRAAL_PYTHON_VM_ARGS={HEAP}``', '``-n 3``', '``timeout --signal=INT --kill-after=3m 110m``',
                       f'``prlimit --fsize={FSIZE}``', '``Containment summary``', '``pcapkit-probe-<pid>.scope``',
                       '117-151 minutes', '137', f'``MemoryMax={SCOPE_MEMORY}``',
                       '``No memory cap``', '``$RUNNER_TEMP/tests-status``', '``tests timed out at 110 minutes``',
                       '``tests lost a process to the OOM killer``', '``tests raised MemoryError``'):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, page)


if __name__ == '__main__':
    unittest.main()
