# -*- coding: utf-8 -*-
"""Tests for the apt ``.deb`` cache and fallback mirror in :file:`unit-tests.yml` (#1432).

#1432: ``azure.archive.ubuntu.com`` served ~75 kB/s, so ``timeout 180`` killed
both tshark install attempts, three times in one day. The fix wraps the
unchanged install step (pinned by
:class:`tests.project.test_unit_tests_queue.TestAptRetry`) with a plan step that
computes a cache key, ``actions/cache`` restore/seed/collect/save steps, and a
retry that drops azure from the runner's ``mirror+file:`` list.

Each property below is exercised by running the step's real ``run:`` script
under ``bash -e`` with ``sudo``/``timeout``/``apt-get`` stubbed, the way
``TestAptRetry`` does, or by reading the step text where only the Actions runner
could execute it:

* the azure line is dropped before attempt 2 only, and only when another
  ``http`` mirror would remain;
* each job's ``APT_PACKAGES`` (which the key is computed from) names exactly
  what its install step installs, for every engine in the matrix;
* the key is ``apt-debs-<ImageOS>-<arch>-<APT_SET>-<digest>`` of the sorted
  ``Inst`` lines, and ``restore-keys`` is that same-image, same-set prefix only;
* only one job per key saves, so ``pypcap-parity``'s two cells do not race to
  reserve the same entry.

"""

from __future__ import annotations

import hashlib
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from typing import TYPE_CHECKING

from tests.project.test_unit_tests_queue import job, step_script

if TYPE_CHECKING:
    from typing import Optional

#: The runner image's mirror list, as configure-apt-sources.sh writes it.
MIRRORS = ('http://azure.archive.ubuntu.com/ubuntu/\tpriority:1\n'
           'https://archive.ubuntu.com/ubuntu/\tpriority:2\n'
           'https://security.ubuntu.com/ubuntu/\tpriority:3\n')
#: The path the install steps edit, replaced by a scratch file in these tests.
MIRRORS_PATH = '/etc/apt/apt-mirrors.txt'

#: (job, plan step, install step) for both apt sites.
SITES = (
    ('engine-tests', "Plan this engine's system packages", "Install this engine's system packages"),
    ('pypcap-parity', 'Plan the system packages', 'Install libpcap headers, a C toolchain, and tshark'),
)

#: ``apt-get`` logs ``<subcommand>:<azure lines in $MIRRORS>`` per call, and an
#: install's operands; the first ``$FAIL_UPDATES`` updates fail; ``install -s``
#: prints ``$STUB_SIM``.
STUBS = {
    'sudo': 'exec env "$@"\n',
    'timeout': 'shift\nexec "$@"\n',
    'apt-get': textwrap.dedent('''\
        azure=0
        if [ -f "${MIRRORS:-}" ]; then azure=$(grep -c azure "$MIRRORS" || true); fi
        echo "$1:$azure" >> "$STUB_LOG.apt"
        if [ "$1" = update ]; then
          n=$(grep -c '^update' "$STUB_LOG.apt")
          [ "$n" -gt "${FAIL_UPDATES:-0}" ]
        elif [ "$1" = install ] && [ "$2" = -s ]; then
          cat "$STUB_SIM"
        elif [ "$1" = install ]; then
          shift
          for arg in "$@"; do
            case "$arg" in -*) ;; *) printf '%s ' "$arg" >> "$STUB_LOG.pkgs" ;; esac
          done
        fi
        '''),
    'dpkg': 'exit 0\n',
    'debconf-set-selections': 'cat > /dev/null\n',
}


class _Stubbed(unittest.TestCase):
    """A scratch directory with the stubs first on ``PATH``."""

    def setUp(self) -> None:
        if shutil.which('bash') is None:  # pragma: no cover
            self.skipTest('bash is not available')
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-1432-')  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.tmp = pathlib.Path(tmp.name)
        self.bin = self.tmp / 'bin'
        self.bin.mkdir()
        for command, body in STUBS.items():
            path = self.bin / command
            path.write_text('#!/bin/bash\n' + body, encoding='utf-8')
            path.chmod(0o755)
        self.log = self.tmp / 'stub'
        self.reset()

    def reset(self) -> None:
        """Empty the stub logs, so each subtest reads only its own calls."""
        for suffix in ('.apt', '.pkgs'):
            pathlib.Path(f'{self.log}{suffix}').write_text('', encoding='utf-8')

    def run_script(self, script: 'str', env: 'dict[str, str]') -> 'tuple[int, str]':
        """Run ``script`` under ``bash -e``; return its status and combined output."""
        full = dict(os.environ, **env, PATH=f'{self.bin}{os.pathsep}{os.environ["PATH"]}',
                    STUB_LOG=str(self.log))
        proc = subprocess.run(['bash', '-e', '-c', script], env=full, check=False,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        return proc.returncode, proc.stdout

    def apt_calls(self) -> 'list[str]':
        """Every stubbed ``apt-get`` call, as ``<subcommand>:<azure lines>``."""
        return pathlib.Path(f'{self.log}.apt').read_text(encoding='utf-8').split()

    def installed(self) -> 'list[str]':
        """The operands of every stubbed ``apt-get install``."""
        return pathlib.Path(f'{self.log}.pkgs').read_text(encoding='utf-8').split()


class TestFallbackMirror(_Stubbed):
    """#1432: azure is dropped before the retry, because apt never fails over on slowness."""

    def run_install(self, job_name: 'str', name: 'str', mirrors: 'Optional[str]',
                    fail_updates: 'int') -> 'tuple[int, str, list[str], Optional[str]]':
        """Run ``job_name``'s install step against a scratch mirror list."""
        script = step_script(job(job_name), name)
        self.assertEqual(script.count(MIRRORS_PATH), 1,
                         f'{name!r} no longer names {MIRRORS_PATH} exactly once')
        self.reset()
        fake = self.tmp / 'apt-mirrors.txt'
        if fake.exists():
            fake.unlink()
        if mirrors is not None:
            fake.write_text(mirrors, encoding='utf-8')
        status, output = self.run_script(
            script.replace(MIRRORS_PATH, str(fake)),
            {'ENGINE': 'PyShark', 'MIRRORS': str(fake), 'FAIL_UPDATES': str(fail_updates)})
        after = fake.read_text(encoding='utf-8') if mirrors is not None else None
        return status, output, self.apt_calls(), after

    def test_azure_is_dropped_before_attempt_two(self) -> None:
        """Attempt 1 sees azure; attempt 2 does not; the other mirrors stay, in order."""
        for job_name, _, name in SITES:
            with self.subTest(job=job_name):
                status, output, calls, after = self.run_install(job_name, name, MIRRORS, 1)
                self.assertEqual(status, 0, output)
                self.assertEqual(calls, ['update:1', 'update:0', 'install:0'])
                self.assertEqual(after, ''.join(MIRRORS.splitlines(True)[1:]))
                self.assertIn('::warning title=apt retry on a fallback mirror', output)
                self.assertIn('Retrying against https://archive.ubuntu.com/ubuntu/', output)

    def test_a_clean_first_attempt_leaves_the_list_alone(self) -> None:
        """No failure, no edit."""
        for job_name, _, name in SITES:
            with self.subTest(job=job_name):
                status, output, calls, after = self.run_install(job_name, name, MIRRORS, 0)
                self.assertEqual((status, calls, after), (0, ['update:1', 'install:1'], MIRRORS))
                self.assertNotIn('fallback mirror', output)

    def test_an_azure_only_list_is_left_alone(self) -> None:
        """Dropping the only mirror would leave apt with none, so the retry keeps it."""
        only = MIRRORS.splitlines(True)[0]
        for job_name, _, name in SITES:
            with self.subTest(job=job_name):
                status, output, calls, after = self.run_install(job_name, name, only, 1)
                self.assertEqual((status, calls, after), (0, ['update:1', 'update:1', 'install:1'], only))
                self.assertNotIn('fallback mirror', output)

    def test_the_drop_happens_once_and_a_second_failure_still_fails(self) -> None:
        """Two failures: one edit, before attempt 2 only, then a failed step."""
        for job_name, _, name in SITES:
            with self.subTest(job=job_name):
                status, output, calls, after = self.run_install(job_name, name, MIRRORS, 2)
                self.assertNotEqual(status, 0)
                self.assertEqual(calls, ['update:1', 'update:0'])
                self.assertEqual(output.count('fallback mirror'), 1)
                self.assertNotIn('azure', after or '')

    def test_a_missing_list_is_not_an_error(self) -> None:
        """An image without the mirror file still gets its plain retry."""
        for job_name, _, name in SITES:
            with self.subTest(job=job_name):
                status, output, calls, _ = self.run_install(job_name, name, None, 1)
                self.assertEqual((status, calls), (0, ['update:0', 'update:0', 'install:0']), output)


def matrix_engines() -> 'list[str]':
    """``engine-tests``'s matrix, in order."""
    match = re.search(r'(?m)^        engine:\n((?:          - \S+\n)+)', job('engine-tests'))
    if match is None:
        raise AssertionError('engine-tests has no engine matrix')
    return re.findall(r'- (\S+)', match.group(1))


def job_env(job_name: 'str', key: 'str') -> 'str':
    """The raw value of ``key`` in ``job_name``'s job-level ``env:``."""
    match = re.search(rf'(?m)^      {re.escape(key)}: (.+)$', job(job_name))
    if match is None:
        raise AssertionError(f'{job_name} sets no job-level {key}')
    return match.group(1)


def engine_packages() -> 'dict[str, str]':
    """``engine-tests``'s APT_PACKAGES, evaluated for every engine in its matrix."""
    expression = job_env('engine-tests', 'APT_PACKAGES')
    if not re.fullmatch(r"\$\{\{ (?:matrix\.engine == '\w+' && '[^']*' \|\| )+'' \}\}", expression):
        raise AssertionError(f'unrecognised APT_PACKAGES expression: {expression}')
    named = dict(re.findall(r"matrix\.engine == '(\w+)' && '([^']*)'", expression))
    return {engine: named.get(engine, '') for engine in matrix_engines()}


class TestPackageListsAgree(_Stubbed):
    """The key describes APT_PACKAGES, so it must be what the install step installs."""

    def test_every_engine_named_in_the_expression_is_in_the_matrix(self) -> None:
        """A renamed engine would silently fall through to ``''``."""
        expression = job_env('engine-tests', 'APT_PACKAGES')
        named = set(re.findall(r"matrix\.engine == '(\w+)'", expression))
        self.assertTrue(named)
        self.assertLessEqual(named, set(matrix_engines()))

    def test_engine_tests_installs_what_it_plans(self) -> None:
        """Per engine, the install step's apt-get operands equal APT_PACKAGES."""
        script = step_script(job('engine-tests'), SITES[0][2])
        for engine, packages in engine_packages().items():
            with self.subTest(engine=engine):
                self.reset()
                status, output = self.run_script(script, {'ENGINE': engine})
                self.assertEqual(status, 0, output)
                self.assertEqual(self.installed(), packages.split())

    def test_pypcap_parity_installs_what_it_plans(self) -> None:
        """The parity job's literal list equals its install step's operands."""
        packages = job_env('pypcap-parity', 'APT_PACKAGES')
        status, output = self.run_script(step_script(job('pypcap-parity'), SITES[1][2]), {})
        self.assertEqual(status, 0, output)
        self.assertEqual(self.installed(), packages.split())
        self.assertTrue(self.installed())


#: ``apt-get install -s`` output: noise, ``Conf`` lines and unsorted ``Inst`` lines.
SIMULATION = ('NOTE: This is only a simulation!\n'
              'Inst tshark (4.2.2-1.1build3 Ubuntu:24.04/noble [amd64])\n'
              'Conf tshark (4.2.2-1.1build3 Ubuntu:24.04/noble [amd64])\n'
              'Inst libwireshark17t64 (4.2.2-1.1build3 Ubuntu:24.04/noble [amd64])\n')


class TestCacheKey(_Stubbed):
    """The key moves with any version and nothing else; restore-keys stays on one image and set."""

    def plan(self, job_name: 'str', name: 'str', simulation: 'str') -> 'dict[str, str]':
        """Run the plan step against ``simulation``; return what it wrote to GITHUB_OUTPUT."""
        sim = self.tmp / 'sim'
        sim.write_text(simulation, encoding='utf-8')
        out = self.tmp / 'output'
        out.write_text('', encoding='utf-8')
        status, output = self.run_script(step_script(job(job_name), name), {
            'STUB_SIM': str(sim), 'GITHUB_OUTPUT': str(out), 'ImageOS': 'ubuntu24',
            'RUNNER_ARCH': 'X64', 'APT_SET': 'SomeSet', 'APT_PACKAGES': 'tshark'})
        self.assertEqual(status, 0, output)
        return dict(line.split('=', 1) for line in out.read_text(encoding='utf-8').splitlines())

    def test_the_key_format(self) -> None:
        """``apt-debs-<ImageOS>-<arch>-<APT_SET>-`` then 16 hex of the sorted Inst lines."""
        inst = sorted(line for line in SIMULATION.splitlines() if line.startswith('Inst '))
        digest = hashlib.sha256(('\n'.join(inst) + '\n').encode()).hexdigest()[:16]
        for job_name, name, _ in SITES:
            with self.subTest(job=job_name):
                outputs = self.plan(job_name, name, SIMULATION)
                self.assertEqual(outputs, {'restore-prefix': 'apt-debs-ubuntu24-X64-SomeSet-',
                                           'key': f'apt-debs-ubuntu24-X64-SomeSet-{digest}'})

    def test_order_does_not_move_the_key_and_a_version_does(self) -> None:
        """Sorted, so apt's ordering is irrelevant; any version change is a new key."""
        lines = SIMULATION.splitlines(True)
        for job_name, name, _ in SITES:
            with self.subTest(job=job_name):
                key = self.plan(job_name, name, SIMULATION)['key']
                self.assertEqual(self.plan(job_name, name, ''.join(reversed(lines)))['key'], key)
                bumped = SIMULATION.replace('(4.2.2-1.1build3 Ubuntu', '(4.2.2-1.1build4 Ubuntu', 1)
                self.assertNotEqual(self.plan(job_name, name, bumped)['key'], key)

    def test_nothing_to_download_means_no_key(self) -> None:
        """No Inst lines, no cache steps: nothing is written for them to read."""
        for job_name, name, _ in SITES:
            with self.subTest(job=job_name):
                self.assertEqual(self.plan(job_name, name, 'NOTE: This is only a simulation!\n'), {})

    def test_restore_and_save_use_the_plan_and_the_same_path(self) -> None:
        """restore-keys is the plan's prefix only; restore and save share key and path."""
        for job_name, _, _ in SITES:
            with self.subTest(job=job_name):
                text = job(job_name)
                restore = re.search(r'(?ms)uses: actions/cache/restore@\S+\n        with:\n(.*?)\n\n', text)
                save = re.search(r'(?ms)uses: actions/cache/save@\S+\n        with:\n(.*?)\n\n', text)
                self.assertIsNotNone(restore)
                self.assertIsNotNone(save)
                restore_with = dict(re.findall(r'(?m)^          ([\w-]+): (.+)$', restore.group(1)))  # type: ignore[union-attr]
                save_with = dict(re.findall(r'(?m)^          ([\w-]+): (.+)$', save.group(1)))  # type: ignore[union-attr]
                self.assertEqual(restore_with, {
                    'path': '${{ runner.temp }}/apt-debs/*.deb',
                    'key': '${{ steps.apt-plan.outputs.key }}',
                    'restore-keys': '${{ steps.apt-plan.outputs.restore-prefix }}'})
                self.assertEqual(save_with, {'path': restore_with['path'], 'key': restore_with['key']})


class TestOneSaverPerKey(unittest.TestCase):
    """Two jobs saving one key race, and the loser logs ``Unable to reserve cache``."""

    def test_only_one_parity_cell_saves(self) -> None:
        """APT_CACHE_SAVE selects exactly one of the parity matrix's Python versions."""
        value = job_env('pypcap-parity', 'APT_CACHE_SAVE')
        match = re.fullmatch(r"\$\{\{ matrix\.python-version == '([\d.]+)' \}\}", value)
        self.assertIsNotNone(match, value)
        versions = re.findall(r'(?m)^          - "([\d.]+)"$', job('pypcap-parity'))
        self.assertIn(match.group(1), versions)  # type: ignore[union-attr]
        self.assertGreater(len(versions), 1)

    def test_each_engine_job_saves_its_own_key(self) -> None:
        """engine-tests has one job per APT_SET, so each saves."""
        self.assertEqual(job_env('engine-tests', 'APT_CACHE_SAVE'), "'true'")

    def test_collect_and_save_are_gated_on_it(self) -> None:
        """Both steps that only matter for a save check the flag."""
        for job_name, _, _ in SITES:
            with self.subTest(job=job_name):
                steps = re.split(r'(?m)^      - ', job(job_name))
                for marker in ('name: Collect ', 'uses: actions/cache/save@'):
                    blocks = [block for block in steps if marker in block]
                    self.assertEqual(len(blocks), 1, marker)
                    self.assertIn("env.APT_CACHE_SAVE == 'true'", blocks[0])


if __name__ == '__main__':
    unittest.main()
