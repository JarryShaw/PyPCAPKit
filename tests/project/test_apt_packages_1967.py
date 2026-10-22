# -*- coding: utf-8 -*-
"""#1967: :file:`util/apt_packages.py`, the apt steps of ``engine-tests`` and ``pypcap-parity``.

* :class:`TestPlan`, :class:`TestSeed`, :class:`TestInstall` and :class:`TestCollect`
  run each subcommand in this process with :func:`subprocess.run` stubbed, so every
  command it would run, and every failure of one, is checked without ``sudo`` or apt.
* :class:`TestTheFormerShellAgrees` runs the shell the steps held before the script,
  and then the steps' own ``run:``, against the same stand-in ``sudo``, ``timeout``,
  ``apt-get``, ``dpkg``, ``dpkg-deb``, ``dpkg-query`` and ``debconf-set-selections``,
  and requires the same status, output, commands and files.
* :class:`TestTheStepsRunTheScript` pins each apt step to the script with its
  ``id``, ``if:``, ``continue-on-error`` and ``timeout-minutes``, the KTLO twin to
  the same steps, and the AppArmor step (#2019) to its inline shell; no other step
  in any workflow keeps apt shell of its own, and #1672's scan of what a KTLO leg
  may write sees the script's warnings.

The retry, the fallback mirror and the cache key are also run through the steps by
:mod:`tests.project.test_unit_tests_queue` and :mod:`tests.project.test_workflow_apt_cache`.

"""

from __future__ import annotations

import contextlib
import hashlib
import io
import os
import pathlib
import shlex
import shutil
import subprocess  # nosec: B404
import sys
import tempfile
import textwrap
import unittest
from typing import TYPE_CHECKING
from unittest import mock

from tests._workflows import WORKFLOWS, load, steps
from tests.project.test_ktlo_legs_stay_green_1672 import KTLO_COMMANDS, commands
from tests.project.test_unit_tests_queue import IMAGE_PYTHON
from util import apt_packages

if TYPE_CHECKING:
    from typing import Any, Callable, Iterator, Optional

ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOW = 'unit-tests.yml'
SCRIPT = 'util/apt_packages.py'

#: ``apt-get install -s`` output: noise, ``Conf`` lines and unsorted ``Inst`` lines.
SIMULATION = (b'NOTE: This is only a simulation!\n'
              b'Inst tshark (4.2.2-1.1build3 Ubuntu:24.04/noble [amd64])\n'
              b'Conf tshark (4.2.2-1.1build3 Ubuntu:24.04/noble [amd64])\n'
              b'Inst libwireshark17t64 (4.2.2-1.1build3 Ubuntu:24.04/noble [amd64])\n')
INST = (b'Inst libwireshark17t64 (4.2.2-1.1build3 Ubuntu:24.04/noble [amd64])\n'
        b'Inst tshark (4.2.2-1.1build3 Ubuntu:24.04/noble [amd64])')
#: The runner image's mirror list, as configure-apt-sources.sh writes it.
MIRRORS = ('http://azure.archive.ubuntu.com/ubuntu/\tpriority:1\n'
           'https://archive.ubuntu.com/ubuntu/\tpriority:2\n'
           'https://security.ubuntu.com/ubuntu/\tpriority:3\n')

UPDATE = ['sudo', 'timeout', '60', 'apt-get', 'update']
DPKG = ['sudo', 'dpkg', '--configure', '-a']
DEBCONF = ['sudo', 'debconf-set-selections']


def install_command(*packages: 'str') -> 'list[str]':
    return ['sudo', 'DEBIAN_FRONTEND=noninteractive', 'timeout', '180', 'apt-get', 'install', '-y',
            '--no-install-recommends', *packages]


class Runner:
    """A stand-in :func:`subprocess.run`: records each command, answers from ``respond``."""

    def __init__(self, respond: 'Callable[[list[str], dict[str, Any]], tuple[int, bytes]]') -> None:
        self.respond = respond
        self.calls = []  # type: list[tuple[list[str], dict[str, Any]]]

    def __call__(self, command: 'list[str]', check: 'bool' = False,
                 **kwargs: 'Any') -> 'subprocess.CompletedProcess[bytes]':
        assert check is False  # nosec: B101
        self.calls.append((list(command), kwargs))
        status, stdout = self.respond(list(command), kwargs)
        return subprocess.CompletedProcess(command, status, stdout if kwargs.get('stdout') else None)

    @property
    def commands(self) -> 'list[list[str]]':
        return [command for command, _ in self.calls]


class _InProcess(unittest.TestCase):
    """A scratch directory, the script's environment, and a way to run :func:`apt_packages.main`."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-1967-apt-')  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.tmp = pathlib.Path(tmp.name)
        self.runner_temp = self.tmp / 'runner-temp'
        self.runner_temp.mkdir()
        self.output = self.tmp / 'output'
        self.output.write_text('earlier=1\n', encoding='utf-8')
        self.archives = self.tmp / 'archives'
        self.archives.mkdir()
        self.mirrors = self.tmp / 'apt-mirrors.txt'
        self.environ = {'APT_PACKAGES': 'tshark', 'APT_SET': 'PyShark', 'ImageOS': 'ubuntu24',
                        'RUNNER_ARCH': 'X64', 'GITHUB_OUTPUT': str(self.output),
                        'RUNNER_TEMP': str(self.runner_temp)}

    def main(self, args: 'list[str]',
             respond: 'Callable[[list[str], dict[str, Any]], tuple[int, bytes]]') -> 'tuple[int, str, Runner]':
        """``apt_packages.main(args)`` with ``respond`` for every command; status, output, runner."""
        runner = Runner(respond)
        out = io.BytesIO()
        stdout = io.TextIOWrapper(out, encoding='utf-8', write_through=True)
        with mock.patch.dict(os.environ, self.environ, clear=True), \
                mock.patch.object(apt_packages.subprocess, 'run', runner), \
                mock.patch.object(apt_packages.sys, 'stdout', stdout):
            status = apt_packages.main(args)
        return status, out.getvalue().decode('utf-8'), runner


def answers(**by_command: 'Any') -> 'Callable[[list[str], dict[str, Any]], tuple[int, bytes]]':
    """A ``respond`` keyed on a command's name: ``update``, ``simulate``, ``install`` or the program.

    Each value is an ``(status, stdout)`` pair, or a list of them taken in turn.

    """
    queues = {key: list(value) if isinstance(value, list) else [value] for key, value in by_command.items()}

    def respond(command: 'list[str]', _: 'dict[str, Any]') -> 'tuple[int, bytes]':
        if command[:2] == ['apt-get', 'install']:
            key = 'simulate'
        elif 'apt-get' in command:
            key = command[command.index('apt-get') + 1]
        else:
            key = command[1] if command[0] == 'sudo' else command[0]
        queue = queues.get(key.replace('-', '_'), [(0, b'')])
        return queue.pop(0) if len(queue) > 1 else queue[0]
    return respond


class TestPlan(_InProcess):
    """Up to two updates, then the key of the sorted ``Inst`` lines of a simulation."""

    def key(self, prefix: 'str') -> 'str':
        return prefix + hashlib.sha256(INST + b'\n').hexdigest()[:16]

    def test_a_clean_plan_writes_the_key(self) -> None:
        status, output, runner = self.main(['plan'], answers(simulate=(0, SIMULATION)))
        self.assertEqual(status, 0)
        self.assertEqual(runner.commands, [UPDATE, ['apt-get', 'install', '-s', '--no-install-recommends', 'tshark']])
        self.assertEqual(runner.calls[1][1], {'stdout': subprocess.PIPE})
        self.assertEqual(output, 'To download:\n' + INST.decode() + '\n')
        prefix = 'apt-debs-ubuntu24-X64-PyShark-'
        self.assertEqual(self.output.read_text(encoding='utf-8'),
                         f'earlier=1\nrestore-prefix={prefix}\nkey={self.key(prefix)}\n')

    def test_every_package_is_simulated(self) -> None:
        self.environ['APT_PACKAGES'] = ' build-essential\tlibpcap-dev  tshark '
        _, _, runner = self.main(['plan'], answers(simulate=(0, b'')))
        self.assertEqual(runner.commands[1][4:], ['build-essential', 'libpcap-dev', 'tshark'])

    def test_image_os_falls_back_to_unknown(self) -> None:
        for value in (None, ''):
            with self.subTest(ImageOS=value):
                self.output.write_text('', encoding='utf-8')
                if value is None:
                    del self.environ['ImageOS']
                else:
                    self.environ['ImageOS'] = value
                self.assertEqual(self.main(['plan'], answers(simulate=(0, SIMULATION)))[0], 0)
                self.assertIn('restore-prefix=apt-debs-unknown-X64-PyShark-\n',
                              self.output.read_text(encoding='utf-8'))

    def test_nothing_to_download_writes_no_key(self) -> None:
        for simulation in (b'', b'NOTE: This is only a simulation!\n', b'Conf tshark (1)\n Inst indented\n'):
            with self.subTest(simulation=simulation):
                status, output, _ = self.main(['plan'], answers(simulate=(0, simulation)))
                self.assertEqual((status, output), (0, 'To download:\n(nothing)\n'))
                self.assertEqual(self.output.read_text(encoding='utf-8'), 'earlier=1\n')

    def test_one_failed_update_is_retried(self) -> None:
        status, output, runner = self.main(['plan'], answers(update=[(124, b''), (0, b'')],
                                                             simulate=(0, SIMULATION)))
        self.assertEqual(status, 0)
        self.assertEqual(runner.commands[:2], [UPDATE, UPDATE])
        self.assertTrue(output.startswith('::warning title=apt-get update attempt 1 of 2 failed (PyShark)::'
                                          'apt-get update failed or exceeded its 60s bound.\nTo download:\n'), output)

    def test_two_failed_updates_fail_before_the_simulation(self) -> None:
        status, output, runner = self.main(['plan'], answers(update=(100, b'')))
        self.assertEqual(status, 1)
        self.assertEqual(runner.commands, [UPDATE, UPDATE])
        self.assertEqual(output.splitlines(), [
            f'::warning title=apt-get update attempt {n} of 2 failed (PyShark)::apt-get update failed or '
            'exceeded its 60s bound.' for n in (1, 2)])
        self.assertEqual(self.output.read_text(encoding='utf-8'), 'earlier=1\n')

    def test_a_failed_simulation_ends_with_its_status(self) -> None:
        for code, expected in ((100, 100), (-9, 137)):
            with self.subTest(code=code):
                status, output, _ = self.main(['plan'], answers(simulate=(code, SIMULATION)))
                self.assertEqual((status, output), (expected, ''))
                self.assertEqual(self.output.read_text(encoding='utf-8'), 'earlier=1\n')

    def test_a_missing_variable_is_an_error(self) -> None:
        for name in ('APT_PACKAGES', 'RUNNER_ARCH', 'GITHUB_OUTPUT'):
            with self.subTest(variable=name):
                del self.environ[name]
                with self.assertRaises(KeyError):
                    self.main(['plan'], answers(simulate=(0, SIMULATION)))
                self.environ[name] = 'restored' if name != 'GITHUB_OUTPUT' else str(self.output)


class TestSeed(_InProcess):
    """The restored files into apt's archive with ``sudo cp``, then their count."""

    def test_the_files_are_copied_and_counted(self) -> None:
        cache = self.runner_temp / 'apt-debs'
        (cache / 'nested').mkdir(parents=True)
        for name in ('b.deb', 'a.deb', 'nested/c.deb', 'notes.txt'):
            (cache / name).write_bytes(b'')
        status, output, runner = self.main(['seed', '--archives', str(self.archives)], answers())
        self.assertEqual(status, 0)
        self.assertEqual(runner.commands, [['sudo', 'cp', str(cache / 'a.deb'), str(cache / 'b.deb'),
                                            f'{self.archives}/']])
        self.assertEqual(output, 'Seeded 3 .deb files\n')

    def test_the_default_archive_is_apts(self) -> None:
        (self.runner_temp / 'apt-debs').mkdir()
        (self.runner_temp / 'apt-debs' / 'a.deb').write_bytes(b'')
        _, _, runner = self.main(['seed'], answers())
        self.assertEqual(runner.commands[0][-1], '/var/cache/apt/archives/')

    def test_nothing_restored_fails_on_the_pattern(self) -> None:
        for code, expected in ((1, 1), (-15, 143)):
            with self.subTest(code=code):
                status, output, runner = self.main(['seed', '--archives', str(self.archives)], answers(cp=(code, b'')))
                self.assertEqual((status, output), (expected, ''))
                self.assertEqual(runner.commands, [['sudo', 'cp', str(self.runner_temp / 'apt-debs' / '*.deb'),
                                                    f'{self.archives}/']])


class TestInstall(_InProcess):
    """debconf for tshark, then up to two update-and-install attempts, the second on a fallback mirror."""

    def install(self, *args: 'str', **by_command: 'Any') -> 'tuple[int, str, Runner]':
        return self.main(['install', '--mirrors', str(self.mirrors), *args], answers(**by_command))

    def test_nothing_to_install_runs_nothing(self) -> None:
        for packages in ('', '  '):
            with self.subTest(packages=packages):
                self.environ['APT_PACKAGES'] = packages
                status, output, runner = self.install()
                self.assertEqual((status, output, runner.commands), (0, '', []))

    def test_a_clean_install(self) -> None:
        self.mirrors.write_text(MIRRORS, encoding='utf-8')
        status, output, runner = self.install()
        self.assertEqual((status, output), (0, ''))
        self.assertEqual(runner.commands, [DEBCONF, UPDATE, install_command('tshark')])
        self.assertEqual(runner.calls[0][1], {'input': apt_packages.DEBCONF})
        self.assertEqual(self.mirrors.read_text(encoding='utf-8'), MIRRORS)

    def test_debconf_only_for_tshark(self) -> None:
        for packages, debconf in (('libpcap0.8', False), ('build-essential libpcap-dev', False),
                                  ('build-essential libpcap-dev tshark', True), ('tshark-extra', False)):
            with self.subTest(packages=packages):
                self.environ['APT_PACKAGES'] = packages
                _, _, runner = self.install()
                self.assertEqual(runner.commands[0] == DEBCONF, debconf)
                self.assertEqual(runner.commands[-1], install_command(*packages.split()))

    def test_a_failed_debconf_ends_with_its_status(self) -> None:
        status, output, runner = self.install(debconf_set_selections=(3, b''))
        self.assertEqual((status, output, runner.commands), (3, '', [DEBCONF]))

    def test_a_failed_first_attempt_retries_on_the_fallback_mirror(self) -> None:
        self.mirrors.write_text(MIRRORS, encoding='utf-8')
        for failing in ('update', 'install'):
            with self.subTest(failing=failing):
                status, output, runner = self.install('--name', 'PyShark', **{failing: [(124, b''), (0, b'')]})
                self.assertEqual(status, 0)
                sed = ['sudo', 'sed', '-i', r'/azure\.archive\.ubuntu\.com/d', str(self.mirrors)]
                first = [UPDATE] if failing == 'update' else [UPDATE, install_command('tshark')]
                self.assertEqual(runner.commands, [DEBCONF, *first, DPKG, sed, UPDATE, install_command('tshark')])
                # The stand-in sed changes nothing, so the list's first line is still azure's.
                self.assertEqual(output.splitlines(), [
                    '::warning title=apt attempt 1 of 2 failed (PyShark)::apt-get update or install failed or '
                    'exceeded its per-attempt bound; retrying once.',
                    '::warning title=apt retry on a fallback mirror (PyShark)::Retrying against '
                    'http://azure.archive.ubuntu.com/ubuntu/ instead of azure.archive.ubuntu.com, resuming the '
                    'partial download.'])

    def test_the_mirror_named_is_the_first_line_after_the_edit(self) -> None:
        self.mirrors.write_text(MIRRORS, encoding='utf-8')
        edited = ''.join(MIRRORS.splitlines(True)[1:])
        otherwise = answers(update=[(1, b''), (0, b'')])

        def respond(command: 'list[str]', kwargs: 'dict[str, Any]') -> 'tuple[int, bytes]':
            if 'sed' in command:
                self.mirrors.write_text(edited, encoding='utf-8')
            return otherwise(command, kwargs)
        status, output, _ = self.main(['install', '--mirrors', str(self.mirrors)], respond)
        self.assertEqual(status, 0)
        self.assertIn('::warning title=apt retry on a fallback mirror::Retrying against '
                      'https://archive.ubuntu.com/ubuntu/ instead', output)

    def test_no_fallback_without_another_http_mirror(self) -> None:
        for mirrors in (None, '', 'http://azure.archive.ubuntu.com/ubuntu/\tpriority:1\n',
                        'ftp://elsewhere/\n http://indented/\n'):
            with self.subTest(mirrors=mirrors):
                if mirrors is None:
                    if self.mirrors.exists():
                        self.mirrors.unlink()
                else:
                    self.mirrors.write_text(mirrors, encoding='utf-8')
                status, output, runner = self.install(update=[(1, b''), (0, b'')])
                self.assertEqual(status, 0)
                self.assertFalse([command for command in runner.commands if 'sed' in command])
                self.assertNotIn('fallback mirror', output)

    def test_a_directory_is_not_a_mirror_list(self) -> None:
        self.mirrors.mkdir()
        status, _, runner = self.install(update=[(1, b''), (0, b'')])
        self.assertEqual(status, 0)
        self.assertFalse([command for command in runner.commands if 'sed' in command])

    def test_a_failed_edit_is_not_announced(self) -> None:
        self.mirrors.write_text(MIRRORS, encoding='utf-8')
        status, output, runner = self.install(update=[(1, b''), (0, b'')], sed=(4, b''))
        self.assertEqual(status, 0)
        self.assertEqual(sum(1 for command in runner.commands if 'sed' in command), 1)
        self.assertNotIn('fallback mirror', output)

    def test_two_failures_fail_after_one_edit_and_two_repairs(self) -> None:
        self.mirrors.write_text(MIRRORS, encoding='utf-8')
        status, output, runner = self.install(update=(124, b''), dpkg=(1, b''))
        self.assertEqual(status, 1)
        self.assertEqual(runner.commands.count(UPDATE), 2)
        self.assertEqual(runner.commands.count(DPKG), 2)
        self.assertEqual(sum(1 for command in runner.commands if 'sed' in command), 1)
        self.assertEqual([line.split('::')[1] for line in output.splitlines()], [
            'warning title=apt attempt 1 of 2 failed', 'warning title=apt retry on a fallback mirror',
            'warning title=apt attempt 2 of 2 failed'])

    def test_the_default_mirror_list_is_the_images(self) -> None:
        self.assertEqual(apt_packages.MIRRORS, '/etc/apt/apt-mirrors.txt')
        with mock.patch.object(apt_packages, 'fallback') as fallback:
            self.main(['install'], answers(update=[(1, b''), (0, b'')]))
        fallback.assert_called_once_with('/etc/apt/apt-mirrors.txt', '')


class TestCollect(_InProcess):
    """Each archived ``.deb`` at its installed version into a fresh cache directory."""

    def deb(self, name: 'str', package: 'str', version: 'str', arch: 'str' = 'amd64') -> 'pathlib.Path':
        path = self.archives / name
        path.write_text(f'Package={package}\nVersion={version}\nArchitecture={arch}\n', encoding='utf-8')
        return path

    def respond(self, installed: 'dict[str, str]', broken: 'tuple[str, ...]' = ()) -> 'Callable[..., Any]':
        def respond(command: 'list[str]', _: 'dict[str, Any]') -> 'tuple[int, bytes]':
            if command[0] == 'dpkg-deb':
                if pathlib.Path(command[2]).name in broken:
                    return 2, b''
                fields = dict(line.split('=', 1) for line in pathlib.Path(command[2]).read_text().splitlines())
                return 0, fields[command[3]].encode() + b'\n\n'
            if command[0] == 'dpkg-query':
                found = installed.get(command[-1])
                return (0, found.encode()) if found is not None else (1, b'')
            raise AssertionError(command)
        return respond

    def test_only_the_installed_versions_are_kept(self) -> None:
        self.deb('tshark_4.2.deb', 'tshark', '4.2')
        self.deb('old_1.deb', 'old', '1')
        self.deb('gone_1.deb', 'gone', '1')
        self.deb('i386_1.deb', 'lib', '1', 'i386')
        (self.archives / 'broken.deb').symlink_to(self.archives / 'nowhere')
        (self.archives / 'partial').mkdir()
        out = self.runner_temp / 'apt-debs'
        out.mkdir()
        (out / 'stale.deb').write_bytes(b'')
        status, output, runner = self.main(['collect', '--archives', str(self.archives)], self.respond(
            {'tshark:amd64': '4.2', 'old:amd64': '2', 'lib:amd64': '1'}))
        self.assertEqual((status, output), (0, 'Collected 1 .deb files\n'))
        self.assertEqual(sorted(path.name for path in out.iterdir()), ['tshark_4.2.deb'])
        self.assertEqual(runner.commands[:4], [
            ['dpkg-deb', '-f', str(self.archives / 'gone_1.deb'), 'Package'],
            ['dpkg-deb', '-f', str(self.archives / 'gone_1.deb'), 'Version'],
            ['dpkg-deb', '-f', str(self.archives / 'gone_1.deb'), 'Architecture'],
            ['dpkg-query', '-W', '-f', '${Version}', 'gone:amd64']])
        self.assertEqual(runner.calls[3][1], {'stdout': subprocess.PIPE, 'stderr': subprocess.DEVNULL})
        self.assertFalse([command for command in runner.commands if str(self.archives / 'broken.deb') in command])

    def test_an_empty_archive_collects_nothing(self) -> None:
        out = self.runner_temp / 'apt-debs'
        out.write_text('a file in the way', encoding='utf-8')
        status, output, runner = self.main(['collect', '--archives', str(self.archives)], self.respond({}))
        self.assertEqual((status, output, runner.commands), (0, 'Collected 0 .deb files\n', []))
        self.assertTrue(out.is_dir())

    def test_a_failed_dpkg_deb_ends_with_its_status(self) -> None:
        self.deb('a.deb', 'a', '1')
        self.deb('b.deb', 'b', '1')
        status, output, runner = self.main(['collect', '--archives', str(self.archives)],
                                           self.respond({'a:amd64': '1'}, broken=('b.deb',)))
        self.assertEqual((status, output), (2, ''))
        self.assertEqual(runner.commands[-1], ['dpkg-deb', '-f', str(self.archives / 'b.deb'), 'Package'])
        self.assertEqual([path.name for path in (self.runner_temp / 'apt-debs').iterdir()], ['a.deb'])

    def test_the_default_archive_is_apts(self) -> None:
        with mock.patch.object(apt_packages, 'debs', return_value=[]) as debs:
            self.main(['collect'], self.respond({}))
        debs.assert_called_once_with('/var/cache/apt/archives')


class TestArguments(_InProcess):
    """One subcommand, and only its own options."""

    def test_refused(self) -> None:
        for args in ([], ['update'], ['plan', 'extra'], ['seed', '--mirrors', 'x'], ['install', 'tshark'],
                     ['collect', '--name', 'x']):
            with self.subTest(args=args), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    self.main(args, answers())
                self.assertEqual(raised.exception.code, 2)


#: The steps' shell before the script, each with the runner paths it named.
FORMER_PLAN = textwrap.dedent(r'''
    set -eu
    for attempt in 1 2; do
      if sudo timeout 60 apt-get update; then
        break
      fi
      echo "::warning title=apt-get update attempt $attempt of 2 failed (${APT_SET})::apt-get update failed or exceeded its 60s bound."
      [ "$attempt" = 1 ] || exit 1
    done
    # shellcheck disable=SC2086
    sim=$(apt-get install -s --no-install-recommends $APT_PACKAGES)
    plan=$(printf '%s\n' "$sim" | grep '^Inst ' | sort || true)
    printf 'To download:\n%s\n' "${plan:-(nothing)}"
    if [ -n "$plan" ]; then
      prefix="apt-debs-${ImageOS:-unknown}-${RUNNER_ARCH}-${APT_SET}-"
      echo "restore-prefix=$prefix" >> "$GITHUB_OUTPUT"
      echo "key=${prefix}$(printf '%s\n' "$plan" | sha256sum | cut -c1-16)" >> "$GITHUB_OUTPUT"
    fi
''').lstrip()  # noqa: E501
FORMER_SEED = textwrap.dedent(r'''
    set -eu
    sudo cp "$RUNNER_TEMP"/apt-debs/*.deb /var/cache/apt/archives/
    echo "Seeded $(find "$RUNNER_TEMP/apt-debs" -name '*.deb' | wc -l) .deb files"
''').lstrip()
FORMER_RETRY = textwrap.dedent(r'''
    for attempt in 1 2; do
      if sudo timeout 60 apt-get update \
         && sudo DEBIAN_FRONTEND=noninteractive timeout 180 apt-get install -y --no-install-recommends PACKAGES; then
        SUCCEED
      fi
      echo "::warning title=apt attempt $attempt of 2 failed SUFFIX::apt-get update or install failed or exceeded its per-attempt bound; retrying once."
      sudo dpkg --configure -a || true
      if [ "$attempt" = 1 ] && [ -f "$mirrors" ] \
         && grep -v 'azure\.archive\.ubuntu\.com' "$mirrors" | grep -q '^http' \
         && sudo sed -i '/azure\.archive\.ubuntu\.com/d' "$mirrors"; then
        echo "::warning title=apt retry on a fallback mirror SUFFIX::Retrying against $(head -n 1 "$mirrors" | cut -f 1) instead of azure.archive.ubuntu.com, resuming the partial download."
      fi
    done
''')  # noqa: E501
FORMER_ENGINE_INSTALL = ('set -eu\nmirrors=/etc/apt/apt-mirrors.txt\napt_install() {\n'
                         + textwrap.indent(FORMER_RETRY.lstrip().replace('PACKAGES', '"$@"')
                                           .replace('SUCCEED', 'return 0').replace(' SUFFIX', ' (${ENGINE})'), '  ')
                         + '  return 1\n}\n' + textwrap.dedent('''\
    if [ "$ENGINE" = "PyShark" ]; then
      echo "wireshark-common wireshark-common/install-setuid boolean false" | sudo debconf-set-selections
      apt_install tshark
    elif [ "$ENGINE" = "PCAP_CT" ]; then
      apt_install libpcap0.8
    elif [ "$ENGINE" = "PyPCAP" ]; then
      apt_install build-essential libpcap-dev
    fi
'''))
FORMER_PARITY_INSTALL = ('set -eu\n'
                         'echo "wireshark-common wireshark-common/install-setuid boolean false" '
                         '| sudo debconf-set-selections\nmirrors=/etc/apt/apt-mirrors.txt\n'
                         + FORMER_RETRY.lstrip().replace('PACKAGES', 'build-essential libpcap-dev tshark')
                         .replace('SUCCEED', 'exit 0').replace(' SUFFIX', '') + 'exit 1\n')
FORMER_COLLECT = textwrap.dedent(r'''
    set -eu
    out="$RUNNER_TEMP/apt-debs"
    rm -rf "$out"
    mkdir -p "$out"
    for deb in /var/cache/apt/archives/*.deb; do
      [ -e "$deb" ] || continue
      pkg=$(dpkg-deb -f "$deb" Package)
      ver=$(dpkg-deb -f "$deb" Version)
      arch=$(dpkg-deb -f "$deb" Architecture)
      # shellcheck disable=SC2016
      if [ "$(dpkg-query -W -f '${Version}' "$pkg:$arch" 2>/dev/null || true)" = "$ver" ]; then
        cp "$deb" "$out/"
      fi
    done
    echo "Collected $(find "$out" -name '*.deb' | wc -l) .deb files"
''').lstrip()

#: ``engine-tests``'s and ``pypcap-parity``'s apt steps, ``(name, id, if, continue-on-error,
#: timeout-minutes, run)``, in order, the AppArmor step (#2019) between install and collect.
ENGINE_STEPS = (
    ("Plan this engine's system packages", 'apt-plan', "env.APT_PACKAGES != ''", None, 4,
     f'{IMAGE_PYTHON} {SCRIPT} plan'),
    ("Seed apt's archive with this engine's cached .deb files", None,
     "steps.apt-cache.outputs.cache-matched-key != ''", None, None, f'{IMAGE_PYTHON} {SCRIPT} seed'),
    ("Install this engine's system packages", None, None, None, 10,
     f'{IMAGE_PYTHON} {SCRIPT} install --name "$ENGINE"'),
    ("Collect this engine's installed .deb files for the cache", None,
     "env.APT_CACHE_SAVE == 'true' && steps.apt-plan.outputs.key != '' && steps.apt-cache.outputs.cache-hit != 'true'",
     None, None, f'{IMAGE_PYTHON} {SCRIPT} collect'),
)
KTLO = '${{ matrix.ktlo == true }}'
PARITY_STEPS = (
    ('Plan the system packages', 'apt-plan', "env.APT_PACKAGES != ''", KTLO, 4, f'{IMAGE_PYTHON} {SCRIPT} plan'),
    ("Seed apt's archive with the cached .deb files", 'apt-seed', "steps.apt-cache.outputs.cache-matched-key != ''",
     KTLO, None, f'{IMAGE_PYTHON} {SCRIPT} seed'),
    ('Install libpcap headers, a C toolchain, and tshark', 'apt-install', None, KTLO, 10,
     f'{IMAGE_PYTHON} {SCRIPT} install'),
    ('Collect the installed .deb files for the cache', None, ENGINE_STEPS[3][2], None, None,
     f'{IMAGE_PYTHON} {SCRIPT} collect'),
)
SITES = {'engine-tests': ENGINE_STEPS, 'pypcap-parity': PARITY_STEPS}
#: Each step's former shell, by the subcommand that replaced it.
FORMER = {'plan': FORMER_PLAN, 'seed': FORMER_SEED, 'collect': FORMER_COLLECT}
APPARMOR = 'Let tshark read the checkout past its AppArmor profile'
#: Text only the apt steps' former shell held.
INLINE = ('apt-get', 'dpkg', 'debconf-set-selections', 'apt-mirrors', '/var/cache/apt', 'apt_install')

#: Stand-ins, each logging its call to ``$CALLS``. ``apt-get``'s first ``$FAIL_UPDATES``
#: updates and ``$FAIL_INSTALLS`` installs fail; ``install -s`` prints ``$STUB_SIM`` and
#: exits ``$SIM_STATUS``. ``dpkg-deb -f`` reads ``Field=value`` lines from the archive
#: itself; ``dpkg-query`` reads ``pkg:arch version`` lines from ``$INSTALLED``.
STUBS = {
    'sudo': 'echo "sudo $*" >> "$CALLS"\nexec env "$@"\n',
    'timeout': 'echo "timeout $1" >> "$CALLS"\nshift\nexec "$@"\n',
    'apt-get': textwrap.dedent('''\
        echo "apt-get $*" >> "$CALLS"
        if [ "$1" = update ]; then
          n=$(grep -c '^apt-get update' "$CALLS")
          echo "Hit:$n http://mirror noble InRelease"
          [ "$n" -gt "${FAIL_UPDATES:-0}" ] || { echo "E: update $n failed" >&2; exit 100; }
        elif [ "$2" = -s ]; then
          cat "$STUB_SIM"
          echo "W: simulated" >&2
          exit "${SIM_STATUS:-0}"
        else
          n=$(grep -c '^apt-get install -y' "$CALLS")
          echo "Setting up $n"
          [ "$n" -gt "${FAIL_INSTALLS:-0}" ] || exit 124
        fi
        '''),
    'dpkg': 'echo "dpkg $*" >> "$CALLS"\necho "dpkg: configured"\nexit "${DPKG_STATUS:-0}"\n',
    'debconf-set-selections': 'echo "debconf $(cat)" >> "$CALLS"\nexit "${DEBCONF_STATUS:-0}"\n',
    'dpkg-deb': textwrap.dedent('''\
        echo "dpkg-deb $*" >> "$CALLS"
        grep -q '^Package=' "$2" 2>/dev/null || { echo "dpkg-deb: error: '$2' is not a Debian format archive" >&2; exit 2; }
        sed -n "s/^$3=//p" "$2"
        '''),  # noqa: E501
    'dpkg-query': textwrap.dedent('''\
        echo "dpkg-query $*" >> "$CALLS"
        v=$(sed -n "s/^$4 //p" "$INSTALLED")
        [ -n "$v" ] || { echo "dpkg-query: no packages found matching $4" >&2; exit 1; }
        printf '%s' "$v"
        '''),
}


@unittest.skipIf(any(shutil.which(tool) is None for tool in ('bash', 'sed', 'grep', 'sort', 'sha256sum', 'cut',
                                                             'find', 'wc', 'head', 'cp', 'env')),
                 'needs bash and the coreutils the former shell ran')
class TestTheFormerShellAgrees(unittest.TestCase):
    """Each step's ``run:`` writes, runs and leaves what its former shell did, on the same stand-ins."""

    def setUp(self) -> None:
        steps(WORKFLOW, 'engine-tests')  # skips the test, not each subtest, without PyYAML
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-1967-apt-parity-')  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.tmp = pathlib.Path(tmp.name)
        self.bin = self.tmp / 'bin'
        self.bin.mkdir()
        for name, body in STUBS.items():
            path = self.bin / name
            path.write_text('#!/bin/bash\n' + body, encoding='utf-8')
            path.chmod(0o755)
        self.mirrors = self.tmp / 'apt-mirrors.txt'
        self.archives = self.tmp / 'archives'
        self.runner_temp = self.tmp / 'runner-temp'
        self.output = self.tmp / 'output'
        self.calls = self.tmp / 'calls'

    def env(self, **extra: 'str') -> 'dict[str, str]':
        env = {key: value for key, value in os.environ.items()
               if key not in ('APT_PACKAGES', 'APT_SET', 'ENGINE', 'ImageOS', 'RUNNER_ARCH', 'RUNNER_TEMP',
                              'GITHUB_OUTPUT', 'PYTHONPATH', 'PYTHONSAFEPATH') and not key.startswith('LC_')}
        env.update(PATH=f'{self.bin}{os.pathsep}{os.environ["PATH"]}', CALLS=str(self.calls), LC_ALL='C',
                   RUNNER_TEMP=str(self.runner_temp), GITHUB_OUTPUT=str(self.output),
                   STUB_SIM=str(self.tmp / 'sim'), INSTALLED=str(self.tmp / 'installed'), RUNNER_ARCH='X64',
                   APT_SET='PyShark', ImageOS='ubuntu24', PYTHONIOENCODING='utf-8')
        env.update(extra)
        return env

    def state(self) -> 'tuple[object, ...]':
        """What a run leaves: its commands, the outputs file, the mirror list, the cache directory."""
        def read(path: 'pathlib.Path') -> 'Optional[str]':
            return path.read_text(encoding='utf-8') if path.is_file() else None
        cache = self.runner_temp / 'apt-debs'
        listing = sorted(str(path.relative_to(cache)) for path in cache.rglob('*')) if cache.is_dir() else None
        return read(self.calls), read(self.output), read(self.mirrors), listing

    def both(self, job: 'str', step: 'str', former: 'str', prepare: 'Callable[[], None]',
             **env: 'str') -> 'tuple[tuple[object, ...], tuple[object, ...]]':
        """``(status, output, *state)`` of the former shell, then of the step's ``run:``, each from ``prepare``."""
        run = next(item for item in steps(WORKFLOW, job) if item.get('name') == step)['run']
        command = run.split(f'{SCRIPT} ', 1)[1].split()[0]
        option = {'install': '--mirrors', 'plan': None}.get(command, '--archives')
        target = self.mirrors if command == 'install' else self.archives
        script = run.replace(IMAGE_PYTHON, shlex.quote(sys.executable))
        if option is not None:
            script = script.replace(f'{SCRIPT} {command}', f'{SCRIPT} {command} {option} {shlex.quote(str(target))}')
        shell = former.replace('/etc/apt/apt-mirrors.txt', str(self.mirrors)) \
                      .replace('/var/cache/apt/archives', str(self.archives))
        found = []
        for text in (shell, script):
            self.reset()
            prepare()
            result = subprocess.run(['bash', '-e', '-c', text], cwd=ROOT, env=self.env(**env),  # nosec: B603
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False, timeout=120)
            found.append((result.returncode, result.stdout.decode('utf-8', 'replace'), *self.state()))
        return found[0], found[1]

    def reset(self) -> None:
        for path in (self.mirrors, self.archives, self.runner_temp, self.output, self.calls,
                     self.tmp / 'sim', self.tmp / 'installed'):
            if path.is_dir():
                shutil.rmtree(path)
            elif path.exists():
                path.unlink()
        self.archives.mkdir()
        self.runner_temp.mkdir()
        self.output.write_text('earlier=1\n', encoding='utf-8')
        self.calls.write_text('', encoding='utf-8')

    def scenarios(self) -> 'Iterator[tuple[str, str, str, dict[str, str]]]':
        """``(job, step, former shell, env)`` for every apt step but the installs."""
        for job, sites in SITES.items():
            for name, _, _, _, _, run in sites:
                command = run.split(f'{SCRIPT} ', 1)[1].split()[0]
                if command in FORMER:
                    yield job, name, FORMER[command], {}

    def test_plan(self) -> None:
        simulations = (SIMULATION, b'', b'NOTE: This is only a simulation!\n', SIMULATION[::-1],
                       b'Inst b (1)\nInst a (2)\nInst B (3)\nInst a-b (1)\nInst a.b (1)\n')
        keyed = 0
        for job, step, former, _ in self.scenarios():
            if former is not FORMER_PLAN:
                continue
            for simulation in simulations:
                for env in ({}, {'FAIL_UPDATES': '1'}, {'FAIL_UPDATES': '2'}, {'SIM_STATUS': '100'},
                            {'ImageOS': ''}, {'APT_PACKAGES': 'build-essential  libpcap-dev\ttshark'}):
                    with self.subTest(job=job, simulation=simulation, env=env):
                        env = {'APT_PACKAGES': 'tshark', **env}
                        old, new = self.both(job, step, former,
                                             lambda: (self.tmp / 'sim').write_bytes(simulation), **env)
                        self.assertEqual(new, old)
                        keyed += 'key=' in str(old[3])
        self.assertTrue(keyed)

    def test_seed(self) -> None:
        def nothing() -> None:
            pass

        def restored() -> None:
            (self.runner_temp / 'apt-debs' / 'deep').mkdir(parents=True)
            for name in ('a.deb', 'b.deb', 'deep/c.deb', 'readme'):
                (self.runner_temp / 'apt-debs' / name).write_text(name, encoding='utf-8')

        for job, step, former, _ in self.scenarios():
            if former is not FORMER_SEED:
                continue
            for prepare in (restored, nothing):
                with self.subTest(job=job, restored=prepare is restored):
                    old, new = self.both(job, step, former, prepare)
                    self.assertEqual(new, old)
                    self.assertEqual(sorted(path.name for path in self.archives.iterdir()),
                                     ['a.deb', 'b.deb'] if prepare is restored else [])

    def test_collect(self) -> None:
        def archive(broken: 'bool') -> 'Callable[[], None]':
            def prepare() -> None:
                for name, fields in (('tshark.deb', 'tshark 4.2 amd64'), ('old.deb', 'old 1 amd64'),
                                     ('gone.deb', 'gone 1 amd64'), ('i386.deb', 'lib 1 i386')):
                    package, version, arch = fields.split()
                    (self.archives / name).write_text(
                        f'Package={package}\nVersion={version}\nArchitecture={arch}\n', encoding='utf-8')
                (self.archives / 'dangling.deb').symlink_to(self.archives / 'nowhere')
                if broken:
                    (self.archives / 'm-broken.deb').write_text('not a deb', encoding='utf-8')
                (self.tmp / 'installed').write_text('tshark:amd64 4.2\nold:amd64 2\nlib:amd64 1\n', encoding='utf-8')
                (self.runner_temp / 'apt-debs').mkdir()
                (self.runner_temp / 'apt-debs' / 'stale.deb').write_text('', encoding='utf-8')
            return prepare

        for job, step, former, _ in self.scenarios():
            if former is not FORMER_COLLECT:
                continue
            for broken in (False, True):
                with self.subTest(job=job, broken=broken):
                    old, new = self.both(job, step, former, archive(broken))
                    self.assertEqual(new, old)
                    self.assertEqual(old[0], 2 if broken else 0)

    def test_install(self) -> None:
        engines = {'Scapy': '', 'PyShark': 'tshark', 'PyPCAPFile': '', 'PyPCAP': 'build-essential libpcap-dev',
                   'PCAP_CT': 'libpcap0.8'}
        cases = [('engine-tests', FORMER_ENGINE_INSTALL, {'ENGINE': engine, 'APT_PACKAGES': packages})
                 for engine, packages in engines.items()]
        cases.append(('pypcap-parity', FORMER_PARITY_INSTALL, {'APT_PACKAGES': 'build-essential libpcap-dev tshark'}))
        step = {job: sites[2][0] for job, sites in SITES.items()}
        seen = set()  # type: set[str]
        for job, former, base in cases:
            for mirrors in (MIRRORS, MIRRORS.splitlines(True)[0], None, ''):
                for failures in ({}, {'FAIL_UPDATES': '1'}, {'FAIL_INSTALLS': '1'}, {'FAIL_UPDATES': '2'},
                                 {'FAIL_UPDATES': '1', 'FAIL_INSTALLS': '1'},
                                 {'FAIL_INSTALLS': '2', 'DPKG_STATUS': '1'}, {'DEBCONF_STATUS': '3'}):
                    def prepare(mirrors: 'Optional[str]' = mirrors) -> None:
                        if mirrors is not None:
                            self.mirrors.write_text(mirrors, encoding='utf-8')
                    with self.subTest(job=job, env=base, mirrors=mirrors, failures=failures):
                        old, new = self.both(job, step[job], former, prepare, **base, **failures)
                        self.assertEqual(new, old)
                        seen.update(piece for piece in ('fallback mirror', 'attempt 2 of 2', 'debconf', 'Setting up')
                                    if piece in str(old))
        # Every path ran: the retry, the fallback, the second failure, debconf and an install.
        self.assertEqual(seen, {'fallback mirror', 'attempt 2 of 2', 'debconf', 'Setting up'})


class TestTheStepsRunTheScript(unittest.TestCase):
    """Each apt step is one call of the script with its guards; no step keeps apt shell."""

    def test_each_site_runs_the_script_with_its_guards(self) -> None:
        for job, sites in {**SITES, 'pypcap-parity-ktlo': PARITY_STEPS}.items():
            found = steps(WORKFLOW, job)
            names = [item.get('name') for item in found]
            for name, step_id, condition, masked, cap, run in sites:
                with self.subTest(job=job, step=name):
                    item = found[names.index(name)]
                    self.assertEqual(item['run'], run)
                    self.assertEqual((item.get('id'), item.get('if'), item.get('continue-on-error'),
                                      item.get('timeout-minutes')), (step_id, condition, masked, cap))
                    self.assertFalse(set(item) - {'name', 'id', 'if', 'continue-on-error', 'timeout-minutes', 'run'})
            positions = [names.index(name) for name, *_ in sites]
            with self.subTest(job=job, order=True):
                self.assertEqual(positions, sorted(positions))
                self.assertEqual(names[positions[2] + 1], APPARMOR)
                self.assertEqual(positions[3], positions[2] + 2)

    def test_a_ktlo_leg_reads_only_warnings_from_it(self) -> None:
        """#1672's scan of a step's commands sees the script's, which are warnings alone."""
        for name, *_, run in PARITY_STEPS:
            with self.subTest(step=name):
                self.assertEqual(commands(run), {'warning'})
                self.assertLessEqual(commands(run), KTLO_COMMANDS)

    def test_the_ktlo_twin_runs_the_same_steps(self) -> None:
        self.assertEqual(steps(WORKFLOW, 'pypcap-parity-ktlo'), steps(WORKFLOW, 'pypcap-parity'))

    def test_the_apparmor_step_stays_inline(self) -> None:
        for job in ('engine-tests', 'pypcap-parity'):
            with self.subTest(job=job):
                item = next(item for item in steps(WORKFLOW, job) if item.get('name') == APPARMOR)
                self.assertNotIn('util/', item['run'])
                self.assertIn('sudo apparmor_parser -r /etc/apparmor.d/tshark', item['run'])

    def test_the_packages_come_from_the_job(self) -> None:
        """Plan and install read one ``APT_PACKAGES``, so the key is of the set installed."""
        jobs = load(WORKFLOW)['jobs']
        for job in (*SITES, 'pypcap-parity-ktlo'):
            with self.subTest(job=job):
                self.assertIn('APT_PACKAGES', jobs[job]['env'])
        self.assertEqual(jobs['pypcap-parity']['env']['APT_PACKAGES'], 'build-essential libpcap-dev tshark')
        self.assertEqual(jobs['pypcap-parity-ktlo']['env']['APT_PACKAGES'],
                         jobs['pypcap-parity']['env']['APT_PACKAGES'])

    def test_no_step_keeps_apt_shell(self) -> None:
        found = []
        covered = {name for sites in SITES.values() for name, *_ in sites}
        for path in sorted(WORKFLOWS.glob('*.yml')):
            for job, spec in (load(path).get('jobs') or {}).items():
                for item in spec.get('steps') or ():
                    run = '\n'.join(line for line in str(item.get('run', '')).splitlines()
                                    if not line.lstrip().startswith('#'))
                    found.extend(f'{path.name} {job} {item.get("name")!r}: {piece}'
                                 for piece in INLINE if piece in run)
                    if SCRIPT in run and (path.name, item.get('name')) not in {(WORKFLOW, name) for name in covered}:
                        found.append(f'{path.name} {job} {item.get("name")!r}: unlisted')
        self.assertEqual(found, [])


if __name__ == '__main__':
    unittest.main()
