# -*- coding: utf-8 -*-
"""#2019: every job that installs tshark lets it read the checkout past its AppArmor profile.

From Ubuntu 25.04, apparmor 4.1 confines ``/usr/bin/tshark`` with a profile whose own
file rules read only ``/tmp`` and ``/usr/share/wireshark``, so on an ``ubuntu-26.04``
runner ``tshark -r`` is denied every capture under ``$GITHUB_WORKSPACE``. The step
after each tshark install appends one read rule for the checkout to the profile's
``local/tshark`` include and reloads the profile. These tests run that step's real
``run:`` script with ``/etc/apparmor.d`` swapped for a scratch directory and
``sudo``/``apparmor_parser`` stubbed, so the guard, the rule and the reload are all
exercised rather than read.

"""

from __future__ import annotations

import os
import pathlib
import re
import shutil
import subprocess  # nosec: B404
import tempfile
import unittest

from tests._workflows import WORKFLOWS, load, steps

WORKFLOW = 'unit-tests.yml'
NAME = 'Let tshark read the checkout past its AppArmor profile'
#: (job, the tshark install step the AppArmor step must directly follow).
SITES = (
    ('engine-tests', "Install this engine's system packages"),
    ('pypcap-parity', 'Install libpcap headers, a C toolchain, and tshark'),
    ('pypcap-parity-ktlo', 'Install libpcap headers, a C toolchain, and tshark'),
)
#: The directory the step edits, replaced by a scratch one in these tests.
APPARMOR = '/etc/apparmor.d'
#: An AppArmor file rule in ``file ACCESS FILEGLOB,`` form granting read on a tree
#: (apparmor.d(5), FILE RULE), the form the shipped tshark profile itself uses.
RULE = re.compile(r'^file r (/\S+)/\*\*,$')
STUBS = {
    'sudo': 'exec env "$@"\n',
    'apparmor_parser': 'echo "$@" >> "$STUB_LOG"\n',
}


def apparmor_step(job_id: 'str') -> 'dict[str, object]':
    """Job ``job_id``'s AppArmor step, as the workflow loader parses it."""
    for item in steps(WORKFLOW, job_id):
        if item.get('name') == NAME:
            return item
    raise AssertionError(f'{job_id} has no step named {NAME!r}')


class TestEveryTsharkInstallIsFollowed(unittest.TestCase):
    """The step sits right after each tshark install, with one body everywhere."""

    def test_the_step_directly_follows_each_install(self) -> None:
        """Each tshark install is followed at once by the step, before any test runs."""
        for job_id, install in SITES:
            with self.subTest(job=job_id):
                names = [item.get('name') for item in steps(WORKFLOW, job_id)]
                self.assertIn(install, names)
                self.assertEqual(names[names.index(install) + 1], NAME)

    def test_every_job_installing_tshark_is_covered(self) -> None:
        """A new tshark install elsewhere in the workflows needs the step too."""
        found = set()
        for path in sorted(WORKFLOWS.glob('*.yml')):
            for job_id, spec in (load(path).get('jobs') or {}).items():
                for item in spec.get('steps') or ():
                    if re.search(r'apt-get install[^\n]*\btshark\b|apt_install tshark\b',
                                 str(item.get('run', ''))):
                        found.add((path.name, job_id))
        self.assertEqual(found, {(WORKFLOW, job_id) for job_id, _ in SITES})

    def test_one_body_everywhere(self) -> None:
        """The jobs run one script, so a fix to it cannot reach only some of them."""
        bodies = {job_id: apparmor_step(job_id)['run'] for job_id, _ in SITES}
        self.assertEqual(len(set(bodies.values())), 1, bodies)

    def test_engine_tests_runs_it_only_for_pyshark(self) -> None:
        """Only the PyShark cell installs tshark, so only it reloads the profile."""
        self.assertEqual(apparmor_step('engine-tests').get('if'), "env.ENGINE == 'PyShark'")

    def test_a_ktlo_parity_leg_is_not_failed_by_it(self) -> None:
        """Every parity leg runs it, and a KTLO leg's failure there stays a warning (#1672)."""
        for job_id in ('pypcap-parity', 'pypcap-parity-ktlo'):
            with self.subTest(job=job_id):
                item = apparmor_step(job_id)
                self.assertNotIn('if', item)
                self.assertEqual(item.get('continue-on-error'), '${{ matrix.ktlo == true }}')


class TestTheStepRuns(unittest.TestCase):
    """The step's real script, against a scratch ``/etc/apparmor.d``."""

    def setUp(self) -> None:
        if shutil.which('bash') is None:  # pragma: no cover
            self.skipTest('bash is not available')
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-2019-')  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.tmp = pathlib.Path(tmp.name)
        self.bin = self.tmp / 'bin'
        self.bin.mkdir()
        for command, body in STUBS.items():
            path = self.bin / command
            path.write_text('#!/bin/bash\n' + body, encoding='utf-8')
            path.chmod(0o755)
        self.etc = self.tmp / 'apparmor.d'
        self.etc.mkdir()
        self.log = self.tmp / 'parser.log'
        self.workspace = '/home/runner/work/PyPCAPKit/PyPCAPKit'

    def run_step(self) -> 'int':
        """Run the step's script against the scratch directory; return its status."""
        script = str(apparmor_step('engine-tests')['run'])
        self.assertEqual(script.count(APPARMOR), 4,
                         f'{NAME!r} no longer names {APPARMOR} four times')
        script = script.replace(APPARMOR, str(self.etc))
        env = dict(os.environ, PATH=f'{self.bin}{os.pathsep}{os.environ["PATH"]}',
                   STUB_LOG=str(self.log), GITHUB_WORKSPACE=self.workspace)
        return subprocess.run(['bash', '-e', '-c', script], env=env, check=False,
                              capture_output=True, text=True).returncode

    def parser_calls(self) -> 'list[str]':
        """The arguments of every stubbed ``apparmor_parser`` call."""
        return self.log.read_text(encoding='utf-8').splitlines() if self.log.exists() else []

    def test_with_the_profile_the_checkout_is_allowed_and_the_profile_reloaded(self) -> None:
        """26.04: one read rule for the workspace lands in local/tshark, then ``-r`` reloads."""
        (self.etc / 'tshark').write_text('include if exists <local/tshark>\n', encoding='utf-8')
        self.assertEqual(self.run_step(), 0)
        lines = (self.etc / 'local' / 'tshark').read_text(encoding='utf-8').splitlines()
        self.assertEqual(len(lines), 1, lines)
        match = RULE.match(lines[0])
        self.assertIsNotNone(match, lines[0])
        self.assertEqual(match.group(1), self.workspace)  # type: ignore[union-attr]
        self.assertEqual(self.parser_calls(), [f'-r {self.etc}/tshark'])

    def test_an_existing_local_file_is_appended_to(self) -> None:
        """A site's own additions in local/tshark are kept."""
        (self.etc / 'tshark').write_text('include if exists <local/tshark>\n', encoding='utf-8')
        (self.etc / 'local').mkdir()
        (self.etc / 'local' / 'tshark').write_text('file r /srv/**,\n', encoding='utf-8')
        self.assertEqual(self.run_step(), 0)
        lines = (self.etc / 'local' / 'tshark').read_text(encoding='utf-8').splitlines()
        self.assertEqual(lines, ['file r /srv/**,', f'file r {self.workspace}/**,'])

    def test_without_the_profile_it_is_a_no_op(self) -> None:
        """24.04: no profile, so nothing is written and nothing is reloaded."""
        self.assertEqual(self.run_step(), 0)
        self.assertFalse((self.etc / 'local').exists())
        self.assertEqual(self.parser_calls(), [])


if __name__ == '__main__':
    unittest.main()
