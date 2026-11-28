# -*- coding: utf-8 -*-
"""#2648: only Create Release waits for a deployment approval.

``github-release`` is the environment with a required reviewer, and it holds the
release App's key, ``RELEASE_APP_PRIVATE_KEY``, for Create Release's ``github``.
The owner ruled on #2648 that an approval at a deployment gate is for Create
Release alone, so the ``pr`` jobs of Python Versions, Issue and PR Kinds and
Sync Develop (#2942), and Stable Branch's ``mirror`` (#3077), read the same key
from ``release-app``, which has no reviewer.

* :class:`TestOnlyCreateReleaseNamesTheGate` scans every workflow: Create
  Release's ``github`` is the only job naming ``github-release``, every other
  job reading the key names ``release-app``, and none is handed every secret.
  Its mutation rows show the scan failing on a ``release-app`` reader pointed
  back at the gate, on ``github`` moved off it, and on any other job, in Create
  Release or elsewhere, reading the key outside ``release-app``.
* :class:`TestTheMintStep` pins every reader's one step minting the App's token:
  one pinned action, the App's inputs, the scopes that reader's token spends,
  and no other step reading a secret. Each workflow's own module pins where its
  token is spent.
* :class:`TestTheKeyCheck` pins how a ``release-app`` reader behaves while that
  environment holds no key: it warns and skips its other steps rather than
  failing at minting. The check's shell runs here under :program:`bash`.

Which environments exist, their reviewers, branch policies and secrets are
repository settings, which no test here can read.

"""

from __future__ import annotations

import os
import pathlib
import re
import shutil
import subprocess  # nosec: B404
import tempfile
import unittest
from typing import TYPE_CHECKING

from tests._support import bash_argv
from tests._workflows import WORKFLOWS, load, pinned, versions
from tests.project.test_release_gates import evaluate_condition, evaluate_expression
from tests.project.test_secret_environments_1968 import environment

if TYPE_CHECKING:
    from typing import Any

#: The environment with the required reviewer, and the one without.
GATE, APP = 'github-release', 'release-app'
#: Create Release, and its job that names :data:`GATE`.
RELEASE, RELEASE_JOB = 'create-release.yml', 'github'
#: The jobs reading the key from :data:`APP`, each with what its check warns there
#: is none of without the key.
APP_READERS = {('cron-issue-pr-kinds.yml', 'pr'): 'pull request', ('cron-python-versions.yml', 'pr'): 'pull request',
               ('stable-branch.yml', 'mirror'): 'stable mirror', ('sync-develop.yml', 'pr'): 'pull request'}
#: A read of the App's private key, as ``secrets.X`` or ``secrets['X']`` in any
#: case, as secret names are; a read of any secret; and every secret handed over
#: at once, this key among them.
KEY = re.compile(r"""secrets\s*(?:\.\s*|\[\s*['"])(?i:RELEASE_APP_PRIVATE_KEY)\b""")
SECRET = re.compile(r'\bsecrets\s*[.\[]')
EVERY_SECRET = re.compile(r'(?i)toJSON\(\s*secrets\s*\)')

#: The first step of every :data:`APP` reader, its ``env:``, and the ``if:`` on
#: every step after it.
CHECK_STEP = "Check for the release App's key"
CHECK_ENV = {'KEY_SET': "${{ secrets.RELEASE_APP_PRIVATE_KEY != '' }}"}
GATED = "${{ steps.key.outputs.set == 'true' }}"

#: Every reader's step minting the App's token: the action, its major version,
#: and the inputs naming the App. Without a ``permission-*`` input the token
#: holds all the installation's permissions (the action's README).
MINT_STEP = "Mint the release App's token"
MINT_ACTION, MINT_MAJOR = 'actions/create-github-app-token', 'v3'
MINT_KEY = {'client-id': '${{ vars.RELEASE_APP_CLIENT_ID }}', 'private-key': '${{ secrets.RELEASE_APP_PRIVATE_KEY }}'}
#: Each reader's mint step ``id``, and the scopes, each ``write``, its token holds.
MINTS = {(RELEASE, RELEASE_JOB): ('app_token', ('contents', 'workflows')),
         ('cron-issue-pr-kinds.yml', 'pr'): ('app', ('contents', 'pull-requests')),
         ('cron-python-versions.yml', 'pr'): ('app', ('contents', 'pull-requests')),
         ('stable-branch.yml', 'mirror'): ('app', ('contents', 'workflows')),
         ('sync-develop.yml', 'pr'): ('app', ('contents', 'pull-requests', 'workflows'))}

BASH = shutil.which('bash')


def workflows() -> 'dict[str, dict[str, Any]]':
    """Every workflow, parsed: a fresh copy, so a test may edit it."""
    return {path.name: load(path.name) for path in sorted(WORKFLOWS.glob('*.yml'))}


def jobs(specs: 'dict[str, dict[str, Any]]') -> 'list[tuple[str, str, dict[str, Any]]]':
    """``(workflow, job id, job)`` for every job in ``specs``."""
    return [(name, job_id, job) for name, spec in sorted(specs.items())
            for job_id, job in sorted((spec.get('jobs') or {}).items())]


def reads(node: 'Any', pattern: 're.Pattern[str]') -> 'bool':
    """Whether a key or string anywhere in ``node`` matches ``pattern``.

    Each string is searched as it stands: :func:`repr` escapes the quotes of
    ``secrets['X']`` in a string that also holds a ``"``.
    """
    if isinstance(node, dict):
        return any(reads(key, pattern) or reads(value, pattern) for key, value in node.items())
    if isinstance(node, list):
        return any(reads(item, pattern) for item in node)
    return isinstance(node, str) and pattern.search(node) is not None


def readers(specs: 'dict[str, dict[str, Any]]') -> 'set[tuple[str, str]]':
    """Each ``(workflow, job id)`` in ``specs`` that reads the App's key."""
    return {(name, job_id) for name, job_id, job in jobs(specs) if reads(job, KEY)}


def violations(specs: 'dict[str, dict[str, Any]]') -> 'list[str]':
    """What in ``specs`` breaks #2648's rule; empty where it holds."""
    found = [f'{name} hands every secret over at once' for name, spec in sorted(specs.items())
             if reads(spec, EVERY_SECRET)]
    gated = sorted((name, job_id) for name, job_id, job in jobs(specs) if environment(job) == GATE)
    if gated != [(RELEASE, RELEASE_JOB)]:
        found.append(f'the jobs naming {GATE} are {gated}, not {RELEASE}\'s {RELEASE_JOB} alone')
    read = readers(specs)
    for name, job_id, job in jobs(specs):
        if (name, job_id) != (RELEASE, RELEASE_JOB) and (name, job_id) in read and environment(job) != APP:
            found.append(f'{name}\'s {job_id} reads the App\'s key from {environment(job)!r}, not {APP}')
    return found


def mint_violations(specs: 'dict[str, dict[str, Any]]') -> 'list[str]':
    """What in ``specs`` breaks the mint step's shape; empty where it holds.

    The version comment, which YAML drops, is read from each file on disk.
    """
    found, pins = [], set()
    for (name, job_id), (step_id, scopes) in sorted(MINTS.items()):
        steps = ((specs[name].get('jobs') or {}).get(job_id) or {}).get('steps') or []
        minting = [step for step in steps if step.get('name') == MINT_STEP]
        if len(minting) != 1:
            found.append(f'{name}\'s {job_id} has {len(minting)} steps named {MINT_STEP!r}')
            continue
        mint, = minting
        pins.add(mint.get('uses'))
        majors = {version.split('.')[0] for version in versions(name, MINT_ACTION)}
        if not pinned(mint.get('uses'), MINT_ACTION) or majors != {MINT_MAJOR}:
            found.append(f'{name}\'s {job_id} mints with {mint.get("uses")!r} at {majors}')
        expected = {**MINT_KEY, **{f'permission-{scope}': 'write' for scope in scopes}}
        if (mint.get('id'), mint.get('with')) != (step_id, expected):
            found.append(f'{name}\'s {job_id} mints as {mint.get("id")!r} with {mint.get("with")!r}')
        # Create Release also spends GITHUB_TOKEN, so only the key's readers count there.
        github = (name, job_id) == (RELEASE, RELEASE_JOB)
        secret = [step.get('name') for step in steps if reads(step, KEY if github else SECRET)]
        if secret != ([MINT_STEP] if github else [CHECK_STEP, MINT_STEP]):
            found.append(f'{name}\'s {job_id} reads {"the key" if github else "a secret"} in {secret}')
    if len(pins) > 1:
        found.append(f'the readers mint with {sorted(map(str, pins))}, not one pin')
    return found


class TestOnlyCreateReleaseNamesTheGate(unittest.TestCase):
    """``github-release`` is Create Release's alone; the key's other readers use ``release-app``."""

    def test_the_rule_holds(self) -> None:
        self.assertEqual(violations(workflows()), [])

    def test_the_scan_finds_the_readers(self) -> None:
        """Not vacuous: ``github`` and the ``release-app`` jobs read the key; another secret is no read."""
        self.assertEqual(readers(workflows()), set(APP_READERS) | {(RELEASE, RELEASE_JOB)})
        for other in ('${{ secrets.RELEASE_APP_PRIVATE_KEY_2 }}', '${{ secrets.OTHER }}'):
            with self.subTest(secret=other):
                specs = workflows()
                specs['lint.yml']['jobs']['probe'] = {'runs-on': 'ubuntu-latest',
                                                      'steps': [{'run': 'true', 'env': {'KEY': other}}]}
                self.assertEqual(readers(specs), set(APP_READERS) | {(RELEASE, RELEASE_JOB)})

    def test_each_mutation_is_caught(self) -> None:
        def point(name: 'str', job: 'str', value: 'Any') -> 'Any':
            def mutate(specs: 'dict[str, dict[str, Any]]') -> 'None':
                if value is None:
                    del specs[name]['jobs'][job]['environment']
                else:
                    specs[name]['jobs'][job]['environment'] = value
            return mutate

        def reader(name: 'str', value: 'Any', step: 'Any' = None) -> 'Any':
            def mutate(specs: 'dict[str, dict[str, Any]]') -> 'None':
                probe = {'runs-on': 'ubuntu-latest',
                         'steps': [step or {'run': 'true', 'env': {'KEY': '${{ secrets.RELEASE_APP_PRIVATE_KEY }}'}}]}
                if value is not None:
                    probe['environment'] = value
                specs[name]['jobs']['probe'] = probe
            return mutate

        mutations = {
            'Python Versions pointed back at the gate': point('cron-python-versions.yml', 'pr', GATE),
            'Issue and PR Kinds pointed back at the gate': point('cron-issue-pr-kinds.yml', 'pr', GATE),
            'a cron reader naming no environment': point('cron-issue-pr-kinds.yml', 'pr', None),
            'Stable Branch pointed back at the gate': point('stable-branch.yml', 'mirror', GATE),
            'Stable Branch naming no environment': point('stable-branch.yml', 'mirror', None),
            "Create Release's github moved off the gate": point(RELEASE, RELEASE_JOB, APP),
            "Create Release's github naming no environment": point(RELEASE, RELEASE_JOB, None),
            'another Create Release job reading the key from conda-tag': reader(RELEASE, 'conda-tag'),
            'another Create Release job reading the key from no environment': reader(RELEASE, None),
            'a job elsewhere reading the key from conda-tag': reader('lint.yml', 'conda-tag'),
            'a job elsewhere reading the key in lower case': reader(
                'lint.yml', None, {'run': 'true', 'env': {'KEY': '${{ secrets.release_app_private_key }}'}}),
            "a job elsewhere reading secrets['...'] in mixed case": reader(
                'lint.yml', None, {'run': 'true', 'env': {'KEY': "${{ secrets['Release_App_Private_Key'] }}"}}),
            "a job elsewhere reading secrets['...'] in a double-quoted run": reader(
                'lint.yml', None, {'run': """echo "${{ secrets['RELEASE_APP_PRIVATE_KEY'] }}" """}),
            'a job handed every secret in release-app': reader(
                'lint.yml', APP, {'run': 'true', 'env': {'ALL': '${{ toJSON(secrets) }}'}}),
        }
        for label, mutate in sorted(mutations.items()):
            with self.subTest(mutation=label):
                specs = workflows()
                mutate(specs)
                self.assertTrue(violations(specs), label)


class TestTheMintStep(unittest.TestCase):
    """Each reader mints in one step, from one pin, with the scopes it spends and no other secret."""

    @staticmethod
    def specs() -> 'dict[str, dict[str, Any]]':
        """The readers' workflows alone, parsed afresh."""
        return {name: load(name) for name in sorted({name for name, _ in MINTS})}

    def test_the_rule_holds(self) -> None:
        self.assertEqual(mint_violations(self.specs()), [])

    def test_each_mutation_is_caught(self) -> None:
        def in_mint(name: 'str', job: 'str', key: 'str', value: 'Any', *path: 'str') -> 'Any':
            def mutate(specs: 'dict[str, dict[str, Any]]') -> 'None':
                step = next(entry for entry in specs[name]['jobs'][job]['steps'] if entry.get('name') == MINT_STEP)
                for part in path:
                    step = step[part]
                if value is None:
                    del step[key]
                else:
                    step[key] = value
            return mutate

        def steps(name: 'str', job: 'str', edit: 'Any') -> 'Any':
            def mutate(specs: 'dict[str, dict[str, Any]]') -> 'None':
                specs[name]['jobs'][job]['steps'] = edit(specs[name]['jobs'][job]['steps'])
            return mutate

        mutations = {}
        for (name, job), (_, scopes) in sorted(MINTS.items()):
            mutations.update({
                f'{name}: no mint step': steps(name, job, lambda found: [
                    entry for entry in found if entry.get('name') != MINT_STEP]),
                f'{name}: two mint steps': steps(name, job, lambda found: found + [
                    next(entry for entry in found if entry.get('name') == MINT_STEP)]),
                f'{name}: another action': in_mint(name, job, 'uses', f'actions/github-script@{"0" * 40}'),
                f'{name}: a tag, not a commit': in_mint(name, job, 'uses', f'{MINT_ACTION}@v3'),
                f'{name}: another id': in_mint(name, job, 'id', 'token'),
                f'{name}: another key': in_mint(name, job, 'private-key', '${{ secrets.OTHER }}', 'with'),
                f'{name}: no client id': in_mint(name, job, 'client-id', None, 'with'),
                f'{name}: a scope more': in_mint(name, job, 'permission-issues', 'write', 'with'),
                f'{name}: a scope fewer': in_mint(name, job, f'permission-{scopes[-1]}', None, 'with'),
                f'{name}: contents read': in_mint(name, job, 'permission-contents', 'read', 'with'),
                f'{name}: another step reading a secret': steps(name, job, lambda found: found + [
                    {'run': 'true', 'env': {'KEY': '${{ secrets.RELEASE_APP_PRIVATE_KEY }}'}}]),
            })
        mutations['Sync Develop on another pin'] = in_mint('sync-develop.yml', 'pr', 'uses',
                                                           f'{MINT_ACTION}@{"0" * 40}')
        for label, mutate in sorted(mutations.items()):
            with self.subTest(mutation=label):
                specs = self.specs()
                mutate(specs)
                self.assertTrue(mint_violations(specs), label)


class TestTheKeyCheck(unittest.TestCase):
    """Without the key in ``release-app``, a reader warns and skips; with it, it runs."""

    @classmethod
    def setUpClass(cls) -> None:
        specs = workflows()
        cls.jobs = {(name, job_id): specs[name]['jobs'][job_id] for name, job_id in sorted(APP_READERS)}

    @staticmethod
    def generic(reader: 'tuple[str, str]', check: 'dict[str, Any]') -> 'str':
        """``check``, with what its job makes and the job's id replaced by placeholders."""
        return repr(check).replace(f'No {APP_READERS[reader]} ', 'No <what> ').replace(
            f'so the {reader[1]} job', 'so the <job> job')

    def test_the_first_step_checks_and_every_other_waits_on_it(self) -> None:
        for (name, job_id), job in self.jobs.items():
            check, *rest = job['steps']
            with self.subTest(workflow=name, job=job_id):
                self.assertEqual((check.get('name'), check.get('id'), check.get('env')),
                                 (CHECK_STEP, 'key', CHECK_ENV))
                self.assertNotIn('if', check)
                self.assertTrue(rest)
                self.assertEqual([step.get('if') for step in rest], [GATED] * len(rest))
        self.assertEqual(len({self.generic(reader, job['steps'][0]) for reader, job in self.jobs.items()}), 1,
                         'the checks differ beyond what their jobs make')

    def test_an_unset_key_skips_every_other_step(self) -> None:
        """An unset secret reads as an empty string; ``env:`` gets the boolean as text."""
        for key, expected in (('', False), ('-----BEGIN RSA PRIVATE KEY-----', True)):
            with self.subTest(key=bool(key)):
                value = evaluate_expression(CHECK_ENV['KEY_SET'], {'secrets': {'RELEASE_APP_PRIVATE_KEY': key}})
                self.assertIs(value, expected)
                context = {'steps': {'key': {'outputs': {'set': str(value).lower()}}}}
                self.assertIs(evaluate_condition(GATED, context), expected)

    @unittest.skipIf(not BASH, 'needs bash on PATH')
    def test_the_check_warns_and_writes_its_output(self) -> None:
        for (name, job_id), job in self.jobs.items():
            script = job['steps'][0]['run']
            for value, warned in (('false', True), ('true', False)):
                with self.subTest(workflow=name, KEY_SET=value), \
                        tempfile.TemporaryDirectory(prefix='pcapkit-2648-') as tmp:
                    root = pathlib.Path(tmp)
                    (root / 'step.sh').write_text(script, encoding='utf-8')
                    output = root / 'output'
                    env = {'PATH': os.environ.get('PATH', ''), 'GITHUB_OUTPUT': str(output), 'KEY_SET': value}
                    result = subprocess.run(bash_argv('-e', str(root / 'step.sh'),  # nosec: B603
                                                      executable=str(BASH)),
                                            cwd=root, env=env, capture_output=True, text=True, check=False,
                                            timeout=60)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(output.read_text(encoding='utf-8'), f'set={value}\n')
                    if warned:
                        self.assertTrue(result.stdout.startswith(
                            f"::warning title=No {APP_READERS[(name, job_id)]} without the release App's key::"),
                            result.stdout)
                        for named in (APP, 'RELEASE_APP_PRIVATE_KEY', 'docs/source/contributing/releasing.rst',
                                      f'so the {job_id} job skips'):
                            self.assertIn(named, result.stdout)
                    else:
                        self.assertEqual(result.stdout, '')


if __name__ == '__main__':
    unittest.main()
