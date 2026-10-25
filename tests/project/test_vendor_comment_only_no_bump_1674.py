# -*- coding: utf-8 -*-
"""#1674: a regeneration that changes only comments or docstrings is committed
without a version bump.

Vendor Update bumped on any changed file, so 1.5.0b9, b10 and b11 were cut for
comment-only regenerations. The owner chose to commit such a regeneration
without the bump, so that documentation still reaches ``main`` and only a code
change cuts a beta.

Three layers:

* :class:`TestTheScriptOnARegeneratedTree` runs
  :file:`util/vendor_code_changed.py` in throwaway repositories, on fixtures
  shaped like b8 (a member rename), b9 (a draft becoming RFC 10049) and b10 (an
  ``:rfc:`` role becoming plain text), and :class:`TestCodeOf` calls the AST
  comparison directly;
* :class:`TestTheStepsDecide` walks ``vendor-update``'s steps the way the runner
  does, with the evaluator :mod:`tests.project.test_release_gates` pins;
* :class:`TestTheDocumentationCommitStep` runs that step's script, including the
  hold that stops documentation commits from chaining.

"""

from __future__ import annotations

import importlib.util
import os
import pathlib
import re
import shlex
import subprocess
import sys
import tempfile
import unittest
from typing import TYPE_CHECKING

from tests._support import scale_timeout
from tests.project.test_release_gates import (_RUN_LITERAL, NULL, STATUS, block_scalar_after,
                                              evaluate_condition, evaluate_expression, job_blocks,
                                              step_block, step_mapping)

if TYPE_CHECKING:
    import types
    from typing import Optional

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'util' / 'vendor_code_changed.py'
WORKFLOW = ROOT / '.github' / 'workflows' / 'cron-vendor.yml'

BOT = ('github-actions[bot]', 'github-actions[bot]@users.noreply.github.com')
HUMAN = ('Jarry Shaw', 'jarryshaw@icloud.com')
DOCS_SUBJECT = 'Updated vendor documentation without a version bump'

#: A generated module, cut down from :file:`pcapkit/const/reg/apptype/udp.py`.
#: The member lines are the ones b8 and b9 changed; the docstring row is b6's.
MODULE = '''\
# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Application Layer Protocol Numbers (UDP)
==============================================

.. module:: pcapkit.const.reg.apptype.udp

This module contains the constant enumeration for **Application Layer Protocol Numbers (UDP)**,
which is automatically generated from :class:`pcapkit.vendor.reg.apptype.udp.UDP`.

"""
from pcapkit.const.reg.apptype.apptype import AppType, TransportProtocol

__all__ = ['UDP']


class UDP(AppType):
    """[UDP] Application Layer Protocol Numbers (UDP)

    .. list-table:: Service names assigned no port number

       * - ``reserved``
         - [N/A] Reserved [:rfc:`6335`]

    """

    #: [UDP] Reserved [:rfc:`6335`]
    reserved_4415 = 4415, 'reserved', TransportProtocol.udp

    #: [UDP] PJJ Media Player discovery
    pjj_player_disc = 4416, 'pjj-player-disc', TransportProtocol.udp

    #: - [TCP] Roughtime time synchronization [RFC-ietf-ntp-roughtime-19]
    #: - [UDP] Roughtime time synchronization [RFC-ietf-ntp-roughtime-19]
    roughtime = 5319, 'roughtime', TransportProtocol.udp

    @classmethod
    def _missing_(cls, value: 'int') -> 'UDP':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return cls._unregistered_member(value, 'Unassigned')
'''

PATH = 'pcapkit/const/reg/apptype/udp.py'

#: ``(case, [(old, new)], whether it is a code change)``, each edit applied to
#: :data:`MODULE` with ``str.replace``.
EDITS = [
    ('b9: a draft becoming RFC 10049, in comments',
     [('[RFC-ietf-ntp-roughtime-19]', '[RFC 10049]')], False),
    ('b10: an :rfc: role becoming plain text, in a comment',
     [('#: [UDP] Reserved [:rfc:`6335`]', '#: [UDP] Reserved [RFC 6335]')], False),
    ('a comment line wrapped in two, as b7 did',
     [('#: [UDP] PJJ Media Player discovery', '#: [UDP] PJJ Media Player\n    #: discovery')], False),
    ('b6: an :rfc: role becoming plain text, in the class docstring',
     [('- [N/A] Reserved [:rfc:`6335`]', '- [N/A] Reserved [RFC 6335]')], False),
    ('the module and method docstrings reworded',
     [('which is automatically generated from', 'generated from'),
      ('Lookup function used when value is not found.', 'Look up a value not found.')], False),
    ('an attribute docstring added under a member',
     [("roughtime = 5319, 'roughtime', TransportProtocol.udp",
       "roughtime = 5319, 'roughtime', TransportProtocol.udp\n    '''Roughtime.'''")], False),
    ('b8: a member renamed',
     [('pjj_player_disc = 4416', 'newmood_player = 4416')], True),
    ('a member value changed',
     [('reserved_4415 = 4415', 'reserved_4415 = 4414')], True),
    ("a member's string value changed",
     [("4416, 'pjj-player-disc'", "4416, 'newmood-player'")], True),
    ('__all__ changed',
     [("__all__ = ['UDP']", "__all__ = ['UDP', 'TransportProtocol']")], True),
    ("b5: _missing_'s return dropped",
     [("        return cls._unregistered_member(value, 'Unassigned')\n",
       "        cls._unregistered_member(value, 'Unassigned')\n        return cls(value)\n")], True),
    ('a member removed',
     [("    #: [UDP] Reserved [:rfc:`6335`]\n    reserved_4415 = 4415, 'reserved', TransportProtocol.udp\n\n",
       '')], True),
    ('an import changed',
     [('import AppType, TransportProtocol', 'import AppType, TransportProtocol, TransType')], True),
    ('a comment fixed alongside a rename',
     [('[RFC-ietf-ntp-roughtime-19]', '[RFC 10049]'), ('pjj_player_disc', 'newmood_player')], True),
]


def edited(edits: 'list[tuple[str, str]]') -> 'str':
    """:data:`MODULE` with ``edits`` applied, each of which must match."""
    text = MODULE
    for old, new in edits:
        if old not in text:
            raise AssertionError(f'{old!r} is not in the fixture')
        text = text.replace(old, new)
    return text


def _load_script() -> 'Optional[types.ModuleType]':
    """:file:`util/vendor_code_changed.py` as a module, or :data:`None` on a tree without it (#1674)."""
    if not SCRIPT.exists():
        return None
    spec = importlib.util.spec_from_file_location('vendor_code_changed', SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ScratchRepository(unittest.TestCase):
    """A throwaway repository whose ``HEAD`` holds :data:`MODULE`."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = pathlib.Path(tmp.name)
        self.repo = self.root / 'repo'

        # As in test_workflow_run_verdict.py: none of the caller's git
        # configuration, and no automatic maintenance to outlive the test.
        home = self.root / 'home'
        home.mkdir()
        (home / '.gitconfig').write_text(
            '[init]\n\tdefaultBranch = main\n[commit]\n\tgpgsign = false\n'
            '[maintenance]\n\tauto = false\n\tautoDetach = false\n'
            '[gc]\n\tauto = 0\n\tautoDetach = false\n', encoding='utf-8')
        self.env = {
            'PATH': os.environ.get('PATH', ''),
            'HOME': str(home),
            'XDG_CONFIG_HOME': str(home / '.config'),
            'GIT_CONFIG_NOSYSTEM': '1',
            'LC_ALL': 'C',
        }
        self.git('init', '-q', str(self.repo), cwd=self.root)
        self.write(PATH, MODULE)
        self.write('pcapkit/const/reg/apptype/tcp.py', MODULE.replace('UDP', 'TCP'))
        self.write('pcapkit/const/README.txt', 'Generated by pcapkit-vendor.\n')
        self.write('pcapkit/__init__.py', "# the package\n__version__ = '9.9.9b9'\n")
        self.write('.gitignore', '__pycache__/\n')
        self.git('add', '.')
        self.commit('fix(vendor): render both IANA citation spellings as :rfc: roles (#1673)', HUMAN)
        self.base = self.git('rev-parse', 'HEAD')

    def git(self, *args: 'str', cwd: 'Optional[pathlib.Path]' = None,
            env: 'Optional[dict[str, str]]' = None) -> 'str':
        result = subprocess.run(['git', *args], cwd=cwd or self.repo, env=env or self.env,
                                capture_output=True, text=True, check=False,
                                timeout=scale_timeout(30))
        self.assertEqual(result.returncode, 0, f'git {" ".join(args)}: {result.stderr}')
        return result.stdout.strip()

    def commit(self, message: 'str', identity: 'tuple[str, str]') -> None:
        self.git('commit', '-q', '-m', message,
                 env=dict(self.env, GIT_AUTHOR_NAME=identity[0], GIT_AUTHOR_EMAIL=identity[1],
                          GIT_COMMITTER_NAME=identity[0], GIT_COMMITTER_EMAIL=identity[1]))

    def write(self, path: 'str', text: 'str | bytes') -> None:
        file = self.repo / path
        file.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(text, bytes):
            file.write_bytes(text)
        else:
            file.write_text(text, encoding='utf-8')


class TestTheScriptOnARegeneratedTree(ScratchRepository):
    """The script's verdict, working tree against ``HEAD``."""

    def run_script(self, *paths: 'str', changed_files: 'Optional[str]' = None,
                   ) -> 'tuple[subprocess.CompletedProcess[str], Optional[str]]':
        """Run the script on ``paths``: the result and the ``code_changed`` it wrote."""
        self.assertTrue(SCRIPT.exists(), f'{SCRIPT.relative_to(ROOT)} does not exist')
        output = self.root / 'output'
        output.write_text('', encoding='utf-8')
        env = dict(self.env, GITHUB_OUTPUT=str(output))
        if changed_files is not None:
            env['CHANGED_FILES'] = changed_files
        result = subprocess.run([sys.executable, str(SCRIPT), *paths], cwd=self.repo, env=env,
                                capture_output=True, text=True, check=False,
                                timeout=scale_timeout(60))
        written = re.findall(r'^code_changed=(.*)$', output.read_text(encoding='utf-8'), re.M)
        self.assertLessEqual(len(written), 1, written)
        return result, written[0] if written else None

    def assertVerdict(self, paths: 'tuple[str, ...]', code: 'bool') -> 'str':
        """Assert the script exits 0 and answers ``code``; its stdout."""
        result, written = self.run_script(*paths)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(written, str(code).lower(), result.stdout)
        return result.stdout

    def test_each_edit_is_classified(self) -> None:
        for case, edits, code in EDITS:
            with self.subTest(case):
                self.write(PATH, edited(edits))
                self.assertVerdict((PATH,), code)

    def test_a_new_file_is_code(self) -> None:
        """Untracked, as ``verify-changed-files`` reports it, with a valid body."""
        new = 'pcapkit/const/reg/apptype/sctp.py'
        self.write(new, MODULE.replace('UDP', 'SCTP'))
        stdout = self.assertVerdict((new,), True)
        self.assertIn(f'code: {new}: new file', stdout)

    def test_a_deleted_file_is_code(self) -> None:
        (self.repo / PATH).unlink()
        self.assertIn(f'code: {PATH}: deleted', self.assertVerdict((PATH,), True))

    def test_a_non_python_file_is_code(self) -> None:
        self.write('pcapkit/const/README.txt', 'Generated by pcapkit-vendor, weekly.\n')
        self.assertVerdict(('pcapkit/const/README.txt',), True)

    def test_a_comment_outside_the_generated_tree_is_code(self) -> None:
        """Only ``pcapkit-vendor``'s own output may skip the bump."""
        self.write('pcapkit/__init__.py', "# the whole package\n__version__ = '9.9.9b9'\n")
        self.assertVerdict(('pcapkit/__init__.py',), True)

    def test_a_mode_change_is_code(self) -> None:
        self.write(PATH, edited(EDITS[0][1]))
        (self.repo / PATH).chmod(0o755)
        self.assertIn('file mode changed', self.assertVerdict((PATH,), True))

    def test_a_module_that_does_not_parse_is_code(self) -> None:
        self.write(PATH, MODULE.replace('class UDP(AppType):', 'class UDP(AppType)'))
        self.assertIn('does not parse', self.assertVerdict((PATH,), True))

    def test_an_unchanged_file_is_code(self) -> None:
        """Listed, yet identical: no positive finding, so the bump stands."""
        self.assertVerdict((PATH,), True)

    def test_a_path_that_is_not_plain_is_code(self) -> None:
        """``./`` is what no ``git`` listing writes; a quoted path names no file."""
        self.write(PATH, edited(EDITS[0][1]))
        self.assertVerdict((f'./{PATH}',), True)
        self.assertVerdict((f'"{PATH}"',), True)

    def test_a_coding_cookie_decides_the_literals(self) -> None:
        """The source is parsed as bytes, so changing the cookie changes a string."""
        source = MODULE.replace("'reserved'", "'r\u00e9serv\u00e9'").encode('utf-8')
        self.write(PATH, source)
        self.git('commit', '-qam', 'accented', env=dict(self.env, GIT_AUTHOR_NAME=HUMAN[0],
                 GIT_AUTHOR_EMAIL=HUMAN[1], GIT_COMMITTER_NAME=HUMAN[0], GIT_COMMITTER_EMAIL=HUMAN[1]))
        self.write(PATH, source.replace(b'coding: utf-8', b'coding: latin-1'))
        self.assertVerdict((PATH,), True)

    def test_one_code_change_among_comments_is_code(self) -> None:
        self.write(PATH, edited(EDITS[0][1]))
        self.write('pcapkit/const/reg/apptype/tcp.py',
                   MODULE.replace('UDP', 'TCP').replace('pjj_player_disc', 'newmood_player'))
        stdout = self.assertVerdict((PATH, 'pcapkit/const/reg/apptype/tcp.py'), True)
        self.assertIn(f'docs: {PATH}: only comments or docstrings differ', stdout)
        self.assertIn('code: pcapkit/const/reg/apptype/tcp.py: code differs', stdout)

    def test_the_changed_files_output_is_read_from_the_environment(self) -> None:
        """What the workflow passes: ``verify-changed-files``' space-separated list."""
        self.write(PATH, edited(EDITS[0][1]))
        self.write('pcapkit/const/reg/apptype/tcp.py',
                   MODULE.replace('UDP', 'TCP').replace('[RFC-ietf-ntp-roughtime-19]', '[RFC 10049]'))
        result, written = self.run_script(changed_files=f'{PATH} pcapkit/const/reg/apptype/tcp.py')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(written, 'false', result.stdout)
        self.assertIn('::notice title=Comments and docstrings only::none of the 2 changed', result.stdout)

    def test_no_paths_is_an_error_and_writes_nothing(self) -> None:
        """The step then fails, and the workflow bumps, as it does without the classifier (#1674)."""
        for changed_files in (None, '', ' \n'):
            with self.subTest(changed_files=changed_files):
                result, written = self.run_script(changed_files=changed_files)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn('::error', result.stdout)
                self.assertIsNone(written)


class TestCodeOf(unittest.TestCase):
    """:func:`code_of` itself: what counts as a docstring, and what does not."""

    def setUp(self) -> None:
        module = _load_script()
        if module is None:
            self.fail(f'{SCRIPT.relative_to(ROOT)} does not exist')
        self.module = module

    def assertSameCode(self, old: 'str', new: 'str', same: 'bool') -> None:
        self.assertEqual(self.module.code_of(old.encode()) == self.module.code_of(new.encode()), same,
                         f'{old!r} -> {new!r}')

    def test_bare_string_statements_are_dropped_wherever_they_are(self) -> None:
        self.assertSameCode('def f():\n    """One."""\n    return 1\n',
                            'def f():\n    """Two."""\n    return 1\n', True)
        self.assertSameCode('if x:\n    y = 1\n', "if x:\n    'note'\n    y = 1\n", True)

    def test_other_expression_statements_are_code(self) -> None:
        """An f-string or a call is evaluated; a bytes literal is not a docstring."""
        self.assertSameCode("x = 1\n", "x = 1\nf'{x}'\n", False)
        self.assertSameCode("x = 1\n", "x = 1\nprint('x')\n", False)
        self.assertSameCode("x = 1\n", "x = 1\nb'x'\n", False)

    def test_a_string_used_as_a_value_is_code(self) -> None:
        self.assertSameCode("x = 'one'\n", "x = 'two'\n", False)


#: The steps whose running the scenarios below decide, in file order.
WATCHED = ('Classify Changed files', 'Bump Version', 'Commit changes',
           'Commit documentation changes', 'Push changes')

#: A step's own keys sit two columns right of its ``- ``.
_STEP_KEY = re.compile(r'^ {8}([A-Za-z_][A-Za-z0-9_-]*):[ \t]*(.*?)[ \t]*$')


def job_steps(block: 'str') -> 'list[dict[str, str]]':
    """``[{key: value}]`` for the top-level keys of each step in a job ``block``,
    with a folded ``if: >-`` joined into one line.

    """
    lines = block.splitlines()
    start = next(index for index, line in enumerate(lines) if line == '    steps:')
    steps = []  # type: list[list[str]]
    for line in lines[start + 1:]:
        if line.strip() and not line.startswith('      ') and not line.lstrip().startswith('#'):
            break
        if line.startswith('      - '):
            steps.append([])
            line = '        ' + line[len('      - '):]
        if steps:
            steps[-1].append(line)

    parsed = []
    for body in steps:
        keys = {}  # type: dict[str, str]
        for index, line in enumerate(body):
            match = _STEP_KEY.match(line)
            if match is None:
                continue
            key, value = match.groups()
            if value in ('>', '>-'):
                folded = []
                for nested in body[index + 1:]:
                    if nested.strip() and not nested.startswith(' ' * 10):
                        break
                    folded.append(nested.strip())
                value = ' '.join(part for part in folded if part)
            keys[key] = value
        parsed.append(keys)
    return parsed


def walk(steps: 'list[dict[str, str]]', context: 'dict[str, object]',
         results: 'dict[str, tuple[str, dict[str, object]]]') -> 'dict[str, str]':
    """``{step name: outcome}`` for one run of the job.

    A step runs when its ``if:`` holds, with the implicit ``success()``: no
    earlier step concluded ``failure``. A step that runs gets the outcome and
    outputs ``results`` gives its ``id``, and ``success`` with none otherwise;
    ``continue-on-error: true`` concludes a failed one ``success``.

    """
    state = {}  # type: dict[str, object]
    failed = False
    outcomes = {}  # type: dict[str, str]
    for step in steps:
        runs = not failed and (not step.get('if') or evaluate_condition(
            step['if'], dict(context, steps=state, **{STATUS: {'cancelled': False}})))
        outcome, outputs = results.get(step.get('id', ''), ('success', {})) if runs else ('skipped', {})
        failed = failed or (outcome == 'failure' and step.get('continue-on-error') != 'true')
        if 'id' in step:
            state[step['id']] = {'outcome': outcome, 'outputs': outputs if runs else {}}
        outcomes[step.get('name') or step.get('uses', '')] = outcome
    return outcomes


#: ``[(row, files_changed, classify's result, Commit documentation changes' outputs,
#: the steps of WATCHED that run)]``.
SCENARIOS = [
    ('nothing changed', 'false', ('success', {}), {},
     ()),
    ('a code change bumps, commits and pushes', 'true', ('success', {'code_changed': 'true'}), {},
     ('Classify Changed files', 'Bump Version', 'Commit changes', 'Push changes')),
    ('comments only: committed without a bump, and pushed', 'true',
     ('success', {'code_changed': 'false'}), {'committed': 'true'},
     ('Classify Changed files', 'Commit documentation changes', 'Push changes')),
    ('comments only, held after a documentation commit: nothing pushed', 'true',
     ('success', {'code_changed': 'false'}), {},
     ('Classify Changed files', 'Commit documentation changes')),
    ('the classifier failed: the bump stands, as before #1674', 'true', ('failure', {}), {},
     ('Classify Changed files', 'Bump Version', 'Commit changes', 'Push changes')),
    ('the classifier wrote neither answer: the bump stands', 'true',
     ('success', {'code_changed': ''}), {},
     ('Classify Changed files', 'Bump Version', 'Commit changes', 'Push changes')),
]  # type: list[tuple[str, str, tuple[str, dict[str, object]], dict[str, object], tuple[str, ...]]]


class WorkflowMixin(unittest.TestCase):
    """``vendor-update``'s text, and its steps as :func:`job_steps` reads them."""

    block = ''  # type: str
    steps = []  # type: list[dict[str, str]]
    names = []  # type: list[Optional[str]]

    @classmethod
    def setUpClass(cls) -> None:
        cls.block = job_blocks(WORKFLOW.read_text(encoding='utf-8'), WORKFLOW)['vendor-update']
        cls.steps = job_steps(cls.block)
        cls.names = [step.get('name') for step in cls.steps]

    def step(self, name: 'str') -> 'dict[str, str]':
        if name not in self.names:
            self.fail(f'`vendor-update` has no step {name!r}')
        return self.steps[self.names.index(name)]


class TestTheStepsDecide(WorkflowMixin):
    """Which steps run, for each answer the classifier can give."""

    def test_every_scenario_decides_correctly(self) -> None:
        for name in WATCHED:
            self.step(name)
        violations = []  # type: list[str]
        for row, files_changed, classify, committed, expected in SCENARIOS:
            context = {'github': {'event_name': 'schedule', 'event': {}}}  # type: dict[str, object]
            results = {
                'verify-changed-files': ('success', {
                    'files_changed': files_changed,
                    'changed_files': PATH if files_changed == 'true' else NULL}),
                'classify': classify,
                'commit-docs': ('success', committed),
            }  # type: dict[str, tuple[str, dict[str, object]]]
            outcomes = walk(self.steps, context, results)
            ran = tuple(name for name in WATCHED if outcomes[name] != 'skipped')
            if ran != expected:
                violations.append(f'{row}: ran {ran}, expected {expected}')
        if violations:
            self.fail('\n'.join(violations))

    def test_the_classifier_runs_after_the_crawl_and_before_the_bump(self) -> None:
        order = [self.steps.index(self.step(name)) for name in
                 ('Update Vendor', 'Verify Changed files') + WATCHED]
        self.assertEqual(order, sorted(order))

    def test_the_classifier_reads_the_changed_files_as_data(self) -> None:
        """Through ``env:``, and a failure of its own does not fail the job."""
        step = self.step('Classify Changed files')
        self.assertEqual(step.get('run'), 'python util/vendor_code_changed.py')
        self.assertTrue(SCRIPT.exists())
        self.assertEqual(step.get('continue-on-error'), 'true')
        env = step_mapping(step_block(self.block, 'Classify Changed files'), 'env')
        self.assertEqual(env, {'CHANGED_FILES': '${{ steps.verify-changed-files.outputs.changed_files }}'})

    def test_only_the_bump_path_runs_bump_version(self) -> None:
        self.step('Commit documentation changes')
        for name in self.names:
            if name is None:
                continue
            with self.subTest(step=name):
                self.assertEqual('bump_version.py' in step_block(self.block, name), name == 'Bump Version')


class TestTheDocumentationCommitStep(WorkflowMixin, ScratchRepository):
    """``Commit documentation changes``' script, run as the runner runs it."""

    def setUp(self) -> None:
        super().setUp()
        # `python -c 'import pcapkit'` in the step reads this tree's version.
        bin_dir = self.root / 'bin'
        bin_dir.mkdir()
        (bin_dir / 'python').write_text(
            f'#!/bin/sh\nexec {shlex.quote(sys.executable)} -S "$@"\n', encoding='utf-8')
        (bin_dir / 'python').chmod(0o755)
        self.env['PATH'] = f'{bin_dir}{os.pathsep}{self.env["PATH"]}'
        self.write(PATH, edited(EDITS[0][1]))

    def run_step(self, event_name: 'str', head_commit: 'Optional[dict[str, object]]' = None,
                 ) -> 'tuple[subprocess.CompletedProcess[str], dict[str, str]]':
        """The step's script, its ``env:`` evaluated for the event; result and outputs."""
        self.step('Commit documentation changes')
        block = step_block(self.block, 'Commit documentation changes')
        github = {'event_name': event_name, 'event': {}}  # type: dict[str, object]
        if head_commit is not None:
            github['event'] = {'workflow_run': {'head_commit': head_commit}}
        context = {'github': github, 'steps': {
            'verify-changed-files': {'outputs': {'files_changed': 'true', 'changed_files': PATH}},
        }}  # type: dict[str, object]
        env = {}  # type: dict[str, str]
        for key, value in step_mapping(block, 'env').items():
            answer = evaluate_expression(value, context)
            env[key] = '' if answer is NULL else str(answer)

        path = self.root / 'step.sh'
        path.write_text(block_scalar_after(block, _RUN_LITERAL), encoding='utf-8')
        output = self.root / 'step.output'
        output.write_text('', encoding='utf-8')
        # `bash -e {0}`: a `run:` with no `shell:` (GitHub, "Workflow syntax for
        # GitHub Actions", `jobs.<job_id>.steps[*].shell`).
        result = subprocess.run(['bash', '-e', str(path)], cwd=self.repo,
                                env=dict(self.env, GITHUB_OUTPUT=str(output), **env),
                                capture_output=True, text=True, check=False,
                                timeout=scale_timeout(60))
        outputs = dict(line.split('=', 1) for line in
                       output.read_text(encoding='utf-8').splitlines() if '=' in line)
        return result, outputs

    def assertCommitted(self, result: 'subprocess.CompletedProcess[str]',
                        outputs: 'dict[str, str]') -> 'str':
        """One bot commit of the comment change, no bump; its message."""
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(outputs, {'committed': 'true'})
        self.assertEqual(self.git('rev-parse', 'HEAD~1'), self.base)
        self.assertEqual(self.git('status', '--porcelain'), '')
        self.assertEqual(self.git('show', '-s', '--format=%ae %ce'), f'{BOT[1]} {BOT[1]}')
        self.assertEqual(self.git('diff', '--name-only', 'HEAD~1', 'HEAD'), PATH)
        message = self.git('show', '-s', '--format=%B')
        self.assertEqual(message.splitlines()[0], DOCS_SUBJECT)
        self.assertIn('the version stays at\n9.9.9b9 (#1674)', message)
        self.assertIn(PATH, message)
        return message

    def assertHeld(self, result: 'subprocess.CompletedProcess[str]', outputs: 'dict[str, str]') -> None:
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(outputs, {})
        self.assertEqual(self.git('rev-parse', 'HEAD'), self.base)
        self.assertEqual(self.git('status', '--porcelain'), f'M {PATH}')
        self.assertIn('::notice title=Documentation changes held::', result.stdout)

    def test_the_schedule_commits_without_a_bump(self) -> None:
        self.assertCommitted(*self.run_step('schedule'))

    def test_a_run_after_a_documentation_commit_holds(self) -> None:
        """No chain: the run its own commit raises does not commit on top of it.

        The first commit comes from the step itself, so the message the hold
        recognises is the one the step writes.

        """
        message = self.assertCommitted(*self.run_step('schedule'))
        self.base = self.git('rev-parse', 'HEAD')
        self.write(PATH, edited([('[RFC-ietf-ntp-roughtime-19]', '[:rfc:`10049`]')]))
        verified = {'author': {'name': BOT[0], 'email': BOT[1]},
                    'message': message}  # type: dict[str, object]
        self.assertHeld(*self.run_step('workflow_run', verified))

    def test_a_run_after_any_other_commit_commits(self) -> None:
        cases = {
            'a merged pull request': (HUMAN, 'fix(vendor): render both IANA citation spellings (#1673)'),
            "the bot's bump": (BOT, 'Bumped version to 1.5.0b12\n\nUpdated vendor constant enumerations.'),
            'the same subject by someone else': (HUMAN, DOCS_SUBJECT),
            'the subject as a later line': (BOT, f'Bumped build to 4\n\n{DOCS_SUBJECT}'),
        }
        for case, (identity, message) in cases.items():
            with self.subTest(case):
                verified = {'author': {'name': identity[0], 'email': identity[1]},
                            'message': message}  # type: dict[str, object]
                self.assertCommitted(*self.run_step('workflow_run', verified))
                self.git('reset', '-q', '--soft', 'HEAD~1')


if __name__ == '__main__':
    unittest.main()
