# -*- coding: utf-8 -*-
"""#1967: :file:`util/release_reset_build.py`, run as Create Release's "Reset Build Number" runs it.

* :class:`TestTheStepMatchesTheReferenceShell` runs the step's inline shell form, the
  reference the script must match, kept here verbatim, and the script, each against a fresh scratch
  repository built the same way at the same path, and requires the same status,
  standard output and error, the refs ``origin`` is left with, and the checkout's
  ``HEAD`` and ``conda/build``. A stand-in ``git`` in front of the real one
  fails a chosen command, or loses a push to a concurrent one. Each case names
  the line its shell ends on, so the table is checked to reach every way the
  shell ends.
* :class:`TestTheStepRunsTheScript` pins the step to its script and its
  ``env:``, after a whole checkout of the repository, its ``git`` calls to ones
  that never pull, merge, rebase, reset or force-push, and the script to Python 3.8's
  syntax.

The shell form runs as a step with no ``shell:`` runs on the runner, ``bash -e``, and
``bash`` prefixes each of its own errors with the script's path and line, which
:meth:`TestTheStepMatchesTheReferenceShell.reference` strips. The step's runs against the
scenarios of #1634, after "Create Tag", are
:mod:`tests.project.test_release_tags_the_run_sha_1634`'s.

"""

from __future__ import annotations

import ast
import os
import pathlib
import re
import shutil
import subprocess  # nosec: B404
import sys
import tempfile
import textwrap
import unittest
from typing import TYPE_CHECKING

from tests._support import bash_argv
from tests._workflows import steps
from tests.project.test_requires_python_floor_2051 import FLOOR

if TYPE_CHECKING:
    from typing import Callable, Optional

#: Test tier (#1958): runs the tree's own script and the step's inline shell form.
__tier__ = 'LATEST'

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'util' / 'release_reset_build.py'
WORKFLOW = 'create-release.yml'
STEP = 'Reset Build Number'
RUN = 'python3 util/release_reset_build.py'
ENV = {'PCAPKIT_VERSION': '${{ needs.version_check.outputs.PCAPKIT_VERSION }}',
       'PCAPKIT_RUN_SHA': '${{ github.sha }}'}
BASH = shutil.which('bash') or ''
GIT = shutil.which('git') or ''

VERSION = '1.5.0b9'

#: The step's inline shell form, the reference the script must match, verbatim.
REFERENCE_RESET = textwrap.dedent(r'''
    set -euo pipefail

    run_commit="$(git rev-parse --verify "${PCAPKIT_RUN_SHA}^{commit}")"
    run_version="$(git show "${run_commit}:pcapkit/__init__.py" | sed -n 's/^__version__ = //p')"
    builds="refs/tags/conda-${PCAPKIT_VERSION}+"

    for attempt in 1 2 3; do
      git fetch --quiet origin "+refs/heads/main:refs/remotes/origin/main"
      tip="$(git rev-parse refs/remotes/origin/main)"

      if ! git merge-base --is-ancestor "$run_commit" "$tip"; then
        echo "::warning title=conda/build not reset::${run_commit} is not on main (tip ${tip}), so main is left alone; its conda/build still reads what it did."
        exit 0
      fi
      tip_build="$(git show "${tip}:conda/build" | tr -d '[:space:]')"
      if [ "$tip_build" = "0" ]; then
        echo "::notice title=No conda build reset needed::main (${tip}) already carries conda/build 0."
        exit 0
      fi
      tip_version="$(git show "${tip}:pcapkit/__init__.py" | sed -n 's/^__version__ = //p')"
      if [ "$tip_version" != "$run_version" ]; then
        echo "::notice title=conda/build not reset::main (${tip}) has moved on to __version__ ${tip_version}; its conda/build ${tip_build} counts that version's builds."
        exit 0
      fi
      tagged="$(git ls-remote --tags --refs origin "${builds}*")"
      taken=""
      while read -r _ ref; do
        build="${ref#"$builds"}"
        if [ "$build" != "$ref" ] && [ "$build" != "0" ]; then
          taken="${taken:+${taken} }+${build}"
        fi
      done <<< "$tagged"
      if [ -n "$taken" ]; then
        echo "::warning title=conda/build not reset::conda-${PCAPKIT_VERSION} is already tagged at ${taken}; resetting conda/build ${tip_build} on main (${tip}) to 0 would let a later Conda Update bump reuse one of those build numbers."
        exit 0
      fi

      git switch --quiet --force --detach "$tip"
      printf 0 > conda/build
      git commit --quiet -m"Reset conda build number" -m"conda-${PCAPKIT_VERSION}+0 was tagged at ${run_commit}." -- conda/build
      if git push origin "HEAD:refs/heads/main"; then
        echo "conda/build reset from ${tip_build} to 0 on main in $(git rev-parse HEAD), on top of ${tip}"
        exit 0
      fi
      echo "push to main rejected on attempt ${attempt}; fetching again"
    done

    echo "::error title=conda/build not reset::main kept moving; three pushes were rejected. ${run_commit} is tagged regardless -- reset conda/build on main by hand if no conda-${PCAPKIT_VERSION}+N tag other than +0 exists."
    exit 1
''').lstrip('\n')

#: A ``git`` in front of the real one: ``$SHIM_FAIL``, the first argument, fails
#: with ``$SHIM_STATUS``; with ``$RACE_SHA`` set, the first push to ``main``
#: is beaten to it by a push of that commit from ``$RACE_FROM``.
SHIM = r'''#!/bin/sh
if [ -n "${SHIM_FAIL:-}" ] && [ "$1" = "$SHIM_FAIL" ]; then
  echo "fatal: $1 refused by the test" >&2
  exit "${SHIM_STATUS:-128}"
fi
case "$1 $*" in
  "push "*refs/heads/main*)
    if [ -n "${RACE_SHA:-}" ] && [ ! -e "$RACE_MARKER" ]; then
      : > "$RACE_MARKER"
      "$REAL_GIT" -C "$RACE_FROM" push -q origin "$RACE_SHA:refs/heads/main" || exit 99
    fi ;;
esac
exec "$REAL_GIT" "$@"
'''

#: Git commands that move a checkout onto ``main``'s history or rewrite it.
FORBIDDEN = frozenset({'pull', 'merge', 'rebase', 'reset'})


class Scratch:
    """An ``origin`` refusing non-fast-forward pushes, a seed clone writing to it, and the job's ``work`` checkout.

    Every commit carries the same dates, so a scenario built twice at the same
    path has the same commits, and its runs can be compared whole.

    """

    def __init__(self, root: 'pathlib.Path') -> 'None':
        self.root = root
        config = root / 'gitconfig'
        # #1644, #1906: no automatic maintenance, which raced the clones here.
        config.write_text('[maintenance]\n\tauto = false\n\tautoDetach = false\n'
                          '[gc]\n\tauto = 0\n\tautoDetach = false\n'
                          '[receive]\n\tautogc = false\n', encoding='utf-8')
        self.env = {
            'PATH': os.environ.get('PATH', ''), 'HOME': str(root), 'LC_ALL': 'C',
            'GIT_CONFIG_GLOBAL': str(config), 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_TERMINAL_PROMPT': '0',
            'GIT_AUTHOR_NAME': 'test', 'GIT_AUTHOR_EMAIL': 'test@example.invalid',
            'GIT_COMMITTER_NAME': 'test', 'GIT_COMMITTER_EMAIL': 'test@example.invalid',
            'GIT_AUTHOR_DATE': '2026-10-23T00:00:00Z', 'GIT_COMMITTER_DATE': '2026-10-23T00:00:00Z',
        }
        self.origin = root / 'origin.git'
        self.seed = root / 'seed'
        self.work = root / 'work'
        self.git('init', '-q', '--bare', '-b', 'main', str(self.origin))
        self.git('-C', str(self.origin), 'config', 'receive.denyNonFastForwards', 'true')
        self.git('-C', str(self.origin), 'config', 'receive.denyDeletes', 'true')
        self.git('init', '-q', '-b', 'main', str(self.seed))
        self.git('-C', str(self.seed), 'remote', 'add', 'origin', str(self.origin))

    def git(self, *args: 'str') -> 'str':
        result = subprocess.run([GIT, *args], env=self.env, capture_output=True, text=True,  # nosec: B603
                                check=False, timeout=60)
        if result.returncode:
            raise AssertionError(f'git {" ".join(args)}: {result.stderr}')
        return result.stdout.strip()

    def commit(self, version: 'Optional[str]', build: 'Optional[str]', note: 'str' = '') -> 'str':
        """Commit ``__version__`` and ``conda/build`` in the seed, :data:`None` leaving each out; the sha.

        A ``build`` ending in ``/`` makes ``conda/build`` a directory.

        """
        for path in ('pcapkit', 'conda'):
            shutil.rmtree(self.seed / path, ignore_errors=True)
            (self.seed / path).mkdir()
        if version is not None:
            (self.seed / 'pcapkit' / '__init__.py').write_text(f"__version__ = '{version}'\n")
        if build is not None and build.endswith('/'):
            (self.seed / 'conda' / 'build').mkdir()
            (self.seed / 'conda' / 'build' / 'file').write_text(build)
        elif build is not None:
            (self.seed / 'conda' / 'build').write_text(build)
        (self.seed / 'NOTE').write_text(note)
        self.git('-C', str(self.seed), 'add', '-A')
        self.git('-C', str(self.seed), 'commit', '-q', '--allow-empty', '-m', f'{version} build {build} {note}')
        return self.git('-C', str(self.seed), 'rev-parse', 'HEAD')

    def push(self, sha: 'str', ref: 'str') -> 'None':
        self.git('-C', str(self.seed), 'push', '-q', 'origin', f'{sha}:{ref}')

    def checkout(self, sha: 'str') -> 'None':
        """What ``actions/checkout`` leaves: every branch and tag fetched, ``HEAD`` detached at ``sha``."""
        self.git('clone', '-q', str(self.origin), str(self.work))
        self.git('-C', str(self.work), 'fetch', '-q', 'origin', '+refs/tags/*:refs/tags/*')
        self.git('-C', str(self.work), 'switch', '-q', '--detach', sha)

    def shim(self, **env: 'str') -> 'None':
        """Put :data:`SHIM` in front of ``git``, with ``env`` for it."""
        bin_dir = self.root / 'bin'
        bin_dir.mkdir(exist_ok=True)
        (bin_dir / 'git').write_text(SHIM, encoding='utf-8')
        (bin_dir / 'git').chmod(0o755)
        self.env.update(env, REAL_GIT=GIT, RACE_FROM=str(self.seed), RACE_MARKER=str(self.root / 'raced'))
        self.env['PATH'] = f'{bin_dir}{os.pathsep}{self.env["PATH"]}'


def released(scratch: 'Scratch', run: 'str', tip: 'Optional[str]' = None) -> 'str':
    """``main`` at ``tip``, or at ``run``, and the run's commit checked out; the run's sha."""
    scratch.push(tip or run, 'refs/heads/main')
    scratch.checkout(run)
    return run


def reset(scratch: 'Scratch') -> 'str':
    """The #1634 shape: three Conda Update bumps on top of the release's build 0."""
    run = scratch.commit(VERSION, '0')
    for build in ('1', '2', '3'):
        tip = scratch.commit(VERSION, build)
    return released(scratch, run, tip)


def stale(scratch: 'Scratch') -> 'str':
    return released(scratch, scratch.commit(VERSION, ' 2\n'))


def off_main(scratch: 'Scratch') -> 'str':
    base = scratch.commit('1.5.0b8', '2')
    run = scratch.commit(VERSION, '2')
    scratch.push(run, 'refs/heads/side')
    return released(scratch, run, base)


def at_zero(scratch: 'Scratch') -> 'str':
    run = scratch.commit(VERSION, '2')
    return released(scratch, run, scratch.commit(VERSION, '0\n'))


def later_version(scratch: 'Scratch') -> 'str':
    run = scratch.commit(VERSION, '2')
    scratch.commit('1.5.0b10', '0')
    return released(scratch, run, scratch.commit('1.5.0b10', '2'))


def tagged(scratch: 'Scratch') -> 'str':
    """``+0`` is not a build taken, ``+`` and ``+10`` are, and another version's are not this one's."""
    run = scratch.commit(VERSION, '0')
    tip = scratch.commit(VERSION, '3')
    for ref in (f'conda-{VERSION}+0', f'conda-{VERSION}+', f'conda-{VERSION}+10', 'conda-1.5.0b8+4'):
        scratch.push(tip, f'refs/tags/{ref}')
    return released(scratch, run, tip)


def only_zero_tagged(scratch: 'Scratch') -> 'str':
    run = scratch.commit(VERSION, '3')
    scratch.push(run, f'refs/tags/conda-{VERSION}+0')
    scratch.push(run, 'refs/tags/conda-1.5.0b8+4')
    return released(scratch, run)


def raced(scratch: 'Scratch') -> 'str':
    run = scratch.commit(VERSION, '2')
    racer = scratch.commit(VERSION, '2', 'pushed while the reset was in flight')
    scratch.shim(RACE_SHA=racer)
    return released(scratch, run)


def failing(command: 'str', status: 'str' = '128') -> 'Callable[[Scratch], str]':
    """:func:`stale`'s shape, with ``git command`` failing with ``status``."""
    def build(scratch: 'Scratch') -> 'str':
        run = stale(scratch)
        scratch.shim(SHIM_FAIL=command, SHIM_STATUS=status)
        return run
    return build


def no_version_file(scratch: 'Scratch') -> 'str':
    return released(scratch, scratch.commit(None, '2'))


def no_build_file(scratch: 'Scratch') -> 'str':
    return released(scratch, scratch.commit(VERSION, None))


def build_directory(scratch: 'Scratch') -> 'str':
    return released(scratch, scratch.commit(VERSION, 'tree/'))


def no_origin(scratch: 'Scratch') -> 'str':
    run = stale(scratch)
    scratch.git('-C', str(scratch.work), 'remote', 'set-url', 'origin', str(scratch.root / 'gone.git'))
    return run


def dirty(scratch: 'Scratch') -> 'str':
    """A checkout the switch must override: ``conda/build`` edited, and an untracked file the tip tracks."""
    run = scratch.commit(VERSION, '0')
    scratch.commit(VERSION, '3', 'main has a note')
    (scratch.seed / 'TRACKED').write_text('on main')
    scratch.git('-C', str(scratch.seed), 'add', 'TRACKED')
    scratch.git('-C', str(scratch.seed), 'commit', '-q', '-m', 'track a file the run commit lacks')
    released(scratch, run, scratch.git('-C', str(scratch.seed), 'rev-parse', 'HEAD'))
    (scratch.work / 'conda' / 'build').write_text('edited in the checkout')
    (scratch.work / 'TRACKED').write_text('untracked in the checkout')
    return run


def no_git(scratch: 'Scratch') -> 'str':
    run = stale(scratch)
    scratch.env['PATH'] = str(scratch.root / 'empty')
    return run


#: ``(name, build, env, the line its shell ends on)``: ``env``'s values are
#: formatted with the run's sha, and one of :data:`None` is left unset.
CASES = (
    ('the 1634 shape is reset', reset, {}, 'conda/build reset from 3 to 0 on main in '),
    ('a counter with whitespace is reset', stale, {}, 'conda/build reset from 2 to 0 on main in '),
    ('a commit off main', off_main, {}, '::warning title=conda/build not reset::'),
    ('a tip at build 0', at_zero, {}, '::notice title=No conda build reset needed::'),
    ('a tip on a later version', later_version, {}, "has moved on to __version__ '1.5.0b10'"),
    ('tagged builds', tagged, {}, f'conda-{VERSION} is already tagged at + +10;'),
    ('only +0 and another version tagged', only_zero_tagged, {}, 'conda/build reset from 3 to 0 on main in '),
    ('a push lost to a concurrent one', raced, {}, 'conda/build reset from 2 to 0 on main in '),
    ('every push rejected', failing('push'), {}, 'three pushes were rejected'),
    ('an unresolvable run sha', stale, {'PCAPKIT_RUN_SHA': 'f' * 40}, 'fatal: Needed a single revision'),
    ('no run sha', stale, {'PCAPKIT_RUN_SHA': None}, 'PCAPKIT_RUN_SHA: unbound variable'),
    ('no version', stale, {'PCAPKIT_VERSION': None}, 'PCAPKIT_VERSION: unbound variable'),
    ('no __init__.py at the run commit', no_version_file, {}, 'pcapkit/__init__.py'),
    ('no conda/build at the tip', no_build_file, {}, 'conda/build'),
    ('conda/build a directory', build_directory, {}, 'conda/build: Is a directory'),
    ('no origin to fetch', no_origin, {}, 'gone.git'),
    ('a failed fetch', failing('fetch'), {}, 'fatal: fetch refused by the test'),
    ('a failed rev-parse, killed', failing('rev-parse', '143'), {}, 'fatal: rev-parse refused by the test'),
    ('a failed merge-base', failing('merge-base', '128'), {}, '::warning title=conda/build not reset::'),
    ('a failed show', failing('show'), {}, 'fatal: show refused by the test'),
    ('a failed ls-remote', failing('ls-remote', '2'), {}, 'fatal: ls-remote refused by the test'),
    ('a failed switch', failing('switch'), {}, 'fatal: switch refused by the test'),
    ('a failed commit', failing('commit', '1'), {}, 'fatal: commit refused by the test'),
    ('no git', no_git, {}, 'git: command not found'),
    ('a dirty checkout is overridden', dirty, {}, 'conda/build reset from 3 to 0 on main in '),
)


@unittest.skipIf(not (BASH and GIT), 'needs bash, which runs the reference shell, and git')
class TestTheStepMatchesTheReferenceShell(unittest.TestCase):
    """The script exits, prints and leaves the repositories exactly as the inline shell form, on every case."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-1967-reset-')  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.tmp = pathlib.Path(tmp.name)
        self.shell = self.tmp / 'step.sh'
        self.shell.write_text(REFERENCE_RESET, encoding='utf-8')

    def scratch(self, build: 'Callable[[Scratch], str]') -> 'tuple[Scratch, str]':
        """A fresh scratch repository at the same path as the last, built by ``build``."""
        root = self.tmp / 'repo'
        shutil.rmtree(root, ignore_errors=True)
        root.mkdir()
        scratch = Scratch(root)
        return scratch, build(scratch)

    def environ(self, scratch: 'Scratch', run: 'str', env: 'dict[str, Optional[str]]') -> 'dict[str, str]':
        found = dict(scratch.env, PCAPKIT_VERSION=VERSION, PCAPKIT_RUN_SHA=run)
        for name, value in env.items():
            if value is None:
                del found[name]
            else:
                found[name] = value.format(run=run)
        return found

    def state(self, scratch: 'Scratch', result: 'subprocess.CompletedProcess[str]') -> 'tuple[object, ...]':
        """Status, both streams, ``origin``'s refs, and the checkout's ``HEAD`` and ``conda/build``."""
        def read(*args: 'str') -> 'str':
            return subprocess.run([GIT, *args], env=dict(scratch.env, PATH=os.environ.get('PATH', '')),  # nosec
                                  capture_output=True, text=True, check=False, timeout=60).stdout
        build = scratch.work / 'conda' / 'build'
        return (result.returncode, result.stdout, result.stderr,
                read('-C', str(scratch.origin), 'for-each-ref', '--format=%(objectname) %(refname)'),
                read('-C', str(scratch.work), 'rev-parse', 'HEAD'),
                build.read_bytes() if build.is_file() else None)

    def reference(self, build: 'Callable[[Scratch], str]', env: 'dict[str, Optional[str]]') -> 'tuple[object, ...]':
        """The inline shell form as a step runs it, ``bash -e``, its own errors' ``<path>: line N:`` dropped."""
        scratch, run = self.scratch(build)
        result = subprocess.run(bash_argv('-e', str(self.shell), executable=BASH), cwd=scratch.work,  # nosec: B603
                                env=self.environ(scratch, run, env), capture_output=True, text=True,
                                check=False, timeout=120)
        result.stderr = re.sub(rf'(?m)^{re.escape(str(self.shell))}: line \d+: ', '', result.stderr)
        return self.state(scratch, result)

    def script(self, build: 'Callable[[Scratch], str]', env: 'dict[str, Optional[str]]') -> 'tuple[object, ...]':
        """``python3 util/release_reset_build.py`` as the step runs it, with this interpreter."""
        scratch, run = self.scratch(build)
        result = subprocess.run([sys.executable, str(SCRIPT)], cwd=scratch.work,  # nosec: B603
                                env=self.environ(scratch, run, env), capture_output=True, text=True,
                                check=False, timeout=120)
        return self.state(scratch, result)

    def test_each_case(self) -> None:
        for name, build, env, _ in CASES:
            with self.subTest(case=name):
                self.assertEqual(self.script(build, env), self.reference(build, env))

    def test_every_case_was_reached(self) -> None:
        """Each case ends the shell on its own line, and together they reach every way it ends."""
        statuses = set()
        for name, build, env, line in CASES:
            with self.subTest(case=name):
                status, stdout, stderr, *_ = self.reference(build, env)
                self.assertIn(line, f'{stdout}{stderr}')
                statuses.add(status)
        self.assertEqual(statuses, {0, 1, 2, 127, 128, 143})


class TestTheStepRunsTheScript(unittest.TestCase):
    """The step runs the script after a whole checkout, and the script never moves ``main`` but forward."""

    def test_the_step_runs_the_script(self) -> None:
        found = [step for step in steps(WORKFLOW, 'tag') if step.get('name') == STEP]
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]['run'], RUN)
        self.assertEqual(found[0].get('env'), ENV)

    def test_no_step_holds_the_reference_shell(self) -> None:
        for job_id in ('tag', 'github', 'pypi', 'conda'):
            for step in steps(WORKFLOW, job_id):
                with self.subTest(job=job_id, step=step.get('name')):
                    self.assertNotIn('printf 0 > conda/build', step.get('run', ''))

    def test_a_whole_checkout_comes_first(self) -> None:
        """A sparse checkout, or none, would leave ``util/`` out."""
        found = steps(WORKFLOW, 'tag')
        names = [step.get('name') for step in found]
        checkout = found[names.index('Checkout code')]
        self.assertLess(names.index('Checkout code'), names.index(STEP))
        self.assertTrue(str(checkout.get('uses', '')).startswith('actions/checkout@'))
        self.assertEqual(checkout['with'].get('fetch-depth'), 0)
        self.assertNotIn('sparse-checkout', checkout['with'])
        self.assertNotIn('path', checkout['with'])
        self.assertNotIn('working-directory', found[names.index(STEP)])

    def test_its_git_never_pulls_merges_rebases_resets_or_forces(self) -> None:
        calls = [node for node in ast.walk(ast.parse(SCRIPT.read_text(encoding='utf-8')))
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'git']
        commands = set()
        for call in calls:
            words = [arg.value if isinstance(arg, ast.Constant) else '<computed>' for arg in call.args]
            commands.add(words[0])
            with self.subTest(call=' '.join(words)):
                self.assertNotIn(words[0], FORBIDDEN)
                if words[0] == 'push':
                    self.assertEqual(words, ['push', 'origin', 'HEAD:refs/heads/main'])
                if words[0] == 'switch':
                    self.assertIn('--force', words, 'a dirty checkout would stop the switch')
                    self.assertIn('--detach', words)
        self.assertEqual(commands, {'rev-parse', 'show', 'fetch', 'merge-base', 'ls-remote', 'switch', 'commit',
                                    'push'})

    def test_it_parses_as_python_3_8(self) -> None:
        """``tag`` has no setup-python, so it runs on the image's ``python3``.

        ``feature_version`` is best-effort on a newer interpreter, so the 3.8
        compat leg's ``Compile the 3.8-floor util scripts`` is the authoritative
        check (#2206).

        """
        ast.parse(SCRIPT.read_text(encoding='utf-8'), feature_version=FLOOR)


if __name__ == '__main__':
    unittest.main()
