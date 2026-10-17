# -*- coding: utf-8 -*-
"""Test a Vendor Update regeneration before it is committed (#1853).

:file:`.github/workflows/cron-vendor.yml` runs ``pcapkit-vendor`` and isort, then
commits what changed. Neither of its gates sees that tree: the Vendor test gate
runs on the schedule alone, and a ``workflow_run`` reads the Unit Tests verdict
on the commit from before the crawl. So 1.5.0b13 was committed with a pinned
test failing on it, and ``main`` stayed red until #1820. The owner's ruling on
#1853 is that the job tests the regenerated tree before it commits, under
#872's rule: a failed sub-vendor's changes are discarded, the others are kept,
and the job as a whole does not fail.

**Modules.** Each crawler writes the module its ``_dest_path()`` names, which
mirrors its own module from ``pcapkit/vendor/`` into :data:`GENERATED_ROOT`, and
nothing else. So a changed module there names the sub-vendor that wrote it, and
discarding that sub-vendor's changes is putting its module back as ``HEAD`` has
it, or removing it where ``HEAD`` has none.

**Attribution.** A failing test does not name the module at fault: the AppType
tests read every per-transport registry, for one. So no test is mapped to a
module. The tests are asked instead, each time with some of the changed modules
on top of ``HEAD``'s tree:

1. All of them. If the tests pass, every module is kept.
2. None of them. If the tests fail on ``HEAD``'s own tree as well, the failure
   is not the regeneration's, and nothing here can tell its good modules from
   its bad ones, so every change is discarded.
3. Halves. A half the tests pass with is kept; a half they fail with is halved
   again, down to a single module, which is discarded.
4. The kept modules together, unless step 3 already ran exactly that set. If
   they fail together, every change is discarded.

So the tree left behind is one the tests passed on, or ``HEAD``'s own. A set of
modules is never run twice, so one that failed once is not kept. Every run
after the first gets ``-x`` through ``PYTEST_ADDOPTS``: it only has to say pass
or fail, and the first run's log already names every failing test.

**Limits.** Each run is a child in a session of its own, with ``RLIMIT_FSIZE``
at ``--max-file-size-mib``. It is killed, and counts as failing, once its
process group holds more than ``--max-memory-mib`` resident, sampled with
``ps``: ``RLIMIT_AS`` caps address space rather than resident memory, and the
job runs on ``macos-latest``, which has no cgroup to cap it with.
``--budget-minutes`` bounds every run together; when it runs out before a
decision, every change is discarded. Each run imports through a
``PYTHONPYCACHEPREFIX`` of its own, removed after it, since a module swapped
back within the same second at the same size would otherwise load from a stale
cache. The run still writes bytecode there: without it, the const and vendor
tests took 234s rather than 157s, measured locally.

Run from the repository root, with the test command after ``--``. Writes
``verdict=`` ``unchanged``, ``passed``, ``partial`` or ``discarded`` to
``$GITHUB_OUTPUT``, the modules and runs to ``$GITHUB_STEP_SUMMARY``, and a
``::warning::`` for what it discards. Exits non-zero only on an error of its
own or when it is stopped, after putting ``HEAD``'s copy of every changed module
back.

"""

from __future__ import annotations

import argparse
import contextlib
import os
import resource
import shutil
import signal
# git, ps and the test command, each with a fixed argument list and no shell.
import subprocess  # nosec B404
import sys
import tempfile
import time
from typing import TYPE_CHECKING, NamedTuple

if TYPE_CHECKING:
    from typing import FrozenSet, NoReturn, Optional, Sequence

#: The tree ``pcapkit-vendor`` writes, relative to the repository root, as in
#: :file:`util/vendor_code_changed.py`.
GENERATED_ROOT = 'pcapkit/const/'

#: Seconds between two samples of a run's memory.
POLL = 1.0

#: Seconds a run has to stop after ``SIGINT`` before it gets ``SIGKILL``.
GRACE = 10.0

MIB = 1 << 20


class Change(NamedTuple):
    """One changed module: its contents in ``HEAD`` and after the crawl, :data:`None` where absent."""

    path: str
    head: 'Optional[bytes]'
    regenerated: 'Optional[bytes]'


class Run(NamedTuple):
    """One run of the test command."""

    number: int
    modules: int
    result: str
    seconds: float


class BudgetExhausted(Exception):
    """The budget ran out before the tests could decide."""


def _git(*args: 'str') -> 'bytes':
    result = subprocess.run(['git', *args], check=False,  # nosec B603 B607
                            capture_output=True)
    if result.returncode != 0:
        raise RuntimeError(f'git {" ".join(args)} failed: '
                           + result.stderr.decode(errors='replace').strip())
    return result.stdout


def changed_modules() -> 'list[str]':
    """Each ``.py`` path under :data:`GENERATED_ROOT` that differs from ``HEAD``,
    new and deleted ones included, as ``Commit changes`` stages them.

    """
    listing = _git('status', '--porcelain=v1', '-z', '--untracked-files=all', '--no-renames',
                   '--', GENERATED_ROOT)
    paths = {os.fsdecode(entry[3:]) for entry in listing.split(b'\0') if entry}
    return sorted(path for path in paths if path.endswith('.py'))


def snapshot(paths: 'Sequence[str]') -> 'list[Change]':
    """Both versions of each of ``paths``."""
    changes = []
    for path in paths:
        head = _git('cat-file', 'blob', f'HEAD:{path}') if _git('ls-tree', '-z', 'HEAD', '--', path) else None
        regenerated = None
        if os.path.lexists(path):
            with open(path, 'rb') as file:
                regenerated = file.read()
        changes.append(Change(path, head, regenerated))
    return changes


def apply(changes: 'Sequence[Change]', selected: 'FrozenSet[str]') -> None:
    """Leave the regenerated version of each module in ``selected``, and ``HEAD``'s of the rest."""
    for change in changes:
        content = change.regenerated if change.path in selected else change.head
        if content is None:
            with contextlib.suppress(FileNotFoundError):
                os.remove(change.path)
            continue
        os.makedirs(os.path.dirname(change.path), exist_ok=True)
        with open(change.path, 'wb') as file:
            file.write(content)


def group_rss(pgid: 'int') -> 'Optional[int]':
    """Bytes resident in the processes of group ``pgid``, or :data:`None` if ``ps`` cannot say."""
    try:
        listing = subprocess.run(['ps', '-A', '-o', 'pgid=', '-o', 'rss='],  # nosec B603 B607
                                 capture_output=True, check=False, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if listing.returncode != 0:
        return None
    total = 0
    for line in listing.stdout.splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[1].isdigit() and fields[0] == str(pgid).encode():
            total += int(fields[1]) * 1024
    return total


def escape(text: 'str') -> 'str':
    """``text`` as the data of a workflow command."""
    return text.replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')


class Gate:
    """The test command, run on some of ``changes`` at a time."""

    def __init__(self, changes: 'Sequence[Change]', command: 'Sequence[str]', budget: 'float',
                 max_memory: 'int', max_file_size: 'int') -> None:
        self.changes = changes
        self.command = list(command)
        self.deadline = time.monotonic() + budget
        self.max_memory = max_memory
        self.max_file_size = max_file_size
        self.results = {}  # type: dict[FrozenSet[str], bool]
        self.runs = []  # type: list[Run]
        self.unsampled = False

    def test(self, selected: 'FrozenSet[str]', fail_fast: 'bool' = True) -> 'bool':
        """Whether the tests pass with ``selected`` on top of ``HEAD``'s tree.

        Raises :exc:`BudgetExhausted` when the budget ran out first.

        """
        if selected in self.results:
            return self.results[selected]
        number = len(self.runs) + 1
        if len(selected) == len(self.changes):
            label = f'Run {number}: the regeneration'
        elif selected:
            label = f'Run {number}: {len(selected)} of {len(self.changes)} regenerated modules on top of HEAD'
        else:
            label = f"Run {number}: HEAD's tree"

        apply(self.changes, selected)
        start = time.monotonic()
        result = self._run(label, fail_fast)
        self.runs.append(Run(number, len(selected), result, time.monotonic() - start))
        print(f'{label}: {result}', flush=True)
        if result == 'budget':
            raise BudgetExhausted
        self.results[selected] = result == 'passed'
        return self.results[selected]

    def _run(self, label: 'str', fail_fast: 'bool') -> 'str':
        """``'passed'``, ``'budget'``, or why the run failed."""
        if time.monotonic() >= self.deadline:
            return 'budget'
        env = dict(os.environ)
        if fail_fast:
            env['PYTEST_ADDOPTS'] = ' '.join(filter(None, (env.get('PYTEST_ADDOPTS'), '-x')))
        limit = self.max_file_size

        def cap() -> None:
            # In the child, between fork and exec.
            resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))

        cache = tempfile.mkdtemp(prefix='vendor-test-gate-')
        env['PYTHONPYCACHEPREFIX'] = cache
        print(f'::group::{label}', flush=True)
        try:
            child = subprocess.Popen(self.command, env=env,  # nosec B603
                                     start_new_session=True, preexec_fn=cap)
            try:
                stopped = self._watch(child)
            finally:
                # Whatever the run left running in its session goes with it,
                # and the run itself is reaped, however this was left.
                with contextlib.suppress(ProcessLookupError, PermissionError):
                    os.killpg(child.pid, signal.SIGKILL)
                with contextlib.suppress(subprocess.TimeoutExpired):
                    child.wait(timeout=GRACE)
        finally:
            print('::endgroup::', flush=True)
            shutil.rmtree(cache, ignore_errors=True)
        if stopped:
            return stopped
        return 'passed' if child.returncode == 0 else f'failed (exit {child.returncode})'

    def _watch(self, child: 'subprocess.Popen[bytes]') -> 'str':
        """Wait for ``child``, stopping it on the budget or the memory cap: why, or ``''``."""
        while True:
            try:
                child.wait(timeout=POLL)
                return ''
            except subprocess.TimeoutExpired:
                pass
            if time.monotonic() >= self.deadline:
                self._stop(child, signal.SIGINT)
                return 'budget'
            rss = group_rss(child.pid)
            if rss is None:
                self.unsampled = True
            elif rss > self.max_memory:
                self._stop(child, signal.SIGKILL)
                return f'killed: {rss // MIB} MiB resident, over the {self.max_memory // MIB} MiB cap'

    @staticmethod
    def _stop(child: 'subprocess.Popen[bytes]', signum: 'int') -> None:
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(child.pid, signum)
        try:
            child.wait(timeout=GRACE)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(child.pid, signal.SIGKILL)
            child.wait()


def bisect(gate: 'Gate', paths: 'Sequence[str]') -> 'list[str]':
    """The modules of ``paths``, a set the tests fail with, that they pass with by halves."""
    if len(paths) == 1:
        return []
    middle = len(paths) // 2
    kept = []  # type: list[str]
    for half in (paths[:middle], paths[middle:]):
        kept.extend(half if gate.test(frozenset(half)) else bisect(gate, half))
    return kept


def decide(gate: 'Gate', paths: 'Sequence[str]') -> 'tuple[FrozenSet[str], str]':
    """The modules to keep, and why the rest are discarded."""
    everything = frozenset(paths)
    if gate.test(everything, fail_fast=False):
        return everything, ''
    if not gate.test(frozenset()):
        return frozenset(), ("The tests fail on HEAD's own tree too, so they cannot tell a good "
                             'module from a bad one')
    if len(paths) == 1:
        return frozenset(), "The tests fail with the regenerated module on top of HEAD's tree"
    kept = frozenset(bisect(gate, paths))
    if not kept:
        return kept, "The tests fail with each regenerated module on top of HEAD's tree"
    if not gate.test(kept):
        return frozenset(), 'The modules the tests passed with by halves fail together'
    return kept, ''


def report(changes: 'Sequence[Change]', kept: 'FrozenSet[str]', reason: 'str', gate: 'Gate',
           command: 'str') -> 'str':
    """Write the summary and the annotations; the verdict."""
    discarded = [change.path for change in changes if change.path not in kept]
    if not discarded:
        verdict = 'passed'
        lines = ['### Vendor test gate: the regeneration passed', '',
                 f'`{command}` passed with every regenerated module, so all of them go on to be committed.']
        print(f'The tests passed with every regenerated module: {", ".join(sorted(kept))}')
    else:
        verdict = 'partial' if kept else 'discarded'
        if kept:
            heading = 'discarded the modules the tests fail with'
            body = (f"`{command}` fails with each module not kept below on top of HEAD's tree, so "
                    "HEAD's copy of it stays, as #872 does for a sub-vendor that raised. The other "
                    'regenerated modules passed and go on to be committed.')
            for path in discarded:
                print(f'::warning title=Vendor test gate discarded a module::{escape(path)}: '
                      f"{escape(command)} fails with it on top of HEAD's tree, so HEAD's copy is kept "
                      'and the rest of the regeneration is committed; see the step summary')
        else:
            heading = 'discarded every regenerated module'
            body = (f"{reason}. HEAD's copy of every module is kept, so nothing from this crawl is "
                    f'committed. The tests are `{command}`.')
            print(f'::warning title=Vendor test gate discarded every regenerated module::'
                  f'{escape(reason)}; see the step summary')
        lines = [f'### :warning: Vendor test gate {heading}', '', body, '',
                 '| Module | Kept |', '| --- | --- |']
        lines.extend(f'| `{change.path}` | {"yes" if change.path in kept else "no"} |' for change in changes)
        lines.extend(['', '| Run | Modules applied | Result | Seconds |', '| --- | --- | --- | --- |'])
        lines.extend(f'| {run.number} | {run.modules} of {len(changes)} | {run.result} | {run.seconds:.0f} |'
                     for run in gate.runs)
    if gate.unsampled:
        print('::warning title=Vendor test gate could not sample memory::ps did not answer, so '
              'the memory cap was not enforced on every sample')
    summary = os.environ.get('GITHUB_STEP_SUMMARY')
    if summary:
        with open(summary, 'a', encoding='utf-8') as file:
            print('\n'.join(lines), file=file)
    return verdict


def write_verdict(verdict: 'str') -> None:
    output = os.environ.get('GITHUB_OUTPUT')
    if output:
        with open(output, 'a', encoding='utf-8') as file:
            print(f'verdict={verdict}', file=file)


def _terminate(signum: 'int', frame: 'object') -> 'NoReturn':  # pylint: disable=unused-argument
    sys.exit(128 + signum)


def main(argv: 'Optional[list[str]]' = None) -> int:
    """Test the regeneration, and keep what the tests pass with."""
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0],
                                     usage='%(prog)s OPTIONS -- COMMAND...')
    parser.add_argument('--budget-minutes', type=float, required=True,
                        help='wall time for every run together')
    parser.add_argument('--max-memory-mib', type=float, required=True,
                        help="resident memory a run's process group may hold")
    parser.add_argument('--max-file-size-mib', type=float, required=True,
                        help='largest file a run may write')
    # Split by hand: how argparse treats `--` before a REMAINDER differs
    # between Python versions.
    argv = sys.argv[1:] if argv is None else list(argv)
    split = argv.index('--') if '--' in argv else len(argv)
    args = parser.parse_args(argv[:split])
    command = argv[split + 1:]
    if not command:
        parser.error('no test command after --')

    paths = changed_modules()
    if not paths:
        print(f'No module under {GENERATED_ROOT} changed, so there is nothing to test.')
        write_verdict('unchanged')
        return 0

    changes = snapshot(paths)
    gate = Gate(changes, command, args.budget_minutes * 60,
                int(args.max_memory_mib * MIB), int(args.max_file_size_mib * MIB))
    # SIGTERM, like SIGINT, still puts HEAD's copies back below, with the run
    # in flight killed. The workflow's next step covers a SIGKILL.
    signal.signal(signal.SIGTERM, _terminate)
    try:
        try:
            kept, reason = decide(gate, paths)
        except BudgetExhausted:
            kept, reason = frozenset(), (f'The {args.budget_minutes:g}-minute budget ran out '
                                         'before the tests could decide')
        apply(changes, kept)
        # Nothing the tests themselves left under the tree is committed either.
        strays = [path for path in changed_modules() if path not in set(paths)]
        apply(snapshot(strays), frozenset())
        for path in strays:
            print(f'::warning title=Vendor test gate restored a module::{escape(path)} changed '
                  'during the test runs, so it is put back as HEAD has it')
    except BaseException:
        apply(changes, frozenset())
        raise
    write_verdict(report(changes, kept, reason, gate, ' '.join(command)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
