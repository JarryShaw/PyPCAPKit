# -*- coding: utf-8 -*-
"""The coverage leg's report: check the data is whole, combine it, and summarise it (#1387).

The ``Report coverage`` step of :file:`.github/workflows/unit-tests.yml`'s ``test``
job runs ``python util/coverage_report.py`` on the coverage leg, after ``Run unit
tests`` measured the unit tier with ``COVERAGE_DEBUG=pid,process`` logging every
measured process to :data:`LOG`. In the checkout, in order:

1. :func:`check`: a worker killed before its atexit save leaves no ``.coverage.*``
   file, and ``coverage combine`` then reports the rest as the whole. So unless
   the controller and every xdist worker, its direct children in the log, left
   one, it writes **Coverage not reported** to the job summary and an
   ``::error`` annotation, and exits 1 before anything is combined. #1423: each
   missing process is named with its command line and whether coverage's atexit
   handler ran in it at all.
2. :data:`COMMANDS`: ``coverage combine``, ``report``, ``html`` into
   ``coverage-html/`` and ``json`` into ``coverage.json``, each under
   :data:`RCFILE`. The first to fail ends the script with its exit status.
3. :func:`summary`: writes ``coverage-comment/coverage-summary.json``, the
   numbers coverage-comment.yml renders as a PR comment, and appends the
   per-package table to ``$GITHUB_STEP_SUMMARY``. ``TESTS_OUTCOME``, the tests
   step's ``outcome``, marks a total measured over failing tests as partial;
   ``PYTHON`` and ``SHA`` name the leg and the commit.

``python util/coverage_report.py check`` and ``... summary`` run one stage alone.

"""

from __future__ import annotations

import argparse
import collections
import glob
import json
import os
import re
# coverage, with a fixed argument list and no shell.
import subprocess  # nosec B404
import sys
from typing import TYPE_CHECKING

try:  # #2047: run as `python util/<script>.py`, with util/ first on sys.path
    import _actions
except ImportError:  # imported as util.<script>, or loaded by path, from the repository root
    from util import _actions

if TYPE_CHECKING:
    from typing import Optional, TextIO

__all__ = ['COMMANDS', 'LOG', 'RCFILE', 'check', 'main', 'summary']

#: The process log ``Run unit tests`` writes through ``COVERAGE_DEBUG_FILE``.
LOG = 'coverage-processes.log'
#: The coverage leg's configuration, relative to the checkout.
RCFILE = '.github/coverage.toml'
#: The coverage commands between :func:`check` and :func:`summary`, each run as ``python -m coverage``.
COMMANDS = (
    ('combine', f'--rcfile={RCFILE}'),
    ('report', f'--rcfile={RCFILE}'),
    ('html', f'--rcfile={RCFILE}', '-d', 'coverage-html'),
    ('json', f'--rcfile={RCFILE}', '-o', 'coverage.json'),
)
#: The per-file counts :func:`summary` adds up by package.
KEYS = ('num_statements', 'missing_lines', 'num_branches', 'num_partial_branches',
        'covered_lines', 'covered_branches')


def check(log: 'str' = LOG) -> 'int':
    """Whether the controller and every xdist worker in ``log`` saved a data file: 0 if so, else 1."""
    parent, cmd, atexit_ = {}, {}, {}  # type: dict[str, str], dict[str, str], dict[str, str]
    lines = open(log, errors='replace').readlines() if os.path.exists(log) else []  # pylint: disable=consider-using-with,unspecified-encoding
    for line in lines:
        match = re.match(r' *(\d+)\.\w+: New process(: cmd| parent pid): (.*)', line)
        if match:
            (parent if match[2] == ' parent pid' else cmd)[match[1]] = match[3]
            continue
        match = re.match(r' *(\d+)\.\w+: (atexit|sigterm): pid: \d+, (.*)', line)
        if match:
            atexit_[match[1]] = f'{match[2]}: {match[3]}'
    root = [pid for pid, line in cmd.items() if f"'run', '--rcfile={RCFILE}'" in line]
    workers = sorted(pid for pid, ppid in parent.items() if root and ppid == root[0])
    saved = set(re.findall(r'\.pid(\d+)\.', ' '.join(glob.glob('.coverage.*'))))
    missing = [pid for pid in root + workers if pid not in saved]
    print(f'controller {root}, {len(workers)} xdist workers, missing data: {missing}')
    # #1423: which process it was, and whether coverage's atexit handler ran
    # in it at all -- a pid with no `atexit:` line died on a signal before
    # saving, one with such a line reached the save and lost it afterwards.
    # Those are different bugs, and the log that distinguishes them is kept
    # as an artifact by the step after `Report coverage` rather than only read here.
    for pid in missing:
        print(f'  pid {pid}: cmd {cmd.get(pid, "<no cmd line logged>")}')
        print(f'  pid {pid}: {atexit_.get(pid, "no atexit/sigterm entry -- died before saving")}')
    if len(root) != 1 or not workers or missing:
        why = f'no data file from pid {missing}' if missing else 'the process log is missing or unreadable'
        _actions.summary(f'**Coverage not reported:** {why} (#1387); a total would under-count.')
        # #2047: the command stays literal, where #1672's scan of a KTLO step's scripts reads it.
        print(f'::error::Coverage data is incomplete: {why}.')
        return 1
    return 0


def _percent(counts: 'collections.Counter[str]') -> 'float':
    total = counts['num_statements'] + counts['num_branches']
    return 100.0 * (counts['covered_lines'] + counts['covered_branches']) / total if total else 100.0


def summary(page: 'TextIO') -> 'int':
    """Write ``coverage-comment/coverage-summary.json`` from ``coverage.json``, and the table to ``page``."""
    with open('coverage.json', encoding='utf-8') as file:
        data = json.load(file)
    packages = collections.defaultdict(collections.Counter)  # type: dict[str, collections.Counter[str]]
    for path, info in data['files'].items():
        parts = path.split('/')
        name = '/'.join(parts[:2]) if len(parts) > 2 else 'pcapkit (top level)'
        packages[name].update({key: info['summary'][key] for key in KEYS})
    rows = [[name, counts['num_statements'], counts['missing_lines'], counts['num_branches'],
             counts['num_partial_branches'], round(_percent(counts), 2)] for name, counts in sorted(packages.items())]
    total = round(data['totals']['percent_covered'], 2)
    tests = os.environ['TESTS_OUTCOME']
    os.makedirs('coverage-comment', exist_ok=True)
    with open('coverage-comment/coverage-summary.json', 'w', encoding='utf-8') as file:
        json.dump({'total': total, 'tests': tests, 'packages': rows, 'python': os.environ['PYTHON']}, file)
    status = '' if tests == 'success' else f' -- **tests {tests}**, so this is partial'
    print(f"**Coverage: {total:.2f}%**{status} (unit tier, Python {os.environ['PYTHON']}, "
          f"`{os.environ['SHA'][:9]}`)", file=page)
    print(file=page)
    print('| Package | Statements | Missed | Branches | Partial | Cover |', file=page)
    print('|---|--:|--:|--:|--:|--:|', file=page)
    for row in rows:
        print('| `{}` | {} | {} | {} | {} | {:.2f}% |'.format(*row), file=page)
    print(file=page)
    print('Per-file detail: the `coverage-html` artifact of this run.', file=page)
    return 0


def _summary_to_job_page() -> 'int':
    with _actions.open_summary() as page:
        return summary(page)


def main(argv: 'Optional[list[str]]' = None) -> 'int':
    """Run ``stage``, or every stage in order; the exit status of the first to fail."""
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    parser.add_argument('stage', nargs='?', choices=('all', 'check', 'summary'), default='all',
                        help='the stage to run alone (default: every stage)')
    args = parser.parse_args(argv)
    if args.stage == 'check':
        return check()
    if args.stage == 'summary':
        return _summary_to_job_page()
    status = check()
    if status:
        return status
    for command in COMMANDS:
        sys.stdout.flush()
        status = subprocess.run([sys.executable, '-m', 'coverage', *command], check=False).returncode  # nosec B603
        if status:
            return status
    return _summary_to_job_page()


if __name__ == '__main__':
    sys.exit(main())
