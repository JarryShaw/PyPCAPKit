# -*- coding: utf-8 -*-
"""Run a workflow step's bash script with a ``python`` that records what it is handed.

The tier selections live in :mod:`tests._tiers`, and each workflow step asks for
them at run time, so what can drift is how a step uses the answer. These helpers
slice a step out of :file:`.github/workflows/unit-tests.yml` and run it from the
root under ``bash -e``, with :data:`PYTHON_STUB` first on ``PATH``, so a test reads
the arguments the step builds rather than what its text appears to say.
:mod:`tests.project.test_tier_steps_1958` runs the steps with them, and
:mod:`tests.test_tier_guard` slices jobs with :func:`job_section` (#3148).

Nothing here imports :mod:`pcapkit`, so a project pin may use it (#1954).

"""
from __future__ import annotations

import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap

from tests import _tiers
from tests._support import bash_argv

__all__ = ['WORKFLOW', 'EXPERIMENTAL_WORKFLOW', 'BASH', 'PYTHON_STUB', 'job_section', 'step_run_block',
           'run_script', 'stubbed_argv', 'leg_argv', 'leg_ignores', 'leg_selects', 'project_pins_run']

#: The unit-tier workflow. Absent from a source distribution, which is why the
#: tests reading it skip rather than fail.
WORKFLOW = _tiers.ROOT / '.github' / 'workflows' / 'unit-tests.yml'
#: The experimental legs' workflow (#1732), whose unit-tier step leaves the ``LATEST`` tier out too.
EXPERIMENTAL_WORKFLOW = _tiers.ROOT / '.github' / 'workflows' / 'experimental.yml'
#: The ``bash`` the workflow steps run under, by absolute path: on Windows a bare
#: ``bash`` resolves to System32's WSL launcher, not the Git Bash this finds (#2103).
BASH = shutil.which('bash')

#: A ``python`` that writes each argument on a line of ``$ARGS_FILE``, and hands a
#: ``-c`` to the real one, which is how the steps ask tests/_tiers.py for the pins. util/cap_file_size.py's
#: command it execs, as the script does, with no real interpreter: under the coverage
#: leg one would be measured, be logged as a second ``coverage run --rcfile``
#: controller, and exec before saving, which fails the #1387 guard (#1969).
#:
#: With ``$SELECTOR_CACHE`` set, a ``-c`` runs the real interpreter once per distinct
#: argument list and replays its output after that (#2254): each selector call rescans
#: the suite in a fresh interpreter, and the steps are asked the same selectors
#: repeatedly. A doctored step that asks something else is keyed apart and runs for
#: real; a failing run is not kept.
PYTHON_STUB = ('#!/bin/sh\n'
               'if [ "$1" = -c ] && [ -n "$SELECTOR_CACHE" ]; then\n'
               '  answer="$SELECTOR_CACHE/$(printf \'%s\\n\' "$@" | cksum | tr \' \' _)"\n'
               '  if [ ! -f "$answer" ]; then\n'
               '    "$REAL_PYTHON" "$@" > "$answer.part" || { status=$?; cat "$answer.part"; exit "$status"; }\n'
               '    mv "$answer.part" "$answer"\n'
               '  fi\n'
               '  exec cat "$answer"\n'
               'fi\n'
               'case "$1" in -c) exec "$REAL_PYTHON" "$@";; util/cap_file_size.py) shift; exec "$@";; esac\n'
               'printf \'%s\\n\' "$@" > "$ARGS_FILE"\n')


def job_section(text: 'str', name: 'str') -> 'str':
    """The YAML text of job ``name``, from its header to the next top-level job.

    A plain slice rather than a real YAML parse: the step runs here and
    :class:`~tests.test_tier_guard.DependencyGateSelectionTests` both need to know
    what one job's steps say without tripping over another job that happens to
    mention the same words, and a two-space-indented ``key:`` line is what marks a
    job boundary in this file however its body is written.

    """
    match = re.search(rf'(?m)^  {re.escape(name)}:\n(.*?)(?=^  \w[\w-]*:\n|\Z)', text, re.DOTALL)
    if match is None:
        raise AssertionError(f'no job named {name!r} found in the workflow')
    return match.group(1)


def step_run_block(section: 'str', step_name: 'str') -> 'str':
    """The ``run:`` block of the step named ``step_name`` within a job section.

    Scoped to one step, not just one job, because a job can hold several
    steps and only one of them is the one a test cares about -- see
    :func:`job_section` for why a text slice rather than a YAML parse.

    """
    match = re.search(
        rf'(?m)^      - name: {re.escape(step_name)}\n(.*?)(?=^      - name:|\Z)',
        section, re.DOTALL,
    )
    if match is None:
        raise AssertionError(f'no step named {step_name!r} found in this job')
    return match.group(1)


def run_script(section: 'str', step_name: 'str') -> 'str':
    """The dedented ``run: |`` script of the step named ``step_name`` in a job section."""
    match = re.search(r'(?ms)^        run: \|\n(.*)', step_run_block(section, step_name))
    if match is None:
        raise AssertionError(f'the step {step_name!r} has no run: | block')
    lines = []
    for line in match.group(1).splitlines():
        if line.strip() and not line.startswith(' ' * 10):
            break
        lines.append(line)
    return textwrap.dedent('\n'.join(lines))


def stubbed_argv(script: 'str', env: 'dict[str, str]') -> 'list[str]':
    """The arguments ``script`` hands ``python``, run from the root under ``bash -e``."""
    with tempfile.TemporaryDirectory(prefix='pcapkit-pins-') as temp:
        stub = pathlib.Path(temp, 'python')
        stub.write_text(PYTHON_STUB, encoding='utf-8')
        stub.chmod(0o755)
        record = pathlib.Path(temp, 'args')
        full = dict(os.environ, **env, ARGS_FILE=str(record), RUNNER_TEMP=temp, REAL_PYTHON=sys.executable,
                    PATH=temp + os.pathsep + os.environ.get('PATH', ''))
        full.pop('PYTHONSAFEPATH', None)  # the runner sets none, and it would hide tests/ from `-c`
        result = subprocess.run(bash_argv('-e', '-c', script, executable=BASH), env=full, cwd=str(_tiers.ROOT),
                                capture_output=True, text=True, check=False, timeout=120)
        if result.returncode:
            raise AssertionError(f'the step failed: {result.stdout[-1000:]}{result.stderr[-1000:]}')
        return record.read_text(encoding='utf-8').splitlines()


def leg_argv(text: 'str', half: 'str' = '', cache: 'str' = '') -> 'list[str]':
    """What the ``Run unit tests`` step hands pytest on a ``test`` leg, or with ``half`` a ``test-latest-tier`` cell.

    ``cache`` is a directory for :data:`PYTHON_STUB`'s ``$SELECTOR_CACHE``; empty runs every selector.

    """
    script = run_script(job_section(text, 'test'), 'Run unit tests')
    # #2005: a leg that runs pytest once, as a PyPy leg's own `SHARDS` would otherwise reach the stubbed step.
    return stubbed_argv(script, {'ANNOTATION_LEVEL': 'error', 'COVERAGE': 'false', 'HALF': half, 'SHARDS': '',
                                 'SELECTOR_CACHE': cache})


def leg_ignores(text: 'str', half: 'str' = '', cache: 'str' = '') -> 'list[str]':
    """The modules :func:`leg_argv` ``--ignore``\\ s, less the fixture tier's directory."""
    return [arg.split('=', 1)[1] for arg in leg_argv(text, half, cache)
            if arg.startswith('--ignore=') and arg != f'--ignore=tests/{next(iter(_tiers.FIXTURE_TIER_DIRS))}']


def leg_selects(text: 'str', half: 'str' = '', cache: 'str' = '') -> 'list[str]':
    """The modules :func:`leg_argv` names for pytest to run, a ``test-latest-tier`` cell's half (#2751)."""
    return [arg for arg in leg_argv(text, half, cache) if not arg.startswith('-') and arg.endswith('.py')]


def project_pins_run(text: 'str', half: 'str', cache: 'str' = '') -> 'list[str]':
    """The modules ``project-tests``'s ``Run the project pins`` step hands pytest in cell ``half`` (#2798).

    ``cache`` is as for :func:`leg_ignores`.

    """
    argv = stubbed_argv(run_script(job_section(text, 'project-tests'), 'Run the project pins'),
                        {'HALF': half, 'SELECTOR_CACHE': cache})
    return [arg for arg in argv if arg.endswith('.py')]
