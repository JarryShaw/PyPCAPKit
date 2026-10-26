# -*- coding: utf-8 -*-
"""Whether a pull request's changed files include code (#1052), or only tests (#2243).

The ``Classify the diff`` step of the ``changes`` job in
:file:`.github/workflows/unit-tests.yml`, :file:`.github/workflows/experimental.yml`
and :file:`.github/workflows/python-compatibility.yml` runs
``python3 util/classify_changes.py`` in the checkout and writes two outputs to
``$GITHUB_OUTPUT``:

``code``
    ``false`` on a docs-only diff, ``true`` otherwise.
``test-only``
    ``true`` on a test-only diff, ``false`` otherwise.

Those outputs decide which expensive legs run at all, so the script fails safe:
anything it cannot classify is code, ``code=true`` and ``test-only=false``.

A file is docs iff :func:`is_docs` holds: it is under ``docs/`` or ends in
``.md``, and is not under one of :data:`CODE_DIRS` -- so a Markdown file in one
of those (a PR template, a test fixture) is not docs, and nor is any other file
(``pyproject.toml``, ``Makefile``, ...). A file is a test iff :func:`is_test`
holds: it is under :data:`TEST_DIR`. That takes in the support files every test
runs under, such as ``tests/conftest.py`` and ``tests/_tiers.py``, and the
fixtures there, since a test-only diff still runs the whole suite on ``latest``.
Every other file is code, so a workflow, a ``util/`` script or an ``examples/``
file is never a test. A diff of docs and tests alone, with at least one test, is
test-only.

The diff is ``HEAD^1..HEAD``, a pull request's merge commit against its first
parent, which is exactly what merging would add; ``--no-renames`` lists both
sides of a rename, so moving a code file under ``docs/`` or ``tests/`` is still
a code change.

Only the workflow's own ``pull_request`` run is classified, which the step
passes as ``OWN_PR=true``. Anything else, a push to ``main`` included, reports
code without reading the diff. A failed or empty ``git diff`` is code, with a
warning.

The step runs on the runner's own ``python3``, as no setup-python precedes it,
so the script is standard library only.

"""

from __future__ import annotations

import os
# git, with a fixed argument list and no shell.
import subprocess  # nosec B404
import sys

try:  # #2047: run as `python util/<script>.py`, with util/ first on sys.path
    import _actions
except ImportError:  # imported as util.<script>, or loaded by path, from the repository root
    from util import _actions

__all__ = ['CODE_DIRS', 'TEST_DIR', 'is_docs', 'is_test', 'kind', 'main']

#: Directories none of whose files is docs, a Markdown one included.
CODE_DIRS = ('.github/', 'pcapkit/', 'tests/', 'util/', 'examples/')
#: The directory whose every file is a test, a Markdown one included (#2243).
TEST_DIR = 'tests/'


def is_docs(path: 'str') -> 'bool':
    """Whether ``path``, relative to the repository root, is documentation only."""
    if path.startswith(CODE_DIRS):
        return False
    return path.startswith('docs/') or path.endswith('.md')


def is_test(path: 'str') -> 'bool':
    """Whether ``path``, relative to the repository root, is a test, a test fixture or a test support file."""
    return path.startswith(TEST_DIR)


def kind(path: 'str') -> 'str':
    """``'docs'``, ``'test'`` or ``'code'``: what :func:`is_docs` and :func:`is_test` make of ``path``."""
    if is_docs(path):
        return 'docs'
    return 'test' if is_test(path) else 'code'


def main() -> 'int':
    """Classify ``HEAD^1..HEAD`` and append ``code=...`` and ``test-only=...`` to ``$GITHUB_OUTPUT``; the exit status."""
    code, test_only = 'true', 'false'
    if os.environ['OWN_PR'] != 'true':
        print("Not this workflow's own pull_request run: everything runs.")
    else:
        # -z: names are NUL-terminated, so a name holding whitespace
        # (or one git would otherwise quote) stays one path.
        diff = subprocess.run(['git', 'diff', '--name-only', '-z', '--no-renames', 'HEAD^1', 'HEAD'],  # nosec B603 B607
                              capture_output=True, text=True, check=False)
        files = [path for path in diff.stdout.split('\0') if path]
        if diff.returncode != 0 or not files:
            # #2047: unescaped, so git's stderr keeps its lines.
            _actions.annotate('warning', f'git diff exited {diff.returncode} with {len(files)} files: '
                              f'{diff.stderr.strip()}. Treating the diff as code.',
                              title='Could not list the changed files', escape=False)
        else:
            kinds = [kind(path) for path in files]
            print(f"{len(files)} changed files, {kinds.count('code')} of them code "
                  f"and {kinds.count('test')} of them tests:")
            for path, found in zip(files, kinds):
                print(f'  {found}  {path}')
            if 'code' not in kinds:
                if 'test' in kinds:
                    test_only = 'true'
                else:
                    code = 'false'
    print(f'code={code}')
    print(f'test-only={test_only}')
    _actions.set_output('code', code)
    _actions.set_output('test-only', test_only)
    return 0


if __name__ == '__main__':
    sys.exit(main())
