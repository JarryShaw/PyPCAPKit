# -*- coding: utf-8 -*-
"""Whether a pull request's changed files include code (#1052).

The ``Classify the diff`` step of the ``changes`` job in
:file:`.github/workflows/unit-tests.yml` and in :file:`.github/workflows/experimental.yml`
runs ``python3 util/classify_changes.py`` in the checkout and writes ``code=true``
or ``code=false`` to ``$GITHUB_OUTPUT``. That output decides whether the
expensive legs run at all, so the script fails safe: anything it cannot classify
is code.

A file is docs iff :func:`is_docs` holds: it is under ``docs/`` or ends in
``.md``, and is not under one of :data:`CODE_DIRS` -- so a Markdown file in one
of those (a PR template, a test fixture) is code, and so is every other file
(``pyproject.toml``, ``Makefile``, ...). The diff is ``HEAD^1..HEAD``, a pull
request's merge commit against its first parent, which is exactly what merging
would add; ``--no-renames`` lists both sides of a rename, so moving a code file
under ``docs/`` is still a code change.

Only the workflow's own ``pull_request`` run is classified, which the step
passes as ``OWN_PR=true``. Anything else reports ``code=true`` without reading
the diff. A failed or empty ``git diff`` is code, with a warning.

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

__all__ = ['CODE_DIRS', 'is_docs', 'main']

#: Directories whose every file is code, a Markdown one included.
CODE_DIRS = ('.github/', 'pcapkit/', 'tests/', 'util/', 'examples/')


def is_docs(path: 'str') -> 'bool':
    """Whether ``path``, relative to the repository root, is documentation only."""
    if path.startswith(CODE_DIRS):
        return False
    return path.startswith('docs/') or path.endswith('.md')


def main() -> 'int':
    """Classify ``HEAD^1..HEAD`` and append ``code=...`` to ``$GITHUB_OUTPUT``; the exit status."""
    code = 'true'
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
            code_files = [path for path in files if not is_docs(path)]
            print(f'{len(files)} changed files, {len(code_files)} of them code:')
            for path in files:
                print(f"  {'code' if path in code_files else 'docs'}  {path}")
            if not code_files:
                code = 'false'
    print(f'code={code}')
    _actions.set_output('code', code)
    return 0


if __name__ == '__main__':
    sys.exit(main())
