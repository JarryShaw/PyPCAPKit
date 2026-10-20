# -*- coding: utf-8 -*-
"""Whether a Vendor Update regeneration changed code, or only comments and docstrings.

:file:`.github/workflows/cron-vendor.yml` runs ``pcapkit-vendor`` and isort, then
lists the changed files with ``git status`` in its ``Verify Changed files`` step.
Without this script any changed file would
bump the version, and every bump starts a release. Of the bumps 1.5.0b5 to b12,
all but b5 and b8 changed only comments or docstrings by this script's rule: b9 a draft
becoming RFC 10049, b10 and b11 reference formatting (#1664). The owner's ruling
on #1674 is that such a regeneration is committed without a bump, and only a
code change cuts a beta.

This script makes that call. It compares each changed path in the working tree
with ``HEAD`` and prints one line per path. A path counts as *documentation*
only when all of these hold:

* it is a ``.py`` file under :data:`GENERATED_ROOT`, the tree ``pcapkit-vendor``
  writes;
* it exists both in ``HEAD`` and in the working tree, as a regular file with the
  same mode;
* both versions parse, and their :mod:`ast` dumps are equal once every statement
  that is only a string literal is dropped.

Comments never reach the AST. A string-literal statement does nothing at run
time, except as a docstring, which sets ``__doc__``. Names, values, ``__all__``,
imports and every other expression stay in the dump. Any other path is *code*:
a new file, a deleted one, a non-Python file, a file outside the generated tree,
a mode or type change, or a file that does not parse. So is a path that is
listed but cannot be read, such as one ``git status`` quoted, and one
identical to ``HEAD``. Only a positive finding that a file
differs in comments or docstrings alone spares the bump.

The source is parsed as bytes, so a coding cookie still decides how its string
literals decode.

Paths are the arguments, or else ``$CHANGED_FILES`` split on whitespace, the
separator that step uses. Writes ``code_changed=true`` or
``code_changed=false`` to ``$GITHUB_OUTPUT``. Exits non-zero, writing nothing,
only when it has no paths to judge, and the workflow then bumps.

"""

from __future__ import annotations

import argparse
import ast
import os
import posixpath
import stat
# git, with a fixed argument list and no shell.
import subprocess  # nosec B404
import sys
import warnings
from typing import TYPE_CHECKING, NamedTuple

if TYPE_CHECKING:
    from typing import Optional

#: The tree ``pcapkit-vendor`` writes, relative to the repository root: every
#: crawler's ``_dest_path()`` mirrors its own module from ``pcapkit/vendor/``
#: into ``pcapkit/const/``.
GENERATED_ROOT = 'pcapkit/const/'

#: The modes git records for a regular file, executable or not.
_REGULAR_MODES = {'100644': False, '100755': True}


class Verdict(NamedTuple):
    """Whether one path's change is a code change, and why, for the log."""

    code: bool
    reason: str


class _DropStringStatements(ast.NodeTransformer):
    """Remove every expression statement whose value is a ``str`` literal."""

    def visit_Expr(self, node: 'ast.Expr') -> 'Optional[ast.AST]':  # pylint: disable=invalid-name
        """Drop a docstring, or any other bare string literal."""
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            return None
        return self.generic_visit(node)


def code_of(source: 'bytes', filename: 'str' = '<unknown>') -> 'str':
    """The :func:`ast.dump` of ``source`` with comments and docstrings gone.

    Raises :exc:`SyntaxError` or :exc:`ValueError` when ``source`` does not
    parse.

    """
    with warnings.catch_warnings():
        # An invalid escape sequence warns at parse time; the dump is the same.
        warnings.simplefilter('ignore')
        tree = ast.parse(source, filename=filename)
    return ast.dump(_DropStringStatements().visit(tree))


def _git(*args: 'str', cwd: 'Optional[str]' = None) -> 'subprocess.CompletedProcess[bytes]':
    return subprocess.run(['git', *args], cwd=cwd, check=False,  # nosec B603 B607
                          capture_output=True)


def classify(path: 'str', cwd: 'Optional[str]' = None) -> 'Verdict':
    """Compare ``path`` in the working tree of ``cwd`` with ``HEAD``."""
    if path.startswith('/') or posixpath.normpath(path) != path:
        return Verdict(True, 'not a plain path relative to the repository root')
    if not (path.startswith(GENERATED_ROOT) and path.endswith('.py')):
        return Verdict(True, f'not a Python module under {GENERATED_ROOT}')

    listed = _git('ls-tree', '-z', 'HEAD', '--', path, cwd=cwd)
    if listed.returncode != 0:
        return Verdict(True, 'git ls-tree failed: ' + listed.stderr.decode(errors='replace').strip())
    if not listed.stdout:
        return Verdict(True, 'new file')
    mode, kind, blob = listed.stdout.split(b'\t', 1)[0].decode().split()
    if kind != 'blob' or mode not in _REGULAR_MODES:
        return Verdict(True, f'not a regular file in HEAD (mode {mode})')

    local = os.path.join(cwd or os.curdir, path)
    if not os.path.lexists(local):
        return Verdict(True, 'deleted')
    status = os.lstat(local)
    if not stat.S_ISREG(status.st_mode):
        return Verdict(True, 'no longer a regular file')
    if bool(status.st_mode & stat.S_IXUSR) != _REGULAR_MODES[mode]:
        return Verdict(True, 'file mode changed')

    old = _git('cat-file', 'blob', blob, cwd=cwd)
    if old.returncode != 0:
        return Verdict(True, 'git cat-file failed: ' + old.stderr.decode(errors='replace').strip())
    with open(local, 'rb') as file:
        new = file.read()
    if new == old.stdout:
        # Listed as changed, yet byte for byte what HEAD has: nothing here
        # shows the change is to comments, so it is not taken to be.
        return Verdict(True, 'listed as changed, but identical to HEAD')

    try:
        if code_of(old.stdout, f'HEAD:{path}') != code_of(new, path):
            return Verdict(True, 'code differs')
    except (SyntaxError, ValueError) as error:
        return Verdict(True, f'does not parse: {error}')
    return Verdict(False, 'only comments or docstrings differ')


def main(argv: 'Optional[list[str]]' = None) -> int:
    """Classify the changed paths and report whether any of them is code."""
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    parser.add_argument('paths', nargs='*', metavar='PATH',
                        help='changed paths, relative to the repository root '
                             '(default: $CHANGED_FILES, split on whitespace)')
    args = parser.parse_args(argv)

    paths = args.paths or os.environ.get('CHANGED_FILES', '').split()
    if not paths:
        print('::error title=No changed files to classify::neither arguments nor $CHANGED_FILES '
              'name a path, so this cannot say the change is documentation only')
        return 1

    code = False
    for path in paths:
        verdict = classify(path)
        code = code or verdict.code
        print(f'{"code" if verdict.code else "docs"}: {path}: {verdict.reason}')

    if code:
        print('A code change: the version is bumped.')
    else:
        print(f'::notice title=Comments and docstrings only::none of the {len(paths)} changed '
              f'file(s) changes code, so the version is not bumped (#1674).')

    output = os.environ.get('GITHUB_OUTPUT')
    if output:
        with open(output, 'a', encoding='utf-8') as file:
            print(f'code_changed={str(code).lower()}', file=file)
    return 0


if __name__ == '__main__':
    sys.exit(main())
