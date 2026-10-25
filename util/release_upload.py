# -*- coding: utf-8 -*-
"""Attach files to an existing GitHub Release, leaving those it already has alone (#1634, #1640).

The step "Upload package to GitHub Release" of the ``pypi`` and ``conda`` jobs
of :file:`.github/workflows/create-release.yml` runs, from the checkout's root::

    python3 util/release_upload.py

with ``GH_TOKEN``, ``PCAPKIT_RELEASE_TAG``, the release's tag, and
``PCAPKIT_ASSETS``, one pattern per line, in the environment: ``dist/*`` in
``pypi``, the build step's package paths in ``conda``. It reads the release's
assets with ``gh release view``, then, for each file each pattern names:

* a name the release holds in state ``uploaded`` is left alone, with a
  ``::notice``, since a rebuild is not byte-identical to it (#1640);
* a name it holds in any other state, an upload that failed partway, gets a
  ``::warning`` and is uploaded with ``--clobber``, which replaces it;
* any other name is uploaded, and ``<name> -> <tag>`` printed.

Only ``gh release view`` and ``gh release upload`` run, neither of which calls
Update a release, where GitHub re-checks the release's target against the
workflow-file rule (#1634). A missing release fails the view, before any upload.

Each line's words, split on spaces and tabs, are expanded as the former shell's
unquoted ``$pattern`` expanded them: a word holding ``*``, ``?`` or ``[`` stands
for the files it matches, sorted, and for itself where it matches none; a word
that is not then a regular file gets an ``::error`` and exits 1. A failing
``gh`` ends the script with its status, as ``set -e`` ended the step.

The script is standard library only, and keeps to Python 3.8's syntax.

"""

from __future__ import annotations

import argparse
import glob
import os
import re
# gh, with a fixed argument list and no shell.
import subprocess  # nosec: B404
import sys
from typing import TYPE_CHECKING

try:  # #2047: run as `python util/<script>.py`, with util/ first on sys.path
    import _actions
except ImportError:  # imported as util.<script>, or loaded by path, from the repository root
    from util import _actions

if TYPE_CHECKING:
    from typing import Dict, List, Optional, Tuple

__all__ = ['ASSETS_JQ', 'gh', 'states', 'expand', 'main']

#: The ``--jq`` reading each asset's name and state, a tab apart.
ASSETS_JQ = '.assets[] | [.name, .state] | @tsv'


def gh(*args: 'str', capture: 'bool' = False) -> 'Tuple[int, str]':
    """Run ``gh args``; its status as the shell reports it, and with ``capture`` its output.

    Its standard error, and without ``capture`` its output, go where the
    script's do. The output is returned without its trailing newlines, as
    ``$(...)`` gives it. A ``gh`` missing from ``PATH`` is status 127.

    """
    sys.stdout.flush()
    try:
        result = subprocess.run(['gh', *args], stdout=subprocess.PIPE if capture else None,  # nosec: B603 B607
                                check=False)
    except FileNotFoundError:
        print('gh: command not found', file=sys.stderr, flush=True)
        return 127, ''
    output = result.stdout.decode('utf-8', 'surrogateescape').rstrip('\n') if capture else ''
    return _actions.exit_status(result.returncode), output


def states(published: 'str') -> 'Dict[str, str]':
    """``{name: state}`` of ``published``, the view's lines; a name listed twice keeps its last state.

    As ``IFS=$'\\t' read -r asset asset_state`` split each line: the tabs around
    it dropped, the name up to the next tab, and the state the rest, its leading
    tabs dropped.

    """
    found = {}  # type: Dict[str, str]
    for line in published.split('\n'):
        name, _, state = line.strip('\t').partition('\t')
        found[name] = state.lstrip('\t')
    return found


def expand(pattern: 'str') -> 'List[str]':
    """The files one line of ``$PCAPKIT_ASSETS`` names, as the shell's unquoted ``$pattern`` gave them."""
    files = []  # type: List[str]
    for word in re.split(r'[ \t]+', pattern):
        if not word:
            continue
        matches = sorted(glob.glob(word)) if glob.has_magic(word) else []
        files.extend(matches or [word])
    return files


def main(argv: 'Optional[List[str]]' = None) -> 'int':
    """Upload what the release lacks of ``$PCAPKIT_ASSETS``; the exit status."""
    argparse.ArgumentParser(description=__doc__.split('\n', 1)[0]).parse_args(argv)
    tag = os.environ['PCAPKIT_RELEASE_TAG']
    repository = os.environ['GITHUB_REPOSITORY']
    status, published = gh('release', 'view', tag, '--repo', repository, '--json', 'assets', '--jq', ASSETS_JQ,
                           capture=True)
    if status:
        return status
    found = states(published)
    for pattern in os.environ['PCAPKIT_ASSETS'].split('\n'):
        if not pattern:
            continue
        for file in expand(pattern):
            if not os.path.isfile(file):
                _actions.annotate('error', f"'{pattern}' matches no file, so {tag} would go without it.",
                                  title='Nothing to upload', escape=False)
                return 1
            name = file.rsplit('/', 1)[-1]
            state = found.get(name, '')
            if state == 'uploaded':
                _actions.annotate('notice', "Left as published (#1640): this run's rebuild is not "
                                            'byte-identical to it.', title=f'{name} already on {tag}', escape=False)
                continue
            if state:
                _actions.annotate('warning', f"{tag} holds it in state '{state}', not 'uploaded' -- an upload "
                                             'that failed partway -- so it is deleted and this file uploaded in '
                                             'its place.', title=f'{name} uploaded again', escape=False)
                status, _ = gh('release', 'upload', tag, file, '--repo', repository, '--clobber')
            else:
                status, _ = gh('release', 'upload', tag, file, '--repo', repository)
            if status:
                return status
            print(f'{name} -> {tag}', flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
