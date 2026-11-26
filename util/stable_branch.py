# -*- coding: utf-8 -*-
"""Keep ``stable`` at ``main``'s head, for Read the Docs to build ``stable`` from (#3077).

Read the Docs builds its ``stable`` version from a branch named ``stable`` where one
exists, rather than from the newest release tag. :file:`.github/workflows/stable-branch.yml`
runs this script on every push to ``main`` and on dispatch, from the checkout's root,
on the runner's ``python3`` and with the release App's token. It reads ``main``'s head
afresh rather than taking the run's commit, so a re-run of an older push cannot move
:data:`MIRROR` back, then creates :data:`MIRROR` there or force-updates it, whatever it
holds, with :func:`sync_develop.mirror`. It writes no other ref, and a read or write
that fails is an error. Standard library and the :program:`gh` CLI only, with
``GH_TOKEN`` in the environment.

"""

from __future__ import annotations

import argparse
import os
import sys
from typing import TYPE_CHECKING

try:  # #2047: run as `python util/<script>.py`, with util/ first on sys.path
    import _actions
    import sync_develop
except ImportError:  # imported as util.<script>, or loaded by path, from the repository root
    from util import _actions, sync_develop

if TYPE_CHECKING:
    from typing import Optional

#: The branch Read the Docs builds ``stable`` from, a mirror of ``main``.
MIRROR = 'stable'


def main(argv: 'Optional[list[str]]' = None) -> 'int':
    parser = argparse.ArgumentParser(description=f'Force-update {MIRROR} to {sync_develop.HEAD}\'s head.')
    parser.add_argument('--repo', default=os.environ.get('GITHUB_REPOSITORY') or sync_develop.REPO,
                        help=f'repository (default: $GITHUB_REPOSITORY, else {sync_develop.REPO})')
    args = parser.parse_args(argv)
    try:
        sync_develop.mirror(args.repo, sync_develop.head_sha(args.repo), MIRROR)
    except sync_develop.ApiError as error:
        _actions.annotate('error', str(error), title=f'{MIRROR} not mirrored')
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
