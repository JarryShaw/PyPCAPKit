# -*- coding: utf-8 -*-
"""The conda jobs' steps, in both conda workflows (#888, #1822, #3133).

Both :file:`.github/workflows/create-release.yml` and
:file:`.github/workflows/cron-conda.yml` build the one ``noarch: python``
package in ``conda-build``, on ``ubuntu-latest``, and publish it from ``conda``
and ``conda-dist`` respectively (#3133). They run it in the forms below, with
``PCAPKIT_CONDA_OS``, the job's ``runs-on``, where it reads it:

``python3 util/release_conda.py leg /tmp/anaconda_release.json``
    "Check whether this leg is already on Anaconda", in ``conda`` alone, which
    has no setup-python, so on the image's ``python3``. It fetches
    ``https://api.anaconda.org/release/jarryshaw/pypcapkit/<PCAPKIT_VERSION>``
    to the path given, as :func:`release_published.fetch` does, and on a ``200``
    counts, on ``python3 -`` as :func:`release_published.count` does, whether a
    distribution is for this leg's platform and a :data:`BUILD` build. It
    appends ``PCAPKIT_LEG_EXISTS``, ``true`` or ``false``, to ``$GITHUB_OUTPUT``,
    and a ``::notice`` where it is ``true``.
``python ../../util/release_conda.py build``
    "Build conda packages", from :file:`conda/pypcapkit` under ``bash -el``, so on
    conda's base ``python``. It runs ``conda build`` into a fresh ``compilation-``
    directory, and appends ``out_dir``, ``host_package``, the first package built
    in byte order, ``packages_csv`` and ``packages``, every package, a comma and a
    line apart, to ``$GITHUB_OUTPUT``. A build that leaves no package, or one
    whose platform is not the leg's (#1822), gets an ``::error`` and exits 1.
    The recipe's host Python is ``PCAPKIT_PYTHON_VERSION``, the setup-python
    that downloaded :file:`conda/wheels`.
``python3 util/release_conda.py downloaded DIRECTORY``
    "Find the conda package", in ``conda`` and ``conda-dist``, which publish the
    package ``conda-build`` built once and ``conda-test`` installed on every
    platform (#3133). It appends ``packages_csv`` and ``packages``, each package
    under ``DIRECTORY`` a comma and a line apart, to ``$GITHUB_OUTPUT``; with no
    package it gets an ``::error`` and exits 1.

:data:`PLATFORMS` maps the job's runner to the platform it publishes.

Both workflows run this one copy of the build. It fails as a shell step under
``set -euo pipefail`` would: a failing command ends the script with its
status, a missing one with 127, and a variable it reads that is unset with
``<name>: unbound variable`` and status 1. The build searches for packages
once.

The script is standard library only, and keeps to Python 3.8's syntax.

"""

from __future__ import annotations

import argparse
import fnmatch
import os
import stat
# conda, with a fixed argument list and no shell.
import subprocess  # nosec: B404
import sys
import tempfile
from typing import TYPE_CHECKING

try:  # #2047: run as `python util/<script>.py`, with util/ first on sys.path
    import _actions
    import release_published
except ImportError:  # imported as util.<script>, or loaded by path, from the repository root
    from util import _actions, release_published

if TYPE_CHECKING:
    from typing import Optional

__all__ = ['PLATFORMS', 'BUILD', 'PATTERNS', 'leg_source', 'env', 'call', 'append', 'packages', 'leg', 'build',
           'downloaded', 'main']

#: The conda platform each runner label builds and publishes: one ``noarch`` package (#3133).
PLATFORMS = {
    'ubuntu-latest': 'noarch',
}
#: The tag a ``noarch: python`` build string starts with, ``py_<number>``, as
#: util/python_versions.py's ``conda-builds``.
BUILD = 'py'
#: The names of the files ``conda build`` writes that are packages.
PATTERNS = ('*.tar.bz2', '*.conda')


def leg_source(path: 'str', platform: 'str', py_tag: 'str') -> 'str':
    """The snippet printing whether the Anaconda reply at ``path`` holds ``platform``'s ``py_tag`` build."""
    return '\n'.join((
        'import json',
        f'with open({path!r}) as f:',
        '    data = json.load(f)',
        f'target_platform = {platform!r}',
        f'py_tag = {py_tag!r}',
        'found = any(',
        "    d.get('attrs', {}).get('subdir') == target_platform",
        "    and d.get('attrs', {}).get('build', '').startswith(py_tag + '_')",
        "    for d in data.get('distributions', [])",
        ')',
        "print('true' if found else 'false')",
    )) + '\n'


def env(name: 'str') -> 'str':
    """``$name``; :exc:`release_published.Unbound` where it is unset."""
    return os.fsdecode(release_published.var(name))


def call(*args: 'str') -> 'int':
    """Run ``args``, its output where the script's goes; its status as the shell reports it, 127 if missing."""
    sys.stdout.flush()
    try:
        result = subprocess.run(list(args), check=False)  # nosec: B603
    except FileNotFoundError:
        print(f'{args[0]}: command not found', file=sys.stderr, flush=True)
        return 127
    return _actions.exit_status(result.returncode)


def append(name: 'str', value: 'bytes') -> 'int':
    """``echo "<name>=<value>" >> "$GITHUB_OUTPUT"``; the exit status."""
    target = env('GITHUB_OUTPUT')
    try:
        with open(target, 'ab') as file:
            file.write(name.encode() + b'=' + value + b'\n')
    except OSError as error:
        sys.stdout.flush()
        print(f'{target}: {os.strerror(error.errno or 0)}', file=sys.stderr, flush=True)
        return 1
    return 0


def packages(out_dir: 'str') -> 'list[str]':
    """Each regular file under ``out_dir`` that :data:`PATTERNS` names, sorted, as ``find | sort`` lists them."""
    found = []
    for root, _, files in os.walk(out_dir):
        for name in files:
            path = os.path.join(root, name)
            if any(fnmatch.fnmatchcase(name, pattern) for pattern in PATTERNS) \
                    and stat.S_ISREG(os.lstat(path).st_mode):
                found.append(path)
    return sorted(found)


def leg(reply: 'str') -> 'int':
    """``PCAPKIT_LEG_EXISTS``: whether anaconda.org has this leg's distribution already (#888)."""
    platform = PLATFORMS.get(env('PCAPKIT_CONDA_OS'), '')
    version = release_published.var('PCAPKIT_VERSION')
    status = release_published.fetch(release_published.ANACONDA_URL.encode() + version, reply)
    exists = b'false'
    if status == b'200':
        exists = release_published.count(leg_source(reply, platform, BUILD))
    failed = append('PCAPKIT_LEG_EXISTS', exists)
    if failed:
        return failed
    if exists == b'true':
        _actions.emit(b"::notice title=conda leg already published::pypcapkit " + version + b' for '
                      + platform.encode() + b' / ' + BUILD.encode() + b' is already on anaconda.org/jarryshaw (http '
                      + status + b"); skipping this leg's upload.\n")
    return 0


def build() -> 'int':
    """``conda build`` this leg's package, and output where it is (#1822)."""
    label = env('PCAPKIT_CONDA_OS')
    env('PCAPKIT_PYTHON_VERSION')  # the recipe's host Python, so unset fails here rather than in conda build
    out_dir = tempfile.mkdtemp(prefix='compilation-')
    _actions.set_output('out_dir', out_dir)
    status = call('conda', 'build', '.', '--package-format', '.tar.bz2', '--no-anaconda-upload',
                  '--output-folder', out_dir)
    if status:
        return status
    built = packages(out_dir)
    if not built:
        _actions.annotate('error', 'No conda package was built', escape=False)
        return 1
    target = PLATFORMS.get(label, '')
    _actions.set_output('host_package', built[0])
    host = os.path.basename(os.path.dirname(built[0]))
    if host != target:
        _actions.annotate('error', f'{label} publishes {target or "nothing"}, and conda built {host} here; a package '
                                   'is published only for the platform it was built for.',
                          title=f'{host} package on a {target or "unmapped"} leg (#1822)', escape=False)
        return 1
    print('\n'.join(built), flush=True)
    _actions.set_output('packages_csv', ','.join(built))
    _actions.set_output('packages', '\n'.join(built))
    return 0


def downloaded(directory: 'str') -> 'int':
    """Output the packages the publishing job downloaded under ``directory`` (#3133)."""
    found = packages(directory)
    if not found:
        _actions.annotate('error', f'No conda package was downloaded to {directory}', escape=False)
        return 1
    print('\n'.join(found), flush=True)
    _actions.set_output('packages_csv', ','.join(found))
    _actions.set_output('packages', '\n'.join(found))
    return 0


def main(argv: 'Optional[list[str]]' = None) -> 'int':
    """Run the subcommand ``argv`` names; the exit status."""
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('leg', help='whether anaconda.org has this leg already').add_argument(
        'reply', help='where curl writes the reply, which the check reads')
    commands.add_parser('build', help="build this leg's package")
    commands.add_parser('downloaded', help='output the packages downloaded to publish').add_argument(
        'directory', help='where the package artifact was downloaded')
    args = parser.parse_args(argv)
    try:
        if args.command == 'leg':
            return leg(args.reply)
        if args.command == 'downloaded':
            return downloaded(args.directory)
        return build()
    except release_published.Unbound as error:
        sys.stdout.flush()
        print(f'{error}: unbound variable', file=sys.stderr, flush=True)
        return 1
    except release_published.Failed as error:
        return error.status


if __name__ == '__main__':
    sys.exit(main())
