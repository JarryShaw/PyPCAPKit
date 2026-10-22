# -*- coding: utf-8 -*-
"""Plan, seed, install and collect a job's system packages (#1967).

The apt steps of :file:`.github/workflows/unit-tests.yml`'s ``engine-tests`` and
``pypcap-parity`` jobs (and so ``pypcap-parity-ktlo``) run, from the checkout's
root and on the image's ``/usr/bin/python3``::

    /usr/bin/python3 util/apt_packages.py plan
    /usr/bin/python3 util/apt_packages.py seed
    /usr/bin/python3 util/apt_packages.py install [--name NAME]
    /usr/bin/python3 util/apt_packages.py collect

``APT_PACKAGES``, the job's environment, names the packages, separated by
whitespace, for both ``plan`` and ``install``, so the cache key cannot describe a
set other than the one installed. Each subcommand runs the commands the steps'
shell ran, ``sudo`` included, and writes the same lines and annotations:

``plan``
   ``sudo timeout 60 apt-get update``, up to twice, with a ``::warning`` titled by
   ``APT_SET`` after each failure and exit 1 after the second. Then ``apt-get
   install -s --no-install-recommends APT_PACKAGES``, whose failure ends the
   script with its status. Its ``Inst`` lines, sorted, are printed under ``To
   download:``, or ``(nothing)``; when there are some, ``restore-prefix``,
   ``apt-debs-<ImageOS>-<RUNNER_ARCH>-<APT_SET>-``, and ``key``, that prefix and the
   first 16 hex digits of the lines' SHA-256, are appended to ``$GITHUB_OUTPUT``.
   ``ImageOS`` is ``unknown`` when unset or empty.
``seed``
   ``sudo cp $RUNNER_TEMP/apt-debs/*.deb /var/cache/apt/archives/``, its status the
   script's on a failure, then how many ``.deb`` files that directory holds.
``install``
   Nothing when ``APT_PACKAGES`` is empty. Otherwise, when it names ``tshark``,
   pre-seeds debconf against its "non-superusers may capture" prompt, then up to
   two attempts of ``sudo timeout 60 apt-get update`` and ``sudo
   DEBIAN_FRONTEND=noninteractive timeout 180 apt-get install -y
   --no-install-recommends APT_PACKAGES``. After a failed attempt: a ``::warning``,
   ``sudo dpkg --configure -a``, its failure ignored, and, after the first, azure's
   line is dropped from :file:`/etc/apt/apt-mirrors.txt` with ``sudo sed`` when
   another ``http`` mirror would remain, with a second ``::warning`` naming the
   mirror now first (#1432). Exit 1 after the second. ``--name`` appends `` (NAME)``
   to both titles.
``collect``
   Empties :file:`$RUNNER_TEMP/apt-debs`, copies into it each
   :file:`/var/cache/apt/archives/*.deb` whose package and architecture are
   installed at its version, as ``dpkg-deb -f`` and ``dpkg-query -W`` report them,
   and says how many it holds. A failed ``dpkg-deb`` ends the script with its status.

The bounds stay GNU's ``timeout(1)`` run under ``sudo``, as in the shell, rather than
a :mod:`subprocess` timeout: apt runs as root, so this process could signal
``sudo`` alone and not apt's own children, its download methods, which ``timeout``,
running as root in a process group of its own, ends with apt. It is given no
option, so uutils' ``timeout`` on Ubuntu 26.04 behaves as GNU's (#2020). The
step's ``timeout-minutes`` stays the hang detector. The script is standard library
only, and runs on every interpreter the matrices hold, 3.7 included.

"""

from __future__ import annotations

import argparse
import glob
import hashlib
import os
import shutil
import subprocess  # nosec: B404
import sys
from typing import TYPE_CHECKING

try:  # #2047: run as `python util/<script>.py`, with util/ first on sys.path
    import _actions
except ImportError:  # imported as util.<script>, or loaded by path, from the repository root
    from util import _actions

if TYPE_CHECKING:
    from typing import Callable, Optional, Sequence

__all__ = ['ATTEMPTS', 'UPDATE_BOUND', 'INSTALL_BOUND', 'MIRRORS', 'ARCHIVES', 'CACHE_DIR', 'AZURE',
           'DEBCONF', 'main']

#: How many times ``plan`` updates, and ``install`` updates and installs.
ATTEMPTS = 2
#: ``timeout``'s bound, in seconds, on each ``apt-get update`` (#974).
UPDATE_BOUND = 60
#: ``timeout``'s bound, in seconds, on each ``apt-get install`` (#1306).
INSTALL_BOUND = 180
#: The runner image's ``mirror+file:`` list, which ``install`` edits before its retry.
MIRRORS = '/etc/apt/apt-mirrors.txt'
#: apt's archive, which ``seed`` fills and ``collect`` reads.
ARCHIVES = '/var/cache/apt/archives'
#: The cached ``.deb`` files, under ``$RUNNER_TEMP``.
CACHE_DIR = 'apt-debs'
#: The mirror that serves slowly rather than failing, so apt never leaves it (#1432).
AZURE = b'azure.archive.ubuntu.com'
#: The debconf answer that stops tshark's postinst prompting.
DEBCONF = b'wireshark-common wireshark-common/install-setuid boolean false\n'


def call(command: 'Sequence[str]', **kwargs: 'object') -> 'subprocess.CompletedProcess[bytes]':
    """Run ``command`` to its end, its streams this process's unless ``kwargs`` says otherwise."""
    return subprocess.run(list(command), check=False, **kwargs)  # type: ignore[call-overload] # nosec: B603


def packages() -> 'list[str]':
    """``APT_PACKAGES``, split on whitespace as the shell split it."""
    return os.environ['APT_PACKAGES'].split()


def count_debs(path: 'str') -> 'int':
    """How many entries under ``path`` match ``*.deb``, as ``find PATH -name '*.deb' | wc -l`` counts."""
    found = 0
    for _, dirs, files in os.walk(path):
        found += sum(1 for name in dirs + files if name.endswith('.deb'))
    return found


def debs(directory: 'str') -> 'list[str]':
    """``directory/*.deb`` as the shell expands it, sorted, hidden files left out."""
    return sorted(glob.glob(os.path.join(glob.escape(directory), '*.deb')))


def plan() -> 'int':
    """Update apt's indexes, then write the cache key of what this image still lacks."""
    for attempt in range(1, ATTEMPTS + 1):
        if call(['sudo', 'timeout', str(UPDATE_BOUND), 'apt-get', 'update']).returncode == 0:
            break
        # #2047: each command stays literal, where #1672's scan of a KTLO step's scripts reads it.
        _actions.say(f'::warning title=apt-get update attempt {attempt} of {ATTEMPTS} failed '
                     f'({os.environ["APT_SET"]})::apt-get update failed or exceeded its {UPDATE_BOUND}s bound.')
        if attempt == ATTEMPTS:
            return 1

    simulated = call(['apt-get', 'install', '-s', '--no-install-recommends', *packages()], stdout=subprocess.PIPE)
    if simulated.returncode != 0:
        return _actions.exit_status(simulated.returncode)
    lines = sorted(line for line in simulated.stdout.rstrip(b'\n').split(b'\n') if line.startswith(b'Inst '))
    listed = b'\n'.join(lines)
    sys.stdout.buffer.write(b'To download:\n' + (listed or b'(nothing)') + b'\n')
    sys.stdout.buffer.flush()
    if lines:
        prefix = f'apt-debs-{os.environ.get("ImageOS") or "unknown"}-{os.environ["RUNNER_ARCH"]}-' \
                 f'{os.environ["APT_SET"]}-'
        digest = hashlib.sha256(listed + b'\n').hexdigest()[:16]
        _actions.set_output('restore-prefix', prefix)
        _actions.set_output('key', prefix + digest)
    return 0


def seed(archives: 'str') -> 'int':
    """Copy the restored ``.deb`` files into apt's archive."""
    cache = os.path.join(os.environ['RUNNER_TEMP'], CACHE_DIR)
    # An unmatched glob stays the pattern, as the shell's does, so `cp` fails on it.
    copied = call(['sudo', 'cp', *(debs(cache) or [os.path.join(cache, '*.deb')]), archives + '/'])
    if copied.returncode != 0:
        return _actions.exit_status(copied.returncode)
    _actions.say(f'Seeded {count_debs(cache)} .deb files')
    return 0


def fallback(mirrors: 'str', suffix: 'str') -> 'None':
    """Drop azure from ``mirrors`` when another ``http`` mirror would remain, and say so."""
    if not os.path.isfile(mirrors):
        return
    try:
        with open(mirrors, 'rb') as file:
            lines = file.read().split(b'\n')
    except OSError:
        return
    if not any(line.startswith(b'http') for line in lines if AZURE not in line):
        return
    if call(['sudo', 'sed', '-i', r'/azure\.archive\.ubuntu\.com/d', mirrors]).returncode != 0:
        return
    try:
        with open(mirrors, 'rb') as file:
            first = file.read().split(b'\n', 1)[0].split(b'\t', 1)[0]
    except OSError:
        first = b''
    _actions.say(f'::warning title=apt retry on a fallback mirror{suffix}::Retrying against '
                 f'{first.decode("utf-8", "surrogateescape")} instead of azure.archive.ubuntu.com, '
                 'resuming the partial download.')


def install(mirrors: 'str', name: 'Optional[str]') -> 'int':
    """Install ``APT_PACKAGES``, retrying once, on a fallback mirror when there is one."""
    wanted = packages()
    if not wanted:
        return 0
    suffix = '' if name is None else f' ({name})'
    if 'tshark' in wanted:
        answered = call(['sudo', 'debconf-set-selections'], input=DEBCONF)
        if answered.returncode != 0:
            return _actions.exit_status(answered.returncode)
    for attempt in range(1, ATTEMPTS + 1):
        if call(['sudo', 'timeout', str(UPDATE_BOUND), 'apt-get', 'update']).returncode == 0 \
                and call(['sudo', 'DEBIAN_FRONTEND=noninteractive', 'timeout', str(INSTALL_BOUND),
                          'apt-get', 'install', '-y', '--no-install-recommends', *wanted]).returncode == 0:
            return 0
        _actions.say(f'::warning title=apt attempt {attempt} of {ATTEMPTS} failed{suffix}::apt-get update or '
                     'install failed or exceeded its per-attempt bound; retrying once.')
        call(['sudo', 'dpkg', '--configure', '-a'])
        if attempt == 1:
            fallback(mirrors, suffix)
    return 1


def field(deb: 'str', name: 'str') -> 'tuple[int, str]':
    """``dpkg-deb -f DEB NAME``'s status and output, trailing newlines stripped."""
    result = call(['dpkg-deb', '-f', deb, name], stdout=subprocess.PIPE)
    status = _actions.exit_status(result.returncode)
    return status, result.stdout.decode('utf-8', 'surrogateescape').rstrip('\n')


def collect(archives: 'str') -> 'int':
    """Copy into the cache each archived ``.deb`` whose version is the one installed."""
    out = os.path.join(os.environ['RUNNER_TEMP'], CACHE_DIR)
    # `rm -rf`, then `mkdir -p`: a failure of either ends the script.
    if os.path.isdir(out) and not os.path.islink(out):
        shutil.rmtree(out)
    elif os.path.lexists(out):
        os.remove(out)
    os.makedirs(out, exist_ok=True)
    for deb in debs(archives):
        if not os.path.exists(deb):
            continue
        fields = {}  # type: dict[str, str]
        for name in ('Package', 'Version', 'Architecture'):
            status, fields[name] = field(deb, name)
            if status != 0:
                return status
        installed = call(['dpkg-query', '-W', '-f', '${Version}', f'{fields["Package"]}:{fields["Architecture"]}'],
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        if installed.stdout.decode('utf-8', 'surrogateescape').rstrip('\n') == fields['Version']:
            shutil.copy(deb, out)
    _actions.say(f'Collected {count_debs(out)} .deb files')
    return 0


def main(argv: 'Optional[list[str]]' = None) -> 'int':
    """Run one subcommand; its exit status."""
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    commands = parser.add_subparsers(dest='command', metavar='COMMAND')
    commands.required = True
    commands.add_parser('plan', help='update the indexes and write the cache key')
    for command, text in (('seed', 'copy the restored .deb files into apt\'s archive'),
                          ('collect', 'copy the installed versions\' .deb files into the cache')):
        sub = commands.add_parser(command, help=text)
        sub.add_argument('--archives', default=ARCHIVES, help=f'apt\'s archive (default: {ARCHIVES})')
    sub = commands.add_parser('install', help='install APT_PACKAGES, retrying once')
    sub.add_argument('--name', help='what the annotation titles name, in parentheses')
    sub.add_argument('--mirrors', default=MIRRORS, help=f'the mirror list (default: {MIRRORS})')
    args = parser.parse_args(argv)

    run = {
        'plan': plan,
        'seed': lambda: seed(args.archives),
        'install': lambda: install(args.mirrors, args.name),
        'collect': lambda: collect(args.archives),
    }[args.command]  # type: Callable[[], int]
    sys.stdout.flush()
    return run()


if __name__ == '__main__':
    sys.exit(main())
