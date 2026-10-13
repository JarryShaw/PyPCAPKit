# -*- coding: utf-8 -*-
"""The Python version tiers in :file:`.github/python-versions.json`, as the workflows read them (#1660).

Every workflow matrix that runs Python legs, and the version of every job that
runs on one interpreter, comes from that file through this script. A workflow
runs it with the runner's own ``python3`` -- so it is standard library only and
parses on 3.8 -- as ``python3 util/python_versions.py --github-output``, which
appends one step output per name below to ``$GITHUB_OUTPUT``:

``latest``
    The newest supported CPython, for the single-interpreter jobs.
``test``, ``integration``, ``compatibility``
    Both tiers. A KTLO leg carries ``ktlo: true``, and ``os`` where
    ``ubuntu-latest`` cannot provide it; ``test`` marks the ``latest`` leg
    ``coverage: true``.
``pypcap-parity``
    The versions below 3.12 that run on ``ubuntu-latest``.
``pypi``
    CPython, then PyPy, both tiers, on ``ubuntu-latest``.
``conda``
    The supported CPython versions, as one matrix axis.
``engine-supported``, ``engine-ktlo``
    What ``engine-tests`` installs on ``ubuntu-latest``, one version per line,
    as ``actions/setup-python`` reads a list.
``pypi-wheels``, ``conda-builds``
    The supported tier's wheel tags and conda build tags, which Create Release's
    completeness checks count.

Each matrix keeps the shape its job had when the versions were spelled out in
the workflow -- a ``python-version`` axis, then ``include`` -- so GitHub expands
it to the same legs in the same order.
``tests/project/test_python_versions_1660.py`` compares the two.

Run without arguments it prints every output; with names, just their values.

"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import sys
import uuid
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any, Callable, Optional

ROOT = pathlib.Path(__file__).resolve().parents[1]
FILE = ROOT / '.github' / 'python-versions.json'

#: Each implementation, and how its versions are spelled.
SPELLING = {'cpython': re.compile(r'3\.(\d+)'), 'pypy': re.compile(r'pypy3\.(\d+)')}
TIERS = ('supported', 'ktlo', 'pre-release')
#: The images a version may name as its ``runner``.
RUNNER = re.compile(r'ubuntu-\d{2}\.04')
#: Wheel tag prefix per implementation, as util/wheel_rename.py writes it.
WHEEL_PREFIX = {'cpython': 'cp', 'pypy': 'pp'}
#: PyPCAP's and PyPCAPFile's ``python_version < '3.12'`` markers in pyproject.toml:
#: from 3.12 the parity job would install neither and cover nothing new.
PARITY_BELOW = (3, 12)


def key(version: 'str') -> 'tuple[int, int]':
    """``'3.10'`` or ``'pypy3.10'`` as ``(3, 10)``, for ordering."""
    minor = re.search(r'3\.(\d+)$', version)
    if minor is None:
        raise ValueError(f'not a Python version: {version!r}')
    return 3, int(minor.group(1))


def load(path: 'pathlib.Path' = FILE) -> 'dict[str, Any]':
    """The tier file, validated.

    Raises :exc:`ValueError` naming the first problem: an unknown key or tier, a
    misspelt version or runner, a ``latest`` that is not a supported CPython, an
    exemption missing a field, or a pre-release entry -- no workflow has the
    non-blocking pre-release legs one needs (``allow-prereleases``, a name of its
    own) yet, so listing one fails here instead of running it as something else.

    """
    data = json.loads(pathlib.Path(path).read_text(encoding='utf-8'))
    if not isinstance(data, dict) or set(data) - {'//', 'latest', 'versions', 'exemptions'}:
        raise ValueError('the top level holds only "//", "latest", "versions" and "exemptions"')
    versions = data.get('versions')
    if not isinstance(versions, dict) or set(versions) != set(SPELLING):
        raise ValueError(f'"versions" maps exactly {sorted(SPELLING)} to their versions')
    for impl, entries in versions.items():
        if not isinstance(entries, dict) or not entries:
            raise ValueError(f'{impl} lists no versions')
        for version, entry in entries.items():
            where = f'{impl} {version}'
            if not SPELLING[impl].fullmatch(version):
                raise ValueError(f'{where}: not spelt as {SPELLING[impl].pattern}')
            if not isinstance(entry, dict) or 'tier' not in entry or set(entry) - {'tier', 'runner'}:
                raise ValueError(f'{where}: an entry is {{"tier": ...}}, with an optional "runner"')
            if entry['tier'] not in TIERS:
                raise ValueError(f'{where}: tier {entry["tier"]!r} is not one of {TIERS}')
            if entry['tier'] == 'pre-release':
                raise ValueError(f'{where}: no workflow runs pre-release legs yet; wire their '
                                 'non-blocking mechanics before listing one (#1660)')
            if 'runner' in entry and not RUNNER.fullmatch(str(entry['runner'])):
                raise ValueError(f'{where}: runner {entry["runner"]!r} is not an ubuntu-YY.04 image')
        if list(entries) != sorted(entries, key=key):
            raise ValueError(f'{impl}: list the versions oldest first')
    if data.get('latest') not in tier(data, 'cpython', 'supported'):
        raise ValueError(f'latest {data.get("latest")!r} is not a supported CPython version')
    for index, exemption in enumerate(data.get('exemptions', [])):
        fields = ('workflow', 'job', 'where', 'value', 'reason')
        if (not isinstance(exemption, dict) or set(exemption) != set(fields)
                or not all(isinstance(exemption[name], str) and exemption[name] for name in fields)):
            raise ValueError(f'exemption {index}: give each of {fields}, as a non-empty string')
    return data


def tier(data: 'dict[str, Any]', impl: 'str', name: 'str') -> 'list[str]':
    """The versions of ``impl`` in tier ``name``, oldest first."""
    return [version for version, entry in data['versions'][impl].items() if entry['tier'] == name]


def runner(data: 'dict[str, Any]', impl: 'str', version: 'str') -> 'Optional[str]':
    """The image ``version`` needs, or :data:`None` for ``ubuntu-latest``."""
    return data['versions'][impl][version].get('runner')


def on_latest(data: 'dict[str, Any]', impl: 'str', name: 'str', job: 'str') -> 'list[str]':
    """Tier ``name`` of ``impl`` as a job pinned to ``ubuntu-latest`` can run it.

    A KTLO version needing an older image is left out. A supported one cannot be,
    so that raises: ``job`` would silently stop testing it.

    """
    found = []
    for version in tier(data, impl, name):
        if runner(data, impl, version) is None:
            found.append(version)
        elif name == 'supported':
            raise ValueError(f'{job} runs on ubuntu-latest only, which cannot run supported {version}')
    return found


def tiered(data: 'dict[str, Any]', impl: 'str' = 'cpython') -> 'dict[str, Any]':
    """The supported tier as the axis, each KTLO version added by ``include``."""
    include = []
    for version in tier(data, impl, 'ktlo'):
        leg = {'python-version': version, 'ktlo': True}  # type: dict[str, Any]
        if runner(data, impl, version) is not None:
            leg['os'] = runner(data, impl, version)
        include.append(leg)
    return {'python-version': tier(data, impl, 'supported'), 'include': include}


def test_matrix(data: 'dict[str, Any]') -> 'dict[str, Any]':
    """unit-tests.yml's ``test``: both tiers, the one coverage leg on ``latest``."""
    matrix = tiered(data)
    matrix['include'].insert(0, {'python-version': data['latest'], 'coverage': True})
    return matrix


def parity_matrix(data: 'dict[str, Any]') -> 'dict[str, Any]':
    """unit-tests.yml's ``pypcap-parity``: every version below :data:`PARITY_BELOW` it can run.

    The axis lists both tiers and ``include`` marks the KTLO ones, as the job did.

    """
    supported = [v for v in on_latest(data, 'cpython', 'supported', 'pypcap-parity') if key(v) < PARITY_BELOW]
    ktlo = [v for v in on_latest(data, 'cpython', 'ktlo', 'pypcap-parity') if key(v) < PARITY_BELOW]
    return {'python-version': sorted(ktlo + supported, key=key),
            'include': [{'python-version': version, 'ktlo': True} for version in ktlo]}


def pypi_matrix(data: 'dict[str, Any]') -> 'dict[str, Any]':
    """create-release.yml's ``pypi``: one wheel per CPython and PyPy version, both tiers."""
    impls = tuple(SPELLING)
    return {'python-version': [v for impl in impls for v in on_latest(data, impl, 'supported', 'pypi')],
            'include': [{'python-version': v, 'ktlo': True}
                        for impl in impls for v in on_latest(data, impl, 'ktlo', 'pypi')]}


def wheel_tag(version: 'str') -> 'str':
    """``'3.11'`` as ``'cp311'``, ``'pypy3.11'`` as ``'pp311'``."""
    impl = 'pypy' if version.startswith('pypy') else 'cpython'
    return WHEEL_PREFIX[impl] + ''.join(map(str, key(version)))


#: Each output's builder.
OUTPUTS = {
    'latest': lambda data: data['latest'],
    'test': test_matrix,
    'integration': tiered,
    'compatibility': tiered,
    'pypcap-parity': parity_matrix,
    'pypi': pypi_matrix,
    'conda': lambda data: tier(data, 'cpython', 'supported'),
    'engine-supported': lambda data: '\n'.join(on_latest(data, 'cpython', 'supported', 'engine-tests')),
    'engine-ktlo': lambda data: '\n'.join(on_latest(data, 'cpython', 'ktlo', 'engine-tests')),
    'pypi-wheels': lambda data: ' '.join(map(wheel_tag, pypi_matrix(data)['python-version'])),
    'conda-builds': lambda data: ' '.join('py' + ''.join(map(str, key(v))) for v in tier(data, 'cpython', 'supported')),
}  # type: dict[str, Callable[[dict[str, Any]], Any]]


def outputs(data: 'dict[str, Any]') -> 'dict[str, str]':
    """Every output, as the string a workflow reads: JSON for a matrix, plain text otherwise."""
    found = {}
    for name, build in OUTPUTS.items():
        value = build(data)
        found[name] = value if isinstance(value, str) else json.dumps(value, separators=(',', ':'))
    return found


def write_github_output(values: 'dict[str, str]', path: 'str') -> 'None':
    """Append ``values`` to a ``$GITHUB_OUTPUT`` file, a multi-line one under a fresh delimiter."""
    with open(path, 'a', encoding='utf-8') as file:
        for name, value in values.items():
            if '\n' in value:
                delimiter = f'EOF_{uuid.uuid4().hex}'
                file.write(f'{name}<<{delimiter}\n{value}\n{delimiter}\n')
            else:
                file.write(f'{name}={value}\n')


def main(argv: 'Optional[list[str]]' = None) -> 'int':
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    parser.add_argument('names', nargs='*', metavar='NAME', help='print only these outputs, one per line')
    parser.add_argument('--file', type=pathlib.Path, default=FILE, help='the tier file (default: %(default)s)')
    parser.add_argument('--github-output', action='store_true', help='append every output to $GITHUB_OUTPUT')
    args = parser.parse_args(argv)

    try:
        values = outputs(load(args.file))
        unknown = sorted(set(args.names) - set(values))
        if unknown:
            raise ValueError(f'no output named {", ".join(unknown)}; there are {", ".join(values)}')
    except (OSError, ValueError) as error:  # json.JSONDecodeError is a ValueError
        message = str(error).replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')
        print(f'::error title=Cannot read the Python version tiers::{args.file}: {message}')
        return 1

    if args.github_output:
        path = os.environ.get('GITHUB_OUTPUT')
        if not path:
            print('::error title=GITHUB_OUTPUT is not set::--github-output only works inside a workflow step')
            return 1
        write_github_output(values, path)
    for name in args.names:
        print(values[name])
    if not args.names:
        for name, value in values.items():
            print(f'{name}: {value}'.replace('\n', ' '))
    return 0


if __name__ == '__main__':
    sys.exit(main())
