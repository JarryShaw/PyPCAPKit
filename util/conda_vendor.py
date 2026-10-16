# -*- coding: utf-8 -*-
"""The third-party packages the conda recipe vendors into :file:`pcapkit/_extern` (#1814).

The conda package declares no run requirements. ``conda/pypcapkit/build.sh`` and
``bld.bat`` install every wheel that ``pip download -r conda/requirements.txt``
fetched into :file:`pcapkit/_extern`, which :file:`pcapkit/__init__.py` appends
to :data:`sys.path`. So :file:`conda/requirements.txt` is the conda
distribution's whole dependency list, and this script derives it from
:file:`pyproject.toml` instead of leaving it to be edited by hand. Each package
falls in exactly one of these classes:

``needed``
    ``[project] dependencies`` and the ``all`` extra. A conda user has no
    extras to ask for, and ``all`` is the set the owner ruled on #910 to be what
    the library needs to work at full functionality. The capture engines and the
    crawlers' ``vendor`` extra are installed on demand there, so a conda user
    installs them into the environment, where they take precedence over
    anything vendored.
``transitive``
    What a needed package requires in turn, with the extras it was asked for,
    as the installed distributions' metadata declares it.
``dead``
    A requirement whose marker is false on every interpreter a conda package is
    built for: the supported CPython tier of :file:`.github/python-versions.toml`,
    on the platforms in :data:`PLATFORMS`. It is left out.
``stale``
    Anything else the file names.

Each line pins the version installed here, as ``conda-update`` in
:file:`.github/workflows/cron-conda.yml` installs ``.[all]`` before running this
script. Resolving the newest releases is that install step's job, and needs the
network; this script reads only what is installed, so it works offline. The one
exception is :data:`PLATFORM_PINS`: a package whose newest release has no wheel
for some platform keeps an older pin for it, on a line of its own whose marker
names that platform, beside the installed pin for the rest (#1827). The conda
legs build natively, so each leg's ``pip download`` evaluates those markers on
its own runner.

Run without arguments it rewrites :file:`conda/requirements.txt`. With
``--check`` it writes nothing, and exits 1 when the file names a different set of
packages or markers than it derives, a platform pin other than
:data:`PLATFORM_PINS`, or when that table names a package no build vendors --
the other pins aside, since they move with every release and the weekly run
refreshes them. Lines pinning one package differently under one marker fail it
too, since pip cannot install them together when the pins disagree (#1852).
With ``--smoke PACKAGE`` it unpacks a
built ``.tar.bz2`` conda package and checks that every distribution vendored in
it shipped every file its ``RECORD`` lists, and that each of its modules imports
from :file:`pcapkit/_extern` with nothing else on the path. It also checks that
the package is for this runner's platform, and that every native binary in it
is for that platform too (#1822): ``conda convert`` relabels a package without
touching its binaries, so a relabelled one imports cleanly on the runner that
built it and fails everywhere it was relabelled for. That mode needs only the
standard library.

"""

from __future__ import annotations

import argparse
import importlib.metadata
import importlib.util
import json
import pathlib
import platform
import subprocess  # nosec B404
import sys
import tarfile
import tempfile
import textwrap
import tomllib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Callable, Iterable, Literal, Optional

    from packaging.markers import Marker
    from packaging.requirements import Requirement

ROOT = pathlib.Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / 'pyproject.toml'
FILE = ROOT / 'conda' / 'requirements.txt'

#: The extras the conda distribution carries, besides ``dependencies``.
EXTRAS = ('all',)
#: The platforms the conda workflows build on -- ``cron-conda.yml`` and
#: ``create-release.yml`` -- by the conda subdir each leg publishes, as
#: ``sys.platform``, ``platform.system()`` and ``platform.machine()`` read on its
#: runner: ``ubuntu-latest``, the Intel ``macos-26-intel`` and the arm64
#: ``macos-latest``. Each leg publishes only its own runner's platform (#1822).
#: Their Windows legs are commented out, and with them the recipe's ``bld.bat``.
PLATFORMS = {
    'linux-64': ('linux', 'Linux', 'x86_64'),
    'osx-64': ('darwin', 'Darwin', 'x86_64'),
    'osx-arm64': ('darwin', 'Darwin', 'arm64'),
}
#: The packages pinned apart on some of :data:`PLATFORMS`, as {package: {conda
#: subdir: version}} (#1827). cryptography stopped shipping Intel macOS wheels at
#: 49.0.0, so osx-64 vendors 48.0.1, the newest release with one (universal2);
#: otherwise its build would compile cryptography from source.
PLATFORM_PINS = {'cryptography': {'osx-64': '48.0.1'}}
#: The object format and the machine of every native binary a package for each
#: of :data:`PLATFORMS` may carry (#1822). A universal Mach-O passes when one of
#: its slices is the machine.
BINARIES = {'linux-64': ('ELF', 'x86_64'), 'osx-64': ('Mach-O', 'x86_64'), 'osx-arm64': ('Mach-O', 'arm64')}
#: What ELF's ``e_machine`` and Mach-O's ``cputype`` say, as :data:`BINARIES` spells it.
ELF_MACHINES = {3: 'i386', 20: 'ppc', 21: 'ppc64', 40: 'arm', 62: 'x86_64', 183: 'arm64', 243: 'riscv'}
MACHO_CPUS = {7: 'i386', 0x01000007: 'x86_64', 12: 'arm', 0x0100000c: 'arm64', 0x0200000c: 'arm64_32',
              18: 'ppc', 0x01000012: 'ppc64'}
#: File names a native extension or library goes by, so one whose header this
#: cannot read is reported rather than passed over.
NATIVE_SUFFIXES = ('.so', '.dylib', '.pyd', '.dll')


def _load_python_versions() -> 'object':
    """:file:`util/python_versions.py`, the tier file's reader, beside this script."""
    spec = importlib.util.spec_from_file_location('python_versions',
                                                  pathlib.Path(__file__).with_name('python_versions.py'))
    assert spec is not None and spec.loader is not None  # nosec B101
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def conda_pythons() -> 'list[str]':
    """The CPython versions a conda package is built for, as ``conda`` in python_versions.py."""
    versions = _load_python_versions()
    return list(versions.tier(versions.load(), 'cpython', 'supported'))  # type: ignore[attr-defined]


def environments(pythons: 'Iterable[str]') -> 'list[dict[str, str]]':
    """A marker environment per conda build: each Python on each of :data:`PLATFORMS`."""
    found = []
    for python in pythons:
        for sys_platform, system, machine in PLATFORMS.values():
            found.append({
                'python_version': python, 'python_full_version': f'{python}.0',
                'implementation_name': 'cpython', 'platform_python_implementation': 'CPython',
                'implementation_version': f'{python}.0', 'sys_platform': sys_platform,
                'platform_system': system, 'os_name': 'posix',
                'platform_machine': machine, 'platform_release': '', 'platform_version': '',
            })
    return found


def direct(pyproject: 'pathlib.Path' = PYPROJECT) -> 'list[Requirement]':
    """``[project] dependencies`` and the :data:`EXTRAS`, as written in ``pyproject``."""
    from packaging.requirements import Requirement  # pylint: disable=import-outside-toplevel
    project = tomllib.loads(pathlib.Path(pyproject).read_text(encoding='utf-8'))['project']
    lines = list(project.get('dependencies', []))
    for extra in EXTRAS:
        lines.extend(project.get('optional-dependencies', {})[extra])
    return [Requirement(line) for line in lines]


def _live(marker: 'Optional[Marker]', env: 'dict[str, str]', extras: 'Iterable[str]') -> 'bool':
    if marker is None:
        return True
    return any(marker.evaluate(dict(env, extra=extra)) for extra in (tuple(extras) or ('',)))


class NotInstalled(Exception):
    """Packages some conda build needs that this interpreter has no metadata for."""


def describe(builds: 'Iterable[int]', envs: 'list[dict[str, str]]') -> 'str':
    """``builds`` in words: their Pythons, then their platforms."""
    chosen = [envs[index] for index in builds]
    pythons = sorted({env['python_version'] for env in chosen},
                     key=lambda version: tuple(map(int, version.split('.'))))
    platforms = sorted({env['sys_platform'] for env in chosen})
    return f'Python {", ".join(pythons)} on {", ".join(platforms)}'


def _not_installed(missing: 'dict[str, set[str]]', found: 'dict[str, dict[str, object]]',
                   envs: 'list[dict[str, str]]') -> 'NotInstalled':
    host = (f'{sys.version_info.major}.{sys.version_info.minor}', sys.platform)
    reasons = []
    for name, via in sorted(missing.items()):
        builds = found[name]['builds']  # type: ignore[assignment]
        here = any((envs[index]['python_version'], envs[index]['sys_platform']) == host
                   for index in builds)
        hint = ('install .[{}] first'.format(','.join(EXTRAS)) if here else
                'its marker leaves it out here, so pip did not install it; run this on one '
                'of those builds, or install it here by hand')
        reasons.append(f'{name} is needed on {describe(builds, envs)} ({"; ".join(sorted(via))}), '
                       f'and Python {host[0]} on {host[1]}, which runs this, does not have it: {hint}')
    return NotInstalled('\n'.join(reasons))


def derive(requirements: 'list[Requirement]', envs: 'list[dict[str, str]]',
           requires: 'Callable[[str], Optional[list[str]]]') -> 'dict[str, dict[str, object]]':
    """Each package to vendor, by canonical name: its class and the builds needing it.

    ``requires`` returns a distribution's ``Requires-Dist`` lines, as
    :func:`importlib.metadata.requires` does, and raises
    :class:`importlib.metadata.PackageNotFoundError` for one not installed.
    A requirement live in no environment is recorded as ``dead`` and not walked.
    One that is live but not installed here raises :class:`NotInstalled` once the
    walk is done, naming every such package, what required it and where.
    """
    # pylint: disable-next=import-outside-toplevel
    from packaging.requirements import Requirement
    from packaging.utils import canonicalize_name  # pylint: disable=import-outside-toplevel
    found = {}  # type: dict[str, dict[str, object]]
    missing = {}  # type: dict[str, set[str]]
    queue = [(req, frozenset(range(len(envs))), 'needed', f'pyproject.toml asks for {req}')
             for req in requirements]
    seen = set()  # type: set[tuple[str, frozenset[str], int]]
    while queue:
        req, parents, kind, via = queue.pop(0)
        name = canonicalize_name(req.name)
        where = frozenset(index for index in parents if _live(req.marker, envs[index], ()))
        if not where:
            if name not in found and kind == 'needed':
                found[name] = {'class': 'dead', 'builds': frozenset(), 'marker': str(req.marker)}
            continue
        entry = found.get(name)
        if entry is None or entry['class'] == 'dead':
            entry = found[name] = {'class': kind, 'builds': frozenset()}
        elif kind == 'needed':
            entry['class'] = 'needed'
        entry['builds'] = entry['builds'] | where  # type: ignore[operator]
        extras = frozenset(canonicalize_name(extra) for extra in req.extras)
        if name in missing:
            missing[name].add(via)
            continue
        for index in where:
            key = (name, extras, index)
            if key in seen:
                continue
            seen.add(key)
            try:
                declared = requires(name) or ()
            except importlib.metadata.PackageNotFoundError:
                missing[name] = {via}
                break
            for line in declared:
                child = Requirement(line)
                if _live(child.marker, envs[index], extras):
                    queue.append((Requirement(str(child).split(';')[0]),
                                  frozenset((index,)), 'transitive', f'{name} requires {child}'))
    if missing:
        raise _not_installed(missing, found, envs)
    return found


def render_marker(builds: 'frozenset[int]', envs: 'list[dict[str, str]]') -> 'Optional[str]':
    """The marker selecting exactly ``builds``, or :data:`None` when that is all of them."""
    if len(builds) == len(envs):
        return None
    pythons = sorted({envs[index]['python_version'] for index in builds},
                     key=lambda version: tuple(map(int, version.split('.'))))
    whole = {index for index, env in enumerate(envs) if env['python_version'] in pythons}
    if whole != set(builds):
        raise ValueError('needed on some platforms of one Python and not the others; '
                         'conda/requirements.txt cannot say so with a python_version marker')
    return ' or '.join(f'python_version == "{python}"' for python in pythons)


def platform_marker(subdirs: 'Iterable[str]', negate: 'bool' = False) -> 'str':
    """The marker selecting the builds on ``subdirs`` of :data:`PLATFORMS`, or with ``negate`` all others."""
    terms = []
    for subdir in sorted(subdirs):
        sys_platform, _, machine = PLATFORMS[subdir]
        terms.append(f'sys_platform != "{sys_platform}" or platform_machine != "{machine}"' if negate else
                     f'sys_platform == "{sys_platform}" and platform_machine == "{machine}"')
    if len(terms) == 1:
        return terms[0]
    return (' and ' if negate else ' or ').join(f'({term})' for term in terms)


def pins(name: 'str', entry: 'dict[str, object]',
         envs: 'list[dict[str, str]]') -> 'list[tuple[Optional[str], Optional[str]]]':
    """Each line ``name`` gets: its marker, and the version :data:`PLATFORM_PINS` fixes or :data:`None`."""
    python = render_marker(entry['builds'], envs)  # type: ignore[arg-type]
    # One for a platform no leg builds is unpinnable()'s to report.
    fixed = {subdir: version for subdir, version in PLATFORM_PINS.get(name, {}).items() if subdir in PLATFORMS}
    if not fixed:
        return [(python, None)]
    groups = {}  # type: dict[str, set[str]]
    for subdir, version in fixed.items():
        groups.setdefault(version, set()).add(subdir)
    found = [(platform_marker(subdirs), version)
             for version, subdirs in sorted(groups.items())]  # type: list[tuple[str, Optional[str]]]
    found.append((platform_marker(fixed, negate=True), None))
    return [(marker if python is None else f'({python}) and ({marker})', version)
            for marker, version in found]


def lines(found: 'dict[str, dict[str, object]]', envs: 'list[dict[str, str]]',
          version: 'Callable[[str], str]') -> 'list[str]':
    """:file:`conda/requirements.txt`'s lines, sorted: a pin per vendored package, and per platform pin."""
    result = []
    for name, entry in sorted(found.items()):
        if entry['class'] == 'dead':
            continue
        for marker, fixed in pins(name, entry, envs):
            pin = f'{name}=={fixed or version(name)}'
            result.append(pin if marker is None else f'{pin}; {marker}')
    return result


class Conflicting(ValueError):
    """A requirements file pinning one package differently on lines under one marker (#1852)."""


def _read(text: 'str') -> 'tuple[dict[str, dict[Optional[str], str]], list[str]]':
    """:func:`parse`'s result, with each marker's first pin, and each conflict it would raise."""
    from packaging.requirements import Requirement  # pylint: disable=import-outside-toplevel
    from packaging.utils import canonicalize_name  # pylint: disable=import-outside-toplevel
    result = {}  # type: dict[str, dict[Optional[str], str]]
    specifiers = {}  # type: dict[tuple[str, Optional[str]], list[str]]
    for line in text.splitlines():
        line = line.split('#', 1)[0].strip()
        if not line:
            continue
        req = Requirement(line)
        name, marker = canonicalize_name(req.name), None if req.marker is None else str(req.marker)
        versions = [spec.version for spec in req.specifier if spec.operator == '==']
        result.setdefault(name, {}).setdefault(marker, versions[0] if versions else '')
        seen = specifiers.setdefault((name, marker), [])
        if str(req.specifier) not in seen:
            seen.append(str(req.specifier))
    conflicts = []  # type: list[str]
    for (package, under), pinned in sorted(specifiers.items(), key=lambda item: str(item[0])):
        if len(pinned) > 1:
            conflicts.append(f'conflict: {package} pins {" and ".join(map(repr, pinned))} '
                             f'under the marker {under!r}')
    return result, conflicts


def parse(text: 'str') -> 'dict[str, dict[Optional[str], str]]':
    """A requirements file's packages, by canonical name, each as {its markers: the versions they pin}.

    pip applies every line whose marker holds, so two lines naming one package
    under one marker, with version specifiers that cannot both hold, make ``pip
    download -r`` fail. Once the whole text is read, :class:`Conflicting` names
    each package and marker whose lines pin it differently, whether or not the
    pins could both hold, since the writer gives each a single line (#1852). An
    identical duplicate line is accepted: pip resolves it, and it changes nothing
    this reads.

    """
    result, conflicts = _read(text)
    if conflicts:
        raise Conflicting('\n'.join(conflicts))
    return result


def unpinnable(found: 'dict[str, dict[str, object]]') -> 'list[str]':
    """Each :data:`PLATFORM_PINS` entry no conda build can use, one line apiece."""
    problems = []
    for name, fixed in sorted(PLATFORM_PINS.items()):
        entry = found.get(name)
        if entry is None or entry['class'] == 'dead':
            problems.append(f'override: {name} is pinned for {", ".join(sorted(fixed))}, '
                            'and no conda build vendors it')
        for subdir in sorted(set(fixed) - set(PLATFORMS)):
            problems.append(f'override: {name} is pinned for {subdir}, which no conda leg builds')
    return problems


def _show(markers: 'Iterable[Optional[str]]') -> 'str':
    shown = sorted(markers, key=str)
    return repr(shown[0]) if len(shown) == 1 else repr(shown)


def compare(text: 'str', found: 'dict[str, dict[str, object]]',
            envs: 'list[dict[str, str]]') -> 'list[str]':
    """Why ``text`` is stale against ``found``, one line per package; empty when current."""
    from packaging.markers import Marker  # pylint: disable=import-outside-toplevel
    problems = unpinnable(found)
    have, conflicts = _read(text)
    problems.extend(conflicts)
    want = {name: {None if marker is None else str(Marker(marker)): fixed
                   for marker, fixed in pins(name, entry, envs)}
            for name, entry in found.items() if entry['class'] != 'dead'}
    for name in sorted(set(have) | set(want)):
        if name not in have:
            problems.append(f'missing: {name} ({found[name]["class"]})')
        elif name not in want:
            if name in found:
                problems.append(f'dead: {name} -- its marker {found[name]["marker"]} is false '
                                'on every conda build')
            else:
                problems.append(f'stale: {name} -- neither the dependencies nor the '
                                f'{", ".join(EXTRAS)} extra need it, directly or not')
        elif set(have[name]) != set(want[name]):
            problems.append(f'marker: {name} has {_show(have[name])}, derived {_show(want[name])}')
        else:
            for marker, fixed in sorted(want[name].items(), key=str):
                if fixed is not None and have[name][marker] != fixed:
                    problems.append(f'pin: {name} pins {have[name][marker]!r} where {marker}, '
                                    f'and PLATFORM_PINS {fixed!r}')
    return problems


def _requires(name: 'str') -> 'Optional[list[str]]':
    return importlib.metadata.requires(name)


def _version(name: 'str') -> 'str':
    return importlib.metadata.version(name)


#: Run with ``-I -S`` and the unpacked ``site-packages`` as its argument, so that
#: nothing outside the package can satisfy an import.
PROBE = textwrap.dedent('''\
    import importlib, os, sys
    sys.path.insert(0, sys.argv[1])
    import pcapkit
    extern = os.path.realpath(pcapkit._extern)
    assert extern in map(os.path.realpath, sys.path), 'pcapkit/_extern is not on sys.path'
    failures = 0
    infos = sorted(name for name in os.listdir(extern) if name.endswith('.dist-info'))
    tops = {}
    for info in infos:
        with open(os.path.join(extern, info, 'RECORD'), encoding='utf-8') as file:
            paths = [row.rsplit(',', 2)[0] for row in file.read().splitlines() if row]
        paths = [path for path in paths if not path.startswith('..')
                 and '__pycache__' not in path.split('/')]
        missing = [path for path in paths if not os.path.exists(os.path.join(extern, path))]
        names = set()
        for path in paths:
            head = path.split('/', 1)[0]
            if head.endswith('.dist-info') or head.endswith('.data') or head in ('bin', 'share'):
                continue
            if '/' in path or head.endswith('.py') or '.cpython-' in head or head.endswith(('.so', '.pyd')):
                names.add(head.split('.', 1)[0])
        tops[info] = sorted(names)
        status = 'ok' if not missing else 'MISSING ' + ', '.join(missing[:5])
        print(f'{info}: {len(paths) - len(missing)}/{len(paths)} files, {status}')
        failures += bool(missing)
    provided = {name for names in tops.values() for name in names}
    for info, names in tops.items():
        for name in names:
            try:
                module = importlib.import_module(name)
            except ModuleNotFoundError as error:
                if (error.name or '').split('.')[0] in provided:
                    print(f'  {name}: FAILED, {error!r}')
                    failures += 1
                else:
                    print(f'  {name}: skipped, needs {error.name}, which is not vendored')
                continue
            except Exception as error:  # pylint: disable=broad-except
                print(f'  {name}: FAILED, {error!r}')
                failures += 1
                continue
            where = os.path.realpath(getattr(module, '__file__', None) or list(module.__path__)[0])
            if not where.startswith(extern + os.sep):
                print(f'  {name}: FAILED, imported from {where}')
                failures += 1
            else:
                print(f'  {name}: imported from pcapkit/_extern')
    if not infos:
        print('pcapkit/_extern holds no dist-info at all')
        failures += 1
    sys.exit(1 if failures else 0)
''')


def native(head: 'bytes') -> 'Optional[tuple[str, frozenset[str]]]':
    """The object format and machines of a binary starting with ``head``; :data:`None` for any other file."""
    magic = head[:4]
    if magic == b'\x7fELF' and len(head) >= 20 and head[5] in (1, 2):
        order = 'little' if head[5] == 1 else 'big'  # type: Literal['little', 'big']
        machine = int.from_bytes(head[18:20], order)
        return 'ELF', frozenset((ELF_MACHINES.get(machine, f'e_machine {machine}'),))
    thin = {b'\xcf\xfa\xed\xfe': 'little', b'\xce\xfa\xed\xfe': 'little',
            b'\xfe\xed\xfa\xcf': 'big', b'\xfe\xed\xfa\xce': 'big'}  # type: dict[bytes, Literal['little', 'big']]
    if magic in thin and len(head) >= 8:
        cpu = int.from_bytes(head[4:8], thin[magic])
        return 'Mach-O', frozenset((MACHO_CPUS.get(cpu, f'cputype {cpu:#x}'),))
    if magic in (b'\xca\xfe\xba\xbe', b'\xca\xfe\xba\xbf') and len(head) >= 8:
        count = int.from_bytes(head[4:8], 'big')
        # A Java class file shares the magic, and there the next word is its
        # version, 45 and up, where a universal binary counts its slices.
        if not 0 < count < 30:
            return None
        size = 20 if magic == b'\xca\xfe\xba\xbe' else 32
        cpus = [int.from_bytes(head[8 + size * index:12 + size * index], 'big') for index in range(count)]
        return 'Mach-O', frozenset(MACHO_CPUS.get(cpu, f'cputype {cpu:#x}') for cpu in cpus)
    return None


def foreign(root: 'pathlib.Path', subdir: 'str') -> 'tuple[int, list[str]]':
    """How many native binaries ``root`` holds, and each one that does not run on ``subdir``.

    ``noarch`` may hold none; a platform outside :data:`BINARIES` fails every one.
    A file named as a native library whose header is neither ELF nor Mach-O is
    reported too, since this cannot vouch for it.

    """
    want = BINARIES.get(subdir)
    count, problems = 0, []
    for path in sorted(root.rglob('*')):
        if path.is_symlink() or not path.is_file():
            continue
        with path.open('rb') as file:
            head = file.read(4096)
        found = native(head)
        name = path.relative_to(root).as_posix()
        if found is None:
            if path.name.endswith(NATIVE_SUFFIXES) or '.so.' in path.name:
                problems.append(f'{name}: neither ELF nor Mach-O, so its machine is unknown')
            continue
        count += 1
        kind, machines = found
        if want is None or kind != want[0] or want[1] not in machines:
            what = f'{kind} {", ".join(sorted(machines))}'
            problems.append(f'{name}: {what}, but {subdir} has no native machine' if want is None else
                            f'{name}: {what}, not {want[0]} {want[1]} as {subdir} needs')
    return count, problems


def runner_platform() -> 'Optional[str]':
    """This machine's conda subdir among :data:`PLATFORMS`, or :data:`None` when it is none of them."""
    here = (platform.system(), platform.machine())
    return next((subdir for subdir, (_, system, machine) in PLATFORMS.items() if (system, machine) == here),
                None)


def smoke(package: 'pathlib.Path') -> 'int':
    """Unpack a built ``.tar.bz2`` conda package, check its platform and binaries, and run :data:`PROBE`."""
    with tempfile.TemporaryDirectory() as temp:
        with tarfile.open(package, 'r:bz2') as archive:
            archive.extractall(temp, filter='data')
        inits = sorted(pathlib.Path(temp).glob('**/site-packages/pcapkit/__init__.py'))
        if len(inits) != 1:
            print(f'{package}: expected one site-packages/pcapkit, found {len(inits)}', file=sys.stderr)
            return 1
        site = inits[0].parents[1]
        built = site.parent.name
        if built != f'python{sys.version_info.major}.{sys.version_info.minor}':
            print(f'{package} is built for {built}, and this is {sys.version}', file=sys.stderr)
            return 1
        try:
            index = json.loads((pathlib.Path(temp) / 'info' / 'index.json').read_text(encoding='utf-8'))
            subdir = str(index['subdir'])
        except (OSError, ValueError, TypeError, KeyError) as error:
            print(f'{package}: info/index.json names no subdir ({error!r}), so its platform is unknown',
                  file=sys.stderr)
            return 1
        runner = runner_platform()
        if subdir not in ('noarch', runner):
            print(f'{package} is filed under {subdir}, and this runner is '
                  f'{runner or " ".join((platform.system(), platform.machine()))}: '
                  'a package is checked on the platform it is for', file=sys.stderr)
            return 1
        count, problems = foreign(pathlib.Path(temp), subdir)
        for problem in problems:
            print(f'FOREIGN {problem}')
        print(f'{subdir}: {count} native binaries read, {len(problems) or "none"} failing', flush=True)
        status = subprocess.run([sys.executable, '-I', '-S', '-c', PROBE, str(site)],  # nosec B603
                                check=False).returncode
        return 1 if problems else status


def main(argv: 'Optional[list[str]]' = None) -> 'int':
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--check', action='store_true',
                       help='write nothing; exit 1 when conda/requirements.txt is stale')
    group.add_argument('--smoke', metavar='PACKAGE', type=pathlib.Path,
                       help='check the vendored packages of a built .tar.bz2 conda package')
    args = parser.parse_args(argv)

    if args.smoke is not None:
        return smoke(args.smoke)

    envs = environments(conda_pythons())
    try:
        found = derive(direct(), envs, _requires)
    except NotInstalled as error:
        print(error, file=sys.stderr)
        return 2

    if args.check:
        problems = compare(FILE.read_text(encoding='utf-8'), found, envs)
        for problem in problems:
            print(f'{FILE.relative_to(ROOT)}: {problem}')
        return 1 if problems else 0

    problems = unpinnable(found)
    if problems:
        print('\n'.join(problems), file=sys.stderr)
        return 1

    FILE.write_text(''.join(f'{line}\n' for line in lines(found, envs, _version)), encoding='utf-8')
    return 0


if __name__ == '__main__':
    sys.exit(main())
