# -*- coding: utf-8 -*-
"""The third-party packages the conda recipe vendors into :file:`pcapkit/_extern` (#1814, #3133).

The conda package is one ``noarch: python`` build carrying the core
functionality alone (#3133). Its run requirements are the ``[project]
dependencies`` that conda-forge has, :data:`CONDA_FORGE`, which
:file:`conda/pypcapkit/meta.yaml` lists. ``conda/pypcapkit/build.sh`` installs
every wheel ``pip download -r conda/requirements.txt`` fetched into
:file:`pcapkit/_extern`, which :file:`pcapkit/__init__.py` appends to
:data:`sys.path`, so anything pip-installed into the environment comes first. This
script derives that file from :file:`pyproject.toml` instead of leaving it to be
edited by hand. Each package falls in exactly one of these classes:

``needed``
    A ``[project] dependencies`` entry outside :data:`CONDA_FORGE`. No extra is
    vendored: a conda user pip-installs an optional feature into the environment.
``transitive``
    What a needed package requires in turn, with the extras it was asked for,
    as the installed distributions' metadata declares it, but for
    :data:`CONDA_FORGE`'s, which the run requirements supply.
``dead``
    A requirement whose marker is false on every interpreter the package
    installs on: each CPython of the supported and KTLO tiers of
    :file:`.github/python-versions.toml`, on the platforms in :data:`PLATFORMS`.
    It is left out.
``stale``
    Anything else the file names.

One set of files serves every interpreter, so a requirement live on some of them
only cannot be vendored, and deriving the file fails on it: take that package from
conda-forge instead.

Each line pins the version installed here, as ``conda-update`` in
:file:`.github/workflows/cron-conda.yml` installs ``.`` before running this
script. Resolving the newest releases is that install step's job, and needs the
network; this script reads only what is installed, so it works offline.

Run without arguments it rewrites :file:`conda/requirements.txt`. With
``--check`` it writes nothing, and exits 1 when the file names a different set of
packages than it derives, or pins one under a marker. Lines pinning one package
differently under one marker fail it too, since pip cannot install them together
when the pins disagree (#1852). With ``--smoke PACKAGE`` it unpacks a built
``.tar.bz2`` conda package and checks that it is ``noarch: python`` with no native
binary in it (#1822), that every distribution vendored in it shipped every file
its ``RECORD`` lists, and that each of its modules imports from
:file:`pcapkit/_extern` with nothing else on the path. That mode needs only the
standard library.

With ``--same-dependencies REV`` it reads ``REV``'s :file:`pyproject.toml` with
``git show`` and exits :data:`NOT_SAME`, naming both sets, when what
:func:`direct` reads there differs from this tree's. ``conda-update`` builds the
release tag's tree with this tree's recipe, so it does not build then (#2841).

"""

from __future__ import annotations

import argparse
import importlib.metadata
import importlib.util
import json
import pathlib
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

#: The ``[project] dependencies`` conda-forge has, by canonical name, as the
#: package is named there: the recipe's run requirements besides Python (#3133).
CONDA_FORGE = {
    'aenum': 'aenum',
    'chardet': 'chardet',
    'typing-extensions': 'typing_extensions',
}
#: The platforms the package installs on, by conda subdir, as ``sys.platform``,
#: ``platform.system()`` and ``platform.machine()`` read there, for the markers
#: :func:`environments` evaluates.
PLATFORMS = {
    'linux-64': ('linux', 'Linux', 'x86_64'),
    'osx-64': ('darwin', 'Darwin', 'x86_64'),
    'osx-arm64': ('darwin', 'Darwin', 'arm64'),
    'win-64': ('win32', 'Windows', 'AMD64'),
}
#: ``--same-dependencies``' exit status where the two sets differ (#2841),
#: as util/verdict_covers_checkout.py's ``--exit-code`` reports its refusal.
NOT_SAME = 3
#: What ELF's ``e_machine``, Mach-O's ``cputype`` and PE's ``Machine`` say, for
#: :func:`native`'s report of a binary.
ELF_MACHINES = {3: 'i386', 20: 'ppc', 21: 'ppc64', 40: 'arm', 62: 'x86_64', 183: 'arm64', 243: 'riscv'}
MACHO_CPUS = {7: 'i386', 0x01000007: 'x86_64', 12: 'arm', 0x0100000c: 'arm64', 0x0200000c: 'arm64_32',
              18: 'ppc', 0x01000012: 'ppc64'}
PE_MACHINES = {0x014c: 'i386', 0x01c4: 'arm', 0x8664: 'x86_64', 0xaa64: 'arm64'}
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
    """The CPython versions the package installs on: the supported and KTLO tiers, oldest first."""
    versions = _load_python_versions()
    data = versions.load()  # type: ignore[attr-defined]
    found = [version for name in ('ktlo', 'supported')
             for version in versions.tier(data, 'cpython', name)]  # type: ignore[attr-defined]
    return sorted(found, key=versions.key)  # type: ignore[attr-defined]


def environments(pythons: 'Iterable[str]') -> 'list[dict[str, str]]':
    """A marker environment per interpreter the package installs on: each Python on each of :data:`PLATFORMS`."""
    found = []
    for python in pythons:
        for sys_platform, system, machine in PLATFORMS.values():
            found.append({
                'python_version': python, 'python_full_version': f'{python}.0',
                'implementation_name': 'cpython', 'platform_python_implementation': 'CPython',
                'implementation_version': f'{python}.0', 'sys_platform': sys_platform,
                'platform_system': system, 'os_name': 'nt' if sys_platform == 'win32' else 'posix',
                'platform_machine': machine, 'platform_release': '', 'platform_version': '',
            })
    return found


def direct(pyproject: 'pathlib.Path' = PYPROJECT) -> 'list[Requirement]':
    """``[project] dependencies``, as written in ``pyproject``."""
    return _direct(pathlib.Path(pyproject).read_text(encoding='utf-8'))


def _direct(text: 'str') -> 'list[Requirement]':
    """:func:`direct`, of a ``pyproject.toml`` already read as ``text``."""
    from packaging.requirements import Requirement  # pylint: disable=import-outside-toplevel
    project = tomllib.loads(text)['project']
    return [Requirement(line) for line in project.get('dependencies', [])]


def _live(marker: 'Optional[Marker]', env: 'dict[str, str]', extras: 'Iterable[str]') -> 'bool':
    if marker is None:
        return True
    return any(marker.evaluate(dict(env, extra=extra)) for extra in (tuple(extras) or ('',)))


class NotInstalled(Exception):
    """Packages some interpreter needs vendored that this one has no metadata for."""


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
        hint = ('install . first' if here else
                'its marker leaves it out here, so pip did not install it; run this on one '
                'of those interpreters, or install it here by hand')
        reasons.append(f'{name} is needed on {describe(builds, envs)} ({"; ".join(sorted(via))}), '
                       f'and Python {host[0]} on {host[1]}, which runs this, does not have it: {hint}')
    return NotInstalled('\n'.join(reasons))


def derive(requirements: 'list[Requirement]', envs: 'list[dict[str, str]]',
           requires: 'Callable[[str], Optional[list[str]]]') -> 'dict[str, dict[str, object]]':
    """Each package to vendor, by canonical name: its class and the interpreters needing it.

    ``requires`` returns a distribution's ``Requires-Dist`` lines, as
    :func:`importlib.metadata.requires` does, and raises
    :class:`importlib.metadata.PackageNotFoundError` for one not installed.
    A requirement live in no environment is recorded as ``dead`` and not walked,
    and one :data:`CONDA_FORGE` names is not walked either.
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
        if name in CONDA_FORGE:
            continue
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


class Partial(ValueError):
    """A package needed on some interpreters only, which one noarch package cannot vendor (#3133)."""


def partial(found: 'dict[str, dict[str, object]]', envs: 'list[dict[str, str]]') -> 'list[str]':
    """Each package of ``found`` vendored for some of ``envs`` and not the others, one line apiece."""
    return [f'partial: {name} is needed on {describe(entry["builds"], envs)} only '  # type: ignore[arg-type]
            '(and not on every interpreter one noarch package serves), so take it from conda-forge instead'
            for name, entry in sorted(found.items())
            if entry['class'] != 'dead' and len(entry['builds']) != len(envs)]  # type: ignore[arg-type]


def lines(found: 'dict[str, dict[str, object]]', envs: 'list[dict[str, str]]',
          version: 'Callable[[str], str]') -> 'list[str]':
    """:file:`conda/requirements.txt`'s lines, sorted: a pin per vendored package; :class:`Partial` on a marker."""
    problems = partial(found, envs)
    if problems:
        raise Partial('\n'.join(problems))
    return [f'{name}=={version(name)}' for name, entry in sorted(found.items()) if entry['class'] != 'dead']


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


def _show(markers: 'Iterable[Optional[str]]') -> 'str':
    shown = sorted(markers, key=str)
    return repr(shown[0]) if len(shown) == 1 else repr(shown)


def compare(text: 'str', found: 'dict[str, dict[str, object]]',
            envs: 'list[dict[str, str]]') -> 'list[str]':
    """Why ``text`` is stale against ``found``, one line per package; empty when current."""
    problems = partial(found, envs)
    have, conflicts = _read(text)
    problems.extend(conflicts)
    want = {name for name, entry in found.items() if entry['class'] != 'dead'}
    for name in sorted(set(have) | want):
        if name not in have:
            problems.append(f'missing: {name} ({found[name]["class"]})')
        elif name not in want:
            if name in found:
                problems.append(f'dead: {name} -- its marker {found[name]["marker"]} is false '
                                'on every interpreter the package installs on')
            else:
                problems.append(f'stale: {name} -- no [project] dependency outside CONDA_FORGE needs it, '
                                'directly or not')
        elif set(have[name]) != {None}:
            problems.append(f'marker: {name} has {_show(have[name])}, and one noarch package takes no marker')
    return problems


def _requires(name: 'str') -> 'Optional[list[str]]':
    return importlib.metadata.requires(name)


def _version(name: 'str') -> 'str':
    return importlib.metadata.version(name)


def _escape(text: 'str') -> 'str':
    """``text`` as a workflow command's data."""
    return text.replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')


def same_dependencies(rev: 'str') -> 'int':
    """``--same-dependencies``: whether ``rev``'s :file:`pyproject.toml` names what :data:`PYPROJECT` does (#2841).

    It prints why, as workflow-command data, and returns 0 when they match and
    :data:`NOT_SAME` when not, so the caller picks the annotation; 1 with an
    ``::error`` where ``rev`` has no :file:`pyproject.toml` to read.

    """
    shown = subprocess.run(['git', 'show', f'{rev}:pyproject.toml'], cwd=ROOT,  # nosec B603 B607
                           capture_output=True, check=False)
    if shown.returncode != 0:
        print(f'::error title=No pyproject.toml at {rev}::'
              + _escape(shown.stderr.decode('utf-8', 'replace').strip()), flush=True)
        return 1
    theirs = sorted({str(requirement) for requirement in _direct(shown.stdout.decode('utf-8'))})
    ours = sorted({str(requirement) for requirement in direct()})
    if theirs == ours:
        print(f'{rev} names the dependencies main does, which the conda recipe takes from conda-forge or vendors',
              flush=True)
        return 0
    print(_escape(f"{rev}'s tree would be built with main's conda recipe, and the two name different "
                  f"dependencies. {rev}: {', '.join(theirs) or 'none'}. main: {', '.join(ours) or 'none'}."),
          flush=True)
    return NOT_SAME


#: Run with ``-I -S`` and the unpacked ``pcapkit/_extern`` as its argument, so
#: that nothing outside it can satisfy an import.
PROBE = textwrap.dedent('''\
    import importlib, os, sys
    extern = os.path.realpath(sys.argv[1])
    sys.path.insert(0, extern)
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
    # #2060: a PE image, as a ``.pyd`` or ``.dll`` is: the DOS header's
    # ``e_lfanew``, at 0x3c, points at ``PE\0\0`` and the COFF ``Machine`` after it.
    if magic[:2] == b'MZ' and len(head) >= 0x40:
        offset = int.from_bytes(head[0x3c:0x40], 'little')
        if head[offset:offset + 4] == b'PE\0\0' and len(head) >= offset + 6:
            machine = int.from_bytes(head[offset + 4:offset + 6], 'little')
            return 'PE', frozenset((PE_MACHINES.get(machine, f'Machine {machine:#06x}'),))
        return None
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


def foreign(root: 'pathlib.Path') -> 'list[str]':
    """Each native binary ``root`` holds, which a ``noarch`` package may not (#1822).

    A file named as a native library whose header is not ELF, Mach-O or PE is
    reported too, since this cannot vouch for it.

    """
    problems = []
    for path in sorted(root.rglob('*')):
        if path.is_symlink() or not path.is_file():
            continue
        with path.open('rb') as file:
            head = file.read(4096)
        found = native(head)
        name = path.relative_to(root).as_posix()
        if found is None:
            if path.name.endswith(NATIVE_SUFFIXES) or '.so.' in path.name:
                problems.append(f'{name}: not ELF, Mach-O or PE, so its machine is unknown')
            continue
        kind, machines = found
        problems.append(f'{name}: {kind} {", ".join(sorted(machines))}, and noarch has no native machine')
    return problems


def smoke(package: 'pathlib.Path') -> 'int':
    """Unpack a built ``.tar.bz2`` conda package, check it is ``noarch: python``, and run :data:`PROBE`."""
    with tempfile.TemporaryDirectory() as temp:
        with tarfile.open(package, 'r:bz2') as archive:
            archive.extractall(temp, filter='data')
        inits = sorted(pathlib.Path(temp).glob('**/site-packages/pcapkit/__init__.py'))
        if len(inits) != 1:
            print(f'{package}: expected one site-packages/pcapkit, found {len(inits)}', file=sys.stderr)
            return 1
        try:
            index = json.loads((pathlib.Path(temp) / 'info' / 'index.json').read_text(encoding='utf-8'))
            kind = (index['subdir'], index.get('noarch'))
        except (OSError, ValueError, TypeError, KeyError) as error:
            print(f'{package}: info/index.json names no subdir ({error!r}), so its platform is unknown',
                  file=sys.stderr)
            return 1
        if kind != ('noarch', 'python'):
            print(f'{package} is filed under {kind[0]} as noarch {kind[1]!r}, and the package is one '
                  'noarch: python build (#3133)', file=sys.stderr)
            return 1
        problems = foreign(pathlib.Path(temp))
        for problem in problems:
            print(f'FOREIGN {problem}')
        print(f'noarch: {len(problems) or "no"} native binaries', flush=True)
        status = subprocess.run([sys.executable, '-I', '-S', '-c', PROBE,  # nosec B603
                                 str(inits[0].parent / '_extern')], check=False).returncode
        return 1 if problems else status


def main(argv: 'Optional[list[str]]' = None) -> 'int':
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--check', action='store_true',
                       help='write nothing; exit 1 when conda/requirements.txt is stale')
    group.add_argument('--smoke', metavar='PACKAGE', type=pathlib.Path,
                       help='check the vendored packages of a built .tar.bz2 conda package')
    group.add_argument('--same-dependencies', metavar='REV',
                       help="exit 3 when REV's pyproject.toml names other dependencies than this one's")
    args = parser.parse_args(argv)

    if args.smoke is not None:
        return smoke(args.smoke)
    if args.same_dependencies is not None:
        return same_dependencies(args.same_dependencies)

    envs = environments(conda_pythons())
    try:
        found = derive(direct(), envs, _requires)
    except NotInstalled as error:
        print(error, file=sys.stderr)
        return 2

    if args.check:
        problems = [f'{FILE.relative_to(ROOT)}: {problem}'
                    for problem in compare(FILE.read_text(encoding='utf-8'), found, envs)]
        for problem in problems:
            print(problem)
        return 1 if problems else 0

    try:
        text = ''.join(f'{line}\n' for line in lines(found, envs, _version))
    except Partial as error:
        print(error, file=sys.stderr)
        return 1
    FILE.write_text(text, encoding='utf-8')
    return 0


if __name__ == '__main__':
    sys.exit(main())
