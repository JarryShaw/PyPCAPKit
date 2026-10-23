# -*- coding: utf-8 -*-
"""The test suite's tier rule, and the machinery that enforces it.

The suite runs in two tiers, and the split is a property of a module's *path*
rather than of the command that happens to collect it:

=================================== ==========================================
Tier                                Modules
=================================== ==========================================
unit                                everything under :file:`tests/` except the
                                    fixture-dependent ones
fixture-dependent                   :file:`tests/integration/`,
                                    :file:`*_runtime.py`, :file:`*_regression.py`
=================================== ==========================================

The unit tier has to pass on a fresh clone with nothing installed but
``pip install -e '.[test]'``, which is exactly how the ``test`` job of
:file:`.github/workflows/unit-tests.yml` runs it -- see
:data:`UNIT_TIER_SELECTION` for the selection it uses. The fixture-dependent
tier runs only after :file:`examples/generators/make_samples.py` has rebuilt
:file:`examples/captures/`, so it may read any capture it likes.

That leaves one way to break the unit tier which is invisible to the developer
who does it: read a *generated* capture from a unit-tier module. Only a handful
of the files under :file:`examples/captures/` are committed; the rest are built
on demand and gitignored. A machine that has run ``make samples`` has them all,
so the test passes locally and then fails on a fresh CI checkout with a
missing-file error that blames the fixture rather than the tier rule. It has
happened more than once (GitHub pull requests #372 and #384 among them), and
each time it cost a CI round-trip to work out.

So this module answers, cheaply and without needing the fixtures themselves:

* :func:`is_unit_tier` -- which tier does this module belong to?
* :func:`committed_captures` -- which captures does *git* track? Asked of git
  rather than hardcoded, because a hardcoded list of names silently rots the
  moment somebody commits another capture, or stops committing one.
* :func:`audit_module` -- does this module read a generated capture without
  handling its absence?
* :func:`check_unit_tier_read` -- may this particular
  :func:`~tests._support.sample_path` call go ahead?
* :func:`explain` -- the message that says what is wrong and what to do about
  it.
* :func:`skip_idiom_modules`, :func:`skip_idiom_test_ids`, and
  :func:`fixture_tier_paths` -- which unit-tier modules (and, more precisely,
  which of their test methods) skip a generated capture rather than reading it
  for real, and the complete pytest selection the fixture-dependent tier needs
  in order to still exercise them.
* :func:`module_tier` -- which *test tier* does this module run in (#1958):
  ``ALL``, on every leg, or ``LATEST``, on ``latest`` alone? ``ALL`` is opt-in:
  a module is in it only when it says so with ``__tier__ = 'ALL'``
  (:func:`declared_tier`), and :data:`DEFAULT_TIER`, ``LATEST``, otherwise.
  :func:`all_tier_paths` and :func:`latest_tier_paths` list the two tiers; every
  leg but ``latest`` leaves the second out. See "The curated ``ALL`` tier" below
  for which modules opt in.
* :func:`is_project_pin` and :func:`project_pin_paths` -- which
  :file:`tests/project` modules give one answer on every interpreter, and so run
  once per push, in the ``project-tests`` job, rather than on every leg (#1954)?

:file:`tests/conftest.py` runs :func:`is_unit_tier` and :func:`audit_module` --
and through it :func:`committed_captures` and :func:`explain` -- at collection
time, and :func:`tests._support.sample_path` consults :func:`check_unit_tier_read`
on every call. Both paths no-op when git cannot answer, so an unpacked source
tarball still runs its tests.

:func:`fixture_tier_paths` is what the ``integration`` job of
:file:`.github/workflows/unit-tests.yml` runs directly, rather than embedding
its own copy of the selection: the job calls this module at run time (``python
-c "from tests._tiers import fixture_tier_paths; ..."``, see
:data:`FIXTURE_TIER_SELECTOR`) instead of spelling out ``tests/integration``
and the two globs itself. That closes the same gap :data:`UNIT_TIER_SELECTION`
leaves open in the other direction: a workflow that asks this module for the
answer cannot drift from it, whereas one that repeats the answer as literal
flags always can. See :func:`fixture_tier_paths`'s docstring for why the
selection is more than just the complement of the unit tier.

The two halves cover each other. The collection-time audit is static, so it sees
a violation in a test that never runs -- one skipped for a missing optional
engine, say -- but only when the capture name is a string literal. The call-time
check sees the name however it was computed, e.g. ``sample_path(sample)`` in a
parametrised loop, but only once the call is reached.

What neither catches, deliberately: a unit-tier module that opens a capture
without going through :func:`~tests._support.sample_path` at all, e.g. by joining
:file:`examples/captures/` and a name itself. No *unit-tier* module does this:
:file:`tests/protocols/misc/test_pcapng_unit.py` was the last one, and
reads ``sample_path('dhcp_big_endian.pcapng')`` inside the ``try``/``except
FileNotFoundError`` idiom :func:`explain` recommends. Only the *unit* tier is
claimed there, deliberately: fixture-tier modules join the directory freely and
are entitled to, e.g. :file:`tests/protocols/test_option_coverage_runtime.py`,
which imports :data:`SAMPLE_ROOT` from here and joins names onto it -- legal,
because that tier runs only once the fixtures exist. The one unit-tier module that
touches :data:`SAMPLE_ROOT` at all, :file:`tests/test_tier_guard.py`, stats
:file:`in.pcap` directly -- which is committed -- and separately loops over every
name :func:`committed_captures` reports, each committed by construction, since that
is git's own tracked listing rather than a name the test made up. But nothing stops
the next unit-tier module from opening a *generated* capture that way, and the shape
stays invisible here.

Flagging it in general was considered and rejected, with a measurement behind the
decision. A rule as broad as "any string literal ending in ``.pcap``" matches 18
distinct literal values in the unit-tier modules under :file:`tests/`, across 85
occurrences of them -- 199 occurrences once the fixture tier is counted too. Only
two of the 18 are a :func:`~tests._support.sample_path` argument at all, and both
are already legal: ``'in.pcap'`` is committed, and ``'test.pcap'`` is read inside
the sanctioned ``try``/``except``. The other 16 name no capture at all --
``'out.pcap'``, ``'input.pcap'``, ``'capture.pcap'``, scratch paths written by
tests that read no fixture, and ``'pcapkit.foundation.engines.pcap'``, which is a
dotted module name rather than a path. So the figure that matters is 16 false
positives, counted as distinct literal values in the unit tier: the broad rule
would invent every one of them and catch nothing this rule misses, and a false
positive here aborts collection for everybody rather than failing one test.
Narrowing it would mean recognising a second, much woollier "the absence is
handled" idiom -- an :func:`os.path.isfile` check and a skip -- on top of the
``try``/``except`` one. So the rule this module enforces is stated as it is:
capture reads go through :func:`~tests._support.sample_path`, and that is the door
with the lock on it.

The curated ``ALL`` tier
------------------------

``ALL`` is a tailored list rather than whatever a rule guesses (#1958, #1963): it
is what every leg off ``latest`` runs, so it has to be short enough to save time,
the same on every leg so QA stays consistent, and enough on its own to validate a
change on each interpreter. ``latest`` runs the whole suite, and is the gate.

A module opts in with ``__tier__ = 'ALL'`` when it exercises behaviour that can
differ between interpreters or versions:

* compat shims and ``sys.version_info`` or ``sys.implementation`` gates;
* C-accelerated versus pure paths, and code sensitive to garbage collection,
  weak references or finalisation;
* ``int``, ``bytes`` and :mod:`struct` edge cases, and ``sys.maxsize`` or
  recursion limits;
* pickling and copying, metaclass and ABC machinery, and enum mechanics;
* stream and buffer semantics, threading and locking, and the warning and
  exception hooks;
* a third-party engine whose installable releases vary by interpreter, which
  ``latest`` alone could not cover;
* the hand-picked round trips, the ``*_edge_roundtrip_unit`` tables among them,
  which the owner ruled run on ``ALL`` as part of QA; and
* the smoke slice: a representative module per protocol family and per
  package, so each leg still drives the main parse and build paths.

Everything else is ``LATEST`` by default: the per-protocol field-by-field tests,
whose behaviour is interpreter-independent pure Python, the real sweeps, and the
docs, project and structure tests. A module that branches on the interpreter
itself (:func:`branches_on_interpreter`, a syntactic, best-effort check) has to
state its tier either way, so a version gate never lands on ``latest`` alone by
omission; a ``LATEST`` marker is otherwise optional, and records why a module
someone might expect on every leg is not.

Scapy is opted in like the other third-party engines: the ``integration`` and
``pypcap-parity`` legs install it on every interpreter, and a ``test`` leg off
``latest``, which does not, skips it. The vendor extra is installed on ``latest``
alone, and the crawlers are pure Python over ``requests`` and ``bs4``, so the vendor
modules are ``LATEST``, each saying so, but for the file-restore and
environment-variable tests, which stay on every leg.

Nothing here imports :mod:`tests._support` -- the dependency runs the other way,
and adding the reverse edge would make it a cycle. Nothing here imports
:mod:`pcapkit`, :mod:`pytest` or any optional engine either, so the guard is
usable from the earliest possible moment and cannot itself be the reason a
fresh clone fails.

Nothing in this file is collected by :program:`pytest`: ``python_files`` in
:file:`pyproject.toml` is ``test_*.py``.

"""
from __future__ import annotations

import ast
import functools
import pathlib
import re
import subprocess
from typing import TYPE_CHECKING, NamedTuple

if TYPE_CHECKING:
    from typing import Optional

__all__ = [
    'GeneratedFixtureInUnitTierError', 'TierGuardWarning', 'SampleCall',
    'ROOT', 'TESTS_ROOT', 'SAMPLE_ROOT', 'REGENERATE_SAMPLES_CMD', 'UNIT_TIER_SELECTION',
    'FIXTURE_TIER_SUFFIXES', 'FIXTURE_TIER_DIRS', 'FIXTURE_TIER_SELECTOR',
    'TIER_ALL', 'TIER_LATEST', 'TIERS', 'TIER_MARKER', 'LATEST_TIER_SELECTOR', 'FIXTURE_ALL_TIER_SELECTOR',
    'InvalidTierError', 'DEFAULT_TIER', 'suite_modules', 'declared_tier', 'branches_on_interpreter', 'module_tier',
    'PROBE_MODULE_NAME', 'is_probe_module',
    'all_tier_paths', 'latest_tier_paths',
    'PROJECT_PINS_DIR', 'PROJECT_PINS_SELECTOR', 'PROJECT_PIN_PACKAGE', 'LOADABLE_DIRS',
    'varies_by_interpreter', 'is_project_pin', 'project_pin_paths',
    'is_unit_tier', 'committed_captures', 'committed_capture_names',
    'guard_unavailable_reason', 'handled_lines', 'sample_path_calls',
    'audit_module', 'check_unit_tier_read', 'explain',
    'skip_idiom_modules', 'skip_idiom_test_ids', 'fixture_tier_paths',
]

#: Repository root, i.e. the parent of the directory holding this file. The
#: single definition of it for the whole suite: :mod:`tests._support` imports it
#: from here rather than recomputing it.
ROOT = pathlib.Path(__file__).resolve().parents[1]
#: Directory holding the test suite, which is what tier membership is relative to.
TESTS_ROOT = ROOT / 'tests'
#: Reserved name for the probe module
#: :class:`tests.test_tier_guard_xdist.XdistSubprocessTests` writes to disk, at
#: :func:`is_probe_module`'s path, to reproduce a real tier violation under a real
#: :program:`pytest` run. Defined here, and imported by :mod:`tests.conftest`,
#: which has to recognise the probe without importing that module: the nested
#: :program:`pytest` subprocess the probe test spawns loads the conftest but never
#: collects ``test_tier_guard_xdist.py`` at all.
PROBE_MODULE_NAME = 'test_zzz_xdist_guard_probe_unit.py'
#: Directory holding the sample captures, committed and generated alike.
SAMPLE_ROOT = ROOT / 'examples' / 'captures'
#: Command that rebuilds every generated capture. ``make samples`` runs it too.
REGENERATE_SAMPLES_CMD = 'python examples/generators/make_samples.py'
#: The unit-tier selection, verbatim from the ``test`` job of
#: :file:`.github/workflows/unit-tests.yml`. Quoted in the failure message so the
#: reader can run exactly what CI runs; :func:`is_unit_tier` below is the
#: executable statement of the same rule, and the two have to agree.
UNIT_TIER_SELECTION = (
    "pytest tests --ignore=tests/integration "
    "--ignore-glob='*_runtime.py' --ignore-glob='*_regression.py'"
)
#: Module file-name suffixes that put a module in the fixture-dependent tier,
#: matching the ``--ignore-glob`` patterns above.
FIXTURE_TIER_SUFFIXES = ('_runtime.py', '_regression.py')
#: Directories under :file:`tests/` that are fixture-dependent in their entirety,
#: matching the ``--ignore`` arguments above.
FIXTURE_TIER_DIRS = frozenset({'integration'})
#: The fixture-dependent tier's selector, verbatim from the ``integration`` job of
#: :file:`.github/workflows/unit-tests.yml`. Unlike :data:`UNIT_TIER_SELECTION` this
#: cannot be written as a fixed list of flags: which paths belong in the
#: selection depends on git (which captures are committed) and on which unit-tier
#: modules use the skip idiom, neither of which is stable source text pytest
#: flags could name. So the workflow does not repeat the answer -- it asks this
#: module for it at run time, with this exact invocation, quoted here so a reader
#: can run precisely what CI runs. See :func:`fixture_tier_paths`.
FIXTURE_TIER_SELECTOR = (
    'python -c "from tests._tiers import fixture_tier_paths; '
    'print(\' \'.join(fixture_tier_paths()))"'
)
#: The test tiers (#1958), which say on which legs a module runs. Orthogonal to the
#: unit and fixture-dependent tiers above, which say what a module may read: ``ALL``
#: modules run on every leg of every job that collects them, ``LATEST`` ones on the
#: ``latest`` leg alone. See :func:`module_tier`.
TIER_ALL = 'ALL'
#: See :data:`TIER_ALL`.
TIER_LATEST = 'LATEST'
#: Every test tier, the values a :data:`TIER_MARKER` may take.
TIERS = (TIER_ALL, TIER_LATEST)
#: The tier of a module that states none: ``ALL`` is opt-in (#1958, #1963), so a
#: new module runs on ``latest``, the gate, until it says why every leg needs it.
DEFAULT_TIER = TIER_LATEST
#: The module-level constant that states a module's test tier outright, e.g.
#: ``__tier__ = 'LATEST'``, read by AST in :func:`declared_tier`. A constant rather
#: than a pytest marker, so plain :mod:`unittest` runs see the same module.
TIER_MARKER = '__tier__'
#: The ``LATEST`` tier's selector, verbatim from the workflows: every leg of ``test``
#: but ``latest``, and every ``experimental`` leg, passes each path it prints as an
#: ``--ignore``. Asked at run time, as :data:`FIXTURE_TIER_SELECTOR` is, so no
#: workflow lists the tier. See :func:`latest_tier_paths`.
LATEST_TIER_SELECTOR = (
    'python -c "from tests._tiers import latest_tier_paths; '
    'print(\' \'.join(latest_tier_paths()))"'
)
#: The fixture-dependent tier's ``ALL``-tier selection, verbatim from the workflows:
#: what ``integration`` runs on every leg but ``latest``, and ``pypcap-parity`` on each
#: of its legs. See :func:`fixture_tier_paths`.
FIXTURE_ALL_TIER_SELECTOR = (
    'python -c "from tests._tiers import fixture_tier_paths; '
    'print(\' \'.join(fixture_tier_paths(\'ALL\')))"'
)
#: The directory whose platform- and version-independent modules, the *project
#: pins*, run once per push in the ``project-tests`` job of
#: :file:`.github/workflows/unit-tests.yml` rather than on every leg (#1954). See
#: :func:`is_project_pin`.
PROJECT_PINS_DIR = 'project'
#: The project pins' selector, verbatim from the workflows: the ``project-tests``
#: job runs what it prints, and every ``test`` and ``experimental`` leg passes each
#: path as an ``--ignore``. Asked at run time, as :data:`FIXTURE_TIER_SELECTOR` is,
#: so neither workflow can drift from :func:`is_project_pin`.
PROJECT_PINS_SELECTOR = (
    'python -c "from tests._tiers import project_pin_paths; '
    'print(\' \'.join(project_pin_paths()))"'
)
#: The package whose behaviour varies by interpreter, so a module that reaches it
#: runs on every leg (#1954).
PROJECT_PIN_PACKAGE = 'pcapkit'
#: The directories, besides :file:`tests/`, whose Python files a test module may load
#: by path -- a ``util/`` script, a generator, :file:`docs/source/conf.py` -- and
#: :func:`varies_by_interpreter` follows. :file:`pcapkit/` is left out on purpose: a test
#: that names a file there reads its text, which is the same on every leg.
LOADABLE_DIRS = ('tests', 'util', 'examples', 'docs')
#: Suffixes that make a tracked file worth suggesting as a replacement capture.
#: Committedness itself is whatever git says -- this filter only keeps the
#: suggestion in :func:`explain` from offering :file:`out.txt` as a capture.
CAPTURE_SUFFIXES = ('.pcap', '.pcapng', '.cap')
#: Module quoted in :func:`explain` as the worked example of the skip idiom.
SKIP_IDIOM_EXAMPLE = 'tests/toolkit/test_dpkt_unit.py'
#: Exception names whose handler would catch a missing capture. The list is
#: deliberately generous: a false positive aborts the suite for everybody,
#: whereas a missed detection in the rare module that wraps a capture read in
#: ``except Exception`` costs nothing beyond this guard staying quiet. The
#: sanctioned idiom is ``except FileNotFoundError``; the rest are here so that
#: code which already handles the failure some other way is not flagged.
HANDLES_MISSING_FILE = frozenset({
    'FileNotFoundError', 'OSError', 'IOError', 'EnvironmentError',
    'Exception', 'BaseException',
})

#: ``try`` statement node types. :class:`ast.TryStar` is 3.11+, and CI runs
#: older interpreters as well (#1633), so it is looked up rather than named.
_TRY_NODES = (ast.Try,) + ((ast.TryStar,) if hasattr(ast, 'TryStar') else ())  # type: ignore[attr-defined]


class GeneratedFixtureInUnitTierError(FileNotFoundError):
    """A unit-tier module asked for a capture that only ``make samples`` writes.

    Subclasses :exc:`FileNotFoundError` on purpose. This guard is not allowed to
    turn a read that would have been skipped into a hard error, so anything
    already handling the missing-capture case keeps working; and the condition
    genuinely is "that file is not available to you", so the hierarchy stays
    honest. In practice the subclass is only ever raised at a call site with no
    handler, which is what makes it a mistake rather than a tolerated read.

    """


class TierGuardWarning(UserWarning):
    """The tier guard could not run, or ran into something unexpected.

    A warning rather than an error: not being able to *check* the tier rule is
    not a reason to fail a test run that may be perfectly fine.

    """


class InvalidTierError(ValueError):
    """A test module's :data:`TIER_MARKER` cannot be read as one of :data:`TIERS`.

    Raised rather than ignored: a marker that silently fell back to the default would
    put the module on legs its author ruled it off, or the other way round.

    """


class SampleCall(NamedTuple):
    """One ``sample_path(...)`` call found in a module's source."""

    #: Line the call starts on.
    lineno: 'int'
    #: The capture name, when it was spelled as a string literal; :data:`None`
    #: when it is computed, e.g. ``sample_path(sample)`` in a parametrised loop.
    name: 'Optional[str]'
    #: Whether a missing capture would be handled at this call site, i.e.
    #: whether the call sits in the body of a ``try`` that catches it.
    handled: 'bool'


def is_unit_tier(path: 'pathlib.Path | str') -> 'bool':
    """Whether ``path`` names a module in the unit tier.

    The executable statement of :data:`UNIT_TIER_SELECTION`: a module is
    unit-tier when it lives under :file:`tests/`, not under one of
    :data:`FIXTURE_TIER_DIRS`, and its name ends with none of
    :data:`FIXTURE_TIER_SUFFIXES`.

    Deciding by path rather than by which ignore flags the current invocation
    passed is deliberate. It makes the answer the same for ``pytest tests
    --ignore=...`` as for a bare ``pytest``, so the full-suite run enforces the
    rule as well -- and it does not depend on whether the fixtures happen to be
    on disk, which is the whole point of the guard.

    Args:
        path: Path to a module, absolute or relative to :data:`ROOT`.

    Returns:
        :data:`True` for a unit-tier module, :data:`False` for a
        fixture-dependent one and for anything outside :file:`tests/`.

    """
    candidate = pathlib.Path(path)
    if not candidate.is_absolute():
        candidate = ROOT / candidate

    try:
        relative = candidate.resolve().relative_to(TESTS_ROOT)
    except ValueError:
        return False

    if relative.name.endswith(FIXTURE_TIER_SUFFIXES):
        return False
    return FIXTURE_TIER_DIRS.isdisjoint(relative.parts[:-1])


#: Calls that import the module their first argument names. ``patch`` is
#: :func:`unittest.mock.patch`, which imports its target's module, and ``find_spec``
#: imports a dotted name's parents.
_IMPORTING_CALLS = frozenset({'import_module', '__import__', 'patch', 'find_spec'})
#: Of those, the ones whose computed argument may import anything at all.
_COMPUTED_IMPORTS = frozenset({'import_module', '__import__'})
#: Calls that run a file or a child process, so the files, directories and modules
#: their arguments name run too.
_RUNNING_CALLS = frozenset({
    'spec_from_file_location', 'run_path', 'SourceFileLoader', 'load_source', 'run', 'Popen',
    'call', 'check_call', 'check_output', 'system', 'create_subprocess_exec', 'create_subprocess_shell',
    'exec', 'eval',
})
#: Source text that imports :data:`PROJECT_PIN_PACKAGE` in a child interpreter: a
#: ``python -c`` script, or ``-m pcapkit``. Not ``from pcapkit/__init__.py``, a path.
_IMPORT_TEXT = re.compile(rf'(?:\b(?:import|from)|-m)\s+{PROJECT_PIN_PACKAGE}(?:\.\w+)*(?![\w/.])')
#: A string that is wholly a relative path, e.g. ``util/ci_timing.py`` or ``tests/cli``.
_PATH_TEXT = re.compile(r'[\w.-]+(?:/[\w.-]+)*/?\Z')
#: A string that is wholly a dotted module name, e.g. ``tests.project.test_no_setup_py_2061``.
_DOTTED_NAME = re.compile(r'[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+\Z')

#: What a module asks of the running interpreter when it branches on it:
#: ``sys.version_info``, ``sys.implementation``, ``platform.python_version()``.
_INTERPRETER_FACTS = frozenset({'version_info', 'hexversion', 'implementation', 'python_implementation',
                                'python_version', 'python_version_tuple'})
#: The same, imported bare: ``from sys import version_info``.
_INTERPRETER_NAMES = frozenset({'version_info', 'hexversion'})

#: One unit of :func:`varies_by_interpreter`'s search: a file, and the top-level names of it
#: that run -- :data:`None` for the whole file, as when it is the test module itself,
#: is loaded by path, or is imported as a module object.
_Region = 'tuple[pathlib.Path, Optional[frozenset[str]]]'


def _is_package(name: 'str') -> 'bool':
    return name == PROJECT_PIN_PACKAGE or name.startswith(PROJECT_PIN_PACKAGE + '.')


@functools.lru_cache(maxsize=1)
def _loadable_files() -> 'tuple[pathlib.Path, ...]':
    """Every Python file a test may run by path: those under :data:`LOADABLE_DIRS`, and the root's."""
    files = set(ROOT.glob('*.py'))
    for name in LOADABLE_DIRS:
        files.update(path for path in (ROOT / name).rglob('*.py') if '__pycache__' not in path.parts)
    return tuple(sorted(files))


@functools.lru_cache(maxsize=None)
def _paths_named(text: 'str') -> 'frozenset[pathlib.Path]':
    """The loadable files a path string names: the files whose path ends with it,
    e.g. ``conf.py``, or every file under the directory it is, e.g. ``tests/cli``.

    A single word is no directory: ``ROOT / 'util'`` is a prefix being built, and
    ``'examples'`` an argument as often as a path.

    """
    relative = text.strip('/')
    while relative.startswith('./'):
        relative = relative[2:]
    if relative.endswith('.py'):
        return frozenset(path for path in _loadable_files()
                         if ('/' + path.relative_to(ROOT).as_posix()).endswith('/' + relative))
    directory = ROOT / relative
    if '/' not in relative or not directory.is_dir():
        return frozenset()
    return frozenset(path for path in _loadable_files() if directory in path.parents)


def _module_file(name: 'str') -> 'Optional[pathlib.Path]':
    """The file of the repository module ``name``, e.g. ``tests._support``, if there is one.

    A ``util/`` script counts as a module too, as the tests that put :file:`util/`
    on :data:`sys.path` import it: ``import run_unittest_leg``.

    """
    for root in (ROOT, ROOT / 'util'):
        base = root.joinpath(*name.split('.'))
        for candidate in (base.with_suffix('.py'), base / '__init__.py'):
            if candidate.is_file():
                return candidate
    return None


@functools.lru_cache(maxsize=None)
def _parse_module(path: 'pathlib.Path') -> 'Optional[ast.Module]':
    try:
        return ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
    except (OSError, UnicodeDecodeError, SyntaxError, ValueError):
        return None


def _called(call: 'ast.Call') -> 'Optional[str]':
    """The bare name a call is made through, e.g. ``run`` for ``subprocess.run(...)``."""
    func = call.func
    return func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else None


def _defined_names(node: 'ast.stmt') -> 'set[str]':
    """The top-level names a module-level statement binds, in a block it holds too:
    ``if sys.version_info >= (3, 11): import tomllib`` binds ``tomllib``."""
    if isinstance(node, (ast.If, ast.Try, ast.With, ast.For, ast.While)) or type(node).__name__ == 'TryStar':
        return {name for field in ('body', 'orelse', 'finalbody', 'handlers')
                for child in getattr(node, field, ()) for name in _defined_names(child)}
    if isinstance(node, ast.ExceptHandler):
        return {name for child in node.body for name in _defined_names(child)}
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return {node.name}
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        return {(alias.asname or alias.name).partition('.')[0] for alias in node.names}
    targets = []  # type: list[ast.expr]
    if isinstance(node, ast.Assign):
        targets = node.targets
    elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
        targets = [node.target]
    return {name.id for target in targets for name in ast.walk(target) if isinstance(name, ast.Name)}


@functools.lru_cache(maxsize=None)
def _import_time_nodes(tree: 'ast.Module') -> 'tuple[ast.AST, ...]':
    """Every import and call of ``tree`` outside a function body, which run on import."""
    inside = set()  # type: set[int]
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            for statement in node.body if isinstance(node.body, list) else [node.body]:
                inside.update(id(child) for child in ast.walk(statement))
    return tuple(node for node in ast.walk(tree)
                 if isinstance(node, (ast.Import, ast.ImportFrom, ast.Call)) and id(node) not in inside)


def _executed_nodes(tree: 'ast.Module',
                    names: 'Optional[frozenset[str]]') -> 'tuple[list[ast.AST], list[ast.AST]]':
    """The nodes of ``tree`` that run when ``names`` of it are used, as two lists.

    The first is what runs on import -- every import and every call outside a
    function -- and the second the definitions of ``names``, with the other
    top-level names those use. For :data:`None`, the whole module is the second.

    """
    if names is None:
        return [], [tree]
    on_import = list(_import_time_nodes(tree))
    nodes = []  # type: list[ast.AST]
    wanted, todo = set(), list(names)  # type: set[str], list[str]
    while todo:
        name = todo.pop()
        if name in wanted:
            continue
        wanted.add(name)
        for statement in tree.body:
            if name in _defined_names(statement):
                nodes.append(statement)
                todo.extend(node.id for node in ast.walk(statement)
                            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load))
    return on_import, nodes


def _compares_interpreter(node: 'ast.AST') -> 'bool':
    """Whether ``node`` compares the running interpreter, e.g. ``sys.version_info < (3, 12)``."""
    if not isinstance(node, ast.Compare):
        return False
    for operand in [node.left] + list(node.comparators):
        for part in ast.walk(operand):
            if isinstance(part, ast.Name) and part.id in _INTERPRETER_NAMES:
                return True
            if (isinstance(part, ast.Attribute) and part.attr in _INTERPRETER_FACTS
                    and isinstance(part.value, ast.Name) and part.value.id in ('sys', 'platform')):
                return True
    return False


#: The key :func:`_bindings` files a ``self.name`` or ``cls.name`` attribute under.
_SELF = -1


@functools.lru_cache(maxsize=None)
def _scopes(tree: 'ast.Module') -> 'tuple[dict[int, int], dict[int, int]]':
    """Each node's scope in ``tree``, and each scope's enclosing one, by ``id``.

    A scope is the module, a function or a lambda; a class body belongs to the
    scope around it, as its names are reached through ``self`` or ``cls``.

    """
    scope_of = {id(tree): id(tree)}  # type: dict[int, int]
    parent = {}  # type: dict[int, int]
    todo = [(tree, id(tree))]  # type: list[tuple[ast.AST, int]]
    while todo:  # not recursion: a long ``'a' + 'b' + ...`` nests as deep as it is long
        node, scope = todo.pop()
        for child in ast.iter_child_nodes(node):
            scope_of[id(child)] = scope
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                parent[id(child)] = scope
                todo.append((child, id(child)))
            else:
                todo.append((child, scope))
    return scope_of, parent


@functools.lru_cache(maxsize=None)
def _bindings(tree: 'ast.Module') -> 'dict[tuple[int, str], tuple[ast.AST, ...]]':
    """What each name of each scope of ``tree``, and each ``self.`` attribute, is bound to.

    Keyed by ``(scope, name)``, ``(_SELF, attribute)`` for an attribute of ``self``
    or ``cls``. An assignment binds its target to its value, a ``for`` loop or a
    comprehension its target to what it iterates, and a function's parameter to
    its default and to each argument the module passes it -- every one, since
    which call runs is not known.

    """
    scope_of = _scopes(tree)[0]
    found = {}  # type: dict[tuple[int, str], list[ast.AST]]

    def bind(target: 'ast.AST', value: 'ast.AST') -> None:
        for node in ast.walk(target):
            if isinstance(node, ast.Name):
                found.setdefault((scope_of[id(node)], node.id), []).append(value)
            elif (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
                  and node.value.id in ('self', 'cls')):
                found.setdefault((_SELF, node.attr), []).append(value)

    functions = {}  # type: dict[str, list[tuple[int, ast.arguments]]]
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                bind(target, node.value)
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr)) and node.value is not None:
            bind(node.target, node.value)
        elif isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
            bind(node.target, node.iter)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions.setdefault(node.name, []).append((id(node), node.args))
            for arg, default in zip(reversed(node.args.args), reversed(node.args.defaults)):
                found.setdefault((id(node), arg.arg), []).append(default)
    for call in ast.walk(tree):
        if not isinstance(call, ast.Call):
            continue
        for scope, arguments in functions.get(_called(call) or '', ()):
            params = [arg.arg for arg in arguments.posonlyargs + arguments.args]
            if params[:1] in (['self'], ['cls']) and isinstance(call.func, ast.Attribute):
                params = params[1:]
            for param, value in zip(params, call.args):
                found.setdefault((scope, param), []).append(value)
            if arguments.vararg is not None:
                found.setdefault((scope, arguments.vararg.arg), []).extend(call.args[len(params):])
            for keyword in call.keywords:
                if keyword.arg is not None:
                    found.setdefault((scope, keyword.arg), []).append(keyword.value)
    return {key: tuple(values) for key, values in found.items()}


def _bound_values(tree: 'ast.Module', node: 'ast.AST') -> 'tuple[ast.AST, ...]':
    """What the name or ``self.`` attribute ``node`` may hold, from its own scope outwards."""
    bindings = _bindings(tree)
    if isinstance(node, ast.Attribute):
        return bindings.get((_SELF, node.attr), ())
    assert isinstance(node, ast.Name)
    scope_of, parent = _scopes(tree)
    scope = scope_of.get(id(node), id(tree))
    while True:
        values = bindings.get((scope, node.id))
        if values is not None or scope == id(tree):
            return values or ()
        scope = parent[scope]


def _imported_from(tree: 'ast.Module', path: 'pathlib.Path', name: 'str') -> 'Optional[tuple[pathlib.Path, str]]':
    """Where ``tree`` imports ``name`` from, as the module's file and the name there."""
    for node in tree.body:
        if isinstance(node, ast.ImportFrom):
            for module, taken in _imports(node, path):
                found = _module_file(module)
                if found is not None and taken is not None:
                    for alias in node.names:
                        if (alias.asname or alias.name) == name and alias.name in taken:
                            return found, alias.name
    return None


def _flowing_strings(expressions: 'list[ast.AST]', path: 'pathlib.Path') -> 'tuple[set[str], bool]':
    """The strings that may flow into ``expressions``, and whether a ``.py`` name is computed.

    Followed through :func:`_bindings`, and through a name imported from another
    repository module to its bindings there.

    """
    strings = set()  # type: set[str]
    seen = set()  # type: set[tuple[pathlib.Path, int]]
    origins = set()  # type: set[tuple[pathlib.Path, str]]
    todo = [(expression, path) for expression in expressions]
    while todo:
        node, where = todo.pop()
        if (where, id(node)) in seen:
            continue
        seen.add((where, id(node)))
        if isinstance(node, ast.Constant):
            if isinstance(node.value, str):
                strings.add(node.value)
        elif isinstance(node, ast.JoinedStr):
            for before, after in zip(node.values, node.values[1:]):
                # ``f'{name}.py'``: a file whose name is computed.
                if (isinstance(before, ast.FormattedValue) and isinstance(after, ast.Constant)
                        and str(after.value).startswith('.py')):
                    return strings, True
            todo.extend((value, where) for value in node.values)
        elif isinstance(node, (ast.Name, ast.Attribute)):
            if isinstance(node, ast.Attribute):
                todo.append((node.value, where))
                if not (isinstance(node.value, ast.Name) and node.value.id in ('self', 'cls')):
                    continue  # ``sys.executable``: nothing this module binds
            tree = _parse_module(where)
            if tree is None:
                continue
            values = _bound_values(tree, node)
            todo.extend((value, where) for value in values)
            origin = _imported_from(tree, where, node.id) if isinstance(node, ast.Name) and not values else None
            if origin is not None and origin not in origins:
                origins.add(origin)
                todo.append((ast.Name(id=origin[1], ctx=ast.Load()), origin[0]))
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            # ``ROOT / 'util' / 'ci_timing.py'`` names ``util/ci_timing.py``, not ``util``.
            parts = []  # type: list[ast.expr]
            while isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
                parts.append(node.right)
                node = node.left
            parts.append(node)
            joined = []  # type: list[str]
            for part in reversed([None] + parts):  # type: ignore[list-item]
                if isinstance(part, ast.Constant) and isinstance(part.value, str):
                    joined.append(part.value)
                    continue
                if joined:
                    strings.add('/'.join(joined))
                    joined = []
                if part is not None:
                    todo.append((part, where))
        elif isinstance(node, ast.Call):
            todo.extend((arg, where) for arg in node.args)
            todo.extend((keyword.value, where) for keyword in node.keywords)
            if isinstance(node.func, ast.Attribute):
                todo.append((node.func.value, where))
        elif not isinstance(node, (ast.Lambda, ast.FunctionDef, ast.AsyncFunctionDef)):
            todo.extend((child, where) for child in ast.iter_child_nodes(node))
    return strings, False


def _attributes_used(tree: 'ast.Module', name: 'str') -> 'Optional[frozenset[str]]':
    """The attributes ``tree`` reads off the module it binds to ``name``, or :data:`None`
    when it uses that module some other way, e.g. passes it on."""
    return _name_uses(tree).get(name, frozenset())


@functools.lru_cache(maxsize=None)
def _name_uses(tree: 'ast.Module') -> 'dict[str, Optional[frozenset[str]]]':
    """For each name ``tree`` reads, the attributes it reads off it, :data:`None` once it is
    used bare."""
    values = {id(node.value) for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
    used = {}  # type: dict[str, Optional[set[str]]]
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            found = used.setdefault(node.value.id, set())
            if found is not None:
                found.add(node.attr)
        elif isinstance(node, ast.Name) and id(node) not in values:
            used[node.id] = None
    return {name: None if attrs is None else frozenset(attrs) for name, attrs in used.items()}


def _imports(node: 'ast.AST', path: 'pathlib.Path',
             tree: 'Optional[ast.Module]' = None) -> 'list[tuple[str, Optional[frozenset[str]]]]':
    """The modules an ``import`` statement runs, and the names it takes from each.

    A module bound to a name of its own -- ``from tests.project import
    test_release_gates as gates`` -- gives the attributes ``tree`` reads off it.

    """
    if isinstance(node, ast.Import):
        return [(alias.name, _attributes_used(tree, alias.asname) if tree is not None and alias.asname else None)
                for alias in node.names]
    assert isinstance(node, ast.ImportFrom)
    module = node.module or ''
    if node.level:
        try:
            package = path.parent.relative_to(ROOT).parts
        except ValueError:  # a module outside the repository, as a test writes one
            package = ()
        package = package[:len(package) - node.level + 1]
        module = '.'.join(package + ((module,) if module else ()))
    found = []  # type: list[tuple[str, Optional[frozenset[str]]]]
    names = set()  # type: set[str]
    for alias in node.names:
        # ``from tests.project import test_release_gates`` imports a module, not a name.
        if alias.name != '*' and _module_file(f'{module}.{alias.name}') is not None:
            taken = _attributes_used(tree, alias.asname or alias.name) if tree is not None else None
            found.append((f'{module}.{alias.name}', taken))
        else:
            names.add(alias.name)
    if names:
        found.append((module, None if '*' in names else frozenset(names)))
    return found


@functools.lru_cache(maxsize=None)
def _region_reach(path: 'pathlib.Path', names: 'Optional[frozenset[str]]') -> 'tuple[bool, frozenset[_Region]]':
    """Whether the region of ``path`` that ``names`` runs varies by interpreter itself,
    and the regions of other repository files it runs.

    By the AST alone, and erring towards "varies": an unparsable file does, and so
    does an import whose target is computed, or a file run whose name is. A
    comparison counts in what the region defines, not in what merely runs on
    import: a ``skipIf`` on a class nothing asked for decides nothing here.

    """
    tree = _parse_module(path)
    if tree is None:
        return True, frozenset()
    modules = []  # type: list[tuple[str, Optional[frozenset[str]]]]
    files = set()  # type: set[pathlib.Path]
    on_import, definitions = _executed_nodes(tree, names)
    for root in on_import + definitions:
        for node in ast.walk(root):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                modules.extend(_imports(node, path, tree))
            elif isinstance(node, ast.Call) and _called(node) in _IMPORTING_CALLS:
                target = node.args[0] if node.args else None
                if isinstance(target, ast.Constant) and isinstance(target.value, str):
                    modules.append((target.value, None))
                elif _called(node) in _COMPUTED_IMPORTS:
                    return True, frozenset()
            elif isinstance(node, ast.Call) and _called(node) in _RUNNING_CALLS:
                strings, computed = _flowing_strings(list(node.args) + [keyword.value for keyword in node.keywords],
                                                     path)
                if computed or any(_IMPORT_TEXT.search(text) for text in strings):
                    return True, frozenset()
                for text in strings:
                    if _DOTTED_NAME.match(text) and _module_file(text) is not None:
                        modules.append((text, None))
                    elif _PATH_TEXT.match(text):
                        files.update(_paths_named(text))
            elif _compares_interpreter(node) and root in definitions:
                return True, frozenset()
            elif isinstance(node, (ast.List, ast.Tuple)):
                # ``[sys.executable, '-m', 'pcapkit']``
                values = [element.value if isinstance(element, ast.Constant) else None for element in node.elts]
                if any(first == '-m' and isinstance(second, str) and _is_package(second)
                       for first, second in zip(values, values[1:])):
                    return True, frozenset()

    regions = {(file, None) for file in files}  # type: set[_Region]
    for module, taken in modules:
        if _is_package(module):
            return True, frozenset()
        found = _module_file(module)
        if found is not None:
            regions.add((found, taken))
    regions.discard((path, names))
    return False, frozenset(regions)


@functools.lru_cache(maxsize=None)
def varies_by_interpreter(path: 'pathlib.Path | str') -> 'bool':
    """Whether running the module at ``path`` may give another answer on another interpreter (#1954).

    By the AST of the module and of the repository code it runs. It may when any
    of that imports :data:`PROJECT_PIN_PACKAGE` -- an ``import`` at any depth;
    :func:`importlib.import_module`, :func:`__import__`, :func:`unittest.mock.patch`
    or :func:`importlib.util.find_spec` naming it; a child interpreter's ``import
    pcapkit`` or ``-m pcapkit`` -- or compares ``sys.version_info``,
    ``sys.implementation`` or the like. The module runs whole, and so does a module
    it imports as an object, unless it only reads attributes off it, which run as
    names taken from it do: the module's imports and the calls it makes on import,
    and the definitions of those names. A file or directory runs whole when a
    string naming it flows into a call that runs one, e.g.
    ``spec_from_file_location`` or ``subprocess.run``: a ``util/`` script, a
    generator, :file:`docs/source/conf.py`, a test directory a child ``pytest``
    collects. A computed import, a computed ``.py`` name, or a file that cannot be
    parsed counts as importing the package.

    Args:
        path: Path to a module, absolute or relative to :data:`ROOT`.

    """
    start = pathlib.Path(path)
    if not start.is_absolute():
        start = ROOT / start
    seen = set()  # type: set[_Region]
    todo = [(start.resolve(), None)]  # type: list[_Region]
    while todo:
        region = todo.pop()
        if region in seen:
            continue
        seen.add(region)
        reaches, regions = _region_reach(*region)
        if reaches:
            return True
        todo.extend(regions - seen)
    return False


def is_probe_module(path: 'pathlib.Path | str') -> 'bool':
    """Whether ``path`` is the reserved probe module, :data:`PROBE_MODULE_NAME` in :file:`tests/protocols/`.

    Never a suite module, though it is a ``test_*.py`` file while it exists:
    :mod:`tests.conftest`'s ``collect_ignore`` keeps it out of every recursive
    collection, and :func:`suite_modules` leaves it out.

    Args:
        path: Path to a module, absolute or relative to :data:`ROOT`.

    """
    candidate = pathlib.Path(path)
    if not candidate.is_absolute():
        candidate = ROOT / candidate
    return candidate == TESTS_ROOT / 'protocols' / PROBE_MODULE_NAME


def suite_modules() -> 'tuple[str, ...]':
    """Every test module under :file:`tests/`, relative to :data:`ROOT`, sorted.

    What pytest collects and :file:`util/run_unittest_leg.py` discovers: the
    ``test_*.py`` files, ``python_files`` in :file:`pyproject.toml`, less the
    :func:`probe module <is_probe_module>`, which pytest never collects either.

    """
    # The probe comes and goes under another worker's feet, and the tier lock
    # that serialises it is a no-op off POSIX: listed, it fails module_tier()
    # once it has gone (#2114).
    return tuple(sorted(path.relative_to(ROOT).as_posix() for path in TESTS_ROOT.rglob('test_*.py')
                        if '__pycache__' not in path.parts and not is_probe_module(path)))


def _test_module(path: 'pathlib.Path | str') -> 'pathlib.Path':
    """``path`` resolved, once it is known to be a test module under :file:`tests/`."""
    candidate = pathlib.Path(path)
    if not candidate.is_absolute():
        candidate = ROOT / candidate
    candidate = candidate.resolve()
    try:
        candidate.relative_to(TESTS_ROOT)
    except ValueError:
        raise ValueError(f'{path} is not under {TESTS_ROOT}, so it has no test tier') from None
    if not (candidate.name.startswith('test_') and candidate.suffix == '.py' and candidate.is_file()):
        raise ValueError(f'{path} is not a test module (tests/**/test_*.py), so it has no test tier')
    return candidate


@functools.lru_cache(maxsize=None)
def _declared_tier(candidate: 'pathlib.Path') -> 'Optional[str]':
    tree = _parse_module(candidate)
    if tree is None:
        return None
    where = _display_path(candidate)
    top = [node for node in tree.body
           if (isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == TIER_MARKER
                                                    for target in node.targets))
           or (isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
               and node.target.id == TIER_MARKER)]
    stores = [node for node in ast.walk(tree)
              if isinstance(node, ast.Name) and node.id == TIER_MARKER and isinstance(node.ctx, ast.Store)]
    if len(stores) != len(top) or len(top) > 1:
        raise InvalidTierError(
            f'{where} assigns {TIER_MARKER} {len(stores)} times, {len(top)} of them at module level; '
            f'state the tier once, as a module-level {TIER_MARKER} = {TIER_LATEST!r} or {TIER_ALL!r}'
        )
    if not top:
        return None
    value = top[0].value
    if not (isinstance(value, ast.Constant) and isinstance(value.value, str) and value.value in TIERS):
        shown = (ast.get_source_segment(candidate.read_text(encoding='utf-8'), value) or ast.dump(value)
                 if value is not None else 'nothing')
        raise InvalidTierError(
            f'{where}:{top[0].lineno}: {TIER_MARKER} is set to {shown}, which is not a test tier; '
            f'it must be one of the string literals {", ".join(map(repr, TIERS))}'
        )
    return value.value


def declared_tier(path: 'pathlib.Path | str') -> 'Optional[str]':
    """The test tier the module at ``path`` states with :data:`TIER_MARKER`, if it does.

    Read by AST, never by importing the module: one module-level statement,
    ``__tier__ = 'ALL'`` or ``__tier__ = 'LATEST'``, the value a string literal.
    A module that does not parse states nothing here, and :data:`DEFAULT_TIER`
    answers for it.

    Args:
        path: Path to a test module, absolute or relative to :data:`ROOT`.

    Raises:
        ValueError: ``path`` is not a test module under :file:`tests/`.
        InvalidTierError: The marker is not one of :data:`TIERS`, not a string
            literal, assigned more than once, or assigned anywhere but at the
            module's top level.

    """
    return _declared_tier(_test_module(path))


#: Attributes of :mod:`sys` whose mere use asks which build is running, compared or not:
#: ``sys.flags.context_aware_warnings``, ``sys._is_gil_enabled()``.
_BUILD_FACTS = frozenset({'flags', '_is_gil_enabled'})
#: Builtins that probe :mod:`sys` for an attribute, e.g. ``hasattr(sys, 'tracebacklimit')``.
_PROBES = frozenset({'hasattr', 'getattr'})


def _probes_interpreter(node: 'ast.AST') -> 'bool':
    """Whether ``node`` asks the running interpreter something outside a comparison.

    ``sys.flags`` or ``sys._is_gil_enabled``, a comparison with ``sys.maxsize``, a
    ``sysconfig.get_config_var()`` call such as ``Py_GIL_DISABLED``'s, or a
    ``hasattr``/``getattr`` probe of :mod:`sys`.

    """
    if isinstance(node, ast.Attribute):
        return node.attr in _BUILD_FACTS and isinstance(node.value, ast.Name) and node.value.id == 'sys'
    if isinstance(node, ast.Compare):
        return any(isinstance(part, ast.Attribute) and part.attr == 'maxsize' and isinstance(part.value, ast.Name)
                   and part.value.id == 'sys' for operand in [node.left] + list(node.comparators)
                   for part in ast.walk(operand))
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Attribute) and func.attr == 'get_config_var':
        return isinstance(func.value, ast.Name) and func.value.id == 'sysconfig'
    if isinstance(func, ast.Name) and func.id == 'get_config_var':
        return True
    return (isinstance(func, ast.Name) and func.id in _PROBES and bool(node.args)
            and isinstance(node.args[0], ast.Name) and node.args[0].id == 'sys')


def branches_on_interpreter(path: 'pathlib.Path | str') -> 'bool':
    """Whether the test module at ``path`` itself asks which interpreter is running (#1958).

    By its own AST alone, unlike :func:`varies_by_interpreter`, which follows what
    the module runs: a comparison of ``sys.version_info``, ``sys.implementation``,
    ``platform.python_version()`` or the like; a use of ``sys.flags`` or
    ``sys._is_gil_enabled``; a comparison with ``sys.maxsize``; a
    ``sysconfig.get_config_var()`` call, such as
    ``Py_GIL_DISABLED``'s; or a ``hasattr``/``getattr`` probe of :mod:`sys`, anywhere
    in it. Such a module has to state its tier with :data:`TIER_MARKER`, so a
    version gate never runs on ``latest`` alone just because nobody opted it in to
    ``ALL``. A module that does not parse branches on nothing here.

    The detection is syntactic and best-effort, not proof that a module is
    interpreter-independent: it does not see :mod:`sys` under an alias, a probe of
    any other module, a flag imported from :mod:`pcapkit.utilities.compat` or
    another helper, or a gate in code the module imports. A module that relies on
    any of those states its tier by hand.

    Args:
        path: Path to a test module, absolute or relative to :data:`ROOT`.

    Raises:
        ValueError: ``path`` is not a test module under :file:`tests/`.

    """
    tree = _parse_module(_test_module(path))
    return tree is not None and any(_compares_interpreter(node) or _probes_interpreter(node)
                                    for node in ast.walk(tree))


def module_tier(path: 'pathlib.Path | str') -> 'str':
    """The test tier of the module at ``path``: :data:`TIER_ALL` or :data:`TIER_LATEST` (#1958).

    Its :func:`declared_tier` where it states one, :data:`DEFAULT_TIER` otherwise,
    so every test module has exactly one and ``ALL`` is opt-in: see "The curated
    ``ALL`` tier" in this module's docstring for which modules opt in. ``ALL``
    modules run on every leg; ``LATEST`` ones on ``latest`` alone, which is also
    the coverage leg, the ``gate`` job's interpreter, and every
    ``unittest-ordering`` cell's. Within a tier, the unit and fixture-dependent
    tiers still decide which job collects a module.

    Args:
        path: Path to a test module, absolute or relative to :data:`ROOT`.

    Raises:
        ValueError: ``path`` is not a test module under :file:`tests/`.
        InvalidTierError: Its marker is malformed; see :func:`declared_tier`.

    """
    return _declared_tier(_test_module(path)) or DEFAULT_TIER


@functools.lru_cache(maxsize=1)
def all_tier_paths() -> 'tuple[str, ...]':
    """Every :data:`TIER_ALL` test module, relative to :data:`ROOT`, sorted.

    The curated tier every leg runs: the complement of :func:`latest_tier_paths`
    within :func:`suite_modules`, and each of them marked ``__tier__ = 'ALL'``.

    """
    return tuple(path for path in suite_modules() if module_tier(path) == TIER_ALL)


@functools.lru_cache(maxsize=1)
def latest_tier_paths() -> 'tuple[str, ...]':
    """Every :data:`TIER_LATEST` test module, relative to :data:`ROOT`, sorted.

    What :data:`LATEST_TIER_SELECTOR` prints: the modules every leg but ``latest``
    passes as an ``--ignore``. Unit-tier and fixture-dependent modules alike; the
    unit tier's own flags ignore the latter already, and :func:`fixture_tier_paths`
    leaves them out of its ``ALL`` selection.

    """
    return tuple(path for path in suite_modules() if module_tier(path) == TIER_LATEST)


def is_project_pin(path: 'pathlib.Path | str') -> 'bool':
    """Whether ``path`` names a project pin, which runs once per push (#1954).

    A project pin is a unit-tier test module under
    :file:`tests/`:data:`PROJECT_PINS_DIR` whose run does not
    :func:`vary by interpreter <varies_by_interpreter>`: it reads the repository's
    text or drives a ``util/`` script, so the ``project-tests`` job runs it once, on
    ``latest``. Every pin is in the :data:`TIER_LATEST` test tier (#1958): a module
    that marks itself :data:`TIER_ALL` is no pin, and one that marks itself
    ``LATEST`` while it imports ``pcapkit`` is no pin either, and runs on the
    ``latest`` leg of ``test``, under coverage.

    Args:
        path: Path to a module, absolute or relative to :data:`ROOT`.

    """
    candidate = pathlib.Path(path)
    if not candidate.is_absolute():
        candidate = ROOT / candidate
    candidate = candidate.resolve()
    try:
        relative = candidate.relative_to(TESTS_ROOT / PROJECT_PINS_DIR)
    except ValueError:
        return False
    return (relative.name.startswith('test_') and relative.suffix == '.py' and candidate.is_file()
            and is_unit_tier(candidate) and not varies_by_interpreter(candidate)
            and module_tier(candidate) == TIER_LATEST)


@functools.lru_cache(maxsize=1)
def project_pin_paths() -> 'tuple[str, ...]':
    """Every :func:`project pin <is_project_pin>`, relative to :data:`ROOT`, sorted.

    What :data:`PROJECT_PINS_SELECTOR` prints: the ``project-tests`` job's
    selection, and the ``--ignore`` list of the ``latest`` leg of ``test``. Each is
    in :func:`latest_tier_paths` too, which every other leg leaves out.

    """
    return tuple(sorted(path.relative_to(ROOT).as_posix()
                        for path in (TESTS_ROOT / PROJECT_PINS_DIR).rglob('test_*.py')
                        if is_project_pin(path)))


def _git(*args: 'str') -> 'Optional[str]':
    """Run :program:`git` in :data:`ROOT` and return its standard output.

    Returns:
        The output as text, or :data:`None` if git could not answer -- no
        executable on :envvar:`PATH`, no repository, a non-zero exit, or a
        hung invocation. Every one of those is a "cannot tell", never a
        "not committed": guessing the other way would fail a source tarball's
        test run for a rule it cannot possibly break.

    """
    try:
        completed = subprocess.run(
            ('git', *args), cwd=str(ROOT), stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=30, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.decode('utf-8', 'surrogateescape')


@functools.lru_cache(maxsize=1)
def _git_state() -> 'tuple[Optional[frozenset[str]], Optional[str]]':
    """The set of git-tracked capture names, or why it could not be determined.

    Cached for the process: one :program:`git` invocation for a whole test run,
    however many call sites ask.

    Returns:
        ``(names, None)`` on success, where ``names`` holds each tracked path
        under :data:`SAMPLE_ROOT` relative to it, or ``(None, reason)``.

    """
    toplevel = _git('rev-parse', '--show-toplevel')
    if toplevel is None:
        return None, (
            f'git could not be run in {ROOT} -- either the executable is missing or this is '
            f'not a checkout, e.g. an unpacked source tarball'
        )

    # Guard against answering from the wrong repository: a tarball unpacked
    # inside some other checkout would otherwise get that repository's index,
    # which knows nothing about these captures and would call every one of them
    # generated. A git worktree reports its own root here, so worktrees are fine.
    resolved = pathlib.Path(toplevel.strip()).resolve()
    if resolved != ROOT:
        return None, (
            f'git reports its work tree as {resolved}, not {ROOT}, so its answers are about '
            f'some other repository'
        )

    relative_root = SAMPLE_ROOT.relative_to(ROOT).as_posix()
    # -z rather than the default: without it git quotes and escapes paths that
    # hold unusual bytes, and the names would have to be unquoted again.
    listing = _git('ls-files', '-z', '--', relative_root)
    if listing is None:
        return None, f'`git ls-files` failed for {relative_root}'

    prefix = relative_root + '/'
    names = {
        entry[len(prefix):] for entry in listing.split('\0')
        if entry and entry.startswith(prefix)
    }
    return frozenset(names), None


def committed_captures() -> 'Optional[frozenset[str]]':
    """Names of the captures git tracks, relative to :data:`SAMPLE_ROOT`.

    Returns:
        The tracked names, or :data:`None` when git could not be asked -- see
        :func:`guard_unavailable_reason`.

    """
    return _git_state()[0]


def guard_unavailable_reason() -> 'Optional[str]':
    """Why the guard cannot run, in one sentence, or :data:`None` when it can."""
    return _git_state()[1]


def committed_capture_names() -> 'tuple[str, ...]':
    """Tracked captures worth suggesting as a replacement, sorted.

    Filtered to :data:`CAPTURE_SUFFIXES` so the suggestion in :func:`explain`
    offers captures rather than the committed reference outputs that live in the
    same directory.

    """
    tracked = committed_captures() or frozenset()
    return tuple(sorted(name for name in tracked if name.endswith(CAPTURE_SUFFIXES)))


def _normalize(name: 'str') -> 'str':
    """A capture name as git spells it, i.e. relative and slash-separated."""
    return pathlib.PurePath(name).as_posix()


def _is_committed(name: 'str', tracked: 'frozenset[str]') -> 'bool':
    return _normalize(name) in tracked


def _exception_name(node: 'ast.expr') -> 'Optional[str]':
    """The bare name of an exception spelled in an ``except`` clause."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _handles_missing_file(handler: 'ast.ExceptHandler') -> 'bool':
    """Whether ``handler`` would catch a missing capture."""
    if handler.type is None:  # a bare `except:` catches everything
        return True
    clauses = handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
    return any(_exception_name(clause) in HANDLES_MISSING_FILE for clause in clauses)


def _parse(module_path: 'str') -> 'Optional[ast.Module]':
    """Parse a module, or return :data:`None` if it cannot be read or parsed.

    An unreadable or unparseable module is not this guard's problem -- pytest
    will report the syntax error far better than a warning from here would.

    """
    try:
        source = pathlib.Path(module_path).read_text(encoding='utf-8')
    except (OSError, UnicodeDecodeError):
        return None
    # Cheap gate before the parse: nearly every module in the suite never
    # mentions sample_path, and parsing them all would be work for nothing.
    if 'sample_path' not in source:
        return None
    try:
        return ast.parse(source, filename=module_path)
    except (SyntaxError, ValueError):
        return None


@functools.lru_cache(maxsize=None)
def handled_lines(module_path: 'str') -> 'frozenset[int]':
    """Lines of ``module_path`` on which a missing capture would be handled.

    Every line in the *body* of a ``try`` whose handlers catch a missing file --
    ``else`` and ``finally`` are excluded, since a failure there is not caught.
    Whole line ranges rather than the statement's first line, because the runtime
    check matches a frame's ``f_lineno`` against this set and the two need not
    agree on which line of a multi-line call the call "is" on.

    """
    tree = _parse(module_path)
    if tree is None:
        return frozenset()

    lines = set()  # type: set[int]
    for node in ast.walk(tree):
        if not isinstance(node, _TRY_NODES):
            continue
        if not any(_handles_missing_file(handler) for handler in node.handlers):
            continue
        for statement in node.body:
            end = getattr(statement, 'end_lineno', None) or statement.lineno
            lines.update(range(statement.lineno, end + 1))
    return frozenset(lines)


def _literal_name(call: 'ast.Call') -> 'Optional[str]':
    """The capture name a ``sample_path(...)`` call asks for, if it is a literal."""
    if call.args:
        first = call.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            return first.value
        return None  # computed, or *args
    for keyword in call.keywords:
        if keyword.arg == 'name' and isinstance(keyword.value, ast.Constant):
            if isinstance(keyword.value.value, str):
                return keyword.value.value
    return None


def _is_sample_path(func: 'ast.expr') -> 'bool':
    """Whether ``func`` names :func:`tests._support.sample_path`.

    Matched on the attribute name alone, so ``sample_path(...)`` and
    ``_support.sample_path(...)`` both count. Nothing else in the suite is
    called ``sample_path``, and a false positive here only means a capture name
    is checked against git that did not need to be.

    """
    if isinstance(func, ast.Name):
        return func.id == 'sample_path'
    if isinstance(func, ast.Attribute):
        return func.attr == 'sample_path'
    return False


@functools.lru_cache(maxsize=None)
def sample_path_calls(module_path: 'str') -> 'tuple[SampleCall, ...]':
    """Every ``sample_path(...)`` call in ``module_path``, in source order.

    Source order -- ascending ``(lineno, col_offset)`` -- is a promise that has
    to be kept by sorting, because :func:`ast.walk` does not give it. It walks
    breadth-first, so it yields a call written near the top of the file but nested
    inside a method *after* one written at the bottom at module level. Measured on
    the four-call module that
    ``test_calls_and_findings_come_out_in_source_order`` in
    :file:`tests/test_tier_guard.py` builds for the purpose: an unsorted walk
    reported its calls as lines 14, 11, 7, 7, i.e. the file read backwards.

    That matters because :func:`audit_module` emits one finding per call in this
    order, and this guard's entire value is a diagnostic the reader can act on.
    Breadth-first order is not the order anything appears in the file, and it
    shifts when unrelated code moves between nesting levels -- so the same set of
    violations gets listed differently from one edit to the next, and a reader
    comparing two runs cannot tell a reordering from a new finding.

    Sorted rather than collected by a lexical-order visitor, because the sort is
    the whole fix in one expression and needs nothing kept in step with it: a
    second traversal written by hand is another thing that can disagree with
    :func:`ast.walk` about where calls live.

    ``col_offset`` is the other half of the key, and which AST shapes actually need
    it is the reusable fact. A tuple does not: :class:`ast.Tuple` holds its
    elements in one field list, so ``(sample_path('a.pcap'),
    sample_path('b.pcap'))`` already comes out of the walk left to right and
    ``lineno`` alone would do. Two shapes do need it, because they spread one
    line's expressions across separate fields that the walk visits in an order
    source does not use: :class:`ast.Dict`, whose ``keys`` are all visited before
    any of its ``values``, and :class:`ast.IfExp`, which stores
    ``test, body, orelse`` but is written ``body if test else orelse``. So
    ``sample_path('a.pcap') if sample_path('b.pcap') else None`` is walked b then
    a, and sorting on ``lineno`` alone keeps it that way -- the sort is stable, so
    a tie is left in walk order. That is the shape
    ``test_calls_and_findings_come_out_in_source_order`` puts on one line, which is
    what makes dropping ``col_offset`` turn that test red.

    """
    tree = _parse(module_path)
    if tree is None:
        return ()

    handled = handled_lines(module_path)
    calls = sorted(
        (node for node in ast.walk(tree)
         if isinstance(node, ast.Call) and _is_sample_path(node.func)),
        key=lambda node: (node.lineno, node.col_offset),
    )
    return tuple(
        SampleCall(node.lineno, _literal_name(node), node.lineno in handled)
        for node in calls
    )


def _display_path(module_path: 'pathlib.Path | str') -> 'str':
    """``module_path`` relative to the repository root, when it is inside it."""
    path = pathlib.Path(module_path)
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return str(path)


def explain(name: 'str', module_path: 'pathlib.Path | str',
            lineno: 'Optional[int]' = None) -> 'str':
    """The message a caught tier violation reports.

    Long on purpose. The mistake it describes is not obvious from its symptom --
    a file that is missing on one machine and present on another -- so the
    message has to say what kind of file it is, why the tier it was read from
    may not have it, and what the two real ways out are. A message the reader
    has to research is the failure this guard exists to replace.

    Args:
        name: Capture the call asked for.
        module_path: Module the call was made from.
        lineno: Line of the call, when known.

    Returns:
        A multi-line, self-contained explanation.

    """
    location = _display_path(module_path)
    if lineno is not None:
        location = f'{location}:{lineno}'

    committed = committed_capture_names()
    suggestion = ', '.join(committed) if committed else 'no capture at all, currently'

    return (
        f'{location} is a unit-tier test module and reads {name!r}, which is a generated '
        f'fixture.\n'
        f'\n'
        f'git does not track examples/captures/{name} -- it is one of the fixtures '
        f'{REGENERATE_SAMPLES_CMD!r} (equivalently `make samples`) writes on demand, and a '
        f'fresh clone does not have it.\n'
        f'\n'
        f"The unit tier has to pass on a fresh clone with nothing but `pip install -e "
        f"'.[test]'`, so it must not depend on a generated fixture. CI runs it as\n"
        f'\n'
        f'    {UNIT_TIER_SELECTION}\n'
        f'\n'
        f'on a checkout where examples/captures/ holds only the committed files, so this read '
        f'fails there even when it passes on a machine that has run `make samples`.\n'
        f'\n'
        f'Two ways to fix it:\n'
        f'  1. read a committed capture instead -- git tracks {suggestion}; or\n'
        f'  2. move the test into a fixture-dependent tier, which is allowed to read '
        f'generated captures: rename the module to *_runtime.py (or *_regression.py), or put '
        f'it under tests/integration/. Both run only after the fixtures have been built.\n'
        f'\n'
        f'If the test really wants a generated capture and is happy to be skipped without '
        f'one, handle the absence at the call site, the way {SKIP_IDIOM_EXAMPLE} does:\n'
        f'\n'
        f'    try:\n'
        f'        path = sample_path({name!r})\n'
        f'    except FileNotFoundError as exc:\n'
        f'        self.skipTest(str(exc))\n'
    )


def audit_module(module_path: 'pathlib.Path | str') -> 'list[str]':
    """Tier violations in ``module_path``, one explanation each.

    A static pass, so it sees a violation in a test that never runs -- one
    skipped for a missing optional engine, say -- and it does not care whether
    the fixtures are on disk. That is what makes it fire on the developer's
    machine rather than only on CI, which is the whole point.

    Only calls whose capture name is a string literal can be checked here;
    ``sample_path(sample)`` in a parametrised loop is invisible to a static
    pass, and :func:`check_unit_tier_read` catches those at call time instead.

    The caller decides tier membership -- this function audits whatever it is
    handed, so a module can be audited by name in a test without having to be
    in the unit tier itself.

    Args:
        module_path: Module to audit.

    Returns:
        One :func:`explain` message per violation, empty when there are none or
        when git could not be asked.

    """
    tracked = committed_captures()
    if tracked is None:
        return []

    return [
        explain(call.name, module_path, call.lineno)
        for call in sample_path_calls(str(module_path))
        if call.name is not None and not call.handled and not _is_committed(call.name, tracked)
    ]


def check_unit_tier_read(name: 'str', module_path: 'Optional[str]',
                         lineno: 'Optional[int]' = None) -> 'Optional[str]':
    """Whether a :func:`~tests._support.sample_path` call may go ahead.

    The runtime half of the guard, and deliberately independent of whether the
    capture is on disk: a unit-tier module reading a generated capture is a tier
    violation on the developer's machine exactly as much as on a fresh CI
    checkout, and a guard that only fires when the file is missing is the same
    late failure it is meant to replace.

    Unlike :func:`audit_module` this sees the capture name however it was
    computed, which is what covers ``sample_path(sample)`` in a loop.

    Args:
        name: Capture the call asked for.
        module_path: ``__file__`` of the calling module, or :data:`None` when it
            could not be determined -- in which case the call is allowed, since
            tier membership is unknowable.
        lineno: Line the call was made from, used both to locate the call in the
            message and to spot the ``try``/``except FileNotFoundError`` idiom
            that opts a call out.

    Returns:
        :data:`None` when the read is fine, otherwise the :func:`explain`
        message for it.

    """
    if module_path is None or not is_unit_tier(module_path):
        return None

    tracked = committed_captures()
    if tracked is None or _is_committed(name, tracked):
        return None

    # A call that handles the capture being absent is tier-safe by construction:
    # it degrades to a skip on a fresh clone instead of failing. Leave it alone,
    # including on a machine that has the fixtures, so the read keeps its
    # coverage there.
    if lineno is not None and lineno in handled_lines(module_path):
        return None

    return explain(name, module_path, lineno)


@functools.lru_cache(maxsize=1)
def skip_idiom_modules() -> 'tuple[pathlib.Path, ...]':
    """Unit-tier modules that skip rather than read, when a capture is absent.

    A unit-tier module is allowed to read a generated capture provided it
    handles the capture's absence at the call site -- the sanctioned
    ``try``/``except FileNotFoundError`` idiom :data:`SKIP_IDIOM_EXAMPLE`
    demonstrates. On the ``test`` job, which never runs
    :data:`REGENERATE_SAMPLES_CMD`, such a call always finds the capture
    missing and the test skips; :func:`~tests._support.sample_path` raises a
    bare :exc:`FileNotFoundError` rather than
    :exc:`GeneratedFixtureInUnitTierError` for exactly this reason. So the
    call's *real* body -- the assertions that run once the capture is actually
    read -- is only ever exercised on a run that has built the fixtures
    first, i.e. the fixture-dependent tier.

    That makes this function's result the missing half of the fixture
    tier's selection: :data:`FIXTURE_TIER_DIRS` and
    :data:`FIXTURE_TIER_SUFFIXES` name the modules that are fixture-dependent
    *in their entirety*, but these modules are unit-tier by every other
    measure and would never be selected by that rule alone. Leaving them out
    of the fixture tier's selection would mean their skip-idiom reads are
    exercised nowhere at all once the unit and fixture tiers stop overlapping.
    See :func:`fixture_tier_paths`, which folds this in.

    Only literal capture names are seen here, the same limitation
    :func:`audit_module` carries and for the same reason: a name computed at
    call time, e.g. ``sample_path(sample)`` in a parametrised loop, is
    invisible to a static pass. No module in the suite does this inside a
    handled call -- see ``test_every_handled_call_names_a_literal_capture``
    in :file:`tests/test_tier_guard.py`, which exists to catch the day one does,
    since such a call would silently drop out of this function's result and
    its fixture-backed coverage would quietly stop running anywhere.

    Returns:
        Absolute paths, sorted, to every unit-tier module with at least one
        handled read of a capture git does not track. Empty when git cannot
        answer :func:`committed_captures` -- with no committed-capture list to
        compare against, nothing can be told apart from a committed read, and
        claiming otherwise would be a guess.

    """
    tracked = committed_captures()
    if tracked is None:
        return ()

    modules = []
    for path in sorted(TESTS_ROOT.rglob('*.py')):
        if not is_unit_tier(path):
            continue
        for call in sample_path_calls(str(path)):
            if call.handled and call.name is not None and not _is_committed(call.name, tracked):
                modules.append(path)
                break
    return tuple(modules)


def _enclosing_scope(tree: 'ast.Module', lineno: 'int') -> 'Optional[tuple[Optional[str], str]]':
    """The ``(class name or None, function name)`` most tightly wrapping ``lineno``.

    A manual recursive descent rather than :func:`ast.walk`: the answer needs
    the *nesting path* down to a line -- which function, and which class (if
    any) that function is a method of -- and a breadth-first walk does not
    carry that context as it goes. "Most tightly" is decided by span, so a
    helper function defined inside a test method and containing the line in
    question would win over the test method itself; nothing in this suite's
    skip idiom does that, but the rule is stated so a future one is
    handled the same way :func:`sample_path_calls` already treats nesting.

    Returns:
        :data:`None` if no function definition contains ``lineno`` at all --
        a module-level call, which does not happen in this suite.

    """
    best = None  # type: Optional[tuple[Optional[str], str, int]]

    def visit(node: 'ast.AST', class_name: 'Optional[str]') -> None:
        nonlocal best
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                start = child.lineno
                end = getattr(child, 'end_lineno', None) or start
                if start <= lineno <= end:
                    span = end - start
                    if best is None or span < best[2]:
                        best = (class_name, child.name, span)
                visit(child, class_name)
            elif isinstance(child, ast.ClassDef):
                visit(child, child.name)
            else:
                visit(child, class_name)

    visit(tree, None)
    if best is None:
        return None
    return best[0], best[1]


@functools.lru_cache(maxsize=1)
def skip_idiom_test_ids() -> 'tuple[str, ...]':
    """Precise pytest node IDs for every call :func:`skip_idiom_modules` counts.

    :func:`skip_idiom_modules` names the *files* that need to run again in the
    fixture-dependent tier; this names the individual test methods inside
    them. The difference matters because those files are not small --
    :file:`tests/protocols/misc/test_pcapng_unit.py`'s
    ``PCAPNGUnitTests`` alone runs to thousands of lines and dozens of
    unrelated methods -- and pulling in the whole module to reach the one that
    actually needs the fixtures would reintroduce, for just these modules, the
    same duplication :func:`fixture_tier_paths` exists to remove everywhere
    else. Each :class:`unittest.TestCase` method here gets its own ``setUp``,
    with no ``setUpClass`` state shared across siblings in the classes this
    has been checked against, so selecting one by node ID runs it exactly as
    it would run as part of the whole file.

    Falls back to the *module* path when a handled call cannot be resolved to
    one enclosing function -- :func:`_enclosing_scope` returns :data:`None` for
    a module-level call, which is not a shape this suite's skip idiom uses,
    but a fallback that still runs the file is safer than one that
    drops the call's coverage entirely.

    Returns:
        Node IDs (``path/to/module.py::TestClass::test_method``) and/or plain
        module paths, sorted, relative to :data:`ROOT` and POSIX-separated.
        Empty under the same condition as :func:`skip_idiom_modules`.

    """
    tracked = committed_captures()
    if tracked is None:
        return ()

    ids = []
    for path in sorted(TESTS_ROOT.rglob('*.py')):
        if not is_unit_tier(path):
            continue

        relevant = [
            call for call in sample_path_calls(str(path))
            if call.handled and call.name is not None and not _is_committed(call.name, tracked)
        ]
        if not relevant:
            continue

        relative = path.relative_to(ROOT).as_posix()
        tree = _parse(str(path))
        if tree is None:
            # sample_path_calls() above already parsed this module successfully,
            # so this should not happen -- but if it somehow does, run the whole
            # file rather than claim no coverage is needed.
            ids.append(relative)
            continue

        for call in relevant:
            scope = _enclosing_scope(tree, call.lineno)
            if scope is None:
                ids.append(relative)
                continue
            class_name, func_name = scope
            ids.append(f'{relative}::{class_name}::{func_name}' if class_name else f'{relative}::{func_name}')

    return tuple(sorted(set(ids)))


@functools.lru_cache(maxsize=None)
def fixture_tier_paths(tier: 'Optional[str]' = None) -> 'tuple[str, ...]':
    """The complete pytest selection the fixture-dependent tier needs to run.

    Three things go into it:

    * one directory argument per :data:`FIXTURE_TIER_DIRS` entry, e.g.
      ``'tests/integration'``, rather than every file under it individually;
    * every module under :file:`tests/` whose name matches
      :data:`FIXTURE_TIER_SUFFIXES` and is not already reachable through one
      of those directory arguments, found on disk rather than assumed, so a
      new ``*_runtime.py`` module is picked up the moment it is added; and
    * :func:`skip_idiom_test_ids`, without which those calls' fixture-backed
      reads would never run for real anywhere -- see its docstring and
      :func:`skip_idiom_modules`'s.

    The third component is node IDs, not module paths, deliberately: it is
    added by :func:`skip_idiom_test_ids` rather than by
    :func:`skip_idiom_modules` directly, so that pulling in one skip-idiom test
    does not also pull in every unrelated method the same module happens to
    hold. Without that, the skip-idiom modules would add every one of their
    tests back into this selection -- well over a hundred -- to reach the
    handful that actually need it.

    This is deliberately *not* "the complement of :func:`is_unit_tier`"
    expressed as a single predicate the way :func:`is_unit_tier` itself is: the
    third component is not part of the fixture tier by path, only by the
    coverage gap leaving it out would open. Combining them here, once, is what
    lets the ``integration`` job of :file:`.github/workflows/unit-tests.yml`
    ask a single function for its selection instead of re-deriving it -- see
    :data:`FIXTURE_TIER_SELECTOR`.

    With ``tier``, only that test tier's part of it (#1958): ``'ALL'`` is what
    every leg but ``latest`` runs, :data:`FIXTURE_ALL_TIER_SELECTOR`. Each entry
    whose module is in another tier is dropped, and a directory argument holding
    such a module is replaced by its modules of ``tier``, since pytest applies no
    ``--ignore`` to a path it was handed.

    Args:
        tier: One of :data:`TIERS`, or :data:`None` for every tier.

    Returns:
        Paths and/or node IDs relative to :data:`ROOT`, POSIX-separated,
        sorted, and deduplicated -- ready to hand to ``pytest`` as positional
        arguments. Never empty while :data:`FIXTURE_TIER_DIRS` is non-empty:
        the directory arguments do not depend on git, so they are always
        present even when :func:`skip_idiom_test_ids` cannot answer.

    Raises:
        ValueError: ``tier`` is not one of :data:`TIERS`.

    """
    if tier is not None and tier not in TIERS:
        raise ValueError(f'{tier!r} is not a test tier; expected one of {", ".join(map(repr, TIERS))}')
    paths = {f'tests/{name}' for name in FIXTURE_TIER_DIRS}

    for path in sorted(TESTS_ROOT.rglob('*.py')):
        relative_to_tests = path.relative_to(TESTS_ROOT)
        if not FIXTURE_TIER_DIRS.isdisjoint(relative_to_tests.parts[:-1]):
            continue  # already reachable through a directory argument above
        if path.name.endswith(FIXTURE_TIER_SUFFIXES):
            paths.add(path.relative_to(ROOT).as_posix())

    paths.update(skip_idiom_test_ids())

    if tier is not None:
        kept = set()  # type: set[str]
        for entry in paths:
            module = entry.partition('::')[0]
            if (ROOT / module).is_dir():
                members = [path for path in suite_modules() if path.startswith(module.rstrip('/') + '/')]
                within = [path for path in members if module_tier(path) == tier]
                kept.update([entry] if within == members else within)
            elif module_tier(module) == tier:
                kept.add(entry)
        paths = kept

    return tuple(sorted(paths))
