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
happened three times (GitHub pull requests #372 and #384, and once more), and
each time it cost a CI round-trip to work out.

So this module answers, cheaply and without needing the fixtures themselves:

* :func:`is_unit_tier` -- which tier does this module belong to?
* :func:`committed_captures` -- which captures does *git* track? Asked of git
  rather than hardcoded, because a hardcoded list of names silently rots the
  moment somebody commits another capture (there are six today, not the two
  the rule started with).
* :func:`audit_module` -- does this module read a generated capture without
  handling its absence?
* :func:`check_unit_tier_read` -- may this particular
  :func:`~tests._support.sample_path` call go ahead?
* :func:`explain` -- the message that says what is wrong and what to do about
  it.

:file:`tests/conftest.py` drives the first four at collection time, and
:func:`tests._support.sample_path` consults :func:`check_unit_tier_read` on
every call. Both paths no-op when git cannot answer, so an unpacked source
tarball still runs its tests.

The two halves cover each other. The collection-time audit is static, so it sees
a violation in a test that never runs -- one skipped for a missing optional
engine, say -- but only when the capture name is a string literal. The call-time
check sees the name however it was computed, e.g. ``sample_path(sample)`` in a
parametrised loop, but only once the call is reached.

What neither catches, deliberately: a unit-tier module that opens a capture
without going through :func:`~tests._support.sample_path` at all.
:file:`tests/protocols/misc/test_pcapng_unit.py` does this today at the line
holding ``os.path.join('examples', 'captures', 'dhcp_big_endian.pcapng')``, and
it is tier-safe -- it checks :func:`os.path.isfile` and skips -- but it is
invisible here. Flagging that shape would mean recognising a second,
much woollier "the absence is handled" idiom on top of the ``try``/``except``
one, and getting it wrong would fail correct code for everybody. So the rule
this module enforces is stated as it is: capture reads go through
:func:`~tests._support.sample_path`, and that is the door with the lock on it.

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
import subprocess
from typing import TYPE_CHECKING, NamedTuple

if TYPE_CHECKING:
    from typing import Optional

__all__ = [
    'GeneratedFixtureInUnitTierError', 'TierGuardWarning', 'SampleCall',
    'ROOT', 'TESTS_ROOT', 'SAMPLE_ROOT', 'REGENERATE_SAMPLES_CMD', 'UNIT_TIER_SELECTION',
    'FIXTURE_TIER_SUFFIXES', 'FIXTURE_TIER_DIRS',
    'is_unit_tier', 'committed_captures', 'committed_capture_names',
    'guard_unavailable_reason', 'handled_lines', 'sample_path_calls',
    'audit_module', 'check_unit_tier_read', 'explain',
]

#: Repository root, i.e. the parent of the directory holding this file. The
#: single definition of it for the whole suite: :mod:`tests._support` imports it
#: from here rather than recomputing it.
ROOT = pathlib.Path(__file__).resolve().parents[1]
#: Directory holding the test suite, which is what tier membership is relative to.
TESTS_ROOT = ROOT / 'tests'
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

#: ``try`` statement node types. :class:`ast.TryStar` is 3.11+, and Python 3.10
#: is the floor, so it is looked up rather than named.
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
    """Every ``sample_path(...)`` call in ``module_path``, in source order."""
    tree = _parse(module_path)
    if tree is None:
        return ()

    handled = handled_lines(module_path)
    return tuple(
        SampleCall(node.lineno, _literal_name(node), node.lineno in handled)
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and _is_sample_path(node.func)
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
