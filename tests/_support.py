from __future__ import annotations

import abc
import collections.abc
import contextlib
import importlib.util
import inspect
import math
import pathlib
import signal
import sys
import time
import types
import unittest
from typing import Iterable, Iterator, Optional

from tests._tiers import (ROOT, SAMPLE_ROOT, REGENERATE_SAMPLES_CMD,
                          GeneratedFixtureInUnitTierError, check_unit_tier_read)


@contextlib.contextmanager
def time_limit(seconds: int = 5) -> Iterator[None]:
    """Fail the calling test if its body has not finished in ``seconds`` seconds.

    A parser defect that degenerates into a loop making no progress -- GitHub
    issue #431 is one -- offers a test nothing to assert on: the call under test
    simply never returns. A test written for it without a deadline does not fail,
    it *wedges*, taking the rest of the run with it, so the deadline is as much a
    part of the regression test as the assertion is.

    :func:`signal.alarm` is what interrupts the body, rather than a watchdog
    thread: the loops this guards are pure Python and hold the GIL for the whole
    of an iteration, so nothing in another thread gets to run and stop them,
    whereas a signal is delivered between bytecodes. That also rules out
    :data:`signal.SIGTERM` from an outer :program:`timeout`, which such a loop
    likewise never gets around to handling.

    There is only ever one pending alarm per process, so arming this one cancels
    whatever was already scheduled -- an enclosing ``time_limit``, or a deadline the
    test runner set for itself. Both the handler and that pending alarm are put back
    on the way out, the alarm with the seconds spent in the body deducted, so an
    enclosing deadline keeps counting down across the ``with`` rather than being
    silently dropped.

    An enclosing deadline whose moment falls inside the body is not delivered on
    time, and the reason is this helper rather than the body: arming an alarm
    *replaces* the pending one, so the enclosing deadline was already cancelled
    before the body began and there was nothing left to fire when it came due. It
    is re-armed for one second on the way out rather than dropped -- honouring it
    late is the lesser wrong, and dropping it is how an enclosing timeout goes
    missing altogether. That one-second floor covers every case where the body ran
    for longer than the enclosing deadline had left.

    Args:
        seconds: Whole seconds to allow the body. :func:`signal.alarm` counts in
            whole seconds, so this cannot usefully be fractional.

    Yields:
        Nothing. The deadline applies to the body of the ``with`` statement.

    Raises:
        TimeoutError: If the body has not finished within ``seconds`` seconds.

    """
    # An interval timer is a POSIX facility, and the deadline is the whole point
    # of this helper: silently running the body without one would restore exactly
    # the wedged run it exists to prevent, so the test is skipped instead.
    if not hasattr(signal, 'SIGALRM'):
        raise unittest.SkipTest('signal.alarm is unavailable on this platform')

    def expire(signum: int, frame: object) -> None:
        raise TimeoutError(f'did not finish within {seconds}s')

    previous_handler = signal.signal(signal.SIGALRM, expire)

    # NOTE: ``signal.alarm`` returns the seconds left on the alarm it replaces, or
    # zero when there was none. That return value is the only record of an
    # enclosing deadline, so it is read here rather than discarded -- there is no
    # way to ask for it again afterwards.
    pending = signal.alarm(seconds)
    started = time.monotonic()
    try:
        yield
    finally:
        # Cancel first, so that an alarm which fires between here and the handler
        # being restored cannot be delivered to whatever handler was installed
        # before -- and so that the alarm re-armed below belongs to that handler
        # rather than to ``expire``.
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous_handler)
        if pending:
            left = pending - (time.monotonic() - started)
            signal.alarm(max(1, math.ceil(left)))


def sample_path(name: str) -> str:
    """Resolve a sample capture file name to its absolute path.

    The sample captures live in :file:`examples/captures/` under the repository
    root. Tests go through this helper rather than spelling that directory out,
    so that the location is recorded in exactly one place and so that the suite
    does not depend on the working directory :program:`pytest` was invoked from.

    Going through one helper is also what makes the tier rule enforceable: this
    is the single door onto :file:`examples/captures/`, so it is where a
    unit-tier module reading a *generated* capture can be stopped. See
    :mod:`tests._tiers` for the rule and why breaking it is otherwise invisible
    until CI runs on a fresh checkout.

    Args:
        name: Bare file name of the capture, e.g. ``'arp.pcap'`` -- not a path,
            and in particular not ``'sample/arp.pcap'``.

    Returns:
        Absolute path to the capture as a :obj:`str`, ready to be handed to
        :func:`pcapkit.interface.extract` as its ``fin`` argument.
        :obj:`str` rather than :class:`pathlib.Path` is deliberate:
        :meth:`Extractor.make_name <pcapkit.foundation.extraction.Extractor.make_name>`
        branches on ``isinstance(fin, str)`` and treats anything else as an
        already-open binary IO object.

    Raises:
        GeneratedFixtureInUnitTierError: If a unit-tier module asked for a
            capture git does not track, and the call site does not handle the
            capture being absent. Raised whether or not the file is on disk, so
            the mistake surfaces on the machine that made it rather than on the
            next fresh checkout.
        FileNotFoundError: If the capture is not present. Most of the samples
            are generated rather than committed to the repository, so a fresh
            clone has to build them first.

    """
    # Where the call came from, which is what decides its tier. Read out of the
    # calling frame rather than passed in, so that no test has to declare its own
    # tier and none can get the declaration wrong. Both locals are dropped again
    # straight away: a frame reachable from a local keeps the whole chain alive
    # once a traceback references this frame, and this function raises.
    frame = inspect.currentframe()
    caller = frame.f_back if frame is not None else None
    try:
        module_path = caller.f_globals.get('__file__') if caller is not None else None
        lineno = caller.f_lineno if caller is not None else None
    finally:
        del frame, caller

    problem = check_unit_tier_read(name, module_path, lineno)
    if problem is not None:
        raise GeneratedFixtureInUnitTierError(problem)

    path = SAMPLE_ROOT / name
    if not path.is_file():
        raise FileNotFoundError(
            f'sample capture {name!r} not found at {path} -- most of the sample '
            f'captures are generated, not committed; regenerate them by running '
            f'{REGENERATE_SAMPLES_CMD!r} from {ROOT}'
        )
    return str(path)


def ensure_package(name: str, path: pathlib.Path) -> types.ModuleType:
    """Make ``name`` importable as a package, with a bare stub if it is not.

    :func:`load_module` executes one module of the package from source without
    importing the package, so :mod:`importlib` has no parent package to resolve
    the module's name against. This supplies one: a :class:`~types.ModuleType`
    carrying nothing but a ``__path__``, which is the least that makes
    ``pcapkit.corekit.multidict`` a resolvable name.

    That stub is a stand-in over a real module name, and everything
    :func:`isolate_modules` says about those applies to it. It is *emptier* than
    the real package rather than differently-shaped, which is what made issue
    #674 so quiet: a test left a bare ``pcapkit`` bound, and the next test to
    walk ``pcapkit.__all__`` found no exports and reported the library as having
    declared none, rather than failing on anything that looked like pollution.

    Nothing is installed when the name already resolves -- a warm real package is
    returned untouched, so a caller cannot shadow it by accident.

    Args:
        name: Dotted package name, e.g. ``'pcapkit.corekit'``.
        path: Directory the package's ``__path__`` should point at.

    Returns:
        Whatever ``name`` now resolves to: the real package if it was already
        imported, otherwise the stub just installed.

    Raises:
        RuntimeError: If a stub would have to be installed and nothing has
            arranged for :data:`sys.modules` to be put back. See
            :func:`restore_modules_after`.

    """
    module = sys.modules.get(name)
    if module is None:
        # Checked only on the path that actually writes to ``sys.modules``: a
        # caller handed a name that already resolves has nothing to put back, and
        # failing it would be a complaint about pollution that is not happening.
        _require_arranged_restore('ensure_package')

        module = types.ModuleType(name)
        module.__path__ = [str(path)]
        module.__package__ = name
        sys.modules[name] = module
    return module


def load_module(module_name: str, relative_path: str,
                test: 'Optional[unittest.TestCase]' = None):
    """Execute one module of :mod:`pcapkit` from source, without importing the package.

    This is how the unit tier tests a single module against cheap stand-ins
    instead of pulling the whole library in: the file is executed under its real
    dotted name, with :func:`ensure_package` supplying stub parents for whatever
    that name needs.

    Both halves of that write to :data:`sys.modules` -- the stub parents, and
    ``module_name`` itself -- so both are taken back off again when ``test``
    finishes, via :func:`restore_modules_after`. Before issue #674 they were not,
    and five test modules left a bare ``pcapkit`` bound for whatever ran next.

    Args:
        module_name: Dotted name to execute the file under, e.g.
            ``'pcapkit.corekit.multidict'``.
        relative_path: Path to the source file, relative to the repository root.
        test: The running test, whose teardown puts :data:`sys.modules` back.
            Found from the calling frames when omitted, which is what lets the
            call sites stay as they are; pass it explicitly from a classmethod or
            any other frame that has no ``self``.

    Returns:
        The executed module object.

    Raises:
        RuntimeError: If ``test`` is :data:`None` and no running test could be
            found, or if the file cannot be loaded.

    """
    # The return value is what ``bootstrap_core_modules`` passes down; here there
    # is nothing below to pass it to, so only the arranging matters.
    _arrange_module_restore(test, 'load_module')

    parts = module_name.split('.')
    for index in range(1, len(parts)):
        package_name = '.'.join(parts[:index])
        package_path = ROOT.joinpath(*parts[:index])
        ensure_package(package_name, package_path)

    spec = importlib.util.spec_from_file_location(module_name, ROOT / relative_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f'Unable to load module {module_name!r} from {relative_path!r}')

    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def bootstrap_core_modules(test: 'Optional[unittest.TestCase]' = None) -> dict[str, object]:
    """Execute the core :mod:`pcapkit` modules from source, in dependency order.

    The seven modules the unit tier needs before it can test anything else, each
    loaded by :func:`load_module` and so each restored when ``test`` finishes.
    The restore is arranged here as well as in :func:`load_module`, and
    deliberately: :func:`restore_modules_after` registers one cleanup per test
    however many times it is called, so the snapshot kept is the one taken here,
    before the first of the seven loads wrote anything.

    Args:
        test: The running test. Found from the calling frames when omitted, as in
            :func:`load_module` -- including through an intermediate helper that
            has no ``self`` of its own, which is how
            :func:`tests.utilities._harness.bootstrap` reaches this.

    Returns:
        The loaded modules, keyed by their bare names.

    Raises:
        RuntimeError: If ``test`` is :data:`None` and no running test could be
            found.

    """
    test = _arrange_module_restore(test, 'bootstrap_core_modules')

    load_module('pcapkit.utilities.logging', 'pcapkit/utilities/logging.py', test)
    compat = load_module('pcapkit.utilities.compat', 'pcapkit/utilities/compat.py', test)
    exceptions = load_module('pcapkit.utilities.exceptions',
                             'pcapkit/utilities/exceptions.py', test)
    warnings = load_module('pcapkit.utilities.warnings', 'pcapkit/utilities/warnings.py', test)
    multidict = load_module('pcapkit.corekit.multidict', 'pcapkit/corekit/multidict.py', test)
    decorators = load_module('pcapkit.utilities.decorators',
                             'pcapkit/utilities/decorators.py', test)
    protochain = load_module('pcapkit.corekit.protochain',
                             'pcapkit/corekit/protochain.py', test)
    return {
        'compat': compat,
        'exceptions': exceptions,
        'warnings': warnings,
        'multidict': multidict,
        'decorators': decorators,
        'protochain': protochain,
    }


def install_fake_protocol_module(test: 'unittest.TestCase') -> type:
    """Bind a non-generic ``ProtocolBase`` stand-in over the real one.

    The stand-in shares the real class's :attr:`~type.__name__` but is *not*
    :class:`~typing.Generic`, so every ``class X(Protocol[...])`` in the package
    raises :exc:`TypeError` while it is installed. That is the point -- the
    tests using it are unit-testing :mod:`pcapkit.corekit.protochain` against a
    cheap stand-in rather than importing the library -- but it also means the
    stand-in surviving the test that installed it breaks every later test that
    imports :mod:`pcapkit`. See :func:`isolate_modules` for the mechanism and
    issue #660 for what it looked like when it was missing.

    Args:
        test: The running test. Must already be under :func:`isolate_modules`,
            which is what puts :data:`sys.modules` back afterwards. Required
            rather than optional so that a future caller cannot install the
            stand-in without arranging for its removal -- the mistake is a
            :exc:`TypeError` at the call rather than twelve unrelated failures
            in another directory.

    Returns:
        The stand-in class, to subclass in the test.

    Raises:
        RuntimeError: If ``test`` is not under :func:`isolate_modules`.

    """
    require_module_isolation(test, 'install_fake_protocol_module')

    ensure_package('pcapkit.protocols', ROOT / 'pcapkit' / 'protocols')

    protocol_module = types.ModuleType('pcapkit.protocols.protocol')

    class ProtocolBase:
        alias = 'PROTOCOL'

        @classmethod
        def id(cls) -> tuple[str, ...]:
            return (cls.__name__,)

        @classmethod
        def expand_comp(cls, value) -> tuple[object, ...]:
            if isinstance(value, cls):
                return (type(value), value.alias.upper(), *(name.upper() for name in type(value).id()))
            if isinstance(value, type) and issubclass(value, cls):
                return (value, value.__name__.upper(), *(name.upper() for name in value.id()))
            if isinstance(value, str):
                return (value.upper(),)
            return (value,)

    protocol_module.ProtocolBase = ProtocolBase
    sys.modules['pcapkit.protocols.protocol'] = protocol_module
    return ProtocolBase


def install_fake_payload_protocols(test: 'unittest.TestCase', raw_cls: type,
                                   null_cls: type) -> None:
    """Bind ``Raw`` and ``NoPayload`` stand-ins over the real payload protocols.

    Args:
        test: The running test, for the same reason as in
            :func:`install_fake_protocol_module` -- these two names are on the
            import path of most of the package, so leaving stand-ins bound to
            them poisons every later test that imports :mod:`pcapkit`.
        raw_cls: Stand-in to bind as ``pcapkit.protocols.misc.raw.Raw``.
        null_cls: Stand-in to bind as
            ``pcapkit.protocols.misc.null.NoPayload``.

    Raises:
        RuntimeError: If ``test`` is not under :func:`isolate_modules`.

    """
    require_module_isolation(test, 'install_fake_payload_protocols')

    ensure_package('pcapkit.protocols.misc', ROOT / 'pcapkit' / 'protocols' / 'misc')

    raw_module = types.ModuleType('pcapkit.protocols.misc.raw')
    raw_module.Raw = raw_cls
    sys.modules['pcapkit.protocols.misc.raw'] = raw_module

    null_module = types.ModuleType('pcapkit.protocols.misc.null')
    null_module.NoPayload = null_cls
    sys.modules['pcapkit.protocols.misc.null'] = null_module


def _reset_abc_caches() -> None:
    """Clear the stdlib ABC instance-check caches.

    :func:`purge_modules` drops :mod:`pcapkit` from :data:`sys.modules` so the
    next test re-imports it fresh, but the :mod:`collections.abc` ABCs are
    never purged. Each re-import rebuilds pcapkit's ``Mapping`` subclasses
    (``Info``, ``Schema``, ``ContextRegistry``, ``ProtocolContext``, …) as new
    class objects, and their creation churns the C-level ``_abc_impl`` caches
    on the shared ABCs. Those caches then hold stale answers keyed on immortal
    built-ins -- so ``isinstance({}, collections.abc.Mapping)`` can return
    :data:`False`, or ``isinstance({}, Schema)`` :data:`True`, until the cache
    token happens to advance. The effect is order-dependent and invisible when
    a test file runs alone, which is why it only ever bit the full suite.

    :func:`abc._reset_caches` is a CPython internal (present on both the C
    ``_abc`` and pure-python ``_py_abc`` backends); if a future runtime drops
    it this degrades to the previous, occasionally-flaky behaviour rather than
    erroring.
    """
    reset = getattr(abc, '_reset_caches', None)
    if reset is None:  # pragma: no cover
        return
    for obj in vars(collections.abc).values():
        if isinstance(obj, type) and hasattr(obj, '_abc_impl'):
            reset(obj)


#: Default :data:`sys.modules` prefixes the isolation helpers below cover, and
#: the ones :func:`tests.conftest.restore_module_table` puts back after every
#: test. Only the package under test: a test that imports a third-party module
#: for the first time is not polluting anything, and dropping, say, ``scapy``
#: from :data:`sys.modules` between tests would cost a re-import for no gain.
ISOLATED_PREFIXES = ('pcapkit',)

#: Attribute :func:`isolate_modules` sets on the test it is given, and that
#: :func:`require_module_isolation` looks for. Private by name because nothing
#: outside this module should read it.
_ISOLATION_FLAG = '_pcapkit_module_isolation'

#: Attribute :func:`restore_modules_after` sets on the test it is given, so that
#: several helpers arranging a restore for one test register exactly one cleanup.
#:
#: Deliberately *not* the same flag as :data:`_ISOLATION_FLAG`, because the two
#: mean different things and the stand-in installers depend on the difference.
#: This one promises only that the region will be put back; isolation promises
#: that *and* that the region was purged on the way in, which is what makes a
#: stand-in stand in for nothing left over from an earlier test.
_RESTORE_FLAG = '_pcapkit_module_restore'


def _under_prefix(name: str, prefixes: 'tuple[str, ...]') -> bool:
    """Whether ``name`` is one of ``prefixes`` or a submodule of one."""
    return any(name == prefix or name.startswith(prefix + '.') for prefix in prefixes)


def snapshot_modules(prefixes: Iterable[str] = ISOLATED_PREFIXES) -> 'dict[str, types.ModuleType]':
    """The :data:`sys.modules` entries currently under ``prefixes``.

    Args:
        prefixes: Module-name prefixes to capture, matched as in
            :func:`purge_modules`.

    Returns:
        A new mapping of name to module object. The *objects* are shared with
        :data:`sys.modules`, which is what makes :func:`restore_modules` a
        restore rather than a re-import: putting the same object back leaves
        every class it holds identical, so an ``isinstance`` check against a
        class captured before the test still answers the same afterwards.

    """
    prefixes = tuple(prefixes)
    return {name: module for name, module in list(sys.modules.items())
            if _under_prefix(name, prefixes)}


def restore_modules(snapshot: 'dict[str, types.ModuleType]',
                    prefixes: Iterable[str] = ISOLATED_PREFIXES) -> None:
    """Put the ``prefixes`` region of :data:`sys.modules` back to ``snapshot``.

    The inverse of :func:`snapshot_modules` over the *bindings*, and exact in
    both directions: a name the test added is removed, a name it dropped is put
    back, and a name it rebound is bound to what it held before. Nothing outside
    ``prefixes`` is touched.

    Bindings are the whole of it, though, and the limit is worth stating. This
    restores which module object a name refers to; it does not restore the
    *contents* of a module object. A test that reaches into an already-imported
    module and mutates it in place -- adding an entry to a registry dict, say --
    rebinds nothing, so there is nothing here to undo and the mutation outlives
    the test. Isolating against that needs a purge, so that the next import
    rebuilds the module from source, which is what the callers of
    :func:`purge_modules` are doing. Issue #660 was a rebinding, which is why
    this is the right shape for it.

    Args:
        snapshot: The mapping :func:`snapshot_modules` returned.
        prefixes: The prefixes it was taken over. Passing a wider set than was
            snapshotted would delete modules that were never captured, so the
            two calls have to agree -- which is why :func:`isolate_modules`
            makes both of them rather than leaving it to the caller.

    """
    prefixes = tuple(prefixes)
    for name in list(sys.modules):
        if _under_prefix(name, prefixes) and name not in snapshot:
            sys.modules.pop(name, None)
    for name, module in snapshot.items():
        sys.modules[name] = module
    # For the same reason :func:`purge_modules` does it: whatever the test
    # imported while the region was purged built a second set of ``Mapping``
    # subclasses and churned the shared ABC caches, and those stale answers
    # outlive the modules that caused them.
    _reset_abc_caches()


#: Returned by :func:`_is_running_test` when a runtime has no ``_outcome`` at all,
#: so that "cannot tell" is distinguishable from "not running". Any object that is
#: not :data:`None` would do; a named sentinel says why.
_NO_OUTCOME = object()


def _is_running_test(test: 'unittest.TestCase') -> bool:
    """Whether ``test`` is between the start and the end of its own ``run()``.

    :meth:`unittest.TestCase.run` assigns ``_outcome`` before ``setUp`` and clears
    it to :data:`None` in a ``finally``, so it is set throughout every phase a
    loader can be reached from -- ``setUp``, the test method, ``tearDown``, and a
    cleanup -- and unset on an instance that has never run or has finished.
    Measured on CPython 3.10 through 3.14, in all four phases and both idle
    states.

    Private, but deliberately so rather than reluctantly: there is no public way
    to ask a :class:`~unittest.TestCase` whether it is running, and the
    alternative -- inspecting whether the frame is really a method call on the
    candidate -- rejects a decorated test method, whose frame belongs to the
    undecorated function while the class attribute is the wrapper. A false
    rejection breaks a working test; this check cannot produce one.

    ``_outcome`` is assigned in ``TestCase.__init__``, so its *absence* means a
    runtime that has dropped it rather than a test that is idle. That case answers
    :data:`True`, degrading to the unchecked behaviour instead of rejecting every
    candidate and taking the suite down.

    Args:
        test: The candidate found on the stack.

    Returns:
        Whether it is the running test, as far as can be told.

    """
    return getattr(test, '_outcome', _NO_OUTCOME) is not None


def _running_test_case() -> 'Optional[unittest.TestCase]':
    """The nearest *running* :class:`~unittest.TestCase` on the stack above the caller.

    Read out of the calling frames rather than passed in, for the reason
    :func:`sample_path` reads the caller's module path that way: a helper that
    has to be *handed* the running test is a helper every call site can forget to
    hand it to, and forgetting is silent. Issue #674 is the bill for that --
    :func:`bootstrap_core_modules` and :func:`load_module` left stub ``pcapkit``
    entries in :data:`sys.modules` at five call sites, not one of which looked
    wrong, and the resulting failures landed in a different directory.

    The *nearest* enclosing ``self`` wins, and that is the right one rather than
    merely the cheapest to find. Tests run one at a time, so ordinarily the only
    :class:`~unittest.TestCase` on the stack is the running one; where there are
    two, :mod:`tests.test_support_helpers` is why -- it runs a borrowed test case
    inside one of its own -- and it is the borrowed, inner test whose teardown
    should do the restoring.

    A local named ``self`` is not proof of a method call, though, and that gap is
    why :func:`_is_running_test` is consulted rather than the name alone. A *free
    function* taking a parameter it happens to call ``self`` presents exactly the
    same frame, so one handed some other, finished :class:`~unittest.TestCase`
    would otherwise win the walk -- and a cleanup registered on a test that has
    already finished is never run, which is the original leak with an extra step
    and no error to show for it. Measured before the check was added: a ten-name
    leak, silently. Skipping the idle candidate lets the walk continue to the
    method frame above, which is the running test.

    Returns:
        The running test, or :data:`None` when the caller is not inside a running
        :class:`~unittest.TestCase` method at all: a ``setUpClass`` or other
        classmethod, a module-level call, a plain :mod:`pytest` function, or a
        runtime without frame support. Callers turn that into a
        :exc:`RuntimeError` naming the fix, rather than skipping the restore and
        reintroducing #674.

    """
    frame = inspect.currentframe()
    try:
        # This function's own frame is never the answer, so start at its caller.
        frame = frame.f_back if frame is not None else None
        while frame is not None:
            # ``f_locals`` is a plain dict up to 3.12 and a ``FrameLocalsProxy``
            # from 3.13 (PEP 667); both answer ``get``.
            candidate = frame.f_locals.get('self')
            if isinstance(candidate, unittest.TestCase) and _is_running_test(candidate):
                return candidate
            frame = frame.f_back
        return None
    finally:
        # A frame held by a local keeps its whole chain alive the moment a
        # traceback references this one, and the callers of this function raise.
        del frame


def restore_modules_after(test: 'unittest.TestCase',
                          prefixes: Iterable[str] = ISOLATED_PREFIXES) -> None:
    """Snapshot the ``prefixes`` region now, and put it back when ``test`` ends.

    :func:`isolate_modules` without the purge, and the right shape for a test
    that *loads* modules rather than standing something in for one. The loaders
    write to :data:`sys.modules` twice over -- the module asked for, and a bare
    stub package per parent of its name -- and those writes are all this has to
    take back off. Purging on the way in as well would be wrong here: a caller
    that has already purged for its own reasons would find the state it set up
    restored out from under it mid-test.

    Exact in both directions, because :func:`restore_modules` is. Absence is the
    direction a ``dict.update`` of the snapshot would silently get wrong, and it
    is the direction issue #674 actually was: ``pcapkit``, ``pcapkit.corekit``
    and ``pcapkit.utilities`` did not exist before
    :func:`bootstrap_core_modules` ran, so they must not exist after it.

    Registered **once per test** however many times this is called, and the
    snapshot kept is the first one -- the only one taken before any of the loads
    wrote anything. That is what lets :func:`bootstrap_core_modules` announce
    itself and then make seven :func:`load_module` calls without registering
    eight cleanups to eight successively more polluted snapshots.

    Registered with :meth:`~unittest.TestCase.addCleanup` rather than done in a
    ``tearDown``, for the reasons :func:`isolate_modules` gives: it runs even
    when ``setUp`` raises part-way through loading, and no subclass can forget to
    call ``super``.

    Args:
        test: The running test, or anything else exposing
            :meth:`~unittest.TestCase.addCleanup`.
        prefixes: Module-name prefixes to cover, matched as in
            :func:`purge_modules`.

    """
    if getattr(test, _RESTORE_FLAG, False):
        return

    snapshot = snapshot_modules(prefixes)
    setattr(test, _RESTORE_FLAG, True)
    test.addCleanup(_release_module_restore, test, snapshot, tuple(prefixes))


def _release_module_restore(test: 'unittest.TestCase',
                            snapshot: 'dict[str, types.ModuleType]',
                            prefixes: 'tuple[str, ...]') -> None:
    """Restore ``snapshot``, and let ``test`` arrange a fresh restore again."""
    try:
        restore_modules(snapshot, prefixes)
    finally:
        setattr(test, _RESTORE_FLAG, False)


def _arrange_module_restore(test: 'Optional[unittest.TestCase]',
                            helper: str) -> 'unittest.TestCase':
    """Resolve the test a loader should restore for, and arrange the restore.

    Args:
        test: What the caller was given, which is :data:`None` whenever the call
            site did not name a test -- the usual case.
        helper: Name of the calling helper, for the error message.

    Returns:
        The test the restore was arranged on, to pass down to nested loaders so
        they neither repeat the stack walk nor find a different answer.

    Raises:
        RuntimeError: If no running test could be found.

    """
    if test is None:
        test = _running_test_case()
    if test is None:
        raise RuntimeError(
            f'{helper}() could not find the running unittest.TestCase to put '
            f'sys.modules back for, so the stub packages it installs would outlive '
            f'this test and break whatever imports pcapkit next -- see issue #674. '
            f'Pass the test explicitly, {helper}(..., test=self), from a '
            f'classmethod or any other frame with no `self` of its own.'
        )
    restore_modules_after(test)
    return test


def _require_arranged_restore(helper: str) -> None:
    """Refuse to install a stub for a test that has not arranged its removal.

    The counterpart of :func:`require_module_isolation` for the loaders, and
    separate from it because the two guard different promises: a stand-in needs
    the region purged *and* restored, whereas a stub parent package only needs
    restoring.

    Either promise satisfies this. :func:`isolate_modules` makes both, so a test
    under isolation passes without also arranging a second restore.

    Args:
        helper: Name of the calling helper, for the error message.

    Raises:
        RuntimeError: If the running test has arranged neither, or if there is no
            running test to have arranged anything.

    """
    test = _running_test_case()
    if test is not None and (getattr(test, _RESTORE_FLAG, False)
                             or getattr(test, _ISOLATION_FLAG, False)):
        return

    where = type(test).__name__ if test is not None else 'the calling code'
    raise RuntimeError(
        f'{helper}() is about to bind a bare stub package over a real pcapkit '
        f'module name, but {where} has arranged nothing to put sys.modules back '
        f'-- the stub would outlive this test and whatever imports pcapkit next '
        f'would see a package with no exports. Call '
        f'tests._support.restore_modules_after(self), or '
        f'tests._support.isolate_modules(self) if a stand-in is also being bound. '
        f'See issue #674.'
    )


def isolate_modules(test: 'unittest.TestCase',
                    prefixes: Iterable[str] = ISOLATED_PREFIXES) -> None:
    """Purge ``prefixes`` for the duration of ``test``, and restore them after.

    This is :func:`purge_modules` with the other half attached, and it is what
    every test that stands something in for a real module wants instead. The
    difference is the whole of issue #660: purging on the way *in* protects the
    test that does it and nothing else, so a test that replaces
    ``pcapkit.protocols.protocol`` with a stand-in and then finishes leaves that
    stand-in bound for whatever runs next. Twelve tests in
    :mod:`tests.project.test_public_api` and
    :mod:`tests.project.test_documentation_claims` failed with ``TypeError: type
    'ProtocolBase' is not subscriptable`` on exactly that, and only when the
    file that installed the stand-in happened to run before them.

    Restoring on the way *out* makes the order irrelevant, which is the only
    fix worth having here: the failure was hidden for as long as it was because
    some *other* test's purge usually healed the state before anything noticed,
    so any fix that leaves the healing accidental -- moving a file so it sorts
    elsewhere, relying on a sibling to purge -- leaves the defect in place and
    merely re-hides it.

    Registered with :meth:`~unittest.TestCase.addCleanup` rather than done in a
    ``tearDown``, so it also runs when ``setUp`` itself raises part-way through
    installing the stand-ins, and so a subclass cannot forget to call ``super``.

    A test under isolation needs no separate :func:`restore_modules_after`, and
    this says so by setting that helper's flag as well: the one restore
    registered here already covers every write the loaders go on to make, and to
    a snapshot taken *earlier* than one of theirs would have been. A second,
    narrower restore nested inside it would be redundant rather than wrong, but
    the first thing a reader would have to work out is which of the two won.

    Args:
        test: The running test, or anything else exposing
            :meth:`~unittest.TestCase.addCleanup`.
        prefixes: Module-name prefixes to isolate.

    """
    snapshot = snapshot_modules(prefixes)
    setattr(test, _ISOLATION_FLAG, True)
    setattr(test, _RESTORE_FLAG, True)
    # Registered *before* the purge, so the restore still happens if the purge
    # itself raises half-way through the table.
    test.addCleanup(_release_module_isolation, test, snapshot, tuple(prefixes))
    purge_modules(prefixes)


def _release_module_isolation(test: 'unittest.TestCase',
                              snapshot: 'dict[str, types.ModuleType]',
                              prefixes: 'tuple[str, ...]') -> None:
    """Restore ``snapshot`` and mark ``test`` as no longer isolated."""
    try:
        restore_modules(snapshot, prefixes)
    finally:
        # Both flags, since ``isolate_modules`` set both. Cleared in a ``finally``
        # so that a failing restore does not leave the test looking isolated to
        # whatever runs next on the same instance.
        setattr(test, _ISOLATION_FLAG, False)
        setattr(test, _RESTORE_FLAG, False)


def require_module_isolation(test: 'unittest.TestCase', helper: str) -> None:
    """Refuse to install a stand-in for a test that has not arranged its removal.

    Args:
        test: The test the caller was handed.
        helper: Name of the calling helper, for the error message.

    Raises:
        RuntimeError: If ``test`` never called :func:`isolate_modules`, or has
            already released its isolation.

    """
    if not getattr(test, _ISOLATION_FLAG, False):
        raise RuntimeError(
            f'{helper}() needs {type(test).__name__} to be under '
            f'tests._support.isolate_modules(self) first -- otherwise the stand-in it '
            f'binds outlives this test and breaks whatever imports pcapkit next. '
            f'Call isolate_modules(self) in setUp instead of purge_modules([...]); '
            f'see issue #660.'
        )


def purge_modules(prefixes: Iterable[str]) -> None:
    """Drop every :data:`sys.modules` entry under ``prefixes``.

    Purging only, with nothing put back: a test calling this protects *itself*
    from what ran before it and makes no promise to what runs after. That is
    enough for the majority of callers, which purge so that the next ``import
    pcapkit`` re-runs the package from source and then import nothing unusual --
    a re-imported real module is not pollution.

    Purge-only is deliberate and stays that way, which is worth stating because
    the asymmetry reads like an oversight. Dropping a real module is not a change
    another test can observe: the next one that wants it imports it again and gets
    the same thing from the same source. Binding something *else* over the name is
    what cannot be undone by re-importing, so restoration is owed by the helpers
    that bind, not by this one. Making ~120 call sites pay for a restore none of
    them needs would also cost a re-import each, which
    :func:`tests.conftest.pytest_sessionstart` exists to avoid.

    It is *not* enough for a test that binds anything over a real module name.
    Use :func:`isolate_modules` for a stand-in, which snapshots first and restores
    on teardown; the loaders arrange :func:`restore_modules_after` for themselves,
    so a caller that purges and then calls :func:`load_module` or
    :func:`bootstrap_core_modules` is already covered (issue #674).

    Args:
        prefixes: Module-name prefixes. A name matches when it equals a prefix
            or begins with the prefix followed by a dot, so ``'pcapkit'`` takes
            ``pcapkit`` and ``pcapkit.corekit.protochain`` but not
            ``pcapkit_extra``.

    """
    for name in list(sys.modules):
        if _under_prefix(name, tuple(prefixes)):
            sys.modules.pop(name, None)
    _reset_abc_caches()


def _close_quietly(target: object) -> None:
    """Call ``target.close()``, swallowing any :exc:`Exception` it raises.

    :exc:`BaseException` is deliberately not caught: a
    :exc:`KeyboardInterrupt` or a :exc:`SystemExit` arriving during teardown
    should still end the run.

    Args:
        target: Object to close, or :data:`None`. Anything without a callable
            ``close`` attribute is ignored.

    """
    try:
        # Inside the ``try`` because the lookup itself can raise: a test double
        # with ``close`` as a property, or a custom ``__getattr__``, fails here
        # rather than at the call, and that would defeat the whole point.
        close = getattr(target, 'close', None)
        if not callable(close):
            return
        close()
    except Exception:  # pylint: disable=broad-except
        # This runs from teardown, where raising would replace the real test
        # failure with a secondary error from cleanup and hide what actually
        # broke. A half-constructed engine is the common case: the underlying
        # handle may never have been opened, so closing it raises rather than
        # being a no-op.
        pass


def close_extractor(extractor: object) -> None:
    """Release everything an :class:`~pcapkit.foundation.extraction.Extractor` holds.

    Tests that abandon an extractor part-way through a capture never reach
    :meth:`Extractor._cleanup <pcapkit.foundation.extraction.Extractor._cleanup>`
    or :meth:`Extractor.__exit__ <pcapkit.foundation.extraction.Extractor.__exit__>`,
    so nothing in the library closes up after them. Both of those close the
    input file *and* the engine, and this helper has to do the same: the input
    file is not the only resource. The ``pcap_ct`` and ``pypcap`` engines hold a
    live :class:`pcap.pcap` handle, and ``pyshark`` holds a temporary file, so
    dropping the extractor without closing the engine leaks an OS-level handle
    per test. Under a suite that builds hundreds of extractors that accumulates
    into a file-descriptor exhaustion whose failure surfaces somewhere unrelated.

    Closes in the same order the library does -- input file, then engine -- and
    closes the engine even if closing the input file fails, so one broken
    resource cannot strand the other.

    Args:
        extractor: The extractor to close. Deliberately typed :obj:`object` and
            probed with :func:`getattr`, because teardown also reaches here for
            extractors that failed part-way through ``__init__`` (in which case
            ``_exeng`` was never assigned) and for test doubles that stand in
            for one.

    """
    # ``_exeng`` is read before the input file is touched so that a failure
    # closing the stream cannot lose the reference to the engine.
    stream = getattr(extractor, '_ifile', None)
    engine = getattr(extractor, '_exeng', None)
    try:
        _close_quietly(stream)
    finally:
        _close_quietly(engine)
