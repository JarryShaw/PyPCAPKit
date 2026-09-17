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
from typing import Iterable, Iterator

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

    An enclosing deadline that *expired* while the body ran cannot be delivered at
    the moment it was due, since the body held the process until then. It is
    re-armed for one second instead of cancelled: honouring it a moment late is the
    lesser wrong, and cancelling it is how the enclosing timeout goes missing
    altogether. The same clamp applies when the enclosing deadline was shorter than
    ``seconds`` and this one therefore fired first.

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
    module = sys.modules.get(name)
    if module is None:
        module = types.ModuleType(name)
        module.__path__ = [str(path)]
        module.__package__ = name
        sys.modules[name] = module
    return module


def load_module(module_name: str, relative_path: str):
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


def bootstrap_core_modules() -> dict[str, object]:
    load_module('pcapkit.utilities.logging', 'pcapkit/utilities/logging.py')
    compat = load_module('pcapkit.utilities.compat', 'pcapkit/utilities/compat.py')
    exceptions = load_module('pcapkit.utilities.exceptions', 'pcapkit/utilities/exceptions.py')
    warnings = load_module('pcapkit.utilities.warnings', 'pcapkit/utilities/warnings.py')
    multidict = load_module('pcapkit.corekit.multidict', 'pcapkit/corekit/multidict.py')
    decorators = load_module('pcapkit.utilities.decorators', 'pcapkit/utilities/decorators.py')
    protochain = load_module('pcapkit.corekit.protochain', 'pcapkit/corekit/protochain.py')
    return {
        'compat': compat,
        'exceptions': exceptions,
        'warnings': warnings,
        'multidict': multidict,
        'decorators': decorators,
        'protochain': protochain,
    }


def install_fake_protocol_module() -> type:
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


def install_fake_payload_protocols(raw_cls: type, null_cls: type) -> None:
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


def purge_modules(prefixes: Iterable[str]) -> None:
    for name in list(sys.modules):
        if any(name == prefix or name.startswith(prefix + '.') for prefix in prefixes):
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
