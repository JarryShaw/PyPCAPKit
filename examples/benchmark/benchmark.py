# -*- coding: utf-8 -*-
"""Time ``pcapkit.extract`` on each engine available in *this* environment.

This is the measuring half of the benchmark suite; :mod:`report` is the reporting
half. One invocation covers one Python environment and writes a JSON document
describing what it measured. The suite runs it many times over, because an
environment here is a *(Python version, ``pcap`` distribution)* pair and the matrix
covers several of each:

* several interpreters, one image apiece, because the point of the exercise is a
  table with a column per Python version;
* one or two virtualenvs per interpreter, because ``pypcap`` and ``pcap_ct`` both
  provide the top-level :mod:`pcap` module and cannot be installed side by side, so
  no single environment can hold every engine -- and only one virtualenv where
  ``pypcap`` cannot be installed at all.

:mod:`report` stitches the runs together on the ``default`` engine, which is present
in every one of them.

Methodology is inherited from :file:`examples/legacy_smoke/test_time.py` so the
figures stay comparable in kind with what the project has already published:
:data:`ROUNDS` timed extractions of the same capture per engine, timed with
:func:`time.perf_counter_ns`, first sample discarded as a warm-up, reported as
milliseconds per packet. The deliberate departures are listed in
:file:`README.md` under "Departures from the legacy methodology".

Two properties matter more than the numbers themselves.

**The engine that ran is asserted, not assumed.** A missing or unusable engine
does not raise: :meth:`Extractor.run
<pcapkit.foundation.extraction.Extractor.run>` emits an
:class:`~pcapkit.utilities.warnings.EngineWarning` and falls back to ``pcapkit``'s
own parser, so an extraction that appears to succeed can be timing something else
entirely. Every single extraction therefore has its driver checked against
:func:`expected_drivers`, and a run whose driver ever disagrees is discarded
rather than reported -- see :func:`measure`.

**An engine that cannot run is recorded, not omitted.** :func:`preflight` asks the
engine's own ``unsupported_reason()``, since that is the check :meth:`Extractor.run
<pcapkit.foundation.extraction.Extractor.run>` itself consults and it names the
actual cause. Ahead of it sits one thing the engine cannot know -- whether the image
even tried to install it, which on 3.12 and newer it does not for ``pypcap``; see
:func:`_not_attempted`. Either way the engine is reported with
``status='unmeasured'`` and a reason, so a gap in the table is visibly a gap with an
explanation rather than a missing row or a zero.

"""

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import statistics
import subprocess  # nosec: B404
import sys
import time
import warnings
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any, Optional

    from pcapkit.foundation.extraction import Extractor

__all__ = ['ENGINES', 'ROUNDS', 'REPEATS', 'expected_drivers', 'preflight', 'measure', 'run']

#: Every engine ``pcapkit.extract(engine=...)`` accepts, in the order the suite
#: exercises them. Matches :data:`examples.legacy_smoke._engine_support.ENGINES`.
#: ``'default'`` is ``pcapkit``'s own parser and is the cross-environment
#: baseline, so it is always measured first and never dropped from the list.
ENGINES = ('default', 'dpkt', 'scapy', 'pypcap', 'pcap_ct', 'pypcapfile', 'pyshark')

#: Timed extractions per engine per repeat. The first is discarded as a warm-up
#: round, matching the legacy script, so a repeat reports the mean of
#: ``ROUNDS - 1`` samples.
ROUNDS = 1_000

#: How many times the whole engine set is measured. More than one because a
#: single pass cannot tell a real gap between two engines from the machine having
#: been busy; :mod:`report` turns the spread across repeats into the noise floor.
REPEATS = 3

#: Failed extractions to discard per engine per pass before giving up on it.
#: Small on purpose: this is for a flaky *external process*, not for an engine that
#: does not work. ``pyshark`` starts a :program:`tshark` per extraction, and one
#: crashing in a few thousand spawns is a fact of that design rather than a result;
#: five is enough to survive it and far too few to hide an engine that fails
#: routinely.
TOLERATED_FAILURES = 5

#: Distributions whose resolved version belongs in the report. Keyed by the name
#: ``pip`` knows, which is not always the name that gets imported -- ``pypcapfile``
#: imports as ``pcapfile``, ``pcap-ct`` and ``pypcap`` both as ``pcap``. Asked of
#: the installed metadata rather than of the modules for exactly that reason: the
#: metadata can see a distribution whose module the import system did not resolve
#: to, which is the ``pypcap``/``pcap-ct`` collision this suite exists to work
#: around.
DISTRIBUTIONS = (
    'pypcapkit', 'dpkt', 'scapy', 'pyshark', 'pypcapfile', 'pypcap', 'pcap-ct',
    'libpcap', 'lxml',
)

#: Directory where the image records a package whose install was allowed to fail
#: rather than abort the whole build. Overridable so the harness is still runnable
#: outside the container, where the directory does not exist and its absence simply
#: means nothing was recorded.
INSTALL_FAILURES = os.environ.get('BENCH_INSTALL_FAILURES', '/opt/install-failures')

#: Directory where the image records a package it did not even try to install,
#: because the interpreter cannot hold it. Separate from :data:`INSTALL_FAILURES`
#: because the two are different findings that a single directory would flatten into
#: one: ``pypcap`` on 3.12 is not a build this image got wrong, it is an engine the
#: interpreter rules out, and reporting the second as the first sends the next reader
#: looking for a compiler problem that does not exist. Overridable for the same
#: reason as above.
NOT_ATTEMPTED = os.environ.get('BENCH_NOT_ATTEMPTED', '/opt/not-attempted')


def _distribution_versions() -> 'dict[str, Optional[str]]':
    """Resolved version of every distribution in :data:`DISTRIBUTIONS`.

    Returns:
        Mapping of distribution name to its installed version, or :data:`None`
        where it is not installed here. The absent ones are kept rather than
        dropped, because "``pypcap`` is not in this environment" is a fact the
        report needs in order to explain why a row came from the other one.

    """
    versions = {}  # type: dict[str, Optional[str]]
    for name in DISTRIBUTIONS:
        try:
            versions[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            versions[name] = None
    return versions


def _tshark_version() -> 'Optional[str]':
    """First line of ``tshark --version``, or :data:`None` if it is not there.

    ``pyshark`` shells out to Wireshark's :program:`tshark` for all of its
    parsing, so the binary's version is as much a part of a ``pyshark`` figure as
    the Python package's is.

    """
    try:
        completed = subprocess.run(  # nosec: B603, B607
            ['tshark', '--version'], capture_output=True, text=True, timeout=30, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.splitlines()[0].strip() if completed.stdout else None


def _libpcap_version() -> 'Optional[str]':
    """What :manpage:`libpcap(3)` the ``pcap`` engines will actually map.

    Asked of the library through :mod:`ctypes` rather than of the :mod:`pcap`
    module, because **neither** distribution exposes it: measured in this image,
    ``pypcap`` 1.3.0 and ``pcap-ct`` 1.3.0b3 both lack a ``lib_version`` attribute
    entirely, so reading one off the module silently yields nothing.
    ``pcap_lib_version()`` is part of libpcap's own ABI and is always there.

    :func:`ctypes.util.find_library` is used deliberately rather than a fixed
    soname: it is the *same* resolution ``pcap-ct`` performs, since the ``libpcap``
    distribution ships ``LIBPCAP = None`` in its config and falls through to it.
    So this reports the library that will really be loaded, which is a property of
    the environment rather than of any pinned package version -- and therefore
    cannot be inferred from the pins and has to be asked at run time.

    Returns:
        The library's version banner, or :data:`None` when no system libpcap can
        be found or read.

    """
    import ctypes  # pylint: disable=import-outside-toplevel
    import ctypes.util  # pylint: disable=import-outside-toplevel

    located = ctypes.util.find_library('pcap')
    if located is None:
        return None
    try:
        library = ctypes.CDLL(located)
        library.pcap_lib_version.restype = ctypes.c_char_p
        banner = library.pcap_lib_version()
    except (OSError, AttributeError):
        # Found but unloadable, or loadable but not libpcap. Neither is worth
        # failing a benchmark over; the report simply omits the line.
        return None
    if banner is None:
        return None
    return banner.decode(errors='replace') if isinstance(banner, bytes) else str(banner)


def expected_drivers(engine: 'str') -> 'tuple[str, ...]':
    """The ``__engine_name__`` values that mean *engine* really ran.

    Derived from the registry rather than from a table written out by hand, so it
    cannot drift out of step with the engines: a new engine registered through
    :func:`pcapkit.foundation.registry.foundation.register_extractor_engine` is
    covered automatically, and a renamed ``__engine_name__`` cannot silently turn
    the assertion into a no-op.

    Args:
        engine: Engine name, as passed to ``pcapkit.extract``.

    Returns:
        One name for a third-party engine. Two for ``'default'``/``'pcapkit'``,
        which pick their parser from the file's magic number and are therefore
        correct as either.

    Raises:
        KeyError: If *engine* is not a registered engine name. Deliberately fatal:
            ``Extractor`` would only warn and fall back, and a typo that silently
            benchmarks the default engine under another engine's name is precisely
            the failure this function exists to prevent.

    """
    from pcapkit.foundation.engines.pcap import PCAP  # pylint: disable=import-outside-toplevel
    from pcapkit.foundation.engines.pcapng import PCAPNG  # pylint: disable=import-outside-toplevel
    from pcapkit.foundation.extraction import Extractor  # pylint: disable=import-outside-toplevel

    if engine in ('default', 'pcapkit'):
        return (PCAP.name, PCAPNG.name)

    registered = Extractor.__engine__[engine]
    # A registry entry is either the class or a lazy ``ModuleDescriptor``; the
    # latter resolves the class on attribute access.
    klass = getattr(registered, 'klass', registered)
    return (klass.name,)


def _declared_reason(engine: 'str') -> 'Optional[str]':
    """The engine's own ``unsupported_reason()``, if it declares one.

    This is the same preflight :meth:`Extractor.run
    <pcapkit.foundation.extraction.Extractor.run>` consults, and it is the only
    thing that names the real cause -- a Python ceiling, a missing
    :program:`tshark`, a missing :manpage:`libpcap(3)`, the wrong ``pcap``
    distribution installed. Without it the only available explanation is "its
    package is not installed", which is wrong in every case where the package is
    installed and unusable.

    Args:
        engine: Engine name, as passed to ``pcapkit.extract``.

    Returns:
        The engine's reason, or :data:`None` for ``'default'``, for an engine that
        declares no limitation, or for anything that goes wrong while asking.

    """
    from pcapkit.foundation.extraction import Extractor  # pylint: disable=import-outside-toplevel

    if engine in ('default', 'pcapkit'):
        return None
    registered = Extractor.__engine__.get(engine)
    if registered is None:
        return f'{engine} is not a registered extraction engine'
    try:
        klass = getattr(registered, 'klass', registered)
        return klass.unsupported_reason()
    except Exception as exc:  # pylint: disable=broad-except  # noqa: BLE001
        # Resolving a lazy descriptor imports the engine module, which can fail on
        # its own. That is still an answer -- just not one the engine phrased.
        return f'{type(exc).__name__}: {exc}'


def _extract(engine: 'str', capture: 'str') -> 'Extractor':
    """One extraction, with the arguments the legacy timing script used.

    ``store=False`` and ``nofile=True`` keep the measurement on parsing rather
    than on accumulating frames in memory or serialising them to disk.

    Args:
        engine: Engine name.
        capture: Path to the capture file.

    Returns:
        The finished extractor.

    """
    import pcapkit  # pylint: disable=import-outside-toplevel

    return pcapkit.extract(fin=capture, store=False, nofile=True, verbose=False,
                           engine=engine)  # type: ignore[arg-type]


def _unavailable(exc: 'Exception') -> 'Optional[str]':
    """Explain *exc* if it means the engine cannot run here.

    A last resort behind :func:`_declared_reason`, for the failures no engine
    declares in advance.

    Args:
        exc: Exception the engine raised.

    Returns:
        A reason to record the engine as unmeasured, or :data:`None` if *exc* is a
        real failure the caller should re-raise.

    """
    # pcapkit raises its own ModuleNotFound, which derives from ImportError, so
    # one check covers both it and a plain missing import.
    if isinstance(exc, ImportError):
        return f'{exc.name or exc} is not installed'
    # Matched by name rather than imported, since pyshark may be the thing missing.
    if type(exc).__name__ == 'TSharkNotFoundException':
        return 'the tshark binary from Wireshark is not installed'
    if isinstance(exc, RuntimeError) and 'event loop' in str(exc):
        version = '.'.join(str(part) for part in sys.version_info[:3])
        return (f'{exc} -- pyshark asks for an implicit asyncio event loop, which '
                f'Python {version} no longer provides')
    # ``pcap-ct`` with no system libpcap raises OSError from its loader, which is
    # not an ImportError and so reaches here.
    if isinstance(exc, OSError) and 'libpcap' in str(exc):
        return f'{exc} -- no system libpcap for the `pcap` module to load'
    return None


def _recorded_note(directory: 'str', engine: 'str', separator: 'str') -> 'Optional[str]':
    """One line of whatever *directory* records about *engine*.

    Args:
        directory: Directory the image writes its notes into.
        engine: Engine name, as passed to ``pcapkit.extract``.
        separator: What to join the recorded lines with. Not a detail: pip output is
            a sequence of distinct records and needs a visible separator to stay
            legible once flattened, while a note written as prose is one sentence
            wrapped for the Dockerfile and reads as gibberish if pipes are inserted
            at its wrap points.

    Returns:
        The note, flattened, or :data:`None` when there is none.

    """
    path = os.path.join(directory, f'{engine}.txt')
    try:
        with open(path, encoding='utf-8', errors='replace') as file:
            recorded = file.read()
    except OSError:
        return None
    # Collapsed to one line and capped: this ends up in a table cell and a bullet in
    # the emitted RST, where a dozen lines of pip output would be unreadable. The
    # full text stays in the image for anyone who needs it.
    flattened = separator.join(line.strip() for line in recorded.splitlines() if line.strip())
    return flattened[:400] + (' ...' if len(flattened) > 400 else '') or None


def _install_failure(engine: 'str') -> 'Optional[str]':
    """What the image recorded about this engine's package failing to install.

    The Dockerfile lets exactly one install fail without aborting the build --
    ``pypcap``, the only engine in the set that compiles and therefore the only one
    whose install can fail for reasons the pins do not control. It writes the pip
    error to a file, and this is what turns that file into the reason the engine was
    not measured. Without it the reason would be the generic "its package is not
    installed", which is true but says nothing about *why*, and the build error is
    the whole diagnosis.

    Args:
        engine: Engine name, as passed to ``pcapkit.extract``.

    Returns:
        A one-line summary of the recorded failure, or :data:`None` when none was
        recorded -- which is the normal case, including outside the container.

    """
    return _recorded_note(INSTALL_FAILURES, engine, ' | ')


def _not_attempted(engine: 'str') -> 'Optional[str]':
    """What the image recorded about not trying to install this engine at all.

    The matrix runs one image per Python version, and ``pypcap`` cannot be installed
    on 3.12 or newer -- its pre-generated ``pcap.c`` does not compile against that C
    API. Building a ``pypcap`` virtualenv there would be minutes of compiling to
    produce nothing, so the image does not, and records that instead.

    That distinction has to survive into the report. Left to the engine's own
    :meth:`unsupported_reason`, the answer on a 3.12 image is "the installed ``pcap``
    module is ``pcap-ct``, not ``pypcap``" -- correct, and a description of the
    consequence rather than the cause. The reader is owed the cause, which is a fact
    about the interpreter, not about how this image happened to be assembled.

    Args:
        engine: Engine name, as passed to ``pcapkit.extract``.

    Returns:
        A one-line summary of the recorded note, or :data:`None` when there is none
        -- the normal case for every engine that was installed.

    """
    return _recorded_note(NOT_ATTEMPTED, engine, ' ')


def preflight(engine: 'str', capture: 'str') -> 'tuple[Optional[str], Optional[str]]':
    """Try *engine* once and decide whether it is worth timing.

    Done before the timed rounds rather than during them: a failure partway
    through a thousand extractions throws the whole repeat away, and an engine
    this environment does not have is not a measurement at all.

    Three sources are consulted, in this order, and the order is the point: what the
    image recorded about not installing the engine at all (:func:`_not_attempted`),
    then the engine's own ``unsupported_reason()``, then an actual attempt. The first
    wins outright where it exists, since an engine the interpreter rules out cannot
    describe its own ceiling -- it can only report what it finds in the environment
    that ceiling produced.

    Args:
        engine: Engine name to try.
        capture: Capture file to read.

    Returns:
        ``(reason, driver)``. *reason* is :data:`None` when the engine works and
        the driver it used is returned alongside; otherwise *reason* explains why
        it cannot be measured here and *driver* is whatever ran instead, which is
        :data:`None` when nothing did.

    Raises:
        Exception: Whatever the engine raised, when that is a real failure rather
            than the engine being unavailable in this environment.

    """
    # An engine the interpreter rules out is answered here and nowhere else. The
    # recorded note *replaces* the engine's own reason rather than being appended to
    # it, which is the opposite of how a build failure is handled below, and
    # deliberately: the engine can only describe what it finds in this environment,
    # and on an interpreter where the package cannot be installed at all that
    # description is a symptom. Nothing is lost by dropping it, because it is
    # derivable from the note -- whereas the note is not derivable from it.
    not_attempted = _not_attempted(engine)
    if not_attempted is not None:
        return not_attempted, None

    # Computed up front and appended to whichever reason comes back, because a
    # recorded build failure explains every one of them: an engine whose package
    # never installed will report "not installed", and the interesting part is the
    # compiler error behind that.
    build_failure = _install_failure(engine)

    def _reason(text: 'str') -> 'str':
        """Attach the recorded build failure to *text*, when there is one."""
        return f'{text} -- {build_failure}' if build_failure else text

    reason = _declared_reason(engine)
    if reason is not None:
        return _reason(reason), None

    try:
        extraction = _extract(engine, capture)
    except Exception as exc:  # pylint: disable=broad-except
        reason = _unavailable(exc)
        if reason is None:
            raise
        return _reason(reason), None

    driver = type(extraction.engine).__engine_name__
    if driver not in expected_drivers(engine):
        # The quiet failure: ``Extractor`` warned and fell back, so the extraction
        # succeeded and reported a frame count that has nothing to do with the
        # engine asked for.
        return _reason(f'its package is not installed -- pcapkit fell back to its own '
                       f'{driver} parser, so timing it would measure the wrong thing'), driver
    return None, driver


def measure(engine: 'str', capture: 'str', rounds: 'int',
            tolerate: 'int' = TOLERATED_FAILURES) -> 'dict[str, Any]':
    """Time *rounds* extractions of *capture* on *engine*.

    The driver is checked on **every** extraction, not just on the first. Checking
    once would leave the run open to an engine that starts as itself and stops
    being itself partway through -- and since the fallback only warns, nothing
    else in the stack would object. The check is deliberately outside the timed
    bracket so it cannot bias the figure.

    A small number of failed extractions is tolerated, and this is not
    fastidiousness. ``pyshark`` spawns a :program:`tshark` process per extraction,
    so a default run spawns six thousand of them, and measured here: one of them
    crashed with ``TSharkCrashException ... retcode: 255`` partway through the
    third pass and took the entire run with it -- six working engines went
    unreported because the seventh hiccupped once. A crashed extraction is a
    *non-measurement* rather than a slow measurement, so discarding its sample is
    correct; what would not be honest is discarding it silently, which is why the
    count and the reasons are returned and reported.

    Args:
        engine: Engine name to time.
        capture: Capture file to read.
        rounds: Timed extractions to collect. The first is discarded as a warm-up.
        tolerate: How many failed extractions to discard before giving up on this
            pass.

    Returns:
        A mapping with the mean milliseconds per packet, the totals it was derived
        from, the driver that ran throughout, and anything that was discarded.

    Raises:
        RuntimeError: If the driver ever disagreed with :func:`expected_drivers`,
            or the capture yielded no packets. Fatal rather than warned about,
            because the alternative is publishing a number for an engine that did
            not produce it.
        Exception: Whatever the engine raised, once more than *tolerate*
            extractions have failed. The caller decides whether that costs the
            engine its row or the whole run -- see :func:`run`.

    """
    wanted = expected_drivers(engine)
    samples = []  # type: list[float]
    drivers = set()  # type: set[str]
    discarded = []  # type: list[str]
    length = 0

    # ``EngineWarning`` is escalated to an exception for the whole loop, so a
    # mid-run fallback surfaces here rather than on stderr where it would scroll
    # past. Everything else is silenced: ``ExtractionWarning: EOF reached`` fires
    # on every extraction of a truncated capture and its only effect on a
    # benchmark is noise.
    from pcapkit.utilities.warnings import EngineWarning  # pylint: disable=import-outside-toplevel

    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        warnings.simplefilter('error', EngineWarning)

        while len(samples) < rounds:
            try:
                # NOTE: perf_counter_ns is monotonic. time_ns is wall clock and can
                # step backwards under an NTP adjustment, giving a negative delta.
                now = time.perf_counter_ns()
                extraction = _extract(engine, capture)
                delta = time.perf_counter_ns() - now
            except EngineWarning:
                # Never tolerated: this is the escalated fallback warning, i.e. the
                # engine stopped being itself. Discarding it would turn the harness's
                # central assertion into a shrug.
                raise
            except Exception as exc:  # pylint: disable=broad-except
                discarded.append(f'{type(exc).__name__}: {exc}')
                if len(discarded) > tolerate:
                    raise
                continue

            samples.append(float(delta))
            drivers.add(type(extraction.engine).__engine_name__)
            length = extraction.length

            if len(samples) % 100 == 1:
                # Progress goes to stderr at a hundredth of the legacy script's
                # rate: stdout carries the JSON document, and a flushed write per
                # round is jitter bought for nothing.
                print(f'  {engine}: round {len(samples)}/{rounds}',
                      end='\r', file=sys.stderr, flush=True)

    unexpected = drivers - set(wanted)
    if unexpected:
        raise RuntimeError(
            f'engine {engine!r} was expected to run as {"/".join(wanted)} but '
            f'{"/".join(sorted(drivers))} ran; refusing to report the measurement'
        )
    if length <= 0:
        raise RuntimeError(f'engine {engine!r} reported {length} packets; nothing to divide by')

    if discarded:
        print(f'  {engine}: discarded {len(discarded)} failed extraction(s): '
              f'{discarded[0]}', file=sys.stderr, flush=True)

    samples.pop(0)  # discard the warm-up round, as the legacy script does
    mean_ns = statistics.mean(samples)
    return {
        'driver': drivers.pop(),
        'discarded': discarded,
        'packets': length,
        'rounds': rounds,
        'timed_samples': len(samples),
        'mean_ns_per_extraction': mean_ns,
        'ms_per_packet': mean_ns / length / 1_000_000,
    }


def _capture_facts(capture: 'str') -> 'dict[str, Any]':
    """Identify the capture, so a figure cannot be silently taken on another one.

    Args:
        capture: Path to the capture file.

    Returns:
        Its basename, size, and SHA-256 digest.

    """
    with open(capture, 'rb') as file:
        payload = file.read()
    return {
        'name': os.path.basename(capture),
        'bytes': len(payload),
        'sha256': hashlib.sha256(payload).hexdigest(),
    }


def run(capture: 'str', engines: 'tuple[str, ...]', rounds: 'int', repeats: 'int',
        label: 'str', tolerate: 'int' = TOLERATED_FAILURES) -> 'dict[str, Any]':
    """Measure every engine in *engines*, *repeats* times over.

    The loop is engines-inside-repeats rather than the other way round. A machine
    that gets slower halfway through then affects every engine in a repeat about
    equally, which is what lets :mod:`report` cancel the drift by taking each
    engine's ratio against the ``default`` engine *from the same repeat*.

    Args:
        capture: Capture file to read.
        engines: Engine names to measure.
        rounds: Timed extractions per engine per repeat.
        repeats: How many times to measure the whole set.
        label: Name of this environment, used by :mod:`report` to say where a row
            came from.
        tolerate: Failed extractions to discard per engine per pass before that
            pass is written off. See :func:`measure`.

    Returns:
        A JSON-serialisable document describing the environment and every
        measurement in it. Engines that could not be measured are included, with
        the reason -- never dropped.

    """
    facts = _capture_facts(capture)

    # Preflight once, up front. An engine ruled out here is ruled out for every
    # repeat, and reporting the reason once beats reporting it three times.
    status = {}  # type: dict[str, Optional[str]]
    for engine in engines:
        reason, driver = preflight(engine, capture)
        status[engine] = reason
        if reason is None:
            print(f'{label}: {engine} runs as {driver}', file=sys.stderr, flush=True)
        else:
            print(f'{label}: {engine} not measured -- {reason}', file=sys.stderr, flush=True)

    measurements = {engine: [] for engine in engines if status[engine] is None
                    }  # type: dict[str, list[dict[str, Any]]]
    drivers = {}  # type: dict[str, str]
    packets = {}  # type: dict[str, int]
    failures = {engine: [] for engine in engines}  # type: dict[str, list[str]]

    for repeat in range(repeats):
        print(f'{label}: repeat {repeat + 1}/{repeats}', file=sys.stderr, flush=True)
        for engine in engines:
            if status[engine] is not None:
                continue
            try:
                result = measure(engine, capture, rounds, tolerate)
            except RuntimeError:
                # The harness's own assertions -- wrong driver, no packets. These
                # mean a reported number would be a lie, so they end the run rather
                # than costing one engine its row.
                raise
            except Exception as exc:  # pylint: disable=broad-except
                # A third-party engine gave up partway through this pass. Measured:
                # `tshark` crashed on the third pass of a real run and, before this
                # branch existed, took the six working engines down with it. The
                # pass is lost; the run is not, and the loss is recorded rather than
                # quietly rounded away.
                failures[engine].append(f'pass {repeat + 1}: {type(exc).__name__}: {exc}')
                print(f'{label}: {engine} failed on pass {repeat + 1} -- '
                      f'{type(exc).__name__}: {exc}', file=sys.stderr, flush=True)
                continue

            measurements[engine].append({
                'repeat': repeat,
                'ms_per_packet': result['ms_per_packet'],
                'mean_ns_per_extraction': result['mean_ns_per_extraction'],
                'timed_samples': result['timed_samples'],
                'discarded': result['discarded'],
            })
            drivers[engine] = result['driver']
            packets[engine] = result['packets']

    results = []  # type: list[dict[str, Any]]
    for engine in engines:
        reason = status[engine]
        collected = measurements.get(engine, [])
        if reason is None and not collected:
            # It preflighted cleanly and then failed every pass. Unmeasured, with
            # what went wrong -- not a missing row, and not a zero.
            reason = ('every timed pass failed: '
                      + '; '.join(failures[engine])) if failures[engine] else \
                     'no pass produced a measurement'
        results.append({
            'engine': engine,
            'status': 'unmeasured' if reason is not None else 'measured',
            'reason': reason,
            'driver': drivers.get(engine),
            'packets': packets.get(engine),
            'repeats': collected,
            'failures': failures[engine],
        })

    return {
        'schema': 1,
        'environment': label,
        # `pcapkit` is installed from the working tree rather than from PyPI, so
        # its declared version does not distinguish one commit from another. The
        # revision the image was built from is set by the Dockerfile and is the
        # only thing that does.
        'pcapkit_revision': os.environ.get('PCAPKIT_REVISION') or None,
        # Which image produced this document. The matrix runs one image per Python
        # version, so a report covering several of them cannot name a single image the
        # way a one-interpreter run could: the reference has to travel with the
        # measurement rather than be passed to the report alongside it.
        'image': os.environ.get('BENCH_IMAGE') or None,
        # The base image, by digest, as `python-images.txt` pinned it. Recorded here
        # and deliberately not rendered: the JSON is a published artefact and is where
        # provenance this fine-grained belongs, whereas a row per version in the
        # report's provenance block would push the facts a reader does need off the
        # top of the table. It is also recoverable from the pins file at the
        # `pcapkit` revision above, which is what makes leaving it out of the prose
        # safe rather than lossy.
        'base_image': os.environ.get('PCAPKIT_BASE_IMAGE') or None,
        'python': platform.python_version(),
        'implementation': platform.python_implementation(),
        'machine': platform.machine(),
        'capture': facts,
        'rounds': rounds,
        'repeats': repeats,
        'packages': _distribution_versions(),
        'tshark': _tshark_version(),
        'libpcap': _libpcap_version(),
        'results': results,
    }


def main(argv: 'Optional[list[str]]' = None) -> 'int':
    """Command line entry point.

    Args:
        argv: Argument list, defaulting to :data:`sys.argv`.

    Returns:
        Process exit status.

    """
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--capture', required=True, help='capture file to extract')
    parser.add_argument('--label', required=True,
                        help='name of this environment, e.g. the virtualenv it runs in')
    parser.add_argument('--out', required=True, help='where to write the JSON document')
    parser.add_argument('--rounds', type=int, default=ROUNDS,
                        help=f'timed extractions per engine per pass (default {ROUNDS})')
    parser.add_argument('--repeats', type=int, default=REPEATS,
                        help=f'passes over the whole engine set (default {REPEATS})')
    parser.add_argument('--engines', default=','.join(ENGINES),
                        help='comma-separated engines to measure')
    parser.add_argument('--tolerate', type=int, default=TOLERATED_FAILURES,
                        help=('failed extractions to discard per engine per pass before '
                              f'giving up on it (default {TOLERATED_FAILURES})'))
    args = parser.parse_args(argv)

    if args.rounds < 2:
        parser.error('--rounds must be at least 2; the first round is a discarded warm-up')
    if args.repeats < 1:
        parser.error('--repeats must be at least 1')
    if args.tolerate < 0:
        parser.error('--tolerate cannot be negative')

    engines = tuple(name.strip() for name in args.engines.split(',') if name.strip())
    if 'default' not in engines:
        # Every ratio is taken against ``default`` in the same environment, and it
        # is the only engine present in all of them, so the report cannot stitch
        # anything together without it.
        parser.error("--engines must include 'default'; it is the baseline every ratio uses")

    document = run(args.capture, engines, args.rounds, args.repeats, args.label, args.tolerate)
    with open(args.out, 'w', encoding='utf-8') as file:
        json.dump(document, file, indent=2, sort_keys=True)
        file.write('\n')
    print(f'{args.label}: wrote {args.out}', file=sys.stderr, flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
