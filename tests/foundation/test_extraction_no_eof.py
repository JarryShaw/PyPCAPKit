# -*- coding: utf-8 -*-
"""``no_eof`` has to stop eventually -- #620.

``extract(..., no_eof=True)`` never returned. End of stream was detected
correctly, and ``ExtractionWarning: EOF reached`` fired, but the three loops that
handle it all read

.. code-block:: python

   if self._flag_n:
       continue

with nothing else to stop them, so an exhausted input was retried forever. The
flag suppressed the error that *ended* the loop without supplying any other
ending.

The flag is not pointless, which is why the fix is a termination condition rather
than a deletion. ``pcapkit/__main__.py`` sets ``no_eof = args.fin == '-'``, so
``pcapkit -`` reads a live capture off standard input, and reaching the end of
what has arrived so far genuinely is not the end of that capture. What was
missing was a way to tell a capture that has paused from one that is over.

Measured on ``6c3d1b0d9`` before the fix, which is what these tests reproduce:

* ``extract(in.pcap, nofile=True)`` returns with 6 frames; adding
  ``no_eof=True`` never returns, and ``faulthandler`` killed it at 10s with the
  stack in ``pcapkit/protocols/protocol.py`` ``__init__``.
* The input's position at end of stream is *constant*: eight consecutive ends of
  stream all at 605, of a 605-byte file. That is the signal the fix uses.
* A pipe whose writer is open but idle **blocks** rather than reporting end of
  stream -- frame 2 arrived at t=1.50s across a 1.5s pause -- so retrying was
  never what kept a live capture on a pipe alive.
* ``pcapkit -`` hung too, which the issue did not mention: a pipe reports end of
  stream once its writer closes, and that also spun forever.

What this narrows, deliberately
-------------------------------

A **seekable** input does not block, so the two end-of-stream probes happen
microseconds apart and a file still being appended to ends at whatever was
present when the extraction got there. Measured both ways, with the append
landing on a record boundary 0.6s in: ``6c3d1b0d9`` yields all six frames, and
this yields five. That is a real behaviour change, and it is deliberate -- the
previous behaviour was unbounded by construction, which is the defect #620
reports, so some stopping rule had to be chosen. A timed grace period would only
make the cut-off intermittent instead of absent, so following a growing file is
left to a policy of its own. :class:`NoEOFOverAGrowingFileStopsAtWhatIsThere`
pins the decision so that it stays a decision rather than becoming folklore.

Worth knowing while reading that: an append landing *mid-record* fails with
``ValueError: read length must be non-negative or -1`` on **both** trees, so
``no_eof`` over a growing file only ever worked for a writer flushing whole
records. That is pre-existing and not addressed here.

Why the end-to-end cases run in a child process
-----------------------------------------------

A hang cannot fail an assertion -- the call simply never returns, and a test
written without a deadline wedges the run instead of failing it. The suite's own
:func:`tests._support.time_limit` is the usual answer, and it is used below for
the cases driven by a stand-in engine.

For the cases that parse a real capture it is **not dependable**, which is worse
than it being unusable. Measured on ``6c3d1b0d9``: a ``time_limit``-guarded
version of ``test_call_form_...`` below usually did expire on time, and once did
not -- it escaped the deadline entirely and ran for over ten minutes, reaching
**13.2 GB RSS**, and was killed by hand. The escape has not been reproduced
since. So the honest statement is that the in-process deadline is delivered
*intermittently* here, and an intermittent guard against a hang is worse than
none, because the run it fails to bound is a wedged suite rather than a red test.

Two things this is *not*, both checked, so that the next reader does not repeat
the guesses:

* It is not the parse path's ``except Exception`` handlers absorbing the
  ``SIGALRM``-raised :exc:`TimeoutError`. Those handlers exist -- in
  :mod:`pcapkit.corekit.decorators` and
  :meth:`ProtocolBase._decode_next_layer
  <pcapkit.protocols.protocol.ProtocolBase._decode_next_layer>` -- and
  :exc:`TimeoutError` is indeed an :exc:`Exception`, but neither is *entered*
  during the spin: :func:`~pcapkit.corekit.decorators.prepare` raises end of
  stream before any next-layer decode is reached, and a logger tap over the
  retries recorded nothing from either module.
* The memory is not those handlers logging. It is the retry loop emitting tens of
  thousands of ``EOF reached`` warning and log records per second, which the test
  runner retains.

So those cases are bounded from **outside** the interpreter: a child process with
a wall-clock :mod:`subprocess` timeout, which cannot be absorbed or missed, plus
an ``RLIMIT_AS`` cap so that a child which does hang cannot take the host down
while it waits to be killed. The child also asserts which tree it imported, since
this project is usually installed editable and an editable finder will happily
serve a different checkout than the one under test.

The timeout bounds the extraction, not the interpreter's warm-up (#2085). On
GraalPy 25.4.4 a child spends 4-8s importing :mod:`pcapkit` and 7-13s on its
first extraction, which imports more modules and is otherwise cold code:
about 21 CPU-seconds before the case under test begins, after which every case
here takes 0.02-0.06s. CPython takes 0.9s in all. A single 30s timeout over the
whole child therefore failed four of eleven GraalPy runs on ``main``, the other
exhausted-input cases in each finishing at 25-30s, and called it #620. So the
child warms up with one plain extraction and prints :data:`READY`; that phase
gets :data:`STARTUP`, and only what follows counts against :data:`DEADLINE`.

"""

from __future__ import annotations

import importlib.util
import os
import subprocess  # nosec: B404
import sys
import textwrap
import threading
import types
import unittest
import warnings
from unittest import mock

from tests._support import sample_path, scale_timeout, time_limit
from tests._tiers import ROOT

#: Test tier (#1958): exercises stream and buffer semantics, which differ by
#: interpreter.
__tier__ = 'ALL'

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: Seconds allowed to an extraction of a six-frame, 605-byte capture, once the
#: child has warmed up. Measured at 0.02-0.06s on GraalPy 25.4.4 and under 0.01s
#: on CPython, so this is loose enough not to flake on a loaded machine and still
#: far short of forever.
DEADLINE = 30

#: Seconds allowed to a child before it prints :data:`READY`: interpreter start,
#: importing :mod:`pcapkit`, and one plain extraction (#2085). That is 0.9s on
#: CPython and about 21 CPU-seconds on GraalPy 25.4.4 -- 11s of wall on an idle
#: 16-core host, 21s pinned to 4 CPUs beside 3 busy ones, and up to 30s on the
#: GraalPy leg's runner, where the whole child was cut off at 30s. The sibling
#: CLI child in ``test_extraction_non_seekable_stream_1586_unit.py`` took 52.9s
#: on the same runner and is allowed 120s; this matches it.
STARTUP = 120

#: Address-space ceiling for a child process, in bytes. A child that hangs is
#: going to be killed on the timeout anyway; this stops it consuming the host in
#: the meantime, the unbounded loop having reached 13.2 GB when it was measured.
#: Generous enough that an ordinary extraction never comes near it.
ADDRESS_SPACE_CAP = 2 * 1024 ** 3

#: Printed by a child that got all the way through. Its absence distinguishes
#: "the extraction did not finish" from "the child failed for some other reason".
SENTINEL = 'NO-EOF-RETURNED'

#: Printed, alone on its line, by a child that has warmed up. :data:`DEADLINE`
#: starts here.
READY = 'NO-EOF-READY'

#: How a child caps its address space. GraalPy's ``resource`` has no ``setrlimit``
#: (#1963); a child there is held by the heap cap the leg gives every GraalPy
#: process, in ``GRAAL_PYTHON_VM_ARGS``, which it inherits. Windows has no
#: ``resource`` at all (#2102), so a child there is left uncapped too.
CHILD_CAP = ('' if sys.implementation.name == 'graalpy' or os.name == 'nt'
             else 'import resource\nresource.setrlimit(resource.RLIMIT_AS, ({cap}, {cap}))')

#: Preamble for every child: cap the address space, put the tree under test first
#: on ``sys.path``, *prove* that is the tree which got imported, and warm up with
#: a plain extraction of the capture, which terminates on every tree.
CHILD_PREAMBLE = """
import sys, warnings
""" + CHILD_CAP + """
sys.path.insert(0, {root!r})
warnings.simplefilter('ignore')
import pcapkit
assert pcapkit.__file__.startswith({root!r}), 'wrong tree: ' + pcapkit.__file__
print('TREE ' + pcapkit.__file__, flush=True)
pcapkit.extract(fin={capture!r}, nofile=True, store=False)
print({ready!r}, flush=True)
"""


class ChildTimeout(Exception):
    """A child outlived one of the two allowances :func:`run_child` gives it.

    Args:
        phase: ``'startup'`` if it never printed :data:`READY`, else
            ``'deadline'``.
        seconds: The allowance it outlived.
        output: Everything it printed before it was killed.

    """

    def __init__(self, phase: 'str', seconds: 'float', output: 'str') -> None:
        super().__init__(phase, seconds, output)
        self.phase = phase
        self.seconds = seconds
        self.output = output


def run_child(argv: 'list[str]', startup: 'float', deadline: 'float',
              cwd: 'str | None' = None) -> 'tuple[int, str]':
    """Run ``argv`` to completion, timing its warm-up and its work separately.

    The child gets ``startup`` seconds to print :data:`READY` alone on a line, and
    ``deadline`` seconds from then to exit. A child that exits without printing it
    is waited on for ``deadline`` seconds, so a crash is reported as such.

    Args:
        argv: The command.
        startup: Seconds allowed before :data:`READY`.
        deadline: Seconds allowed after it.
        cwd: Working directory for the child.

    Returns:
        The child's exit status and its output, stderr merged into stdout.

    Raises:
        ChildTimeout: If either allowance ran out; the child has been killed.

    """
    proc = subprocess.Popen(  # nosec: B603
        argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, text=True, errors='replace', cwd=cwd,
    )
    lines = []  # type: list[str]
    settled = threading.Event()

    def drain() -> None:
        assert proc.stdout is not None  # nosec: B101
        for line in proc.stdout:
            lines.append(line)
            if line.rstrip('\r\n') == READY:
                settled.set()
        settled.set()  # end of output: nothing more is coming

    reader = threading.Thread(target=drain, daemon=True)
    reader.start()
    timed_out = None  # type: tuple[str, float] | None
    try:
        if not settled.wait(startup):
            timed_out = ('startup', startup)
        else:
            try:
                proc.wait(deadline)
            except subprocess.TimeoutExpired:
                timed_out = ('deadline', deadline)
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait()
        reader.join(10)
        assert proc.stdout is not None  # nosec: B101
        proc.stdout.close()
    output = ''.join(lines)
    if timed_out is not None:
        raise ChildTimeout(timed_out[0], timed_out[1], output)
    return proc.returncode, output


class ChildBoundedTestCase(unittest.TestCase):
    """Runs a snippet of extraction in a child process under a hard timeout."""

    #: The committed six-frame, 605-byte capture the issue uses. Resolved in the
    #: parent, because :func:`~tests._support.sample_path` is what enforces the
    #: suite's tier rule.
    CAPTURE_PATH = sample_path('in.pcap')

    #: Binds ``capture`` in the child to :attr:`CAPTURE_PATH`.
    CAPTURE = 'capture = {!r}'.format(CAPTURE_PATH)

    def run_bounded(self, body: 'str') -> 'str':
        """Execute ``body`` in a child process and return its output.

        Args:
            body: Python source, dedented for you, run after
                :data:`CHILD_PREAMBLE`. It should print :data:`SENTINEL` once the
                extraction it is testing has returned.

        Returns:
            The child's combined output.

        Raises:
            AssertionError: If the child did not finish inside :data:`DEADLINE`
                seconds of warming up, which is the failure mode #620 is about;
                if it did not warm up inside :data:`STARTUP` seconds; or if it
                exited non-zero. Both allowances are scaled by
                :func:`~tests._support.scale_timeout`.

        """
        script = CHILD_PREAMBLE.format(cap=ADDRESS_SPACE_CAP, root=str(ROOT),
                                       capture=self.CAPTURE_PATH, ready=READY) \
            + textwrap.dedent(body)
        # Scaled like the in-process deadline, so one setting stretches all three.
        try:
            returncode, output = run_child([sys.executable, '-c', script],
                                           startup=scale_timeout(STARTUP),
                                           deadline=scale_timeout(DEADLINE),
                                           cwd=str(ROOT))
        except ChildTimeout as exc:
            if exc.phase == 'startup':
                raise AssertionError(
                    f'the child did not warm up within {exc.seconds}s -- starting, '
                    'importing pcapkit and one plain extraction, before any no_eof '
                    f'case ran -- so this is not #620. Child output so far:\n{exc.output}'
                ) from exc
            raise AssertionError(
                f'the extraction did not return within {exc.seconds}s, which is the '
                f'non-termination #620 reports. Child output so far:\n{exc.output}'
            ) from exc

        self.assertEqual(returncode, 0, f'child exited {returncode}:\n{output}')
        self.assertIn('TREE ' + str(ROOT), output,
                      'the child imported a different tree than the one under '
                      f'test, so its result says nothing:\n{output}')
        self.assertIn(SENTINEL, output,
                      f'the child never reached the end of the extraction:\n{output}')
        return output


class ChildAllowances(unittest.TestCase):
    """:func:`run_child` charges warm-up to :data:`STARTUP`, not :data:`DEADLINE`.

    #2085: one timeout over the whole child failed GraalPy runs whose extraction
    had not even begun, and reported them as #620. These children are bare
    interpreters that sleep, so the cases need no capture and no runtime
    dependencies.

    """

    def child(self, source: 'str') -> 'list[str]':
        """A child running ``source``, with :data:`READY` bound as ``READY``."""
        return [sys.executable, '-c', f'import sys, time\nREADY = {READY!r}\n'
                + textwrap.dedent(source)]

    def test_a_slow_warm_up_is_not_charged_to_the_deadline(self) -> None:
        """Four seconds to get ready, then an instant exit, passes a 2s deadline."""
        returncode, output = run_child(self.child("""
            time.sleep(4)
            print(READY, flush=True)
            print('done', flush=True)
        """), startup=scale_timeout(60), deadline=scale_timeout(2))
        self.assertEqual(returncode, 0, output)
        self.assertIn('done', output)

    def test_a_child_that_hangs_after_warming_up_meets_the_deadline(self) -> None:
        """The #620 shape: ready, then never returning."""
        with self.assertRaises(ChildTimeout) as caught:
            run_child(self.child("""
                print(READY, flush=True)
                print('spinning', flush=True)
                time.sleep(600)
            """), startup=scale_timeout(60), deadline=1)
        self.assertEqual(caught.exception.phase, 'deadline')
        self.assertIn('spinning', caught.exception.output)

    def test_a_child_that_never_warms_up_meets_the_startup_allowance(self) -> None:
        """Hung before :data:`READY` is a startup failure, not a #620 one."""
        with self.assertRaises(ChildTimeout) as caught:
            run_child(self.child("""
                print('starting', flush=True)
                time.sleep(600)
            """), startup=1, deadline=scale_timeout(60))
        self.assertEqual(caught.exception.phase, 'startup')
        self.assertIn('starting', caught.exception.output)

    def test_a_child_that_dies_before_warming_up_reports_its_status(self) -> None:
        """A crash is not waited on for the whole startup allowance."""
        returncode, output = run_child(self.child("""
            print('crashing', flush=True)
            sys.exit(3)
        """), startup=scale_timeout(60), deadline=scale_timeout(60))
        self.assertEqual(returncode, 3, output)
        self.assertIn('crashing', output)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class NoEOFTerminatesOnAnExhaustedInput(ChildBoundedTestCase):
    """The reproduction from #620, over all three loops that handle end of stream.

    ``record_frames`` (the ``auto=True`` path), ``__next__`` and ``__call__`` each
    carried their own copy of the unbounded retry, so each needs its own case:
    the issue reproduced the first two and this covers the third as well.

    Every case here parses a real capture, so every case runs in a child process
    -- see the module docstring for why an in-process deadline does not hold.

    """

    def test_auto_extraction_with_no_eof_returns(self) -> None:
        """``extract(..., no_eof=True)`` returns, with the same frames as without.

        The control matters as much as the subject: a fix that terminated by
        losing frames would beat the deadline and still be wrong, so the child
        compares the two frame lists rather than only counting them.

        """
        output = self.run_bounded(f"""
            {self.CAPTURE}
            control = pcapkit.extract(fin=capture, nofile=True, store=True)
            assert len(control.frame) == 6, len(control.frame)

            subject = pcapkit.extract(fin=capture, nofile=True, store=True,
                                      no_eof=True)
            numbers = [frame.info.number for frame in subject.frame]
            assert numbers == [frame.info.number for frame in control.frame], numbers
            assert subject._flag_e, 'the EOF flag should have been set'
            print('frames ' + repr(numbers), flush=True)
            print({SENTINEL!r}, flush=True)
        """)
        self.assertIn('frames [1, 2, 3, 4, 5, 6]', output)

    def test_manual_iteration_with_no_eof_stops(self) -> None:
        """Iterating an ``auto=False``, ``no_eof=True`` extractor ends."""
        output = self.run_bounded(f"""
            {self.CAPTURE}
            extractor = pcapkit.extract(fin=capture, nofile=True, store=False,
                                        auto=False, no_eof=True)
            numbers = [frame.info.number for frame in extractor]
            assert numbers == [1, 2, 3, 4, 5, 6], numbers
            print('frames ' + repr(numbers), flush=True)
            print({SENTINEL!r}, flush=True)
        """)
        self.assertIn('frames [1, 2, 3, 4, 5, 6]', output)

    def test_call_form_with_no_eof_raises_once_the_input_is_finished(self) -> None:
        """``extractor()`` reports end of stream rather than retrying forever.

        ``__call__`` has to return a frame or raise, and once the input is
        finished there is no frame -- so :exc:`EOFError` is the only truthful
        answer, and ``no_eof`` defers it rather than suppressing it outright. That
        matches the plain form, which
        :file:`tests/integration/test_frame_iteration.py` already pins.

        This is the case that proved an in-process deadline cannot bound: on
        ``6c3d1b0d9`` it absorbed the ``SIGALRM`` into the parse path's
        ``except Exception`` and then ran unbounded.

        """
        self.run_bounded(f"""
            {self.CAPTURE}
            extractor = pcapkit.extract(fin=capture, nofile=True, store=False,
                                        auto=False, no_eof=True)
            for _ in range(6):
                extractor()

            try:
                extractor()
            except EOFError:
                pass
            else:
                raise AssertionError('an exhausted input should report EOF')
            print({SENTINEL!r}, flush=True)
        """)

    def test_a_pipe_whose_writer_closed_terminates(self) -> None:
        """The ``pcapkit -`` case: a non-seekable input, exhausted.

        ``pcapkit/__main__.py`` sets ``no_eof`` precisely for ``fin='-'``, so this
        is the flag's own documented use. #620 does not mention it, but it hung
        too: a pipe reports end of stream once its writer has closed, and that was
        retried forever like any other. A ``BufferedReader`` over a non-seekable
        raw stream is what ``sys.stdin.buffer`` is.

        """
        self.run_bounded(f"""
            import io
            {self.CAPTURE}

            class NonSeekableRaw(io.RawIOBase):
                name = 'in.pcap'

                def __init__(self, payload):
                    super().__init__()
                    self._payload = payload
                    self._pos = 0

                def readable(self):
                    return True

                def seekable(self):
                    return False

                def readinto(self, buffer):
                    chunk = self._payload[self._pos:self._pos + len(buffer)]
                    buffer[:len(chunk)] = chunk
                    self._pos += len(chunk)
                    return len(chunk)

            with open(capture, 'rb') as source:
                payload = source.read()

            extractor = pcapkit.extract(fin=io.BufferedReader(NonSeekableRaw(payload)),
                                        nofile=True, store=True, no_eof=True)
            assert len(extractor.frame) == 6, len(extractor.frame)
            print({SENTINEL!r}, flush=True)
        """)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class NoEOFOverAGrowingFileStopsAtWhatIsThere(ChildBoundedTestCase):
    """The deliberate narrowing: a seekable file being appended to is not followed.

    This is the one case where the fix is a behaviour *change* rather than a
    repair, so it is pinned rather than left to be discovered. A pipe is safe
    because its read blocks across a pause; a regular file reports end of stream
    at once, so the two probes fall microseconds apart and the extraction ends at
    the data present when it arrived.

    Measured with the append landing on a record boundary 0.6s in: ``6c3d1b0d9``
    yields all six frames, this yields five. Following a writer needs a policy --
    a grace period, a poll interval, an explicit follow mode -- and a timed grace
    would make the cut-off intermittent rather than absent, which is harder to
    reason about than a crisp rule. So the rule is crisp and written down here.

    The case below sequences the append on the extractor's own end of stream, not
    on that 0.6s timer: a loaded runner took longer than 0.6s to get there, read
    the sixth frame, and failed (#1583).

    """

    def test_a_file_appended_to_after_the_read_yields_only_what_was_there(self) -> None:
        """Five of six frames, the sixth having been appended too late.

        "Too late" is an event, not a delay. The extractor announces each end of
        stream it meets as ``ExtractionWarning: EOF reached``, through the ``warn``
        that :mod:`pcapkit.foundation.extraction` imports, so the child wraps that
        name and appends the sixth frame inside the *second* announcement: the
        extractor has met end of stream, retried once, and met it again at the
        same position. That is where it has reached end of stream, and the frame
        is on disk before it decides to stop, so any later look at the file -- a
        grace period, a poll, a size check -- would find it.

        The first announcement is the wrong trigger. The retry after it exists for
        a capture that has merely paused, so a frame appended there is read, and
        should be -- :class:`NoEOFStillRetriesAnInputThatGrows`.

        The child is bounded like the others: on ``6c3d1b0d9`` the retry never
        stops, so it reads the appended frame and then does not terminate, and the
        case doubles as another reproduction.

        """
        output = self.run_bounded(f"""
            import os, tempfile
            import pcapkit.foundation.extraction as extraction
            {self.CAPTURE}

            with open(capture, 'rb') as source:
                payload = source.read()

            # Record boundaries of in.pcap; 430 is five whole frames, so the append
            # lands exactly on one -- what a per-packet-flushing writer produces.
            # An append landing mid-record raises ValueError on every tree, which
            # is a separate, pre-existing matter.
            split = 430
            with tempfile.TemporaryDirectory(prefix='pcapkit-grow-') as tmp:
                path = os.path.join(tmp, 'growing.pcap')
                with open(path, 'wb') as sink:
                    sink.write(payload[:split])

                # The file's size at each end of stream the extractor announces.
                sizes = []
                announce = extraction.warn

                def append_at_the_second_end_of_stream(message, *args, **kwargs):
                    if str(message) == 'EOF reached':
                        sizes.append(os.path.getsize(path))
                        if len(sizes) == 2:
                            with open(path, 'ab') as sink:
                                sink.write(payload[split:])
                    return announce(message, *args, **kwargs)

                extraction.warn = append_at_the_second_end_of_stream

                extractor = pcapkit.extract(fin=path, nofile=True, store=False,
                                            auto=False, no_eof=True)
                numbers = [next(extractor).info.number for _ in range(5)]
                assert not sizes, 'end of stream before five frames: ' + repr(sizes)

                numbers += [frame.info.number for frame in extractor]
                # Not vacuous: both ends of stream were met on the five-frame
                # file, and the sixth frame was on disk before the extractor
                # stopped.
                assert sizes[:2] == [split, split], 'no append: ' + repr(sizes)
                assert os.path.getsize(path) == len(payload), os.path.getsize(path)
                assert numbers == [1, 2, 3, 4, 5], numbers

            print('frames ' + repr(numbers), flush=True)
            print({SENTINEL!r}, flush=True)
        """)
        self.assertIn('frames [1, 2, 3, 4, 5]', output)


class EOFProgressSignal(unittest.TestCase):
    """``_note_eof_progress`` on its own, including the case that must still retry.

    A termination condition that always said "stop" would pass every test above
    while quietly reducing ``no_eof`` to a no-op, so the retry-when-the-input-moved
    direction is asserted here explicitly. No capture and no runtime dependencies
    are needed, so these run in the unit tier unconditionally.

    """

    @staticmethod
    def _extractor(position: 'int'):  # type: ignore[no-untyped-def]
        """A bare ``Extractor`` whose input reports ``position``."""
        from pcapkit.foundation.extraction import Extractor

        extractor = object.__new__(Extractor)
        extractor._ifile = types.SimpleNamespace(tell=lambda: position)
        extractor._eof_mark = None
        return extractor

    def test_the_first_end_of_stream_always_retries(self) -> None:
        """Nothing is known yet, so one retry is owed."""
        extractor = self._extractor(605)
        self.assertTrue(extractor._note_eof_progress())
        self.assertEqual(extractor._eof_mark, 605)

    def test_a_standing_still_input_stops(self) -> None:
        """Two ends of stream at one position mean nothing arrived in between."""
        extractor = self._extractor(605)
        self.assertTrue(extractor._note_eof_progress())     # first
        self.assertFalse(extractor._note_eof_progress())    # and no further
        self.assertFalse(extractor._note_eof_progress())

    def test_an_advancing_input_keeps_retrying(self) -> None:
        """A live capture that paused and resumed is not cut short.

        This is the half that makes ``no_eof`` still mean something. Each end of
        stream sits further into the input than the last, so each is followed by
        another retry -- and only the one that stands still stops.

        """
        positions = iter((100, 200, 300, 300))
        extractor = self._extractor(0)
        extractor._ifile = types.SimpleNamespace(tell=lambda: next(positions))

        self.assertTrue(extractor._note_eof_progress())     # 100, first
        self.assertTrue(extractor._note_eof_progress())     # 200, moved on
        self.assertTrue(extractor._note_eof_progress())     # 300, moved on
        self.assertFalse(extractor._note_eof_progress())    # 300 again, finished

    def test_an_input_that_cannot_report_its_position_stops(self) -> None:
        """A stream that cannot be asked where it is cannot be shown to progress.

        Stopping is the safe answer, the alternative being the unbounded loop the
        method exists to end. A closed stream raises :exc:`ValueError` from
        ``tell``, which is reachable if the input is closed under the extraction.

        """
        for label, error in (('closed stream', ValueError), ('unseekable', OSError)):
            with self.subTest(case=label):
                extractor = self._extractor(0)
                extractor._ifile = types.SimpleNamespace(
                    tell=mock.Mock(side_effect=error))
                self.assertFalse(extractor._note_eof_progress())

    def test_a_position_that_went_backwards_stops(self) -> None:
        """Only forward movement counts as progress.

        ``record_header`` seeks the input back to zero before the frames are read,
        so a position going backwards is not evidence that data arrived -- and
        treating it as such would restore the unbounded loop for anything that
        rewinds.

        """
        positions = iter((500, 200))
        extractor = self._extractor(0)
        extractor._ifile = types.SimpleNamespace(tell=lambda: next(positions))

        self.assertTrue(extractor._note_eof_progress())     # 500, first
        self.assertFalse(extractor._note_eof_progress())    # 200, backwards


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class NoEOFStillRetriesAnInputThatGrows(unittest.TestCase):
    """``no_eof`` keeps going while frames are still arriving.

    Driven through ``record_frames`` with a stand-in engine, so the sequence of
    ends of stream and frames is exact: end of stream, then a frame, then end of
    stream twice. The first end of stream must be retried -- otherwise the flag is
    dead -- and the run must still finish.

    """

    def test_record_frames_retries_past_an_end_of_stream_that_yielded_more(self) -> None:
        from pcapkit.foundation.extraction import Extractor

        extractor = object.__new__(Extractor)
        extractor._frnum = 0
        extractor._ifnm = 'growing.pcap'
        extractor._flag_a = True
        extractor._flag_n = True
        extractor._flag_e = False
        extractor._flag_t = False
        extractor._tcp = False
        extractor._flag_s = False
        extractor._eof_mark = None

        # The position advances only across the end of stream that is followed by
        # a frame, which is what a capture being appended to looks like.
        positions = iter((100, 200, 200, 200))
        extractor._ifile = types.SimpleNamespace(tell=lambda: next(positions),
                                                 closed=False,
                                                 close=lambda: None)

        frame = types.SimpleNamespace(info=types.SimpleNamespace(number=1))
        extractor._exeng = types.SimpleNamespace(
            read_frame=mock.Mock(side_effect=[EOFError, frame, EOFError, EOFError]),
            close=mock.Mock(),
        )

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            with time_limit(DEADLINE):
                extractor.record_frames()

        # Four calls: end of stream (retried, position 100), the frame, end of
        # stream (retried, position moved to 200), end of stream (200 again, stop).
        self.assertEqual(extractor._exeng.read_frame.call_count, 4,
                         'the ends of stream that had more behind them should have '
                         'been retried, and the one that did not should not')
        self.assertTrue(extractor._flag_e)


if __name__ == '__main__':
    unittest.main()
