# -*- coding: utf-8 -*-
"""The tier guard's diagnostic survives running under pytest-xdist.

:func:`tests.conftest.pytest_collection_modifyitems` raises :exc:`pytest.UsageError`
with a detailed diagnostic when a unit-tier module reads a generated capture. Under
``-n auto --dist load`` that message used to be lost entirely: each xdist worker
runs this hook inside its own nested :program:`pytest` session
(:mod:`xdist.remote`), and that session's ``pytest_collection_finish`` fires from a
``finally:`` regardless of the ``UsageError``, so the controller sees what looks
like a normal collection and may schedule a test to a worker that is already
unwinding. The controller then reports that test as crashed --
``assert not crashitem`` in :mod:`xdist.dsession` -- which prints an
``INTERNALERROR`` instead of the diagnostic and describes the violation as a
worker crash rather than as the tier-guard failure it is.

The fix is to set ``session.shouldfail`` before raising, but only inside a worker
(``hasattr(config, 'workerinput')``): that is the signal the controller already
knows how to shut a worker down on cleanly, with no crash-item assertion, and it is
a no-op outside a worker so the serial path is untouched.

:class:`CollectionModifyItemsXdistTests` pins the hook's own logic directly and
runs unconditionally. :class:`XdistSubprocessTests` reproduces the original bug
end-to-end with a real violation and a real ``pytest -n auto --dist load``
invocation, and skips when :mod:`xdist` is not importable -- the repository venv
this suite normally runs under deliberately has no xdist installed.

A second, independent race lives at the same address. :mod:`tests.test_tier_guard`'s
``SuiteIsCleanTests`` walks the whole :file:`tests/` tree looking for exactly the
kind of violation :class:`XdistSubprocessTests` deliberately writes to disk; under
``-n auto --dist load`` pytest-xdist may run the two in different worker processes
at the same moment, and the scan then reports a violation nobody committed --
measured on a real CI run, ``Integration Python 3.13``, one leg in five, 466s in.
:func:`tests.conftest._tier_guard_lock` closes it with a readers-writer mutex:
:class:`XdistSubprocessTests` below takes the exclusive hold in ``setUp`` for as
long as the probe sits on disk, and :func:`tests.conftest._tier_guard_reader_lock`
takes the shared hold on behalf of every other unit-tier test, including
``SuiteIsCleanTests``, without that module's own source changing at all.
:class:`ProbeWriteLockTests` pins the mutex itself, independently of xdist.

Kept separate from :mod:`tests.test_tier_guard`, which another change is already
modifying: this module touches none of its code, only :mod:`tests.conftest`.

"""
from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import textwrap
import threading
import unittest
import unittest.mock

from tests import _tiers, conftest as _conftest

#: Capture name the probe module in :class:`XdistSubprocessTests` reads. Not
#: tracked by git -- see :func:`tests._tiers.committed_captures` -- so it is a
#: tier violation regardless of what ``make samples`` has built locally.
_GENERATED_CAPTURE = 'xdist_probe_generated.pcap'

#: Diagnostic text that must survive however the suite is run, per
#: :func:`tests.conftest.pytest_collection_modifyitems`.
_DIAGNOSTIC_MARKER = 'read(s) of a generated sample capture'


class _FakeSession:
    """Stands in for :class:`pytest.Session`; the hook touches only this attribute."""

    def __init__(self) -> None:
        self.shouldfail = False  # type: 'bool | str'


class _FakeConfig:
    """Stands in for :class:`pytest.Config`.

    ``workerinput`` is set only by :mod:`xdist.remote` inside an actual worker
    process, and its mere presence -- never its content -- is what the hook
    checks; see ``xdist/remote.py``'s bootstrap, which does
    ``config.workerinput = workerinput``.

    """

    def __init__(self, is_worker: bool) -> None:
        if is_worker:
            self.workerinput = {'workerid': 'gw0'}  # type: dict[str, str]


class CollectionModifyItemsXdistTests(unittest.TestCase):
    """:func:`tests.conftest.pytest_collection_modifyitems` against a fake worker."""

    def _findings(self, session: '_FakeSession', config: '_FakeConfig') -> 'str':
        """Run the hook with one synthetic finding and return the raised message.

        ``_audit`` and ``guard_unavailable_reason`` are patched so the outcome
        depends only on the ``if findings:`` branch under test, never on whether
        this checkout's own git state happens to be clean.

        """
        with unittest.mock.patch.object(_conftest, 'guard_unavailable_reason',
                                         return_value=None), \
             unittest.mock.patch.object(_conftest, '_audit',
                                         return_value=['a synthetic finding']):
            with self.assertRaises(Exception) as caught:
                _conftest.pytest_collection_modifyitems(
                    session=session, config=config, items=[])
        self.assertIsInstance(caught.exception, Exception)
        return str(caught.exception)

    def test_worker_context_sets_shouldfail_before_raising(self) -> None:
        """Inside a worker, the diagnostic is also stashed on ``session.shouldfail``.

        Fails on the code before this change: ``session.shouldfail`` stays at its
        initial :data:`False` because nothing ever assigns to it.

        """
        session = _FakeSession()
        message = self._findings(session, _FakeConfig(is_worker=True))

        self.assertEqual(session.shouldfail, message)
        self.assertIn(_DIAGNOSTIC_MARKER, message)
        self.assertIn('a synthetic finding', message)

    def test_serial_context_leaves_shouldfail_untouched(self) -> None:
        """Outside a worker, behaviour is exactly what it was before this change."""
        session = _FakeSession()
        message = self._findings(session, _FakeConfig(is_worker=False))

        self.assertIs(session.shouldfail, False)
        self.assertIn(_DIAGNOSTIC_MARKER, message)


def _child_environ() -> 'dict[str, str]':
    """The environment a subprocess :program:`pytest` run should inherit.

    Same rationale as :func:`tests.project.test_module_isolation.child_environ`:
    the child must import the tree this test runs from, and must not inherit this
    process's own pytest session variables.

    """
    environ = dict(os.environ)
    environ['PYTHONPATH'] = os.pathsep.join(
        [str(_tiers.ROOT), environ['PYTHONPATH']] if environ.get('PYTHONPATH')
        else [str(_tiers.ROOT)]
    )
    environ.pop('PYTEST_ADDOPTS', None)
    environ.pop('PYTEST_CURRENT_TEST', None)
    return environ


@unittest.skipUnless(importlib.util.find_spec('xdist') is not None,
                      'pytest-xdist not installed')
class XdistSubprocessTests(unittest.TestCase):
    """End-to-end reproduction: a real violation, a real ``pytest`` subprocess.

    Skipped whenever the interpreter running this suite has no ``xdist`` to
    import -- true of the repository's own venv by design, so this class
    contributes nothing there and everything under a venv that has xdist
    installed, such as the one used to verify this fix.

    """

    #: Sorts late and is unambiguously a probe, in case a stray copy is ever left
    #: behind by an interrupted run. Kept as an alias of
    #: :data:`tests.conftest.PROBE_MODULE_NAME` rather than a second literal --
    #: that name is what tells :func:`tests.conftest._tier_guard_reader_lock` to
    #: leave this class's own writes unlocked, and the two must never drift.
    PROBE_NAME = _conftest.PROBE_MODULE_NAME

    def setUp(self) -> None:
        reason = _tiers.guard_unavailable_reason()
        if reason is not None:
            self.skipTest(f'git cannot answer here: {reason}')

        self.probe_path = _tiers.TESTS_ROOT / 'protocols' / self.PROBE_NAME
        self.assertFalse(
            self.probe_path.exists(),
            f'{self.probe_path} already exists -- a previous run did not clean up',
        )

        # Exclusive for as long as the probe sits on disk: see
        # tests.conftest._tier_guard_lock for the SuiteIsCleanTests race this
        # closes under -n auto --dist load. Entered manually, rather than with
        # a `with` block around the rest of setUp, because the hold has to
        # outlive this method and span the test body and cleanup too; released
        # only after the probe is gone -- addCleanup runs LIFO, so registering
        # the release first and the unlink second is what makes the unlink run
        # while still holding the lock and the release run after it.
        lock = _conftest._tier_guard_lock(exclusive=True)
        lock.__enter__()
        self.addCleanup(lock.__exit__, None, None, None)

        source = textwrap.dedent(f"""
            import unittest

            from tests._support import sample_path


            class ProbeTierViolationTests(unittest.TestCase):
                def test_reads_a_generated_capture_with_no_handler(self) -> None:
                    self.assertTrue(sample_path({_GENERATED_CAPTURE!r}))
            """).lstrip('\n')
        self.probe_path.write_text(source, encoding='utf-8')
        self.addCleanup(self.probe_path.unlink, missing_ok=True)

    def _run(self, *extra_args: str) -> 'subprocess.CompletedProcess[str]':
        selection = str(self.probe_path.relative_to(_tiers.ROOT))
        return subprocess.run(
            [sys.executable, '-m', 'pytest', '-p', 'no:cacheprovider', '-q',
             *extra_args, selection],
            cwd=str(_tiers.ROOT), env=_child_environ(), capture_output=True,
            text=True, timeout=120, check=False,
        )

    def test_serial_run_reports_the_diagnostic_and_fails(self) -> None:
        completed = self._run()
        output = completed.stdout + completed.stderr

        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(output.count(_DIAGNOSTIC_MARKER), 1)
        self.assertNotIn('INTERNALERROR', output)

    def test_xdist_run_reports_the_diagnostic_and_fails(self) -> None:
        """The reproduction this change exists for.

        Fails on the code before this change: the run exits non-zero from an
        ``INTERNALERROR`` (``assert not crashitem`` in ``xdist/dsession.py``,
        naming the probe's test id) and ``_DIAGNOSTIC_MARKER`` never appears.

        """
        completed = self._run('-n', '2', '--dist', 'load')
        output = completed.stdout + completed.stderr

        self.assertNotEqual(completed.returncode, 0)
        self.assertGreaterEqual(output.count(_DIAGNOSTIC_MARKER), 1)
        self.assertNotIn('INTERNALERROR', output)
        self.assertNotIn('crashitem', output)


class ProbeWriteLockTests(unittest.TestCase):
    """:func:`tests.conftest._tier_guard_lock` actually excludes a concurrent reader.

    Independent of :mod:`xdist` and of the two classes above: it exercises the
    mutex directly, with a background thread standing in for a concurrent
    worker process. :func:`fcntl.flock` locks are per open file description,
    not per process or thread, so a conflict between two file descriptors
    opened by two threads of one process is the same conflict pytest-xdist's
    separate worker processes would see -- this is not a weaker stand-in for
    the real race, it is the identical kernel mechanism at smaller scale.

    Runs unconditionally in the venv this suite normally runs under: unlike
    :class:`XdistSubprocessTests`, nothing here needs ``xdist`` importable, only
    :mod:`fcntl`, so this is the case that actually exercises the mutex on the
    interpreter without ``xdist`` installed.

    """

    @unittest.skipUnless(_conftest.fcntl is not None,
                          'fcntl unavailable on this platform')
    def test_a_concurrent_reader_waits_out_the_writer(self) -> None:
        """A shared hold cannot be granted while the exclusive one is live.

        Fails on the code before this change: :func:`tests.conftest._tier_guard_lock`
        does not exist yet, so there is nothing to import and nothing to wait on.

        """
        reader_acquired = threading.Event()
        reader_errors = []  # type: list[BaseException]

        def reader() -> None:
            try:
                with _conftest._tier_guard_lock(exclusive=False):
                    reader_acquired.set()
            except BaseException as exc:  # pylint: disable=broad-except
                reader_errors.append(exc)

        with _conftest._tier_guard_lock(exclusive=True):
            thread = threading.Thread(target=reader)
            thread.start()
            # Every chance for the reader to have raced ahead if the writer's
            # hold did not actually exclude it.
            got_it_early = reader_acquired.wait(timeout=0.5)
            self.assertFalse(
                got_it_early,
                'a concurrent reader acquired the shared lock while the writer still held it',
            )

        thread.join(timeout=5)
        self.assertFalse(reader_errors, reader_errors)
        self.assertTrue(
            reader_acquired.wait(timeout=5),
            'the reader never acquired the lock after the writer released it',
        )
