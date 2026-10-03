"""Regression tests for the ``sys.tracebacklimit`` leak in a loud ``BaseError``.

GitHub issue #719: :class:`~pcapkit.utilities.exceptions.BaseError` set
:data:`sys.tracebacklimit` to ``0`` for every loud error outside development
mode, and nothing ever restored it. The attribute is process-global, so after
one pcapkit error every subsequent traceback in the *process* was truncated --
including exceptions that have nothing to do with :mod:`pcapkit`. Measured
against the tree before this fix::

    DEVMODE: False
    before                    hasattr(sys, 'tracebacklimit') = False
    after one loud IntError   hasattr = True, value = 0
    then, unrelated:  [][5] -> IndexError
       traceback.extract_tb(...) -> 0 frames

The fix removes the assignment outright and produces the same terse, one-line
output for a loud error through an exception hook instead --
:func:`pcapkit.utilities.exceptions._excepthook`, installed lazily by
:func:`pcapkit.utilities.exceptions._install_excepthook` the first time a loud
error actually needs it. A hook only shortens the printing of the exception it
recognises as its own; it does not reach into how :mod:`traceback`, or any other
code, formats a *different* exception, which is what let the old mechanism leak
in the first place.

A hook is awkward to probe from inside the very process that installs it --
:data:`sys.excepthook` only fires for an exception that reaches the real
interpreter uncaught, which a ``self.assertRaises`` block never lets happen. Most
of what follows therefore drives a fresh interpreter with :mod:`subprocess` and
reads its ``stderr``, exercising the actual printing path rather than a
simulation of it. The tests that only check *state* -- whether
``sys.tracebacklimit`` or ``sys.excepthook`` were touched at all -- stay
in-process, via the same ``bootstrap``/``capture`` harness the rest of this
directory uses.

"""
from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import threading
import unittest

from tests._support import purge_modules
from tests.utilities._harness import bootstrap, capture

#: Repository root -- three directories up from this file
#: (``tests/utilities/test_exceptions_excepthook.py``). Passed to the child
#: interpreter as ``PYTHONPATH`` explicitly, rather than relied on via the
#: current working directory: ``PYTHONSAFEPATH=1`` strips the cwd from
#: ``sys.path``, so a bare ``PYTHONPATH``-less invocation would silently import
#: whatever ``pcapkit`` happens to be installed, not this checkout.
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def run_in_subprocess(code: 'str', devmode: 'bool' = False) -> 'subprocess.CompletedProcess[str]':
    """Run ``code`` in a fresh interpreter against *this* checkout of :mod:`pcapkit`.

    Prepends an assertion that the ``pcapkit`` the child imports lives under
    :data:`REPO_ROOT` -- not some other copy on the path -- so a green test here
    actually proves something about the tree under review rather than about
    whatever happens to be on ``sys.path`` by default.

    """
    preamble = textwrap.dedent(f'''
        import pcapkit
        assert pcapkit.__file__.startswith({REPO_ROOT!r}), (
            'wrong tree', pcapkit.__file__, {REPO_ROOT!r})
    ''')
    env = dict(os.environ)
    env['PCAPKIT_DEVMODE'] = '1' if devmode else '0'
    env['PYTHONSAFEPATH'] = '1'
    env['PYTHONPATH'] = REPO_ROOT
    return subprocess.run([sys.executable, '-c', preamble + textwrap.dedent(code)],
                          capture_output=True, text=True, env=env, timeout=30)


class UnrelatedTracebackSurvivesALoudErrorTests(unittest.TestCase):
    """The regression itself, live and reproducible against the pre-fix tree."""

    def test_unrelated_exception_keeps_its_frames_after_a_loud_error(self) -> None:
        code = '''
            import traceback
            import pcapkit.utilities.exceptions as exc
            exc.logger.disabled = True

            try:
                raise exc.IntError('boom')
            except exc.IntError:
                pass

            def inner():
                raise ValueError('an exception with nothing to do with pcapkit')
            def middle():
                inner()

            try:
                middle()
            except ValueError:
                import sys as _sys
                etype, value, tb = _sys.exc_info()
                print(len(traceback.extract_tb(tb)))
        '''
        proc = run_in_subprocess(code)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        frame_count = int(proc.stdout.strip())
        self.assertGreater(frame_count, 0,
                           'traceback.extract_tb returned 0 frames for an exception '
                           'that has nothing to do with pcapkit, raised after a loud '
                           'pcapkit error -- the #719 tracebacklimit leak is back')


class TracebacklimitNeverSetTests(unittest.TestCase):
    """No path -- loud or quiet, in development mode or out of it -- sets the limit.

    Folded in with the same matrix: *which* paths install the replacement
    hooks -- both of them, :data:`sys.excepthook` and
    :data:`threading.excepthook`. Only one of the four combinations should -- a
    loud error outside development mode -- and the other three must leave both
    exactly as they found them.

    """

    def setUp(self) -> None:
        self._saved_devmode = os.environ.get('PCAPKIT_DEVMODE')
        self._had_tracebacklimit = hasattr(sys, 'tracebacklimit')
        self._saved_tracebacklimit = getattr(sys, 'tracebacklimit', None)
        self._saved_excepthook = sys.excepthook
        self._saved_threading_excepthook = threading.excepthook

    def tearDown(self) -> None:
        if self._had_tracebacklimit:
            sys.tracebacklimit = self._saved_tracebacklimit
        elif hasattr(sys, 'tracebacklimit'):
            del sys.tracebacklimit
        sys.excepthook = self._saved_excepthook
        threading.excepthook = self._saved_threading_excepthook
        if self._saved_devmode is None:
            os.environ.pop('PCAPKIT_DEVMODE', None)
        else:
            os.environ['PCAPKIT_DEVMODE'] = self._saved_devmode
        purge_modules(['pcapkit'])

    def test_no_combination_of_quiet_and_devmode_sets_tracebacklimit(self) -> None:
        for devmode in (False, True):
            for quiet in (False, True):
                with self.subTest(devmode=devmode, quiet=quiet):
                    if hasattr(sys, 'tracebacklimit'):
                        del sys.tracebacklimit
                    # Clean slate each iteration, so one subTest installing the
                    # hook cannot make a later one's "did it install?" check
                    # ambiguous via the already-marked guard in
                    # ``_install_excepthook``.
                    sys.excepthook = self._saved_excepthook
                    threading.excepthook = self._saved_threading_excepthook

                    modules = bootstrap(devmode=devmode)
                    exceptions = modules['exceptions']
                    logger = modules['logging'].logger

                    with capture(logger):
                        exceptions.BaseError('boom', quiet=quiet)

                    self.assertFalse(hasattr(sys, 'tracebacklimit'))

                    if quiet or devmode:
                        self.assertIsNone(
                            exceptions._previous_excepthook,
                            'a quiet error, or one in development mode, must not '
                            'install the exception hook')
                        self.assertIsNone(
                            exceptions._previous_threading_excepthook,
                            'a quiet error, or one in development mode, must not '
                            'install the threading hook either')
                        self.assertIs(sys.excepthook, self._saved_excepthook)
                        self.assertIs(threading.excepthook, self._saved_threading_excepthook)
                    else:
                        self.assertIs(exceptions._previous_excepthook, self._saved_excepthook)
                        self.assertIs(exceptions._previous_threading_excepthook,
                                      self._saved_threading_excepthook)
                        self.assertTrue(getattr(sys.excepthook, 'installed_by_pcapkit', False))
                        self.assertTrue(getattr(threading.excepthook, 'installed_by_pcapkit', False))


class LoudErrorPrintsOneLineTests(unittest.TestCase):
    def test_a_loud_base_error_reaching_the_hook_prints_one_line(self) -> None:
        code = '''
            import pcapkit.utilities.exceptions as exc
            exc.logger.disabled = True
            raise exc.IntError('boom')
        '''
        proc = run_in_subprocess(code)
        self.assertNotEqual(proc.returncode, 0)
        lines = [line for line in proc.stderr.splitlines() if line.strip()]
        self.assertEqual(len(lines), 1, proc.stderr)
        self.assertIn('IntError: boom', lines[0])
        self.assertNotIn('Traceback', proc.stderr)

    def test_development_mode_keeps_the_full_traceback(self) -> None:
        """The terse form is the outside-DEVMODE behaviour only."""
        code = '''
            import pcapkit.utilities.exceptions as exc
            exc.logger.disabled = True
            raise exc.IntError('boom')
        '''
        proc = run_in_subprocess(code, devmode=True)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn('Traceback (most recent call last):', proc.stderr)
        self.assertIn('IntError: boom', proc.stderr)


class ChainingTests(unittest.TestCase):
    def test_a_non_base_error_is_delegated_to_the_previously_installed_hook(self) -> None:
        code = '''
            import sys
            import pcapkit.utilities.exceptions as exc
            exc.logger.disabled = True

            def previous_hook(etype, value, tb):
                print('PREVIOUS_HOOK_RAN', file=sys.stderr)
                sys.__excepthook__(etype, value, tb)
            sys.excepthook = previous_hook

            try:
                raise exc.IntError('boom')
            except exc.IntError:
                pass

            # Confirm pcapkit's own hook is now what is actually installed,
            # before raising the exception the assertions below are about.
            # Without this, the assertions would also pass on code with no
            # hook mechanism at all: previous_hook would simply still *be*
            # sys.excepthook, unmoved, and would answer the raise directly --
            # nothing would have delegated to it, the marker would appear for
            # free, and the test would prove nothing about chaining.
            print('INSTALLED:', getattr(sys.excepthook, 'installed_by_pcapkit', False),
                  file=sys.stderr)
            print('IS_PCAPKIT_HOOK:', sys.excepthook is exc._excepthook, file=sys.stderr)
            print('PREVIOUS_IS_PREVIOUS_HOOK:', exc._previous_excepthook is previous_hook,
                  file=sys.stderr)

            raise ValueError('route through previous_hook')
        '''
        proc = run_in_subprocess(code)
        self.assertIn('INSTALLED: True', proc.stderr)
        self.assertIn('IS_PCAPKIT_HOOK: True', proc.stderr)
        self.assertIn('PREVIOUS_IS_PREVIOUS_HOOK: True', proc.stderr)
        self.assertIn('PREVIOUS_HOOK_RAN', proc.stderr)
        self.assertIn('ValueError: route through previous_hook', proc.stderr)
        # The thing actually being delegated to is the previous hook, not just
        # something that happens to print the same traceback regardless.
        self.assertNotIn('IntError', proc.stderr.split('PREVIOUS_HOOK_RAN')[-1])


class ChainedExceptionTests(unittest.TestCase):
    """A chained exception must come out in the *shape* ``tracebacklimit = 0``
    produced, not just "one line".

    ``traceback.print_exception(etype, value, None)`` -- the hook's first
    draft -- discards only the *top* exception's own traceback by handing in
    ``tb=None``; it never touches ``value.__cause__`` or ``value.__context__``,
    each of which carries its *own*, real ``__traceback__`` that
    :func:`traceback.print_exception` walks and prints in full regardless,
    since no ``limit`` was given for it to apply there either. The old
    ``sys.tracebacklimit = 0`` applied to the whole chain, because
    :func:`traceback.StackSummary.extract` -- which every link's formatting
    goes through -- consults the global itself, independently, at every link.
    ``limit=0`` against the *real* traceback (not ``None``) is what reaches
    every link the same way, and is what the two tests below compare against:
    not a one-line assertion, but the exact text ``sys.tracebacklimit = 0``
    would have produced for the same exception, chain included.

    """

    def test_an_explicit_from_chain_matches_the_old_shape(self) -> None:
        code = '''
            import contextlib
            import io
            import sys
            import pcapkit.utilities.exceptions as exc
            exc.logger.disabled = True

            def build():
                try:
                    1 / 0
                except ZeroDivisionError as err:
                    raise exc.IntError('wrapped explicitly') from err

            def old_mechanism_output():
                try:
                    build()
                except exc.IntError:
                    etype, value, tb = sys.exc_info()
                sys.tracebacklimit = 0
                buf = io.StringIO()
                with contextlib.redirect_stderr(buf):
                    sys.__excepthook__(etype, value, tb)
                del sys.tracebacklimit
                return buf.getvalue()

            def new_mechanism_output():
                try:
                    build()
                except exc.IntError:
                    etype, value, tb = sys.exc_info()
                buf = io.StringIO()
                with contextlib.redirect_stderr(buf):
                    exc._excepthook(etype, value, tb)
                return buf.getvalue()

            old = old_mechanism_output()
            new = new_mechanism_output()
            if old == new:
                print('MATCH')
            else:
                print('MISMATCH')
                print('old:', repr(old))
                print('new:', repr(new))
        '''
        proc = run_in_subprocess(code)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.strip(), 'MATCH', proc.stdout)

    def test_an_implicit_context_chain_matches_the_old_shape(self) -> None:
        code = '''
            import contextlib
            import io
            import sys
            import pcapkit.utilities.exceptions as exc
            exc.logger.disabled = True

            def build():
                try:
                    1 / 0
                except ZeroDivisionError:
                    raise exc.IntError('wrapped implicitly')  # no `from` -- implicit context

            def old_mechanism_output():
                try:
                    build()
                except exc.IntError:
                    etype, value, tb = sys.exc_info()
                sys.tracebacklimit = 0
                buf = io.StringIO()
                with contextlib.redirect_stderr(buf):
                    sys.__excepthook__(etype, value, tb)
                del sys.tracebacklimit
                return buf.getvalue()

            def new_mechanism_output():
                try:
                    build()
                except exc.IntError:
                    etype, value, tb = sys.exc_info()
                buf = io.StringIO()
                with contextlib.redirect_stderr(buf):
                    exc._excepthook(etype, value, tb)
                return buf.getvalue()

            old = old_mechanism_output()
            new = new_mechanism_output()
            if old == new:
                print('MATCH')
            else:
                print('MISMATCH')
                print('old:', repr(old))
                print('new:', repr(new))
        '''
        proc = run_in_subprocess(code)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.strip(), 'MATCH', proc.stdout)


class DoubleInstallTests(unittest.TestCase):
    def test_installing_twice_does_not_double_print(self) -> None:
        code = '''
            import pcapkit.utilities.exceptions as exc
            exc.logger.disabled = True

            exc._install_excepthook()
            exc._install_excepthook()

            raise exc.IntError('boom')
        '''
        proc = run_in_subprocess(code)
        lines = [line for line in proc.stderr.splitlines() if line.strip()]
        self.assertEqual(len(lines), 1, proc.stderr)

    def test_installing_twice_does_not_wrap_itself(self) -> None:
        code = '''
            import sys
            import pcapkit.utilities.exceptions as exc
            exc.logger.disabled = True

            def previous_hook(etype, value, tb):
                print('PREVIOUS_HOOK_RAN', file=sys.stderr)
                sys.__excepthook__(etype, value, tb)
            sys.excepthook = previous_hook

            exc._install_excepthook()
            first = sys.excepthook
            exc._install_excepthook()
            second = sys.excepthook
            print('SAME_HOOK' if first is second else 'DIFFERENT_HOOK')
            print('PREVIOUS_IS_MY_HOOK' if exc._previous_excepthook is previous_hook
                  else 'PREVIOUS_IS_SOMETHING_ELSE')
        '''
        proc = run_in_subprocess(code)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('SAME_HOOK', proc.stdout)
        self.assertIn('PREVIOUS_IS_MY_HOOK', proc.stdout)

    def test_a_reentrant_delegate_falls_back_instead_of_recursing(self) -> None:
        """A delegate that routes back through the hook must not loop forever."""
        code = '''
            import pcapkit.utilities.exceptions as exc
            exc.logger.disabled = True
            exc._install_excepthook()

            calls = []
            def exploding_delegate(etype, value, tb):
                calls.append(1)
                if len(calls) > 3:
                    raise RecursionError('would spin forever without the guard')
                exc._excepthook(etype, value, tb)
            exc._previous_excepthook = exploding_delegate

            exc._excepthook(ValueError, ValueError('boom'), None)
            print(len(calls))
        '''
        proc = run_in_subprocess(code)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(int(proc.stdout.strip()), 1)


class CrossInstanceReinstallTests(unittest.TestCase):
    """A fresh module instance must install *over* a stale instance's hook.

    GitHub pull request #983: CI caught this one. ``_install_excepthook``'s guard used
    to skip installing whenever :data:`sys.excepthook` already carried the
    ``installed_by_pcapkit`` marker -- a plain ``True``, identical on *every*
    reloaded copy of :func:`~pcapkit.utilities.exceptions._excepthook`, so it
    could not tell "my own instance already installed" from "some *other*,
    possibly long-gone instance did". A worker that had already run some other
    test touching a loud :class:`~pcapkit.utilities.exceptions.BaseError` left
    exactly that: a marked hook with no live module behind it any more. The
    next instance's own :func:`~pcapkit.utilities.exceptions._install_excepthook`
    then saw the marker, concluded there was nothing to do, and left
    ``_previous_excepthook`` at :data:`None` -- never actually installing
    *its own* hook at all.

    This reproduces that directly: install a first instance's hook, drop that
    instance (:func:`tests._support.purge_modules`, same as a reload would),
    then bootstrap a second instance and require it to install over the first
    one's still-active hook rather than mistaking it for its own.

    """

    def setUp(self) -> None:
        self._saved_devmode = os.environ.get('PCAPKIT_DEVMODE')
        self._saved_excepthook = sys.excepthook
        self._saved_threading_excepthook = threading.excepthook

    def tearDown(self) -> None:
        sys.excepthook = self._saved_excepthook
        threading.excepthook = self._saved_threading_excepthook
        if self._saved_devmode is None:
            os.environ.pop('PCAPKIT_DEVMODE', None)
        else:
            os.environ['PCAPKIT_DEVMODE'] = self._saved_devmode
        purge_modules(['pcapkit'])

    def test_a_fresh_instance_installs_over_a_stale_instance_hook(self) -> None:
        # ``capture()`` alone is enough to keep this quiet -- it swaps the
        # logger's handlers out and restores them in a ``finally``. Setting
        # ``logger.disabled`` directly instead, as an earlier revision of this
        # test did, would not be: ``logging.getLogger(name)`` hands back the
        # *same* cached singleton regardless of how many times this module is
        # reloaded, so disabling it here without restoring it would silence
        # every other test in the process sharing that name afterwards --
        # exactly the class of leak this file exists to catch, just aimed at a
        # different piece of global state.
        first = bootstrap(devmode=False)['exceptions']
        with capture(first.logger):
            first.BaseError('boom')

        self.assertIs(sys.excepthook, first._excepthook,
                      'precondition: the first instance must have installed')
        self.assertIs(threading.excepthook, first._threading_excepthook,
                      'precondition: the first instance must have installed the '
                      'threading hook too')

        # Drop the first instance the way a reload would -- its hook is still
        # the live sys.excepthook, but nothing in sys.modules points at the
        # module that installed it any more.
        purge_modules(['pcapkit'])

        second = bootstrap(devmode=False)['exceptions']
        with capture(second.logger):
            second.BaseError('boom')

        self.assertIs(sys.excepthook, second._excepthook,
                      'the second instance must install its own hook rather than '
                      'mistaking the stale first one for its own')
        self.assertIs(second._previous_excepthook, first._excepthook,
                      'the stale hook must be captured and chained through, not '
                      'silently dropped')
        self.assertIs(threading.excepthook, second._threading_excepthook,
                      'the second instance must install its own threading hook too')
        self.assertIs(second._previous_threading_excepthook, first._threading_excepthook,
                      'the stale threading hook must be captured and chained '
                      'through as well')


class ThreadingExcepthookTests(unittest.TestCase):
    """The thread analogue of :class:`LoudErrorPrintsOneLineTests` and friends.

    :data:`threading.excepthook` needed its own hook for a reason distinct from
    "symmetry with :data:`sys.excepthook`": the interpreter's *default*
    :data:`threading.excepthook` itself consults :data:`sys.tracebacklimit`
    when printing, so removing the global without replacing it on this side too
    would have *regressed* a loud :class:`~pcapkit.utilities.exceptions.BaseError`
    on a worker thread from one line to a full default traceback -- the
    opposite of this change's purpose. Measured: 2 lines with
    ``sys.tracebacklimit = 0`` in place, 12 without it and without this hook.

    """

    def test_a_loud_base_error_on_a_thread_matches_the_old_two_line_shape(self) -> None:
        code = '''
            import io
            import sys
            import threading
            import contextlib
            import pcapkit.utilities.exceptions as exc
            exc.logger.disabled = True

            error = exc.IntError('boom on a thread', quiet=True)

            def old_mechanism_output(name):
                def boom():
                    raise error
                captured = io.StringIO()
                saved_hook = threading.excepthook
                threading.excepthook = threading.__excepthook__
                sys.tracebacklimit = 0
                try:
                    t = threading.Thread(target=boom, name=name)
                    with contextlib.redirect_stderr(captured):
                        t.start()
                        t.join()
                finally:
                    del sys.tracebacklimit
                    threading.excepthook = saved_hook
                return captured.getvalue()

            def new_mechanism_output(name):
                exc._install_excepthook()
                def boom():
                    raise error
                captured = io.StringIO()
                t = threading.Thread(target=boom, name=name)
                with contextlib.redirect_stderr(captured):
                    t.start()
                    t.join()
                return captured.getvalue()

            old = old_mechanism_output('CompareWorker')
            new = new_mechanism_output('CompareWorker')
            if old == new:
                print('MATCH')
            else:
                print('MISMATCH')
                print('old:', repr(old))
                print('new:', repr(new))
        '''
        proc = run_in_subprocess(code)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.strip(), 'MATCH', proc.stdout)

    def test_a_chained_error_on_a_thread_also_matches_the_old_shape(self) -> None:
        code = '''
            import io
            import sys
            import threading
            import contextlib
            import pcapkit.utilities.exceptions as exc
            exc.logger.disabled = True

            def build_chained_error():
                try:
                    1 / 0
                except ZeroDivisionError as err:
                    error = exc.IntError('wrapped on a thread', quiet=True)
                    error.__cause__ = err
                    return error

            error = build_chained_error()

            def old_mechanism_output(name):
                def boom():
                    raise error
                captured = io.StringIO()
                saved_hook = threading.excepthook
                threading.excepthook = threading.__excepthook__
                sys.tracebacklimit = 0
                try:
                    t = threading.Thread(target=boom, name=name)
                    with contextlib.redirect_stderr(captured):
                        t.start()
                        t.join()
                finally:
                    del sys.tracebacklimit
                    threading.excepthook = saved_hook
                return captured.getvalue()

            def new_mechanism_output(name):
                exc._install_excepthook()
                def boom():
                    raise error
                captured = io.StringIO()
                t = threading.Thread(target=boom, name=name)
                with contextlib.redirect_stderr(captured):
                    t.start()
                    t.join()
                return captured.getvalue()

            old = old_mechanism_output('ChainedWorker')
            new = new_mechanism_output('ChainedWorker')
            if old == new:
                print('MATCH')
            else:
                print('MISMATCH')
                print('old:', repr(old))
                print('new:', repr(new))
        '''
        proc = run_in_subprocess(code)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.strip(), 'MATCH', proc.stdout)

    def test_a_non_base_error_on_a_thread_is_delegated_to_the_previous_hook(self) -> None:
        code = '''
            import sys
            import threading
            import pcapkit.utilities.exceptions as exc
            exc.logger.disabled = True

            def previous_hook(args):
                print('PREVIOUS_THREADING_HOOK_RAN', file=sys.stderr)
                threading.__excepthook__(args)
            threading.excepthook = previous_hook

            try:
                raise exc.IntError('boom')
            except exc.IntError:
                pass

            print('INSTALLED:', getattr(threading.excepthook, 'installed_by_pcapkit', False),
                  file=sys.stderr)
            print('IS_PCAPKIT_HOOK:', threading.excepthook is exc._threading_excepthook,
                  file=sys.stderr)

            def unrelated():
                raise ValueError('route through previous_hook')

            t = threading.Thread(target=unrelated)
            t.start()
            t.join()
        '''
        proc = run_in_subprocess(code)
        self.assertIn('INSTALLED: True', proc.stderr)
        self.assertIn('IS_PCAPKIT_HOOK: True', proc.stderr)
        self.assertIn('PREVIOUS_THREADING_HOOK_RAN', proc.stderr)
        self.assertIn('ValueError: route through previous_hook', proc.stderr)
        self.assertNotIn('IntError', proc.stderr.split('PREVIOUS_THREADING_HOOK_RAN')[-1])

    def test_installing_twice_does_not_wrap_the_threading_hook_either(self) -> None:
        code = '''
            import sys
            import threading
            import pcapkit.utilities.exceptions as exc
            exc.logger.disabled = True

            def previous_hook(args):
                print('PREVIOUS_THREADING_HOOK_RAN', file=sys.stderr)
                threading.__excepthook__(args)
            threading.excepthook = previous_hook

            exc._install_excepthook()
            first = threading.excepthook
            exc._install_excepthook()
            second = threading.excepthook
            print('SAME_HOOK' if first is second else 'DIFFERENT_HOOK')
            print('PREVIOUS_IS_MY_HOOK' if exc._previous_threading_excepthook is previous_hook
                  else 'PREVIOUS_IS_SOMETHING_ELSE')
        '''
        proc = run_in_subprocess(code)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('SAME_HOOK', proc.stdout)
        self.assertIn('PREVIOUS_IS_MY_HOOK', proc.stdout)

    def test_a_reentrant_threading_delegate_falls_back_instead_of_recursing(self) -> None:
        """The per-thread guard, not the main-thread one, protects this path."""
        code = '''
            import sys
            import threading
            import pcapkit.utilities.exceptions as exc
            exc.logger.disabled = True
            exc._install_excepthook()

            calls = []
            def exploding_delegate(args):
                calls.append(1)
                if len(calls) > 3:
                    raise RecursionError('would spin forever without the guard')
                exc._threading_excepthook(args)
            exc._previous_threading_excepthook = exploding_delegate

            try:
                raise ValueError('boom')
            except ValueError:
                etype, value, tb = sys.exc_info()
            args = threading.ExceptHookArgs([etype, value, tb, threading.current_thread()])
            exc._threading_excepthook(args)
            print(len(calls))
        '''
        proc = run_in_subprocess(code)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(int(proc.stdout.strip()), 1)

    def test_two_threads_raising_concurrently_do_not_confuse_each_others_guard(self) -> None:
        """The per-thread (not shared) re-entrancy flag, under real concurrency.

        A shared ``_excepthook_running``-style flag would make one thread's
        hook see the *other* thread's unrelated, concurrent call as if it were
        its own re-entrancy, and wrongly fall back instead of printing tersely.
        Both threads block on the same barrier immediately after entering the
        hook (via a slow delegate that waits on it), so neither can finish
        before the other has also entered -- forcing the overlap this guards
        against, rather than hoping for it.

        """
        code = '''
            import sys
            import threading
            import pcapkit.utilities.exceptions as exc
            exc.logger.disabled = True
            exc._install_excepthook()

            barrier = threading.Barrier(2)
            results = {}

            def slow_delegate(args):
                # Hold this thread inside the hook until the other thread has
                # also entered it, so the two calls genuinely overlap.
                barrier.wait(timeout=5)
            exc._previous_threading_excepthook = slow_delegate

            def worker(name):
                try:
                    raise exc.IntError(f'boom from {name}')
                except exc.IntError:
                    etype, value, tb = sys.exc_info()
                args = threading.ExceptHookArgs([etype, value, tb, threading.current_thread()])
                # A BaseError does not reach slow_delegate at all -- it is
                # printed directly -- so route a *non*-BaseError through this
                # thread's own call to actually exercise the shared guard
                # object instead, which is the thing under test.
                non_base_args = threading.ExceptHookArgs(
                    [ValueError, ValueError(f'from {name}'), None, threading.current_thread()])
                exc._threading_excepthook(non_base_args)
                results[name] = 'completed without raising'

            threads = [threading.Thread(target=worker, args=(f'T{i}',)) for i in range(2)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=10)

            print(len(results), 'threads completed')
            for name, outcome in sorted(results.items()):
                print(name, outcome)
        '''
        proc = run_in_subprocess(code)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('2 threads completed', proc.stdout)
        self.assertIn('T0 completed without raising', proc.stdout)
        self.assertIn('T1 completed without raising', proc.stdout)


if __name__ == '__main__':
    unittest.main()
