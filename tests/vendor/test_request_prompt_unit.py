# -*- coding: utf-8 -*-
"""Regression tests for the manual-intervention prompt in ``Vendor._request``.

GitHub issue #522: the last resort of
:meth:`pcapkit.vendor.default.Vendor._request` -- ask an operator to save the
page by hand -- was a ``while True`` whose only pause was an ``input()`` call
wrapped in ``contextlib.suppress(Exception)``. With nobody at a keyboard that
suppression is what does the damage rather than the loop: ``input()`` raises
instead of blocking, the suppression discards the exception, the file the loop
waits for never appears, and the iteration repeats immediately. Three lines of
output per pass, measured in the issue at **26.7 million lines / 2.6 GB** before
the process was killed. It was never a hang; it was a printer.

``input()`` fails three different ways depending on how ``stdin`` went away, and
the old code suppressed all three identically -- measured on CPython 3.14.7:

* a ``stdin`` at end of file, i.e. redirected from :file:`/dev/null` or a closed
  pipe, raises :exc:`EOFError`;
* a ``stdin`` that has been *closed* raises :exc:`ValueError`;
* a :data:`sys.stdin` that is :obj:`None` raises :exc:`RuntimeError`.

So a test that only closes stdin pins one third of the defect. Worse, the
loudest real-world shape raises **nothing at all**: under ``yes | make vendor``
``input()`` returns ``'y'`` forever, the file still never appears, and the loop
still spins. No amount of exception handling inside the loop catches that one,
which is why the fix has two halves and this module tests both:

1. **A precondition.** :func:`~pcapkit.vendor.default.stdin_is_interactive`
   decides whether there is a terminal at all, and a run without one is failed
   with the fetch error -- exactly as :envvar:`PCAPKIT_CI_MODE` fails it -- before
   a browser is opened, a temporary directory is made, or a word is printed.
   This is the half that covers the piped-stdin case above.
2. **A loop that cannot spin.** Any failure of ``input()`` now ends the wait with
   the original :exc:`requests.RequestException` instead of being discarded. The
   precondition does not make this redundant: a terminal can go away *during* the
   wait -- an SSH session dropping, a parent closing the descriptor -- and that
   lands in exactly the loop the precondition already let the process into.

Two properties are pinned alongside the fix, because a fix for a runaway loop is
easy to overshoot:

* :meth:`ManualIntervenePromptTests.test_saving_the_page_still_completes_the_fetch`
  and :meth:`~ManualIntervenePromptTests.test_the_prompt_still_repeats_until_the_page_appears`
  drive the path an operator actually uses, including the "not saved yet, press
  ENTER again" round trip the loop exists for.
* :meth:`~ManualIntervenePromptTests.test_keyboard_interrupt_still_aborts_as_itself`
  pins that :exc:`KeyboardInterrupt` is *not* swallowed into a fetch error.
  Ctrl-C is how an operator declines, and it is a :exc:`BaseException`, so it
  escaped the old ``suppress(Exception)`` and must keep escaping the new
  ``except Exception``.

**No case here can wedge the suite, and none of them relies on a timeout to say
so.** :func:`_fake_input` answers a bounded number of prompts and then raises
:class:`_Runaway`, which derives from :exc:`BaseException` precisely so that
neither the old ``suppress(Exception)`` nor the new ``except Exception`` can
catch it: against the unfixed code a case fails in milliseconds with a message
naming the defect, rather than printing until something kills it.
:func:`~tests._support.time_limit` is layered on top as a backstop for a fix that
found some *other* way not to terminate. Standard output is captured throughout,
so the bounded flood is counted rather than spilled into the test report.

Nothing here makes a network call: ``requests.get`` is replaced for the whole of
each case, and :meth:`~ManualIntervenePromptTests.test_a_successful_fetch_never_consults_stdin`
asserts the quiet direction -- that a crawler which *can* fetch never reaches any
of this.

The suite is unit-tier (see :mod:`tests._tiers`): it reads no capture.

"""
from __future__ import annotations

import builtins
import contextlib
import glob
import importlib.util
import io
import os
import pathlib
import sys
import tempfile
import unittest
import warnings
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import purge_modules, time_limit

if TYPE_CHECKING:
    from typing import Any, Iterator

#: Repository root, i.e. the grandparent of the directory holding this file.
ROOT = pathlib.Path(__file__).resolve().parents[2]

#: Every distribution importing :mod:`pcapkit.vendor` needs. Copied from
#: :file:`tests/vendor/test_user_agent_unit.py`, and for its reason: ``requests``
#: alone is not enough, because importing :mod:`pcapkit.vendor.default` imports the
#: :mod:`pcapkit.vendor` package first and its :file:`__init__.py` pulls in
#: subpackages that ``import bs4`` at module scope.
VENDOR_DEPS = ('requests', 'bs4', 'html5lib')

#: Whether the crawlers are importable at all. They ship in the ``vendor`` extra
#: (:file:`pyproject.toml`), not ``test`` -- so these cases skip on the ``test``
#: and ``gate`` jobs of :file:`.github/workflows/unit-tests.yml`, but run for
#: real on ``engine-tests``, which installs ``vendor`` too (#738).
#: Guarded the way :file:`tests/protocols/test_dispatch_registry_unit.py` guards
#: its own optional dependencies rather than making the whole unit tier depend on
#: the crawlers'.
HAS_VENDOR_DEPS = all(importlib.util.find_spec(name) is not None for name in VENDOR_DEPS)

#: How many prompts :func:`_fake_input` will answer before it decides the loop is
#: never going to end. Small enough that the unfixed code's output stays in the
#: tens of lines, large enough that no legitimate case comes near it -- the most
#: any test here needs is two.
PROMPT_BUDGET = 16

#: Whole seconds one case may take, as a backstop under
#: :func:`~tests._support.time_limit`. Every case here is sub-millisecond work;
#: the deadline exists for a regression that finds a way to not terminate which
#: :data:`PROMPT_BUDGET` does not bound.
CASE_TIMEOUT = 10

#: Page body the fake fetches and the fake operator produce. Distinctive so that
#: a test asserting on it cannot be satisfied by an empty string.
PAGE = '<html><body>registry-522</body></html>'


class _Runaway(BaseException):
    """Raised by :func:`_fake_input` once the prompt budget is exhausted.

    Derives from :exc:`BaseException` rather than :exc:`Exception` on purpose.
    The code under test used to wrap its ``input()`` call in
    ``contextlib.suppress(Exception)`` and now wraps it in ``except Exception``;
    a sentinel either of those could catch would be swallowed and the loop would
    carry on spinning, which is the failure this class exists to report. Only a
    :exc:`BaseException` escapes both and reaches the test.

    """


class _Response:
    """The parts of :class:`requests.Response` that ``_request`` looks at."""

    def __init__(self, text: 'str' = PAGE, ok: 'bool' = True) -> 'None':
        self.ok = ok
        self.text = text


class _Stdin:
    """A stand-in for :data:`sys.stdin` whose ``isatty`` the caller dictates.

    Args:
        answer: What ``isatty()`` returns, or an exception for it to raise.
            A real ``stdin`` offers no way to vary this, which is the whole
            reason the fake exists.

    """

    def __init__(self, answer: 'Any') -> 'None':
        self.answer = answer

    def isatty(self) -> 'bool':
        if isinstance(self.answer, BaseException):
            raise self.answer
        return self.answer


def _fake_input(*replies: 'Any', limit: 'int' = PROMPT_BUDGET) -> 'tuple[Any, list[str]]':
    """A bounded stand-in for :func:`input`, and the log of its prompts.

    Each element of ``replies`` answers the corresponding call: a string is
    returned, an exception instance is raised, and a callable is called and its
    result returned -- which is how a test plays the operator who saves the page
    between one ENTER and the next. The final element repeats for every later
    call, so a test that means "always EOF" passes one exception rather than
    guessing how many times it will be asked.

    Past ``limit`` calls the stand-in raises :class:`_Runaway` instead. That is
    what makes a case against the unfixed code fail in milliseconds with a
    diagnosis rather than printing until it is killed, and it is why no case here
    depends on a timeout to detect the runaway loop.

    Args:
        replies: What to answer, in order; the last repeats.
        limit: Calls to answer before declaring the loop unbounded.

    Returns:
        The replacement callable, and the list its prompts accumulate in -- so a
        test can assert on *how many times* the operator was asked, which is the
        quantity the defect was about.

    """
    calls = []  # type: list[str]

    def fake(prompt: 'str' = '') -> 'str':
        calls.append(prompt)
        if len(calls) > limit:
            raise _Runaway(
                f'input() was answered {limit} times and the manual-intervention '
                f'wait still had not ended: the loop is unbounded (#522)')
        reply = replies[min(len(calls), len(replies)) - 1]
        if isinstance(reply, BaseException):
            raise reply
        if callable(reply):
            return reply()
        return reply

    return fake, calls


@unittest.skipUnless(HAS_VENDOR_DEPS, f'vendor extra not installed ({", ".join(VENDOR_DEPS)})')
class StdinInteractivityTests(unittest.TestCase):
    """:func:`~pcapkit.vendor.default.stdin_is_interactive` on every shape of stdin.

    The predicate is what keeps a piped or redirected run out of the
    manual-intervention path altogether, and the cases that matter are the ones
    where asking is itself an error -- a closed ``stdin``, an absent one. A
    predicate that raised would turn the crawler's fetch failure into an
    unrelated traceback, so each of those is pinned to :obj:`False` rather than
    left to whatever ``isatty()`` happened to do.

    """

    if TYPE_CHECKING:
        default: 'Any'

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

        import pcapkit.vendor.default as default

        resolved = pathlib.Path(default.__file__).resolve()
        if ROOT not in resolved.parents:
            self.skipTest(f'{default.__name__} was imported from {resolved}, which is outside '
                          f'{ROOT}; install this checkout with `pip install -e .` to run this '
                          f'suite against it')
        self.default = default

    def _verdict(self, stdin: 'Any') -> 'bool':
        with mock.patch.object(sys, 'stdin', stdin):
            return self.default.stdin_is_interactive()

    def test_a_terminal_is_interactive(self) -> None:
        self.assertTrue(self._verdict(_Stdin(True)))

    def test_a_pipe_or_redirect_is_not_interactive(self) -> None:
        # The ``make vendor``-under-a-pipe case, and the one the precondition
        # exists for: nothing raises, so only ``isatty()`` can tell.
        self.assertFalse(self._verdict(_Stdin(False)))

    def test_an_absent_stdin_is_not_interactive(self) -> None:
        # ``sys.stdin`` is None under a GUI launcher such as pythonw; ``input()``
        # then raises RuntimeError('lost sys.stdin'), so there is nobody to ask.
        self.assertFalse(self._verdict(None))

    def test_a_closed_stdin_is_not_interactive(self) -> None:
        # A closed file object raises ValueError from isatty() rather than
        # answering it, so the predicate must not propagate that.
        handle = io.StringIO('')
        handle.close()
        self.assertFalse(self._verdict(handle))

    def test_a_stdin_without_isatty_is_not_interactive(self) -> None:
        # Nothing in the data model obliges a replacement ``sys.stdin`` to offer
        # isatty(); an AttributeError here would crash the crawler in place of
        # reporting the fetch failure it was already handling.
        self.assertFalse(self._verdict(object()))

    def test_a_stdin_whose_isatty_fails_is_not_interactive(self) -> None:
        self.assertFalse(self._verdict(_Stdin(OSError(5, 'Input/output error'))))


@unittest.skipUnless(HAS_VENDOR_DEPS, f'vendor extra not installed ({", ".join(VENDOR_DEPS)})')
class ManualIntervenePromptTests(unittest.TestCase):
    """``_request``'s last resort, driven with every fetch already failed."""

    if TYPE_CHECKING:
        default: 'Any'
        requests: 'Any'

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

        import requests

        import pcapkit.vendor.default as default

        # The module has to come from this checkout for the assertions to mean
        # anything: a copy imported from an installed distribution elsewhere would
        # be tested instead of the one being changed. That is an environment
        # mismatch rather than a defect, hence a skip.
        resolved = pathlib.Path(default.__file__).resolve()
        if ROOT not in resolved.parents:
            self.skipTest(f'{default.__name__} was imported from {resolved}, which is outside '
                          f'{ROOT}; install this checkout with `pip install -e .` to run this '
                          f'suite against it')

        self.default = default
        self.requests = requests

    def _crawler(self, link: 'str' = 'https://example.invalid/registry') -> 'Any':
        """A throwaway crawler with a ``LINK``, built without touching the disk.

        ``Vendor.__init__`` fetches *and writes a constant module* as a side
        effect of construction, which a test has no business doing to the working
        tree, so the two attributes ``_request`` needs are set by hand. ``request``
        is reduced to the identity, so whatever text the method ends up with comes
        straight back and can be asserted on.

        """
        class _Crawler(self.default.Vendor):  # type: ignore[name-defined,misc]
            FLAG = 'isinstance(value, int)'
            LINK = link

            def count(self, data: 'Any') -> 'Any':
                import collections
                return collections.Counter()

            def request(self, text: 'str') -> 'str':  # type: ignore[override]
                return text

            def process(self, data: 'Any') -> 'Any':
                return [], []

        crawler = _Crawler.__new__(_Crawler)
        crawler.NAME = 'Runaway522'
        crawler.DOCS = 'throwaway'
        return crawler

    @contextlib.contextmanager
    def _cornered(self, interactive: 'bool' = True, ci_mode: 'bool' = False,
                  reply: 'Any' = None, browser: 'bool' = False) -> 'Iterator[dict[str, Any]]':
        """Corner ``_request`` into the manual-intervention branch, and watch it.

        Every fetch raises, :func:`~pcapkit.vendor.default.get_proxies` finds
        nothing so the proxy branch re-raises immediately, and both of the
        decisions the branch then makes are dictated rather than inherited from
        the machine running the tests: ``CI_MODE`` because it is read from the
        environment at import time, and ``stdin_is_interactive`` because a test
        runner's ``stdin`` is a pipe under CI and a terminal on a laptop, which
        would otherwise make the same case pass for opposite reasons.

        Args:
            interactive: What ``stdin_is_interactive`` reports.
            ci_mode: What ``CI_MODE`` holds.
            reply: Response to return from ``requests.get`` instead of raising,
                for the one case that checks the quiet path.
            browser: What :func:`webbrowser.open` reports. A real one answers
                whichever way the machine running the tests happens to be set up,
                which would leave one of the two instruction wordings untested on
                every machine and the other untested on none.

        Yields:
            A mapping of what was observed: ``error`` is the very
            :exc:`requests.RequestException` instance the fake fetch raised, so a
            test can assert the *same object* surfaced rather than merely one of
            its type; ``fetches`` the URLs asked for; ``opened`` the links handed
            to :func:`webbrowser.open`; ``out`` the captured standard output; and
            ``warnings`` the recorded warning messages.

        """
        boom = self.requests.exceptions.RequestException('no route to host')
        fetches = []  # type: list[Any]
        opened = []  # type: list[Any]
        out = io.StringIO()

        def fake_get(url: 'Any' = None, **kwargs: 'Any') -> 'Any':
            fetches.append(url)
            if reply is None:
                raise boom
            return reply

        def fake_open(link: 'Any' = None, *args: 'Any', **kwargs: 'Any') -> 'bool':
            opened.append(link)
            return browser

        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(self.requests, 'get', fake_get))
            stack.enter_context(mock.patch.object(self.default, 'get_proxies', return_value={}))
            stack.enter_context(mock.patch.object(self.default, 'CI_MODE', ci_mode))
            stack.enter_context(mock.patch.object(self.default, 'stdin_is_interactive',
                                                  return_value=interactive))
            stack.enter_context(mock.patch.object(self.default.webbrowser, 'open', fake_open))
            stack.enter_context(contextlib.redirect_stdout(out))
            log = stack.enter_context(warnings.catch_warnings(record=True))
            warnings.simplefilter('always')

            observed = {'error': boom, 'fetches': fetches, 'opened': opened,
                        'out': out, 'warnings': log}
            yield observed
            observed['messages'] = [str(entry.message) for entry in log]

    @contextlib.contextmanager
    def _in_scratch_directory(self) -> 'Iterator[str]':
        """Run the body with the process cwd inside a throwaway directory.

        ``_request`` creates its temporary directory under ``os.curdir``, which is
        the repository root when the suite is run from there. A case that lets it
        do so -- i.e. one that reaches the prompt at all -- runs from a scratch
        directory instead, so a crash between ``mkdtemp`` and its cleanup cannot
        leave ``pcapkit-*-tempdir`` behind in the working tree.

        """
        original = os.getcwd()
        with tempfile.TemporaryDirectory(prefix='pcapkit-tests-522-') as scratch:
            os.chdir(scratch)
            try:
                yield scratch
            finally:
                os.chdir(original)

    def _save_the_page(self) -> 'Any':
        """An operator who saves the page the instructions asked for.

        Returns a zero-argument callable suitable as a :func:`_fake_input` reply.
        The path is discovered by globbing for the temporary directory
        ``_request`` just made under the cwd, rather than by reproducing the way
        the method names it -- a test that hard-coded the layout would pass while
        the printed instructions pointed somewhere else.

        Anything that goes wrong here is re-raised as :class:`_Runaway`, and that
        is not fussiness: this callable runs *inside* the ``input()`` call, so an
        :exc:`AssertionError` or an :exc:`OSError` out of it would be caught by the
        very ``except Exception`` under test and reported as a connection failure,
        hiding the real problem behind the symptom the test was written for.

        """
        def save() -> 'str':
            candidates = glob.glob(os.path.join(os.getcwd(), 'pcapkit-*-tempdir'))
            if len(candidates) != 1:
                raise _Runaway(f'expected exactly one temporary directory under '
                               f'{os.getcwd()!r}, found {candidates}')
            try:
                with open(os.path.join(candidates[0], 'Runaway522.html'), 'w') as file:
                    file.write(PAGE)
            except OSError as exc:
                raise _Runaway(f'could not play the operator saving the page: {exc}') from exc
            return ''
        return save

    # -- the defect ----------------------------------------------------------

    def test_a_stdin_at_eof_ends_the_wait_instead_of_spinning(self) -> None:
        # The heart of #522. ``stdin_is_interactive`` is forced True so that the
        # precondition cannot be what saves this -- the loop itself has to end.
        # Against the unfixed code the EOFError is suppressed, the file never
        # appears, and the prompt is re-asked until _fake_input gives up.
        crawler = self._crawler()
        prompt, calls = _fake_input(EOFError('EOF when reading a line'))

        with self._in_scratch_directory():
            with self._cornered(interactive=True) as observed:
                with mock.patch.object(builtins, 'input', prompt):
                    with time_limit(CASE_TIMEOUT):
                        with self.assertRaises(self.requests.RequestException) as caught:
                            crawler._request()  # pylint: disable=protected-access

        self.assertIs(caught.exception, observed['error'],
                      'the fetch failure should surface unchanged, as under CI_MODE')
        self.assertEqual(len(calls), 1,
                         f'the operator was asked {len(calls)} times after stdin had already '
                         f'reported EOF; one refusal is enough to know nobody is there')
        self.assertNotIn('File not found', observed['out'].getvalue(),
                         'the loop printed its retry notice, so it went round again')

    def test_every_way_input_can_fail_ends_the_wait(self) -> None:
        # ``input()`` reports an unusable stdin three different ways, measured on
        # CPython 3.14.7, and the old ``suppress(Exception)`` discarded all three
        # alike. Pinning only EOFError would leave two thirds of the defect live,
        # so each is driven separately -- a subTest rather than one loop body, so
        # the exit code names which shape regressed.
        failures = {
            'EOFError': EOFError('EOF when reading a line'),
            'ValueError': ValueError('I/O operation on closed file'),
            'RuntimeError': RuntimeError('lost sys.stdin'),
        }
        for label, failure in failures.items():
            with self.subTest(failure=label):
                crawler = self._crawler()
                prompt, calls = _fake_input(failure)

                with self._in_scratch_directory():
                    with self._cornered(interactive=True) as observed:
                        with mock.patch.object(builtins, 'input', prompt):
                            with time_limit(CASE_TIMEOUT):
                                with self.assertRaises(self.requests.RequestException) as caught:
                                    crawler._request()  # pylint: disable=protected-access

                self.assertIs(caught.exception, observed['error'])
                self.assertEqual(len(calls), 1)

    def test_the_prompt_failure_is_chained_as_the_cause(self) -> None:
        # The fetch error is what a caller should see and handle, but *why* the
        # manual path gave up must not be thrown away with it -- otherwise the
        # traceback says "no route to host" and nothing about there being no
        # terminal, which is the more actionable of the two.
        crawler = self._crawler()
        failure = EOFError('EOF when reading a line')
        prompt, _ = _fake_input(failure)

        with self._in_scratch_directory():
            with self._cornered(interactive=True):
                with mock.patch.object(builtins, 'input', prompt):
                    with time_limit(CASE_TIMEOUT):
                        with self.assertRaises(self.requests.RequestException) as caught:
                            crawler._request()  # pylint: disable=protected-access

        self.assertIs(caught.exception.__cause__, failure)

    def test_a_non_interactive_run_never_reaches_the_prompt(self) -> None:
        # The half of the fix no in-loop exception handling can cover: under
        # ``yes | make vendor`` the prompt returns 'y' forever and raises nothing,
        # so the loop has to be *not entered*. Everything the branch would have
        # done as a side effect is asserted absent, since each is wasted or
        # misleading with nobody watching: no browser, no temporary directory, no
        # instructions printed to a log nobody reads.
        crawler = self._crawler()
        prompt, calls = _fake_input('y')

        with self._in_scratch_directory() as scratch:
            with self._cornered(interactive=False) as observed:
                with mock.patch.object(builtins, 'input', prompt):
                    with time_limit(CASE_TIMEOUT):
                        with self.assertRaises(self.requests.RequestException) as caught:
                            crawler._request()  # pylint: disable=protected-access
            leftovers = glob.glob(os.path.join(scratch, 'pcapkit-*-tempdir'))

        self.assertIs(caught.exception, observed['error'])
        self.assertEqual(calls, [], 'a process with no terminal was prompted anyway')
        self.assertEqual(observed['opened'], [],
                         'a browser was opened for a session with no terminal')
        self.assertEqual(leftovers, [],
                         'a temporary directory was created for a page nobody could save')
        self.assertEqual(observed['out'].getvalue(), '',
                         'instructions were printed where nobody can act on them')
        self.assertTrue(any('stdin is not interactive' in message
                            for message in observed['messages']),
                        f'nothing explained the refusal; warnings were {observed["messages"]}')

    def test_ci_mode_still_decides_before_stdin_is_consulted(self) -> None:
        # CI_MODE was already correct and stays the first gate, so a CI job that
        # happens to run on an allocated tty keeps failing fast. Driven with
        # ``interactive=True`` precisely so that only the CI_MODE branch can be
        # what ends the call.
        crawler = self._crawler()
        prompt, calls = _fake_input('')

        with self._in_scratch_directory():
            with self._cornered(interactive=True, ci_mode=True) as observed:
                with mock.patch.object(builtins, 'input', prompt):
                    with time_limit(CASE_TIMEOUT):
                        with self.assertRaises(self.requests.RequestException) as caught:
                            crawler._request()  # pylint: disable=protected-access

        self.assertIs(caught.exception, observed['error'])
        self.assertIsNone(caught.exception.__cause__,
                          'CI_MODE re-raises the fetch error directly, with no prompt to blame')
        self.assertEqual(calls, [])
        self.assertEqual(observed['opened'], [])
        self.assertTrue(any('exit on CI mode' in message for message in observed['messages']),
                        f'warnings were {observed["messages"]}')

    def test_keyboard_interrupt_still_aborts_as_itself(self) -> None:
        # Ctrl-C is how an operator declines the manual path, and it must stay a
        # KeyboardInterrupt rather than being folded into a network error --
        # "connection failed" would be an outright lie about what happened.
        #
        # This one passes on the unfixed code too, and is here deliberately:
        # KeyboardInterrupt is a BaseException and so escaped the old
        # ``suppress(Exception)`` exactly as it escapes the new
        # ``except Exception``. It guards the fix against overshooting into
        # ``except BaseException``, which is the natural over-correction.
        crawler = self._crawler()
        prompt, calls = _fake_input(KeyboardInterrupt())

        with self._in_scratch_directory():
            with self._cornered(interactive=True):
                with mock.patch.object(builtins, 'input', prompt):
                    with time_limit(CASE_TIMEOUT):
                        with self.assertRaises(KeyboardInterrupt):
                            crawler._request()  # pylint: disable=protected-access

        self.assertEqual(len(calls), 1)

    # -- the path an operator actually uses ----------------------------------

    def test_saving_the_page_still_completes_the_fetch(self) -> None:
        # A fix for a runaway loop is easy to overshoot into one that never
        # waits at all, so the working path is pinned: one ENTER, with the page
        # saved where the instructions said, and the text comes back.
        crawler = self._crawler()
        prompt, calls = _fake_input(self._save_the_page())

        with self._in_scratch_directory():
            with self._cornered(interactive=True) as observed:
                with mock.patch.object(builtins, 'input', prompt):
                    with time_limit(CASE_TIMEOUT):
                        text = crawler._request()  # pylint: disable=protected-access

        self.assertEqual(text, PAGE)
        self.assertEqual(len(calls), 1)
        self.assertEqual(observed['opened'], [crawler.LINK],
                         'the browser was not offered the page to open')
        printed = observed['out'].getvalue()
        self.assertIn('Please navigate to the following address', printed,
                      'webbrowser.open reported failure, so the address should be printed')
        self.assertNotIn('File not found', printed)

    def test_an_opened_browser_shortens_the_instructions(self) -> None:
        # The other half of the ``if flag:`` the instructions are chosen by. Both
        # wordings have to say where to save the file -- the whole path is useless
        # without it -- and only the failed-to-open one needs to spell out the URL,
        # since a browser that opened is already showing the page.
        crawler = self._crawler()
        prompt, calls = _fake_input(self._save_the_page())

        with self._in_scratch_directory():
            with self._cornered(interactive=True, browser=True) as observed:
                with mock.patch.object(builtins, 'input', prompt):
                    with time_limit(CASE_TIMEOUT):
                        text = crawler._request()  # pylint: disable=protected-access

        self.assertEqual(text, PAGE)
        self.assertEqual(len(calls), 1)
        printed = observed['out'].getvalue()
        self.assertIn('Please save the page source at', printed)
        self.assertNotIn('Please navigate to the following address', printed,
                         'the address was printed even though the browser opened it')
        self.assertIn('Runaway522.html', printed,
                      'the instructions never said where to save the page')

    def test_the_prompt_still_repeats_until_the_page_appears(self) -> None:
        # The reason the loop is a loop: an operator who presses ENTER too early
        # is told the file is not there and asked again. Losing this would turn a
        # mistimed keystroke into a failed crawl.
        crawler = self._crawler()
        prompt, calls = _fake_input('', self._save_the_page())

        with self._in_scratch_directory():
            with self._cornered(interactive=True) as observed:
                with mock.patch.object(builtins, 'input', prompt):
                    with time_limit(CASE_TIMEOUT):
                        text = crawler._request()  # pylint: disable=protected-access

        self.assertEqual(text, PAGE)
        self.assertEqual(len(calls), 2,
                         'the second ENTER, after the page was saved, should have been read')
        self.assertEqual(observed['out'].getvalue().count('File not found'), 1,
                         'the retry notice should be printed once per premature ENTER')

    def test_a_successful_fetch_never_consults_stdin(self) -> None:
        # The quiet direction, and the cheapest regression to introduce: a
        # precondition evaluated too early would make every crawler depend on
        # having a terminal, breaking the CI job that works today.
        crawler = self._crawler()
        prompt, calls = _fake_input(_Runaway('input() was called on the happy path'))

        with self._cornered(reply=_Response()) as observed:
            with mock.patch.object(self.default, 'stdin_is_interactive',
                                   side_effect=_Runaway('stdin was consulted on the happy path')):
                with mock.patch.object(builtins, 'input', prompt):
                    with time_limit(CASE_TIMEOUT):
                        text = crawler._request()  # pylint: disable=protected-access

        self.assertEqual(text, PAGE)
        self.assertEqual(observed['fetches'], [crawler.LINK])
        self.assertEqual(calls, [])
        self.assertEqual(observed['opened'], [])


if __name__ == '__main__':
    unittest.main()
