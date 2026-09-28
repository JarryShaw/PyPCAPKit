# -*- coding: utf-8 -*-
"""``python -m pcapkit.vendor`` must fail its exit code when a crawler raises.

GitHub issue #872. Before this change, :func:`pcapkit.vendor.__main__.run`
swallowed every exception a crawler raised -- filed as a merely-filterable
:class:`~pcapkit.utilities.warnings.VendorRuntimeWarning` -- and
:func:`pcapkit.vendor.__main__.main` always ``return 0`` (line 93 pre-fix), with
no accounting of whether any target had failed. Because
:meth:`pcapkit.vendor.default.Vendor.__init__` runs its network fetch and
render *before* the ``open(const_file, 'w')`` on its last line, a failed
crawler writes nothing at all: the previous constant file is left untouched,
one warning is emitted (silently, since
:data:`~pcapkit.utilities.logging.VERBOSE` defaults to :data:`False`), and the
process reports success regardless. A no-op regeneration was therefore
indistinguishable from a real one at the only boundary a CI job or a script
actually checks -- the exit code. This was hit for real during GitHub issue
#870's work, where a docstring edit silently failed to propagate.

The fix makes :func:`~pcapkit.vendor.__main__.run` return whether its target
succeeded, and :func:`~pcapkit.vendor.__main__.main` return ``1`` if *any*
target failed while still attempting every target regardless of an earlier
failure -- a crawler that is down should not stop the rest from regenerating.

This suite exercises the real :func:`~pcapkit.vendor.__main__.main` entrypoint
end to end, with the default (no ``--target``) argument path, rather than
calling :func:`~pcapkit.vendor.__main__.run` directly -- the point is to pin
both ``main()`` itself (what an operator or a workflow actually invokes) and
its exit code, not just the helper function underneath it. It makes **no
network call**:
a stub :class:`~pcapkit.vendor.default.Vendor` subclass overrides
:meth:`~pcapkit.vendor.default.Vendor._request` (the low-level fetch
:meth:`Vendor.__init__` calls first) to raise directly, so the failure is
synthetic and instantaneous rather than a real fetch timing out. The default
target list itself is stubbed too, by patching the
``pcapkit.vendor.__main__.vendor_module`` name :func:`main` reads its
``__all__`` from -- so this suite never imports, runs, or writes anything
under the real 117 crawlers, and touches no file under :file:`pcapkit/const/`.

Run against the pre-fix code (``run()`` ending on a bare ``return None`` and
``main()`` ending on a bare ``return 0``), all 5 methods below fail:
:meth:`~ExitCodeTests.test_run_returns_false_for_a_raising_crawler` (``run()``
returns :data:`None`, not the exact value :data:`False` --
:meth:`~unittest.TestCase.assertIs` is what makes this one discriminate: a
plain :meth:`~unittest.TestCase.assertFalse` would pass on both trees, since
:data:`None` is already falsy),
:meth:`~ExitCodeTests.test_run_returns_true_for_a_clean_crawler` (``run()``
returns :data:`None`, not :data:`True`),
:meth:`~ExitCodeTests.test_main_returns_non_zero_when_a_target_raises` and
:meth:`~ExitCodeTests.test_main_still_attempts_every_target_after_an_earlier_one_fails`
(``main()`` returns ``0``, not ``1``), and
:meth:`~ExitCodeTests.test_failing_target_and_error_reach_stderr_unconditionally`
(with warnings filtered out, pre-fix ``run()`` writes nothing to stderr at
all).

"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import types
import unittest
import warnings
from unittest import mock

#: Same two-dependency gate :file:`tests/vendor/test_crawler_reachability_unit.py`
#: and :file:`tests/vendor/test_vendor_dest_path_unit.py` use. Importing
#: :mod:`pcapkit.vendor.__main__` imports :mod:`pcapkit.vendor` (for the
#: ``vendor_module`` default-target-list fallback this suite patches), which
#: pulls in every crawler subpackage unconditionally --
#: :mod:`pcapkit.vendor.default` imports :mod:`requests` at module scope and
#: seven crawlers import :mod:`bs4` at module scope.
VENDOR_DEPS = ('requests', 'bs4')

#: Whether the crawler machinery is importable at all. Both ship in the
#: ``test`` extra (:file:`pyproject.toml`), so this should not skip in CI; kept
#: as belt-and-braces for an environment that lacks them.
HAS_VENDOR_DEPS = all(importlib.util.find_spec(name) is not None for name in VENDOR_DEPS)


@unittest.skipUnless(HAS_VENDOR_DEPS, f'vendor extra not installed ({", ".join(VENDOR_DEPS)})')
class ExitCodeTests(unittest.TestCase):
    """``run()``/``main()`` exit-code accounting for a raising crawler."""

    def setUp(self) -> None:
        import pcapkit.vendor.__main__ as vendor_main
        from pcapkit.vendor.default import Vendor

        self.vendor_main = vendor_main
        self.Vendor = Vendor

    def _make_failing_crawler(self) -> 'type':
        """A ``Vendor`` subclass that raises before ever touching the network.

        Overrides :meth:`~pcapkit.vendor.default.Vendor._request` -- the first
        thing :meth:`Vendor.__init__` calls -- instead of letting a real fetch
        fail, so this is deterministic and makes no network call.

        """
        Vendor = self.Vendor

        class FailingCrawler(Vendor):
            """Stub crawler for GitHub issue #872 -- always raises, no network."""

            def _request(self) -> 'list[str]':
                raise RuntimeError('stub crawler failure for GitHub issue #872')

        return FailingCrawler

    def _make_succeeding_crawler(self) -> 'type':
        """A ``Vendor`` subclass that records it ran and touches nothing else.

        Overrides ``__init__`` entirely, bypassing
        :meth:`~pcapkit.vendor.default.Vendor.__init__`'s network fetch and
        file write -- this class exists only to prove a *later* target still
        runs after an *earlier* one raised, not to exercise real regeneration.

        """
        Vendor = self.Vendor

        class SucceedingCrawler(Vendor):
            """Stub crawler for GitHub issue #872 -- always succeeds, no I/O."""

            ran = False

            def __init__(self) -> None:  # pylint: disable=super-init-not-called
                type(self).ran = True

        return SucceedingCrawler

    def test_run_returns_false_for_a_raising_crawler(self) -> None:
        failing = self._make_failing_crawler()
        # assertIs, not assertFalse: pre-fix run() returns None, which is
        # merely falsy and would pass an assertFalse on both trees, pinning
        # nothing. The exact value False is what main() actually branches
        # on (`if not run(vendor): success = False`), so this has to check
        # for that literal, not for anything that happens to be falsy.
        self.assertIs(self.vendor_main.run(failing), False,
                     'run() must return the exact value False, not merely something '
                     'falsy, when the crawler raises')

    def test_run_returns_true_for_a_clean_crawler(self) -> None:
        succeeding = self._make_succeeding_crawler()
        self.assertTrue(self.vendor_main.run(succeeding),
                        'run() must report success when the crawler does not raise')

    def test_main_returns_non_zero_when_a_target_raises(self) -> None:
        # The regression this issue is about: pre-fix, main() ends on a bare
        # `return 0` with no accounting at all, so this assertion fails
        # (0 != 1) against origin/main; see the module docstring for the
        # full pre-fix failure list.
        failing = self._make_failing_crawler()
        fake_vendor_module = types.SimpleNamespace(__all__=['FailingCrawler'],
                                                    FailingCrawler=failing)

        with mock.patch.object(self.vendor_main, 'vendor_module', fake_vendor_module), \
             mock.patch('sys.argv', ['pcapkit-vendor']):
            exit_code = self.vendor_main.main()

        self.assertEqual(exit_code, 1,
                         'main() must return 1 (its own documented contract) when its only '
                         'target raised, so a no-op regeneration is distinguishable from a '
                         'real one; see GitHub issue #872')

    def test_main_still_attempts_every_target_after_an_earlier_one_fails(self) -> None:
        # "Regenerate everything you can, then exit non-zero": a crawler that
        # is down must not stop a later, unrelated target from running.
        failing = self._make_failing_crawler()
        succeeding = self._make_succeeding_crawler()
        fake_vendor_module = types.SimpleNamespace(
            __all__=['FailingCrawler', 'SucceedingCrawler'],
            FailingCrawler=failing,
            SucceedingCrawler=succeeding,
        )

        with mock.patch.object(self.vendor_main, 'vendor_module', fake_vendor_module), \
             mock.patch('sys.argv', ['pcapkit-vendor']):
            exit_code = self.vendor_main.main()

        self.assertTrue(succeeding.ran,
                        'a target after a raising one must still be attempted')
        self.assertEqual(exit_code, 1,
                         'a partial failure must still be reported as exit code 1, '
                         "main()'s own documented contract")

    def test_failing_target_and_error_reach_stderr_unconditionally(self) -> None:
        # Point 2 of the issue: VendorRuntimeWarning is filterable and VERBOSE
        # defaults False, so the plain print() run() now does is the only
        # thing guaranteed to reach a CI log regardless of warning filters.
        #
        # Warnings are suppressed here *on purpose*, and that is load-bearing
        # rather than incidental: under the default filter, the pre-existing
        # warn() call already writes both the qualified name and the
        # exception repr to stderr on its own (Python's default "once per
        # location" display of an unfiltered warning), so an unsuppressed run
        # would pass this assertion whether or not the print() line exists --
        # pinning nothing. Only with warnings silenced does the print()
        # become the one thing keeping this assertion true, which is the
        # scenario the comment above (and the issue) is actually about: a CI
        # log that has warnings turned off or filtered.
        failing = self._make_failing_crawler()
        buffer = io.StringIO()
        with contextlib.redirect_stderr(buffer), warnings.catch_warnings():
            warnings.simplefilter('ignore')
            self.vendor_main.run(failing)

        stderr = buffer.getvalue()
        self.assertIn(f'{failing.__module__}.{failing.__name__}', stderr,
                     'the failing target\'s qualified name must reach stderr unconditionally, '
                     'even with warnings filtered out')
        self.assertIn('stub crawler failure for GitHub issue #872', stderr,
                     'the exception repr must reach stderr unconditionally, even with '
                     'warnings filtered out')


if __name__ == '__main__':
    unittest.main()
