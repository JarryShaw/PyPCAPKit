# -*- coding: utf-8 -*-
"""Run one unit-tier directory under plain :mod:`unittest`, in a single process.

GitHub issue #981: two test modules --
:mod:`tests.protocols.application.test_http_unit` and
:mod:`tests.test_base_class_contract` -- each pass alone and :program:`pytest`
reports the whole run green when they are collected together, but plain
:mod:`unittest` over the same two modules in one process fails -- four
``subTest`` cases. ``pytest-subtests`` is *not* why: that plugin is not
installed in this project at all (absent from the ``test`` extra in
``pyproject.toml``), and plain :program:`pytest` (9.1.1 in this checkout)
already reports a failed ``subTest`` as its own top-level ``SUBFAILED`` entry
rather than folding it into a passing parent -- confirmed here with a
synthetic two-``subTest`` probe that pytest reported as two separate
failures. The real cause (fixed separately, in
:mod:`tests.test_base_class_contract`) is cross-module ``pcapkit`` reimport
pollution that :mod:`tests.conftest`'s autouse ``restore_module_table``
fixture reconciles after every test -- but only under :program:`pytest`,
because that fixture lives in a ``conftest.py`` that plain :mod:`unittest`
never loads. Without it, whatever a sibling module's
:func:`tests._support.purge_modules` leaves behind survives into the next
module run in the same process.

That is this script's whole reason to exist: it is not a faster or stricter
pytest, it is a *different* test runner, chosen because plain
:mod:`unittest` never loads ``tests/conftest.py`` and so gets none of the
reconciliation :func:`tests.conftest.restore_module_table` performs -- the
same reconciliation that, under ordinary pytest, is what let #981's defect
through undetected. A ``subTest`` failure under
:class:`unittest.TextTestRunner` is a top-level ``FAIL``/``ERROR``, counted
and printed, with no autouse fixture smoothing the import table out from
under it.

A cheaper alternative exists, and is recorded here rather than left
undocumented: running ``pytest --noconftest`` over just those same two
modules, in that order, disables the very same autouse fixture directly and
reproduces the identical four ``subTest`` failures in about 70s on the pre-fix
tree, under the exact :program:`pytest` version this CI already installs.
Whether that single invocation would have been sufficient instead of this
dedicated runner and its per-directory matrix was not evaluated when this
script was written; this paragraph records that gap rather than inventing a
reason for the choice after the fact.

Scope, and why it stops where it does
--------------------------------------

The whole suite in one process is not an option -- it OOMs at 29 GB on the
machine this was diagnosed on. This script instead runs one :file:`tests/`
subdirectory per invocation (its ``directory`` argument), which is what
:file:`.github/workflows/unit-tests.yml`'s ``unittest-ordering`` job calls
once per entry of its own matrix -- the leg list lives in that workflow, not
as a module-level constant here. :mod:`tests.protocols` is the largest leg,
measured in that workflow's own comment at 847s serially. At the other end sit
two legs of two unit-tier modules each, with no clean ordering between them --
:mod:`tests.dumpkit` (199 tests, ~39s) and :mod:`tests.interface` (201 tests,
~37s), dumpkit carrying two fewer tests but running two seconds slower.
Neither small leg is :mod:`tests.const` (478 tests, ~268s), which is larger on
both axes.

Peak RSS was measured for the three cheapest legs only, via
:func:`resource.getrusage` on ``RUSAGE_CHILDREN`` in this venv:
:mod:`tests.cli` 152 MiB, :mod:`tests.dumpkit` 237 MiB, :mod:`tests.interface`
305 MiB. No figure was taken for the larger legs, and that workflow comment's
table carries wall times only, no RSS -- but the largest of the three is still
some 90x short of 29 GB, which is enough to place the OOM on running
*everything* in one process rather than on any one directory.

Every module :func:`root_modules` returns runs in *every* invocation, after the
directory's own modules -- not before, and not interleaved. Issue #981's own
reproduction is a sibling module (``tests.protocols.application.test_http_unit``)
*polluting* a root-level module (:mod:`tests.test_base_class_contract`) that
runs after it in the same process; ``tests.test_base_class_contract`` first and
the directory second would never reproduce that shape, because the pollution
would land after the sensitive module had already made its assertions and
finished. Running the directory first and the root modules second is what gives
any purging module in that directory a chance to desync a root module that
assumes its own import is current -- matching the reproduction exactly for
``protocols`` and ``const``, and giving the same opportunity to every other
directory this script is pointed at, most of which have never been tried in
that configuration before.

What this still does not catch: a defect running the *other* direction (a
root module polluting a directory module), interference between two
directories neither of which is bundled with the other in the same leg, and
anything that only manifests with the fixture-dependent tier
(:data:`tests._tiers.FIXTURE_TIER_DIRS`) alongside it -- ``tests/integration/``
is deliberately never one of the ``unittest-ordering`` job's matrix legs
(defined in :file:`.github/workflows/unit-tests.yml`, not in this module),
both because it needs generated captures this script does not build and
because it is already run whole, under :program:`pytest`, by the
``integration`` job.

"""
from __future__ import annotations

import argparse
import pathlib
import sys
import time
import unittest

#: Repository root -- resolved from this file's own location, not from the
#: working directory or ``PYTHONPATH``, so this script runs the same way
#: whether it is invoked as ``python util/run_unittest_leg.py ...`` from the
#: repository root (what CI does) or from anywhere else.
ROOT = pathlib.Path(__file__).resolve().parents[1]
TESTS_ROOT = ROOT / 'tests'

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests._tiers import is_unit_tier  # noqa: E402  pylint: disable=wrong-import-position

#: Root-level modules bundled, in this order, into *every* leg -- see the
#: module docstring for why they run after the directory's own modules rather
#: than before or interleaved. Discovered rather than hand-listed, so a new
#: ``tests/test_*.py`` file is picked up without this script changing.
#:
#: ``tests.test_tier_guard_xdist`` is excluded on purpose: with
#: ``pytest-xdist`` installed (the ``test`` extra pulls it in, and this
#: script's own CI job installs that extra for the other root modules'
#: sake), its ``XdistSubprocessTests`` spawns a real, deliberately slow
#: ``pytest -n auto --dist load`` subprocess that the pytest-based
#: ``test``/``integration``/``gate`` jobs already exercise -- duplicating
#: that cost here would buy nothing against the ordering class of defect
#: this script exists to catch.
_EXCLUDED_ROOT_MODULES = frozenset({'tests.test_tier_guard_xdist'})


def _dotted(path: 'pathlib.Path') -> 'str':
    """``path`` as the dotted module name :class:`unittest.TestLoader` wants."""
    return '.'.join(path.relative_to(ROOT).with_suffix('').parts)


def root_modules() -> 'tuple[str, ...]':
    """Every root-level ``tests/test_*.py`` module but the excluded one."""
    return tuple(sorted(
        name for name in (_dotted(path) for path in sorted(TESTS_ROOT.glob('test_*.py')))
        if name not in _EXCLUDED_ROOT_MODULES
    ))


def leg_modules(directory: 'str') -> 'tuple[str, ...]':
    """Every unit-tier ``test_*.py`` module under ``tests/<directory>``.

    Args:
        directory: name of a direct subdirectory of :data:`TESTS_ROOT`.

    Returns:
        Dotted module names, in path-sorted order.

    Raises:
        SystemExit: ``directory`` is not a subdirectory of :data:`TESTS_ROOT`.

    """
    leg_root = TESTS_ROOT / directory
    if not leg_root.is_dir():
        raise SystemExit(f'no such tests/ subdirectory: tests/{directory}')

    return tuple(
        _dotted(path) for path in sorted(leg_root.rglob('test_*.py'))
        if is_unit_tier(path)
    )


def build_suite(directory: 'str') -> 'unittest.TestSuite':
    """The combined suite for one leg: ``directory``'s own tests, then root's.

    See the module docstring for why that order, not the reverse.

    """
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for name in leg_modules(directory):
        suite.addTests(loader.loadTestsFromName(name))
    for name in root_modules():
        suite.addTests(loader.loadTestsFromName(name))
    return suite


def main(argv: 'list[str] | None' = None) -> 'int':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        'directory',
        help="a direct subdirectory of tests/ to run alongside the root-level "
             "modules, e.g. 'protocols'",
    )
    parser.add_argument(
        '-v', '--verbose', action='store_true',
        help='pass verbosity 2 to unittest.TextTestRunner instead of the default 1',
    )
    args = parser.parse_args(argv)

    start = time.monotonic()
    suite = build_suite(args.directory)
    runner = unittest.TextTestRunner(verbosity=2 if args.verbose else 1)
    result: 'unittest.TestResult | None' = None
    try:
        result = runner.run(suite)
        return 0 if result.wasSuccessful() else 1
    finally:
        elapsed = time.monotonic() - start
        # In a ``finally`` so the measured number survives a leg that *fails*
        # and a leg that unwinds on an exception -- including the
        # ``KeyboardInterrupt`` CPython's default SIGINT handler raises,
        # which :class:`unittest.case._Outcome`'s ``testPartExecutor``
        # re-raises rather than swallowing. A GitHub Actions
        # ``timeout-minutes`` expiry (see the ``unittest-ordering`` job in
        # .github/workflows/unit-tests.yml) normally *does* still reach this
        # line: the runner sends SIGINT first, with a 7.5s grace period,
        # before SIGTERM (2.5s) and only then SIGKILL --
        # ``actions/runner``'s ``src/Runner.Sdk/ProcessInvoker.cs``
        # (``CancelAndKillProcessTree``, ``_sigintTimeout``/
        # ``_sigtermTimeout``). A job-level timeout uses that same ladder,
        # not a separate one: the backend's cancellation reaches the worker
        # as a ``CancelRequest`` (``Runner.Worker/Worker.cs``), which cancels
        # the token ``JobRunner``/``StepsRunner`` thread into this step's
        # own ``ExecutionContext.CancellationToken`` -- the token
        # ``Handlers/ScriptHandler.cs`` hands ``ProcessInvoker.ExecuteAsync``
        # with ``killProcessOnCancel: false``, which is what selects the
        # SIGINT/SIGTERM ladder for a ``run:`` step like this one, rather
        # than an immediate kill. The real gap is narrower: a test blocked
        # inside a C extension defers signal delivery, so the handler may
        # not run before SIGTERM/SIGKILL follow it -- SIGKILL in particular
        # still runs no Python code at all. What this line buys is the
        # number from a run that finished, or was interrupted by SIGINT,
        # close to the cap -- not one genuinely stuck in C.
        tally = ('interrupted before a result was available' if result is None else
                 f'{result.testsRun} test(s), {len(result.failures)} failure(s), '
                 f'{len(result.errors)} error(s)')
        print(f'tests/{args.directory} + {len(root_modules())} root module(s): '
              f'{tally}, {elapsed:.1f}s elapsed')


if __name__ == '__main__':
    sys.exit(main())
