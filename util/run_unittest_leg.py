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
as a module-level constant here. :mod:`tests.protocols` is the largest leg;
its timings, on three different bases (a local serial run, and CI before and
after it was sharded), are tabulated in that workflow's own comment rather than
restated here. At the other end sit
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

GitHub issue #1029 -- sharding a leg: ``directory`` may be a deeper path such as
``protocols/internet``, and ``--exclude SUBDIR`` (repeatable) drops a
subdirectory, so ``protocols --exclude protocols/internet`` is "the rest". The
workflow uses that pair to split :mod:`tests.protocols` into two cells. Every
leg invoked without ``--exclude`` behaves exactly as before. The price is that
modules in different shards no longer share a process, so pollution between
them is invisible; the workflow comment records the measured pair counts.

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

GitHub issue #1052 -- a stalled leg: ``--stall-dump SECONDS`` (or
``PCAPKIT_UNITTEST_STALL_DUMP``) arms :func:`faulthandler.dump_traceback_later`
so that a leg still running after that long writes every thread's stack to
stderr once, then carries on. The default, 1080s, is just under a 20-minute step
cap, so a leg that is about to be killed says where it was first; ``0`` disables
it.

#1052 also found the memory growth behind the slow ``test_mh_unit`` tail. Every
purge-then-import leaves the previous generation as cyclic garbage, and the
interpreter's own collector intermittently falls behind: three plain runs of
``protocols/internet`` peaked at 1008, 781 and 1650 MiB, the last with ``test_mh_unit``
tests at up to 7.3s rather than 1.2-1.8s. ``--gc-every N`` (default 10) therefore
runs :func:`gc.collect` after every N tests: 491 MiB peak at the same 420s wall.
Every test cost 80s more for 320 MiB.

It is a collect, deliberately *not* the :data:`sys.modules` restore #1052 first
proposed. The loader imports every module before any test runs, so a module's
import-time bindings belong to the generation live at load; restoring that
snapshot hands it back, which is the very skew this leg exists to expose. On
#981's own reproduction (``32bcfba15^``, ``test_http_unit`` then
``test_base_class_contract``) no restore gives 1 failure and 3 errors; restoring
after each module, or around each test, gives 0 and 0; a collect after each test
keeps 1 and 3, since it frees only what no test can reach.

"""
from __future__ import annotations

import argparse
import faulthandler
import gc
import os
import pathlib
import sys
import time
import unittest
from typing import Sequence

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

#: Seconds before a still-running leg dumps every thread's stack (#1052): just
#: under the 20-minute step cap, so the dump lands before the kill.
DEFAULT_STALL_DUMP = 1080

#: Environment override for :data:`DEFAULT_STALL_DUMP`; ``--stall-dump`` wins.
STALL_DUMP_ENV = 'PCAPKIT_UNITTEST_STALL_DUMP'

#: Run a full :func:`gc.collect` after every this many tests (#1052); see the
#: module docstring for the measurements behind it. ``--gc-every 0`` disables.
DEFAULT_GC_EVERY = 10


class _CollectingResult(unittest.TextTestResult):
    """A :class:`~unittest.TextTestResult` that runs :func:`gc.collect` every *n* tests.

    Only unreachable objects are freed, so nothing a later test can reach -- the
    :data:`sys.modules` table above all -- changes; when they would otherwise be
    freed was already up to the interpreter's own thresholds.

    """

    gc_every = DEFAULT_GC_EVERY

    def stopTest(self, test: 'unittest.TestCase') -> None:
        super().stopTest(test)
        if self.gc_every > 0 and self.testsRun % self.gc_every == 0:
            gc.collect()


def _dotted(path: 'pathlib.Path') -> 'str':
    """``path`` as the dotted module name :class:`unittest.TestLoader` wants."""
    return '.'.join(path.relative_to(ROOT).with_suffix('').parts)


def root_modules() -> 'tuple[str, ...]':
    """Every root-level ``tests/test_*.py`` module but the excluded one."""
    return tuple(sorted(
        name for name in (_dotted(path) for path in sorted(TESTS_ROOT.glob('test_*.py')))
        if name not in _EXCLUDED_ROOT_MODULES
    ))


def _resolve(spec: 'str', what: 'str') -> 'pathlib.Path':
    """``spec`` as an existing directory strictly inside :data:`TESTS_ROOT`.

    Raises:
        SystemExit: ``spec`` does not name a directory under ``tests/``.

    """
    path = (TESTS_ROOT / spec).resolve()
    if path == TESTS_ROOT or TESTS_ROOT not in path.parents or not path.is_dir():
        raise SystemExit(f'no such tests/ subdirectory: tests/{spec}' if what == 'leg'
                         else f'--exclude is not a subdirectory of the leg: tests/{spec}')
    return path


def leg_modules(directory: 'str', exclude: 'Sequence[str]' = ()) -> 'tuple[str, ...]':
    """Every unit-tier ``test_*.py`` module under ``tests/<directory>``.

    Args:
        directory: a subdirectory of :data:`TESTS_ROOT` -- a direct child
            (``'protocols'``) or, to shard a leg that is too slow for one job,
            a deeper path (``'protocols/internet'``).
        exclude: subdirectories of ``directory`` (also relative to
            :data:`TESTS_ROOT`) whose modules are left out, so that one shard
            can be "everything in ``directory`` except its sibling shards".
            Empty by default, which is every leg but one.

    Returns:
        Dotted module names, in path-sorted order.

    Raises:
        SystemExit: ``directory`` is not a subdirectory of :data:`TESTS_ROOT`,
            or an ``exclude`` entry is not a subdirectory of ``directory``.

    """
    leg_root = _resolve(directory, 'leg')
    skipped = [_resolve(spec, 'exclude') for spec in exclude]
    for path in skipped:
        if leg_root not in path.parents:
            raise SystemExit(f'--exclude is not a subdirectory of the leg: {path.relative_to(ROOT)}')

    return tuple(
        _dotted(path) for path in sorted(leg_root.rglob('test_*.py'))
        if is_unit_tier(path) and not any(skip in path.parents for skip in skipped)
    )


def build_suite(directory: 'str', exclude: 'Sequence[str]' = ()) -> 'unittest.TestSuite':
    """The combined suite for one leg: ``directory``'s own tests, then root's.

    See the module docstring for why that order, not the reverse.

    """
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for name in leg_modules(directory, exclude):
        suite.addTests(loader.loadTestsFromName(name))
    for name in root_modules():
        suite.addTests(loader.loadTestsFromName(name))
    return suite


def main(argv: 'list[str] | None' = None) -> 'int':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        'directory',
        help="a subdirectory of tests/ to run alongside the root-level "
             "modules, e.g. 'protocols' or 'protocols/internet'",
    )
    parser.add_argument(
        '--exclude', action='append', default=[], metavar='SUBDIR',
        help="a subdirectory of DIRECTORY (relative to tests/) to leave out; "
             "repeatable. Used to run the remainder of a sharded leg.",
    )
    parser.add_argument(
        '-v', '--verbose', action='store_true',
        help='pass verbosity 2 to unittest.TextTestRunner instead of the default 1',
    )
    parser.add_argument(
        '--stall-dump', type=float, default=None, metavar='SECONDS',
        help=f"dump every thread's stack to stderr once the leg has run this long "
             f"(default ${STALL_DUMP_ENV}, else {DEFAULT_STALL_DUMP}); 0 disables",
    )
    parser.add_argument(
        '--gc-every', type=int, default=DEFAULT_GC_EVERY, metavar='N',
        help=f'run gc.collect() after every N tests (default {DEFAULT_GC_EVERY}); 0 disables',
    )
    args = parser.parse_args(argv)
    stall_dump = args.stall_dump
    if stall_dump is None:
        try:
            stall_dump = float(os.environ.get(STALL_DUMP_ENV) or DEFAULT_STALL_DUMP)
        except ValueError:
            parser.error(f'${STALL_DUMP_ENV} is not a number of seconds: '
                         f'{os.environ[STALL_DUMP_ENV]!r}')

    start = time.monotonic()
    if stall_dump > 0:
        # ``sys.__stderr__``, not ``sys.stderr``: faulthandler keeps the file
        # descriptor it is given, and a test that swaps ``sys.stderr`` for a
        # buffer must not be where the dump goes.
        faulthandler.dump_traceback_later(stall_dump, repeat=False,
                                          file=sys.__stderr__ or sys.stderr, exit=False)
    try:
        return _run(args, start)
    finally:
        faulthandler.cancel_dump_traceback_later()


def _run(args: 'argparse.Namespace', start: 'float') -> 'int':
    """Build and run the leg, then print its one-line tally whatever happened."""
    suite = build_suite(args.directory, args.exclude)
    result_class = type('_LegResult', (_CollectingResult,), {'gc_every': args.gc_every})
    runner = unittest.TextTestRunner(verbosity=2 if args.verbose else 1, resultclass=result_class)
    result: 'unittest.TestResult | None' = None
    try:
        result = runner.run(suite)
        return 0 if result.wasSuccessful() else 1
    finally:
        elapsed = time.monotonic() - start
        # In a ``finally`` so a leg that *fails*, and a leg that unwinds on an
        # exception -- including the ``KeyboardInterrupt`` CPython's default
        # SIGINT handler raises, which :class:`unittest.case._Outcome`'s
        # ``testPartExecutor`` re-raises rather than swallowing -- still
        # reports its elapsed time.
        tally = ('interrupted before a result was available' if result is None else
                 f'{result.testsRun} test(s), {len(result.failures)} failure(s), '
                 f'{len(result.errors)} error(s)')
        left_out = ''.join(f' (without tests/{spec})' for spec in args.exclude)
        print(f'tests/{args.directory}{left_out} + {len(root_modules())} root module(s): '
              f'{tally}, {elapsed:.1f}s elapsed')


if __name__ == '__main__':
    sys.exit(main())
