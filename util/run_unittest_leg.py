# -*- coding: utf-8 -*-
"""Run one unit-tier directory under plain :mod:`unittest`, in a single process.

GitHub issue #981: three test modules each pass alone and :program:`pytest`
reports the whole run green when they are collected together, but plain
:mod:`unittest` over the same three modules in one process fails -- four
``subTest`` cases, all swallowed by ``pytest-subtests`` reporting the parent
node ``passed`` while only its ``subTest``\\ s failed. The root cause (fixed
separately, in :mod:`tests.test_base_class_contract`) is cross-module
``pcapkit`` reimport pollution that :mod:`tests.conftest`'s autouse
``restore_module_table`` fixture reconciles after every test -- but only under
:program:`pytest`. Plain :mod:`unittest` loads no ``conftest.py`` at all, so
whatever a sibling module's :func:`tests._support.purge_modules` leaves behind
survives into the next module run in the same process.

That is this script's whole reason to exist: it is not a faster or stricter
pytest, it is a *different* test runner, chosen because its blind spots are not
``pytest-subtests``'s. A ``subTest`` failure under :class:`unittest.TextTestRunner`
is a top-level ``FAIL``/``ERROR``, counted and printed, with no parent node to
hide behind.

Scope, and why it stops where it does
--------------------------------------

The whole suite in one process is not an option -- it OOMs at 29 GB on the
machine this was diagnosed on. This script instead runs one :file:`tests/`
subdirectory per invocation (its ``directory`` argument), which is what
:file:`.github/workflows/unit-tests.yml`'s matrix calls once per entry of
:data:`LEGS` below, each in its own job and so its own process and its own
memory budget. :mod:`tests.protocols`, the largest, measured at 226s and a
peak RSS of 344 MB for :mod:`tests.const` alone (the smallest of the
multi-file directories) -- nowhere near 29 GB -- so the OOM is a property of
running *everything* together, not of any one directory.

Every :data:`ROOT_MODULES` module runs in *every* invocation, ahead of the
directory's own modules -- not interleaved, and not after. Issue #981's own
reproduction is a sibling module (``tests.protocols.application.test_http_unit``)
*polluting* a root-level module
(:mod:`tests.test_base_class_contract`) that runs after it in the same
process; ``tests.test_base_class_contract`` first and the directory second
would never reproduce that shape, because the pollution would land after the
sensitive module had already made its assertions and finished. Running the
directory first and the root modules second is what gives any purging module
in that directory a chance to desync a root module that assumes its own
import is current -- matching the reproduction exactly for ``protocols`` and
``const``, and giving the same opportunity to every other directory this
script is pointed at, most of which have never been tried in that
configuration before.

What this still does not catch: a defect running the *other* direction (a
root module polluting a directory module), interference between two
directories neither of which is bundled with the other in the same leg, and
anything that only manifests with the fixture-dependent tier
(:data:`tests._tiers.FIXTURE_TIER_DIRS`) alongside it -- ``tests/integration/``
is deliberately never one of :data:`LEGS` below, both because it needs
generated captures this script does not build and because it is already run
whole, under :program:`pytest`, by the ``integration`` job.

"""
from __future__ import annotations

import argparse
import pathlib
import sys
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

    suite = build_suite(args.directory)
    runner = unittest.TextTestRunner(verbosity=2 if args.verbose else 1)
    result = runner.run(suite)
    print(f'tests/{args.directory} + {len(root_modules())} root module(s): '
          f'{result.testsRun} test(s), {len(result.failures)} failure(s), '
          f'{len(result.errors)} error(s)')
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(main())
