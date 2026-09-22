# -*- coding: utf-8 -*-
"""The suite's result does not depend on the order its files were collected in.

Issue #660: three files, run in one order, gave ``12 failed, 5 passed``; the same
three in the opposite order gave ``17 passed``. The cause was a test that bound a
non-generic ``ProtocolBase`` stand-in into :data:`sys.modules` and finished
without removing it, so the next test to import :mod:`pcapkit` died at
``pcapkit/protocols/misc/pcap/frame.py:59`` with ``TypeError: type 'ProtocolBase'
is not subscriptable``.

The tests here run :program:`pytest` in a subprocess over the exact selections
that failed. That is the only way to state this invariant: it is a property of
one run of several files against each other, not of anything observable from
inside a single test. Cross-file ordering is also precisely what a normal test
cannot reach -- by the time it executes, the polluting file either has or has not
already run, and the guard under test is the thing that makes the difference
invisible.

Each case is a *pair*: the order that failed, and one file that is known to
pollute paired with one that is known to import the package. Three distinct leaks
were found, and they are covered separately because they fail differently and are
fixed by different halves of the change:

* :meth:`OrderIndependenceTests.test_the_reported_three_file_order_passes` is the
  reproduction from the issue verbatim -- ``tests/corekit/test_protochain.py``
  leaking a fake ``ProtocolBase``.
* :meth:`OrderIndependenceTests.test_the_integration_tier_polluter_order_passes`
  is a second leak, in ``tests/integration/test_module_loading.py``, found while
  fixing the first and not mentioned in the issue. It fails differently -- a stub
  ``pcapkit`` carrying only ``__path__``, so ``__all__`` entries resolve to
  nothing rather than raising.
* :meth:`OrderIndependenceTests.test_a_polluter_outside_the_helpers_is_covered`
  is the one that pins the *structural* half of the fix.
  ``tests/cli/test_main.py`` rolls its own purge loop and never imports
  :mod:`tests._support`, so nothing in that module could have fixed it; only
  :func:`tests.conftest.restore_module_table` does. It is deliberately left as it
  was, as the standing witness that the guard covers a file which has not opted
  into anything.

Why not simply move ``test_protochain.py`` so it sorts after its victims: because
that is what was already happening by accident. It sorts last inside
``tests/corekit/``, so no sibling healed it, and the full CI selection passed only
because unrelated directories sort between it and ``tests/project/``. A fix that
rearranges the collection order leaves the defect in place and re-hides it, and
the next file added anywhere between the two re-exposes it.

This module is unit-tier by location but is not a unit test of anything: it
reads no sample capture, and every subprocess it starts is a narrow, named file
selection -- never the whole suite, which needs tens of gigabytes of memory.

"""
from __future__ import annotations

import os
import subprocess
import sys
import unittest

from tests._tiers import ROOT

#: Selections that failed before #660 was fixed, each as (label, files). The
#: polluting file comes first in every one, because that is the order that broke.
POLLUTING_ORDERS = [
    (
        'the three files from the issue',
        [
            'tests/corekit/test_protochain.py',
            'tests/project/test_public_api.py',
            'tests/project/test_documentation_claims.py',
        ],
    ),
    (
        'the integration-tier bootstrap leak',
        [
            'tests/integration/test_module_loading.py',
            'tests/project/test_public_api.py',
        ],
    ),
    (
        'a polluter that does not use tests._support',
        [
            'tests/cli/test_main.py::CLIMainTests::test_get_parser_parses_expected_arguments',
            'tests/project/test_public_api.py',
        ],
    ),
]


def run_pytest(selection: 'list[str]') -> 'subprocess.CompletedProcess[str]':
    """Run :program:`pytest` over ``selection`` in a subprocess.

    Args:
        selection: Paths or node ids, relative to the repository root.

    Returns:
        The finished process, with output captured.

    """
    environ = dict(os.environ)
    # The child must import the tree this test is running from, not whatever an
    # editable install happens to point at -- the whole question is about which
    # ``pcapkit`` gets imported.
    environ['PYTHONPATH'] = os.pathsep.join(
        [str(ROOT), environ['PYTHONPATH']] if environ.get('PYTHONPATH') else [str(ROOT)]
    )
    # Inherited from a parent run, this would have the child write to the same
    # cache directory as the run that started it.
    environ.pop('PYTEST_ADDOPTS', None)
    environ.pop('PYTEST_CURRENT_TEST', None)

    return subprocess.run(
        [sys.executable, '-m', 'pytest', '-p', 'no:cacheprovider', '-q', *selection],
        cwd=str(ROOT), env=environ, capture_output=True, text=True,
        timeout=600, check=False,
    )


class OrderIndependenceTests(unittest.TestCase):
    """Each selection that used to fail on collection order now passes."""

    def assert_selection_passes(self, label: str, selection: 'list[str]') -> None:
        """Run ``selection`` and fail with its output if pytest did not exit 0."""
        finished = run_pytest(selection)

        self.assertEqual(
            finished.returncode, 0,
            f'pytest exited {finished.returncode} on {label} -- the result still '
            f'depends on collection order (#660).\n\n'
            f'selection: {" ".join(selection)}\n\n'
            f'stdout:\n{finished.stdout[-4000:]}\n\nstderr:\n{finished.stderr[-2000:]}')
        self.assertNotIn('is not subscriptable', finished.stdout,
                         'a stand-in ProtocolBase reached a later test (#660)')

    def test_the_reported_three_file_order_passes(self) -> None:
        label, selection = POLLUTING_ORDERS[0]
        self.assert_selection_passes(label, selection)

    def test_the_integration_tier_polluter_order_passes(self) -> None:
        label, selection = POLLUTING_ORDERS[1]
        self.assert_selection_passes(label, selection)

    def test_a_polluter_outside_the_helpers_is_covered(self) -> None:
        label, selection = POLLUTING_ORDERS[2]
        self.assert_selection_passes(label, selection)

    def test_the_reverse_order_passes_too(self) -> None:
        """The control from the issue: the same files, victims first.

        This one passed before the fix as well, and is kept because it is what
        makes the pair meaningful -- a change that broke it would have traded one
        order dependence for another rather than removing it.

        """
        label, selection = POLLUTING_ORDERS[0]
        self.assert_selection_passes(f'{label}, reversed', list(reversed(selection)))


if __name__ == '__main__':
    unittest.main()
