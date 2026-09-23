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
* :meth:`OrderIndependenceTests.test_the_cli_polluter_order_passes` is the third
  leak, in ``tests/cli/test_main.py``. It used to pin the *structural* half of the
  fix: that file rolled its own purge loop and did not import
  :mod:`tests._support`, so nothing in that module could have fixed it and only
  :func:`tests.conftest.restore_module_table` did, and it was deliberately left
  that way as the standing witness that the guard covers a file which has not
  opted into anything. That turned out to be the wrong trade. The guard healed the
  leak on every run, which is exactly why it took an audit rather than a red test
  to notice the leak was still there -- issue #688. The file now calls
  :func:`tests._support.isolate_modules` like its neighbours, so this case is a
  control on the pairing rather than a witness for the guard, and the witness role
  is left vacant on purpose: a test whose job is to leave :data:`sys.modules`
  broken is a defect the suite would have to maintain deliberately, and the next
  file written without the helpers is covered by the guard whether or not such a
  test exists.

The guard is also why the :program:`pytest` runs above cannot see a leak at all.
What they assert is that the *guarded* suite is order-independent -- which it was
throughout, while #660, #674 and #688 were each live. So :data:`UNMASKED_ORDERS`
runs the same shape of pairing under the stdlib :mod:`unittest` runner, where no
conftest is loaded and nothing heals anything between tests. Both defects the #674
audit turned up are covered there:

* ``tests/utilities/test_compat.py`` faking :data:`sys.version_info` around a real
  ``import``, which memoises the fake in :mod:`aenum`'s import-time version cache
  for the rest of the process -- issue #687. This one is not a
  :data:`sys.modules` leak at all and :func:`tests.conftest.restore_module_table`
  could not have healed it; what hid it was
  :func:`tests.conftest.pytest_sessionstart` importing :mod:`pcapkit`, and so
  :mod:`aenum`, before any test ran. **This is the only place a #687 regression is
  caught**, and that is why it is here rather than left to the file's own
  assertions: the same warm import makes those assertions vacuous under
  :program:`pytest`, so they pass whether or not the fix is in place.
* ``tests/cli/test_main.py`` leaving its stand-ins bound -- issue #688. That one
  *is* caught in the file itself, by
  :meth:`tests.cli.test_main.CLIMainTests.assert_module_table_restored`, which is
  registered as a cleanup ahead of the isolation and so runs before the conftest
  fixture gets to heal anything. This case is the cross-file half of the same
  claim, and cheap enough to keep for the symmetry.

``pytest --noconftest`` over the same files shows both as well and is the quicker
thing to reach for by hand. :mod:`unittest` is what is automated here because it
needs no flag to get there, and because a second runner is worth exercising for
its own sake.

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
        'the CLI stand-in leak',
        [
            'tests/cli/test_main.py::CLIMainTests::test_get_parser_parses_expected_arguments',
            'tests/project/test_public_api.py',
        ],
    ),
]

#: Pairings that :func:`tests.conftest.restore_module_table` and
#: :func:`tests.conftest.pytest_sessionstart` between them hide, so they are run
#: under the stdlib :mod:`unittest` runner instead -- which loads no conftest and
#: heals nothing. Each is (label, dotted module names, the symptom to look for).
#:
#: The symptom is asserted as well as the exit status because the two say different
#: things. A non-zero exit says *something* failed; the symptom says the failure
#: was this one, and not some unrelated breakage in a file that happens to be in
#: the selection.
UNMASKED_ORDERS = [
    (
        'the aenum import-time version cache (#687)',
        ['tests.utilities.test_compat', 'tests.project.test_public_api'],
        "object has no attribute '__set_name__'",
    ),
    (
        'the CLI stand-ins left in sys.modules (#688)',
        ['tests.cli.test_main', 'tests.project.test_public_api'],
        "cannot import name 'show_flag_values' from 'pcapkit.utilities.compat'",
    ),
]


def child_environ() -> 'dict[str, str]':
    """The environment a runner subprocess should inherit.

    Returns:
        A copy of this process's environment, with the repository root on
        :envvar:`PYTHONPATH` and the :program:`pytest` session variables removed.

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
    return environ


def run_pytest(selection: 'list[str]') -> 'subprocess.CompletedProcess[str]':
    """Run :program:`pytest` over ``selection`` in a subprocess.

    Args:
        selection: Paths or node ids, relative to the repository root.

    Returns:
        The finished process, with output captured.

    """
    return subprocess.run(
        [sys.executable, '-m', 'pytest', '-p', 'no:cacheprovider', '-q', *selection],
        cwd=str(ROOT), env=child_environ(), capture_output=True, text=True,
        timeout=600, check=False,
    )


def run_unittest(modules: 'list[str]') -> 'subprocess.CompletedProcess[str]':
    """Run the stdlib :mod:`unittest` runner over ``modules`` in a subprocess.

    The point of using this runner rather than :program:`pytest` is everything it
    does *not* do: it loads no ``conftest.py``, so neither
    :func:`tests.conftest.restore_module_table` nor
    :func:`tests.conftest.pytest_sessionstart` runs, and a test that leaves the
    process in a worse state than it found it gets no help. ``pytest
    --noconftest`` reaches the same place; this needs no flag to get there.

    Modules run in the order given, which is the whole point -- the polluting one
    comes first.

    Args:
        modules: Dotted module names, e.g. ``'tests.cli.test_main'``. Not paths:
            the :mod:`unittest` runner takes names.

    Returns:
        The finished process, with output captured. :mod:`unittest` writes its
        report to stderr rather than stdout.

    """
    return subprocess.run(
        [sys.executable, '-m', 'unittest', *modules],
        cwd=str(ROOT), env=child_environ(), capture_output=True, text=True,
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

    def test_the_cli_polluter_order_passes(self) -> None:
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


class UnmaskedOrderTests(unittest.TestCase):
    """The pairings the conftest hides pass without it.

    Separate from :class:`OrderIndependenceTests` because the claim is a different
    one. That class asserts the *guarded* suite is order-independent, which it was
    even while #660, #674, #687 and #688 were live. This one asserts the files
    themselves are, with nothing healing them -- which is what makes the per-file
    fixes real rather than merely masked.

    """

    def assert_unittest_selection_passes(self, label: str, modules: 'list[str]',
                                         symptom: str) -> None:
        """Run ``modules`` under :mod:`unittest` and fail with its output if not clean."""
        finished = run_unittest(modules)
        output = finished.stdout + finished.stderr

        self.assertEqual(
            finished.returncode, 0,
            f'the unittest runner exited {finished.returncode} on {label} -- the files '
            f'are not isolated from each other, they were only being healed by '
            f'tests/conftest.py.\n\n'
            f'selection: {" ".join(modules)}\n\n'
            f'output:\n{output[-6000:]}')
        self.assertNotIn(symptom, output, f'{label} still reaches a later test')

    def test_the_version_fake_does_not_poison_a_later_import(self) -> None:
        label, modules, symptom = UNMASKED_ORDERS[0]
        self.assert_unittest_selection_passes(label, modules, symptom)

    def test_the_cli_stand_ins_do_not_reach_a_later_test(self) -> None:
        label, modules, symptom = UNMASKED_ORDERS[1]
        self.assert_unittest_selection_passes(label, modules, symptom)


if __name__ == '__main__':
    unittest.main()
