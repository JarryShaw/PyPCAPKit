# -*- coding: utf-8 -*-
"""The suite's result does not depend on the order its files were collected in.

#660: three files gave ``12 failed, 5 passed`` in one order and ``17 passed`` in the
other. A test bound a non-generic ``ProtocolBase`` stand-in into :data:`sys.modules`
and never removed it, so the next test importing :mod:`pcapkit` died at the
:class:`Frame` class statement in :mod:`pcapkit.protocols.misc.pcap.frame.protocol`
with ``TypeError: type 'ProtocolBase' is not subscriptable``.

The tests run :program:`pytest` in a subprocess over the exact selections that failed,
since order-independence is a property of one run of several files, which no single
test can observe: by the time it runs, the polluter has or has not run already.

Each case pairs a file known to pollute with one known to import the package, one
leak per case, since each fails differently and has its own fix:

* :meth:`OrderIndependenceTests.test_the_reported_three_file_order_passes` is the
  issue's reproduction verbatim: ``tests/corekit/test_protochain.py`` leaking a fake
  ``ProtocolBase``.
* :meth:`OrderIndependenceTests.test_the_integration_tier_polluter_order_passes` is a
  leak the issue did not mention, in ``tests/integration/test_module_loading.py``: a
  stub ``pcapkit`` carrying only ``__path__``, so ``__all__`` entries resolve to
  nothing rather than raising.
* :meth:`OrderIndependenceTests.test_the_cli_polluter_order_passes` is the leak in
  ``tests/cli/test_main.py`` (#688). That file calls
  :func:`tests._support.isolate_modules`, so this case is a control on the pairing,
  not a witness that the guard, :func:`tests.conftest.restore_module_table`, covers a
  file that opted into nothing. The witness role is vacant on purpose: a test whose
  job is to leave :data:`sys.modules` broken is a defect the suite would maintain,
  and the guard covers the next unhelpered file anyway.

The guard is also why those :program:`pytest` runs cannot see a leak: they assert
that the *guarded* suite is order-independent, which it stayed while #660, #674 and
#688 were live. So :data:`UNMASKED_ORDERS` runs the same pairings under the stdlib
:mod:`unittest` runner, where no conftest heals anything. It covers both defects
the #674 audit found:

* ``tests/utilities/test_compat.py`` faking :data:`sys.version_info` around a real
  ``import``, which memoises the fake in :mod:`aenum`'s import-time version cache
  for the process (#687). Not a :data:`sys.modules` leak, so the guard could not heal
  it; :func:`tests.conftest.pytest_sessionstart` importing :mod:`pcapkit`, and so
  :mod:`aenum`, before any test hid it. **Only this module catches a #687
  regression**: the same warm import makes the file's own assertions vacuous under
  :program:`pytest`.
* ``tests/cli/test_main.py`` leaving its stand-ins bound (#688). The file itself
  catches it, by :meth:`tests.cli.test_main.CLIMainTests.assert_module_table_restored`,
  a cleanup registered ahead of the isolation so it runs before the conftest fixture
  heals anything; this case is the cheap cross-file half.

A sub-package isolation (#2646), ``isolate_modules(self, ('pcapkit.vendor',))``,
restored the table but left ``pcapkit.vendor`` bound on ``pcapkit`` to the
generation imported inside it, so a later patch of ``pcapkit.vendor`` landed on a
module ``pcapkit.vendor.__main__`` did not read.

``pytest --noconftest`` over the same files shows each leak and is quicker by hand;
:mod:`unittest` is automated here because it needs no flag, and a second runner is
worth exercising.

Moving ``test_protochain.py`` to sort after its victims is not a fix, because sort
order hid #660: it sorted last in ``tests/corekit/``, so no sibling healed it, and
the full selection passed only because unrelated directories sort between it and
``tests/project/``. Reordering re-hides the defect until the next file added between
the two re-exposes it.

This module is unit-tier by location but unit-tests nothing: it reads no sample
capture, and every subprocess it starts is a narrow, named selection, never the whole
suite, which needs tens of gigabytes of memory.

"""
from __future__ import annotations

import os
import subprocess
import sys
import unittest

from tests._tiers import ROOT

#: Test tier (#1958): checks that modules purge and reimport cleanly, which is the
#: interpreter's import system.
__tier__ = 'ALL'

#: Selections that fail without #660's fix, each as (label, files). The
#: polluting file comes first in every one, because that is the order that breaks.
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
#: :func:`tests.conftest.pytest_sessionstart` hide, so they run under the stdlib
#: :mod:`unittest` runner, which loads no conftest. Each is (label, dotted module
#: names, the symptom to look for). The symptom is asserted beside the exit status
#: so the failure is this one, not unrelated breakage in the selection.
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
    (
        'the pcapkit.vendor attribute left on its parent (#2646)',
        ['tests.vendor.test_vendor_exit_code_unit',
         'tests.vendor.test_vendor_ipx_sys_path_2589_unit',
         'tests.vendor.test_vendor_missing_extra_1850_unit'],
        'a target ran',
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
        [sys.executable, '-m', 'pytest', '-p', 'no:cacheprovider', '-q', '-rfE', *selection],
        cwd=str(ROOT), env=child_environ(), capture_output=True, text=True,
        timeout=600, check=False,
    )


def nested_failures(stdout: str) -> 'list[str]':
    """The tests a :func:`run_pytest` run's short summary reports as failed or errored.

    Args:
        stdout: The run's standard output, which ends with that summary because
            :func:`run_pytest` passes ``-rfE``.

    Returns:
        Their node ids, without the reason pytest appends after `` - ``.

    """
    return [line.split(' ', 1)[1].split(' - ', 1)[0]
            for line in stdout.splitlines() if line.startswith(('FAILED ', 'ERROR '))]


def run_unittest(modules: 'list[str]') -> 'subprocess.CompletedProcess[str]':
    """Run the stdlib :mod:`unittest` runner over ``modules`` in a subprocess.

    It loads no ``conftest.py``, so neither :func:`tests.conftest.restore_module_table`
    nor :func:`tests.conftest.pytest_sessionstart` heals a test that leaves the
    process worse than it found it. Modules run in the order given, the polluting
    one first.

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
    """Each selection a module-table leak breaks by collection order passes."""

    def assert_selection_passes(self, label: str, selection: 'list[str]') -> None:
        """Run ``selection`` and fail with its output if pytest did not exit 0.

        The message names the nested tests that failed rather than blaming
        collection order: a test that fails on its own fails here too, and that
        is not #660.

        """
        finished = run_pytest(selection)
        failed = nested_failures(finished.stdout) or ['none named in the summary']

        self.assertEqual(
            finished.returncode, 0,
            f'pytest exited {finished.returncode} on {label}; failing: '
            f'{", ".join(failed)}. That is a collection-order dependence (#660) '
            f'only if each of them passes when run on its own.\n\n'
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

        This one passes with or without the fix, and is kept because it is what
        makes the pair meaningful -- a change that broke it would trade one order
        dependence for another rather than removing it.

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

    def test_a_sub_package_isolation_leaves_the_parent_attribute_alone(self) -> None:
        label, modules, symptom = UNMASKED_ORDERS[2]
        self.assert_unittest_selection_passes(label, modules, symptom)


if __name__ == '__main__':
    unittest.main()
