# -*- coding: utf-8 -*-
"""An edge case's deadline times the case, not the package import.

GitHub issue #1736: ``ethernet/header-only-unknown-type/cut7`` timed out at 30s
on two consecutive ``main`` runs, while it parses and rebuilds in about 4ms. It
is the first case of :class:`~tests.protocols.link.test_link_edge_roundtrip_unit.LinkEdgeRoundTripTests`,
whose ``setUp`` purges :mod:`pcapkit`, so its deadline was armed before the
protocol class was resolved and timed the whole package import -- about 0.5s
here, against 4ms -- on a CI runner then running everything some 50 times
slower than a laptop does.

The check is on order, not on time: the module naming the case's class must
already be imported when the deadline is armed.

"""

import contextlib
import sys
import unittest
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import purge_modules
from tests.protocols import _edge_roundtrip as edge
from tests.protocols._edge_roundtrip import Case, MakeCase

if TYPE_CHECKING:
    from typing import Iterator

#: Test tier (#1958): checks that the edge-case harness arms its deadline after the
#: import, an order fixed by the harness's own code rather than by pcapkit or the
#: interpreter; the edge-case tables it serves run on every leg.
__tier__ = 'LATEST'

ETHERNET = 'pcapkit.protocols.link.ethernet:Ethernet'
MACS = bytes.fromhex('0123456789ab') + bytes.fromhex('fedcba987654')


@unittest.skipUnless(edge.HAS_RUNTIME, 'runtime dependencies not installed')
class EdgeDeadlineTests(unittest.TestCase):
    """The deadline is armed after the class is imported."""

    def _armed_with(self, func: 'object', case: 'Case | MakeCase') -> 'list[bool]':
        """Run ``case`` from a cold import; whether its module was loaded at each arming."""
        module = case.cls.partition(':')[0]
        purge_modules(['pcapkit'])
        self.assertNotIn(module, sys.modules, 'the purge left the module behind')

        real = edge.time_limit
        armed = []  # type: list[bool]

        @contextlib.contextmanager
        def recording(seconds: 'int') -> 'Iterator[None]':
            armed.append(module in sys.modules)
            with real(seconds):
                yield

        probe = type('Probe', (edge.EdgeRoundTripBase,), {'CASES': (case,)})('test_labels_are_unique')
        with mock.patch.object(edge, 'time_limit', recording):
            outcome = probe._run(func, case)  # pylint: disable=protected-access
        self.assertEqual(outcome.status, 'OK', outcome.detail)
        return armed

    def test_a_parse_case_is_timed_without_the_import(self) -> None:
        case = Case('ethernet/header-only-unknown-type/cut7', ETHERNET, (MACS + b'\x88\xb5')[:7])
        self.assertEqual(self._armed_with(edge.run_parse, case), [True])

    def test_a_make_case_is_timed_without_the_import(self) -> None:
        case = MakeCase('ethernet/make/default', ETHERNET, {})
        self.assertEqual(self._armed_with(edge.run_make, case), [True])


if __name__ == '__main__':
    unittest.main()
