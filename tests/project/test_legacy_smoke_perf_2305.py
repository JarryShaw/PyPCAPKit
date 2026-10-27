# -*- coding: utf-8 -*-
"""#2305: :file:`examples/legacy_smoke/test_perf.py` benchmarks every engine it does not skip.

The demo walks :data:`_engine_support.ENGINES` and hands each engine that passes
``preflight`` to ``pyperf``. Looking the benchmark up in a hand-written table that
covers only some of those engines raises a :exc:`KeyError` for the first other
engine to pass ``preflight``, ending the run, so one ``bench`` takes the engine
name instead. Run here with ``pyperf`` and the engine checks stubbed, and with
:func:`pcapkit.extract` recorded rather than run:

* :class:`TestEveryEngineIsBenchmarked`: with every engine available, each one in
  ``ENGINES`` is benchmarked, under its own name, extracting into
  :file:`../captures/engines/<engine>.txt`;
* :class:`TestASkippedEngineIsReported`: an engine ``preflight`` refuses is reported
  with the reason and not benchmarked.

"""

from __future__ import annotations

import importlib.util
import pathlib
import runpy
import sys
import types
import unittest
from typing import TYPE_CHECKING
from unittest import mock

if TYPE_CHECKING:
    from typing import Any, Callable, Optional

#: Test tier (#1958): runs an example script with its harness stubbed.
__tier__ = 'LATEST'

ROOT = pathlib.Path(__file__).resolve().parents[2]
DEMOS = ROOT / 'examples' / 'legacy_smoke'
SCRIPT = DEMOS / 'test_perf.py'


def real_engines() -> 'tuple[str, ...]':
    """``ENGINES`` as :file:`examples/legacy_smoke/_engine_support.py` declares it."""
    spec = importlib.util.spec_from_file_location('_pcapkit_2305_engine_support', DEMOS / '_engine_support.py')
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return tuple(module.ENGINES)


ENGINES = real_engines()


class _Demo(unittest.TestCase):

    def setUp(self) -> None:
        self.benched = []  # type: list[tuple[str, Callable[..., Any], tuple[Any, ...]]]
        self.reports = []  # type: list[tuple[str, str]]

    def run_demo(self, preflight: 'Callable[[str, str], Optional[str]]') -> 'mock.Mock':
        """Run the demo; return the stand-in :func:`pcapkit.extract`."""

        class Runner:
            def bench_func(runner, name: 'str', func: 'Callable[..., Any]', *args: 'Any') -> 'None':  # pylint: disable=no-self-argument
                self.benched.append((name, func, args))

        pyperf = types.ModuleType('pyperf')
        pyperf.Runner = Runner  # type: ignore[attr-defined]
        support = types.ModuleType('_engine_support')
        support.ENGINES = ENGINES  # type: ignore[attr-defined]
        support.preflight = preflight  # type: ignore[attr-defined]
        support.report = lambda engine, detail: self.reports.append((engine, detail))  # type: ignore[attr-defined]
        extract = mock.Mock(name='extract')
        with mock.patch.dict(sys.modules, {'pyperf': pyperf, '_engine_support': support}), \
                mock.patch('pcapkit.extract', extract):
            runpy.run_path(str(SCRIPT), run_name='__main__')
        return extract


class TestEveryEngineIsBenchmarked(_Demo):

    def test_each_engine_is_benchmarked_into_its_own_report(self) -> None:
        extract = self.run_demo(lambda engine, fin: None)
        self.assertEqual([name for name, _, _ in self.benched], list(ENGINES))
        self.assertEqual(self.reports, [])
        for name, func, args in self.benched:
            with self.subTest(engine=name):
                extract.reset_mock()
                func(*args)
                extract.assert_called_once_with(fin='../captures/in.pcap', fout=f'../captures/engines/{name}.txt',
                                                format='tree', engine=name)


class TestASkippedEngineIsReported(_Demo):

    def test_a_refused_engine_is_reported_and_not_benchmarked(self) -> None:
        refused = ENGINES[-1]
        self.run_demo(lambda engine, fin: 'not here' if engine == refused else None)
        self.assertEqual([name for name, _, _ in self.benched], list(ENGINES[:-1]))
        self.assertEqual(self.reports, [(refused, 'skipped -- not here')])


if __name__ == '__main__':
    unittest.main()
