# -*- coding: utf-8 -*-
"""Benchmark ``pcapkit.extract`` across engines with pyperf.

``pyperf`` is not a pcapkit dependency -- it is a benchmarking harness this one demo
uses -- so it will not be present in a plain ``pip install pypcapkit`` environment.
When it is missing the demo says how to get it and stops there rather than dying on
an import traceback.

An engine that is not available on this host is reported as skipped, with the
reason, and only the engines that work are handed to the benchmark runner: pyperf
re-runs each benchmark in worker processes dozens of times, so an engine that
raises would fail the whole run rather than just its own row. See
:mod:`_engine_support` for what counts as unavailable.

"""

import sys

from _engine_support import ENGINES, preflight, report

try:
    import pyperf
except ImportError:
    print('test_perf: skipped -- pyperf is not installed.\n'
          '\n'
          '    This demo needs the pyperf benchmarking harness, which pcapkit does\n'
          '    not depend on. Install it into the same environment as pcapkit:\n'
          '\n'
          '        python -m pip install pyperf\n'
          '\n'
          '    For a timing run with no extra dependency, use test_time.py instead.')
    sys.exit(0)

from pcapkit import extract  # noqa: E402  # pylint: disable=wrong-import-position


def bench(engine: 'str') -> 'None':
    extract(fin='../captures/in.pcap', fout=f'../captures/engines/{engine}.txt',
            format='tree', engine=engine)


runner = pyperf.Runner()

benched = 0
for engine in ENGINES:
    reason = preflight(engine, '../captures/in.pcap')
    if reason is not None:
        report(engine, f'skipped -- {reason}')
        continue

    runner.bench_func(engine, bench, engine)
    benched += 1

if not benched:
    print('test_perf: nothing to benchmark -- every engine was skipped above.')
