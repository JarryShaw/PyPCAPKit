# -*- coding: utf-8 -*-
"""Time ``pcapkit.extract`` on each engine and report milliseconds per packet.

An engine that is not available on this host is reported as skipped, with the
reason, and the remaining engines are still timed -- see :mod:`_engine_support` for
what counts as unavailable. Anything else is a real failure and is left to
propagate.

Note that the engines are tried once each before being timed: a failure halfway
through a thousand rounds throws the whole measurement away, and an engine this
host does not have is not a result worth measuring.

"""

import statistics
import time

import pcapkit
from _engine_support import ENGINES, preflight
from pcapkit.utilities.logging import logger

logger.setLevel('INFO')

#: Timed extractions per engine. The first is discarded as a warm-up round.
ROUNDS = 1_000

for engine in ENGINES:
    reason = preflight(engine, '../captures/in.pcap')
    if reason is not None:
        print(f'Report: [{engine}] skipped -- {reason}')
        continue

    print(f'Testing: [{engine}] starting...', end='', flush=True)

    lid = []  # type: list[float]
    for index in range(0, ROUNDS):
        # NOTE: perf_counter_ns is monotonic; time_ns is wall clock and can step
        # backwards under an NTP adjustment, which would give a negative delta.
        now = time.perf_counter_ns()

        extraction = pcapkit.extract(fin='../captures/in.pcap', store=False, nofile=True, verbose=False, engine=engine)  # type: ignore[arg-type]

        delta = time.perf_counter_ns() - now
        # print(f'[{engine}] No. {index:>3d}: {extraction.length} packets extracted in {delta} seconds.')
        lid.append(float(delta))

        print(f'\rTesting: [{engine}] round no. {index}', end='', flush=True)

    lid.pop(0)
    avetime = statistics.mean(lid)
    average = avetime / extraction.length / 1_000_000
    print(f'\rReport: [{engine}] {average} ms per packet ({avetime / 1_000_000_000} seconds per {extraction.length} packets).')
