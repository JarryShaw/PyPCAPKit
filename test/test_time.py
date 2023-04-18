# -*- coding: utf-8 -*-

import statistics
import time

import dpkt
import pyshark
import scapy.all

import pcapkit
from pcapkit.utilities.logging import logger

logger.setLevel('INFO')

for engine in ['default', 'dpkt', 'scapy', 'pyshark']:
    print(f'Testing: [{engine}] starting...', end='', flush=True)

    lid = []
    for index in range(0, 1_000):
        now = time.time_ns()

        extraction = pcapkit.extract(fin='../sample/in.pcap', store=False, nofile=True, verbose=False, engine=engine)  # type: ignore[arg-type]

        delta = time.time_ns() - now
        # print(f'[{engine}] No. {index:>3d}: {extraction.length} packets extracted in {delta} seconds.')
        lid.append(float(delta))

        print(f'\rTesting: [{engine}] round no. {index}', end='', flush=True)

    lid.pop(0)
    avetime = statistics.mean(lid)
    average = avetime / extraction.length / 1_000_000
    print(f'\rReport: [{engine}] {average} ms per packet ({avetime / 1_000_000_000} seconds per {extraction.length} packets).')
