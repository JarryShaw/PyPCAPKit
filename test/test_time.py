# -*- coding: utf-8 -*-

import multiprocessing
import statistics
import time

import pcapkit

multiprocessing.freeze_support()

for engine in ['default', 'dpkt', 'scapy', 'pyshark', 'pipline', 'server']:
    lid = list()
    for index in range(1, 101):
        now = time.time()

        extraction = pcapkit.extract(fin='../sample/in.pcap', store=False, nofile=True, engine=engine)

        delta = time.time() - now
        # print(f'[{engine}] No. {index:>3d}: {extraction.length} packets extracted in {delta} seconds.')
        lid.append(float(delta))

    avetime = statistics.mean(lid)
    average = avetime / extraction.length
    print(f'Report: [{engine}] {average} seconds per packet.')
