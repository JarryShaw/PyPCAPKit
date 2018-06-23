# -*- coding: utf-8 -*-


import statistics
import time

import jspcap


for engine in {'default', 'pyshark', 'scapy', 'dpkt', 'pipline', 'server'}:
    lid = list()
    for index in range(1, 101):
        now = time.time()

        extraction = jspcap.extract(fin='../sample/in.pcap', store=False, nofile=True, strict=True, engine=engine)

        delta = time.time() - now
        # print(f'[{engine}] No. {index:>3d}: {extraction.length} packets extracted in {delta} seconds.')
        lid.append(float(delta))

    avetime = statistics.mean(lid)
    average = avetime / extraction.length
    print(f'Report: [{engine}] {average} seconds per packet.')
