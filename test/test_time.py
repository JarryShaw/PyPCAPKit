# -*- coding: utf-8 -*-


import statistics
import time

import jspcap


lid = list()
for index in range(1, 101):
    now = time.time()

    extraction = jspcap.tkextract(fin='../sample/in.pcap', tcp=True, store=False, nofile=True, strict=True)

    delta = time.time() - now
    print(f'No. {index:>3d}: {extraction.length} packets extracted and reassembled in {delta} seconds.')
    lid.append(float(delta))

avetime = statistics.mean(lid)
average = avetime / extraction.length
print(f'Report: {average} seconds per packet.')
