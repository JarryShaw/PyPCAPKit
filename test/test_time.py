# -*- coding: utf-8 -*-


import jspcap
import statistics
import time


lid = list()
for index in range(1, 101):
    now = time.time()

    tree = jspcap.Extractor(fin='../sample/test.pcap', tcp=True, store=False, nofile=True, strict=True)

    delta = time.time() - now
    print(f'No. {index:>3d}: {tree.length} packets extracted and reassembled in {delta} seconds.')
    lid.append(float(delta))

avetime = statistics.mean(delta)
average = avetime / tree.length
print(f'Report: {average} seconds per packet.')
