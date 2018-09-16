# -*- coding: utf-8 -*-


import cProfile
import pstats

import pcapkit


for engine in {'default', 'pyshark', 'scapy', 'dpkt', 'pipline', 'server'}:
    test = lambda : pcapkit.extract(fin='../sample/in.pcap', store=False, nofile=True, engine=engine)

    profiler = cProfile.Profile()
    profiler.runcall(test)

    stats = pstats.Stats(profiler)
    stats.strip_dirs()
    stats.sort_stats('cumulative')
    stats.print_stats()
