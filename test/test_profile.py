# -*- coding: utf-8 -*-

import cProfile
import pstats

import pcapkit


def test():
    return pcapkit.extract(fin='../sample/in.pcap',
                           store=False, nofile=True, engine=engine)


for engine in {'default', 'pyshark', 'scapy', 'dpkt', 'pipline', 'server'}:
    profiler = cProfile.Profile()
    profiler.runcall(test)

    stats = pstats.Stats(profiler)
    stats.strip_dirs()
    stats.sort_stats('cumulative')
    stats.print_stats()
