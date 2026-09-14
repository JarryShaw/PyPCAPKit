# -*- coding: utf-8 -*-

import pyperf

from pcapkit import extract


def default() -> 'None':
    extract(fin='../captures/in.pcap', fout='../captures/engines/default.txt',
                format='tree', engine='default')


def scapy() -> 'None':
    extract(fin='../captures/in.pcap', fout='../captures/engines/scapy.txt',
                format='tree', engine='scapy')


def dpkt() -> 'None':
    extract(fin='../captures/in.pcap', fout='../captures/engines/dpkt.txt',
                format='tree', engine='dpkt')


def pyshark() -> 'None':
    extract(fin='../captures/in.pcap', fout='../captures/engines/pyshark.txt',
                format='tree', engine='pyshark')


runner = pyperf.Runner()
runner.bench_func('default', default)
runner.bench_func('scapy', scapy)
runner.bench_func('dpkt', dpkt)
runner.bench_func('pyshark', pyshark)
