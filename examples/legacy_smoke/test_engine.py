# -*- coding: utf-8 -*-

import pcapkit

default = pcapkit.extract(fin='../captures/in.pcap',
                          fout='../captures/engines/default.txt', format='tree', engine='default')
pyshark = pcapkit.extract(fin='../captures/in.pcap',
                          fout='../captures/engines/pyshark.txt', format='tree', engine='pyshark')
scapy = pcapkit.extract(fin='../captures/in.pcap',
                        fout='../captures/engines/scapy.txt', format='tree', engine='scapy')
dpkt = pcapkit.extract(fin='../captures/in.pcap',
                       fout='../captures/engines/dpkt.txt', format='tree', engine='dpkt')

# pipeline = pcapkit.extract(fin='../captures/in.pcap',
#                            nofile=True, engine='pipeline')
# server = pcapkit.extract(fin='../captures/in.pcap', nofile=True, engine='server')
