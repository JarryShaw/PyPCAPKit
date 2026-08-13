# -*- coding: utf-8 -*-

import pcapkit

default = pcapkit.extract(fin='../sample/in.pcap',
                          fout='../sample/engines/default.txt', format='tree', engine='default')
pyshark = pcapkit.extract(fin='../sample/in.pcap',
                          fout='../sample/engines/pyshark.txt', format='tree', engine='pyshark')
scapy = pcapkit.extract(fin='../sample/in.pcap',
                        fout='../sample/engines/scapy.txt', format='tree', engine='scapy')
dpkt = pcapkit.extract(fin='../sample/in.pcap',
                       fout='../sample/engines/dpkt.txt', format='tree', engine='dpkt')

# pipeline = pcapkit.extract(fin='../sample/in.pcap',
#                            nofile=True, engine='pipeline')
# server = pcapkit.extract(fin='../sample/in.pcap', nofile=True, engine='server')
