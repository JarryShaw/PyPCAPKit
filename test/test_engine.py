# -*- coding: utf-8 -*-


import jspcap


default = jspcap.extract(fin='../sample/in.pcap', fout='../sample/engines/default.txt', format='tree', engine='default')
pyshark = jspcap.extract(fin='../sample/in.pcap', fout='../sample/engines/pyshark.txt', format='tree', engine='pyshark')
scapy = jspcap.extract(fin='../sample/in.pcap', fout='../sample/engines/scapy.txt', format='tree', engine='scapy')
dpkt = jspcap.extract(fin='../sample/in.pcap', fout='../sample/engines/dpkt.txt', format='tree', engine='dpkt')
