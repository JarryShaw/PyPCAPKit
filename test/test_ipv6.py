#!/usr/bin/python3
# -*- coding: utf-8 -*-


import jspcap


extractor = jspcap.Extractor(fin='../sample/ipv6.pcap', fout='../sample/ipv6', files=True, format='tree', verbose=True)
