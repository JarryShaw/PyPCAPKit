# -*- coding: utf-8 -*-


import jspcap


extractor = jspcap.Extractor(
    fin='../sample/ipv6.pcap', fout='../sample/ipv6', format='tree',
    files=True, verbose=True, store=False
)
