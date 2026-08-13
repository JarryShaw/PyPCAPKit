# -*- coding: utf-8 -*-

import pcapkit

extraction = pcapkit.extract(
    fin='../sample/ipv6.pcap', fout='../sample/ipv6', format='tree',
    files=True, verbose=True, store=False
)
