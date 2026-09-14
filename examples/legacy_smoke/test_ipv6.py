# -*- coding: utf-8 -*-

import pcapkit

extraction = pcapkit.extract(
    fin='../captures/ipv6.pcap', fout='../captures/ipv6', format='tree',
    files=True, verbose=True, store=False
)
