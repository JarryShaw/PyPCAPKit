# -*- coding: utf-8 -*-

import pcapkit

plist = pcapkit.extract(fin='../captures/tcp.pcap', fout='../captures/tcp.txt', format='tree', verbose=True)
