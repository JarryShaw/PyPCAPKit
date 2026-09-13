# -*- coding: utf-8 -*-

import pcapkit

plist = pcapkit.extract(fin='../sample/tcp.pcap', fout='../sample/tcp.txt', format='tree', verbose=True)
