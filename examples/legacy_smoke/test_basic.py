# -*- coding: utf-8 -*-

import pcapkit

plist = pcapkit.extract(fin='../sample/in.pcap', fout='../sample/out.txt', format='tree', verbose=True)
