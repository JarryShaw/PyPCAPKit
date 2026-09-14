# -*- coding: utf-8 -*-

import pcapkit

plist = pcapkit.extract(fin='../captures/in.pcap', fout='../captures/out.txt', format='tree', verbose=True)
