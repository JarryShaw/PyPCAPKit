# -*- coding: utf-8 -*-

import pcapkit

plist = pcapkit.extract(fin='../captures/in.pcap', fout='../captures/out.plist', format='plist')
json = pcapkit.extract(fin='../captures/in.pcap', fout='../captures/out.json', format='json')
tree = pcapkit.extract(fin='../captures/in.pcap', fout='../captures/out.txt', format='tree')
