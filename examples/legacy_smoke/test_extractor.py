# -*- coding: utf-8 -*-

import pcapkit

plist = pcapkit.extract(fin='../sample/in.pcap', fout='../sample/out.plist', format='plist')
json = pcapkit.extract(fin='../sample/in.pcap', fout='../sample/out.json', format='json')
tree = pcapkit.extract(fin='../sample/in.pcap', fout='../sample/out.txt', format='tree')
