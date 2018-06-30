# -*- coding: utf-8 -*-


import pcapkit


plist = pcapkit.extract(fin='../sample/in.pcap', fout='../sample/out.plist', format='plist')
json = pcapkit.extract(fin='../sample/in.pcap', fout='../sample/out.json', format='json')
# html = pcapkit.extract(fin='../sample/in.pcap', fout='../sample/out.js', format='html')
tree = pcapkit.extract(fin='../sample/in.pcap', fout='../sample/out.txt', format='tree')
# json = pcapkit.extract(fin='../sample/in.pcap', fout='../sample/out.xml', format='xml')
