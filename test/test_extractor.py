# -*- coding: utf-8 -*-


import jspcap
import pprint


plist = jspcap.extract(fin='../sample/in.pcap', fout='../sample/out.plist', format='plist')
plist = jspcap.extract(fin='../sample/in.pcap', fout='../sample/out.json', format='json')
# html = jspcap.extract(fin='../sample/in.pcap', fout='../sample/out.js', format='html')
tree = jspcap.extract(fin='../sample/in.pcap', fout='../sample/out.txt', format='tree', ip=True, tcp=True)
# json = jspcap.extract(fin='../sample/in.pcap', fout='../sample/out.xml', format='xml')
