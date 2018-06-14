# -*- coding: utf-8 -*-


import jspcap


plist = jspcap.extract(fin='../sample/in.pcap', fout='../sample/out.plist', format='plist')
json = jspcap.extract(fin='../sample/in.pcap', fout='../sample/out.json', format='json')
# html = jspcap.extract(fin='../sample/in.pcap', fout='../sample/out.js', format='html')
tree = jspcap.extract(fin='../sample/in.pcap', fout='../sample/out.txt', format='tree')
# json = jspcap.extract(fin='../sample/in.pcap', fout='../sample/out.xml', format='xml')
