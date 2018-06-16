# -*- coding: utf-8 -*-


import jspcap


plist = jspcap.tkextract(fin='../sample/in.pcap', fout='../sample/out.plist', format='plist')
json = jspcap.tkextract(fin='../sample/in.pcap', fout='../sample/out.json', format='json')
# html = jspcap.tkextract(fin='../sample/in.pcap', fout='../sample/out.js', format='html')
tree = jspcap.tkextract(fin='../sample/in.pcap', fout='../sample/out.txt', format='tree')
# json = jspcap.tkextract(fin='../sample/in.pcap', fout='../sample/out.xml', format='xml')
