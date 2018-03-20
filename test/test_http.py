#!/usr/bin/python3
# -*- coding: utf-8 -*-


import jspcap
import pprint


# plist = jspcap.Extractor(fin='../sample/in.pcap', fout='../sample/out.plist', format='plist')
# html = jspcap.Extractor(fin='../sample/in.pcap', fout='../sample/out.js', format='html')
tree = jspcap.Extractor(fin='../sample/http.pcap', fout='../sample/http', format='tree', verbose=True, files=True)
# json = jspcap.Extractor(fin='../sample/in.pcap', fout='../sample/out.xml', format='xml')
