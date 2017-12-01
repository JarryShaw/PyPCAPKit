#!/usr/bin/python3
# -*- coding: utf-8 -*-


from jspcap.extractor import Extractor


a = Extractor(fin='sample/in.pcap', fout='sample/out.plist', fmt='plist')
a = Extractor(fin='sample/in.pcap', fout='sample/out.js', fmt='html')
a = Extractor(fin='sample/in.pcap', fout='sample/out.txt', fmt='tree')
a = Extractor(fin='sample/in.pcap', fout='sample/out.xml', fmt='xml')
