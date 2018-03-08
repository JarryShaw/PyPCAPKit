#!/usr/bin/python3
# -*- coding: utf-8 -*-


import jspcap
import pprint


plist = jspcap.Extractor(fin='../sample/in.pcap', fout='../sample/out.plist', format='plist')
# html = jspcap.Extractor(fin='../sample/in.pcap', fout='../sample/out.js', format='html')
tree = jspcap.Extractor(fin='../sample/in.pcap', fout='../sample/out.txt', format='tree', ip=True, tcp=True)
# json = jspcap.Extractor(fin='../sample/in.pcap', fout='../sample/out.xml', format='xml')

pprint.pprint(tree.frame)

ipv4 = jspcap.IPv4_Reassembly(strict=True)
ipv4.run(tree.frame.ipv4)
ipv6 = jspcap.IPv6_Reassembly(strict=True)
ipv6.run(tree.frame.ipv6)
tcp = jspcap.TCP_Reassembly(strict=True)
tcp.run(tree.frame.tcp)

pprint.pprint(ipv4.datagram)
pprint.pprint(ipv6.datagram)
pprint.pprint(tcp.datagram)
