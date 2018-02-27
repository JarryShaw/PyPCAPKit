#!/usr/bin/python3
# -*- coding: utf-8 -*-


from os import system
from pprint import pprint
from jspcap import Extractor, IPv4_Reassembly, IPv6_Reassembly, TCP_Reassembly


system('> sample/out')

plist = Extractor(fin='sample/in.pcap', fout='sample/out.plist', fmt='plist')
html = Extractor(fin='sample/in.pcap', fout='sample/out.js', fmt='html')
tree = Extractor(fin='sample/in.pcap', fout='sample/out.txt', fmt='tree', ip=True, tcp=True)
json = Extractor(fin='sample/in.pcap', fout='sample/out.xml', fmt='xml')

pprint(tree.frame)

ipv4 = IPv4_Reassembly(strict=True)
ipv4.run(tree.frame.ipv4)
ipv6 = IPv6_Reassembly(strict=True)
ipv6.run(tree.frame.ipv6)
tcp = TCP_Reassembly(strict=True)
tcp.run(tree.frame.tcp)

pprint(ipv4.datagram)
pprint(ipv6.datagram)
pprint(tcp.datagram)
