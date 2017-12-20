#!/usr/bin/python3
# -*- coding: utf-8 -*-


from pprint import pprint
from jspcap import Extractor
from jspcap.reassembly import IPv4_Reassembly, IPv6_Reassembly, TCP_Reassembly


plist = Extractor(fin='sample/in.pcap', fout='sample/out.plist', fmt='plist')
html = Extractor(fin='sample/in.pcap', fout='sample/out.js', fmt='html')
tree = Extractor(
        fin='sample/in.pcap', fout='sample/out.txt', fmt='tree',
        ipv4_reassembly=True, ipv6_reassembly=True, tcp_reassembly=True
    )
json = Extractor(fin='sample/in.pcap', fout='sample/out.xml', fmt='xml')

pprint(tree.frame)

ipv4 = IPv4_Reassembly(tree.frame.ipv4)
ipv6 = IPv6_Reassembly(tree.frame.ipv6)
tcp = TCP_Reassembly(tree.frame.tcp)

pprint(ipv4.datagram)
pprint(ipv6.datagram)
pprint(tcp.datagram)
