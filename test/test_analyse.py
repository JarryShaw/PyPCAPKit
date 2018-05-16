# -*- coding: utf-8 -*-


import jspcap
import pprint


extraction = jspcap.extract(
    fin='../sample/http6.cap', # fout='../sample/http.txt', format='tree',
    store=False, tcp=True, verbose=True, nofile=True, strict=True, extension=False
)
# pprint.pprint(extraction.reassembly.tcp)
print()
for packet in extraction.reassembly.tcp:
    for reassembly in packet.packets:
        if jspcap.HTTP in reassembly.protochain:
            pprint.pprint(reassembly.info)
        else:
            print(reassembly)
    print()
