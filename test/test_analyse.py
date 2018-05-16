# -*- coding: utf-8 -*-


import io
import jspcap
import pprint


tree = jspcap.extract(
    fin='../sample/http6.cap', # fout='../sample/http.txt', format='tree',
    store=False, tcp=True, verbose=True, nofile=True, strict=True, extension=False
)
# pprint.pprint(tree.reassembly.tcp)
print()
for packet in tree.reassembly.tcp:
    for reassembly in packet.packets:
        if jspcap.HTTP in reassembly.protochain:
            pprint.pprint(reassembly.info)
        else:
            print(reassembly)
    print()
