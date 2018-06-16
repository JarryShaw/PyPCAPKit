# -*- coding: utf-8 -*-


import pprint

import jspcap


extraction = jspcap.tkextract(
    fin='../sample/http6.cap', # fout='../sample/http.txt', format='tree',
    store=False, tcp=True, verbose=True, nofile=True, strict=True, extension=False
)
# pprint.pprint(extraction.reassembly.tcp)
print()
for reassembly in extraction.reassembly.tcp:
    for packet in reassembly.packets:
        if jspcap.HTTP in packet.protochain:
            with open('../sample/37fc254c-68c1-4677-9ed1-806c5eab8acb.dat', 'ab') as file:
                file.write(packet.info.raw.header or b'')
            pprint.pprint(packet.info)
        else:
            print(packet)
    print()
