# -*- coding: utf-8 -*-

import pprint

import pcapkit

extraction = pcapkit.extract(
    fin='../sample/http6.cap',  # fout='../sample/http.txt', format='tree',
    store=False, tcp=True, verbose=True, nofile=True, reasm_strict=True, extension=False
)
# pprint.pprint(extraction.reassembly.tcp)
print()
for reassembly in extraction.reassembly.tcp:
    if reassembly.packet is None:
        pprint.pprint(reassembly.payload)
    else:
        if pcapkit.HTTP in reassembly.packet:
            pprint.pprint(reassembly.packet.info.to_dict())
        else:
            print(reassembly.packet)
    print()
