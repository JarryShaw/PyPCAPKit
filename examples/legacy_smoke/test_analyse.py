# -*- coding: utf-8 -*-

import pprint

import pcapkit

# NOTE: without ``reassembly`` the extraction runs to completion and then
# ``extraction.reassembly`` raises ``UnsupportedCall``.
extraction = pcapkit.extract(
    '../captures/http6.cap',
    store=False, verbose=True, reassembly=['tcp'],
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
