# -*- coding: utf-8 -*-

import pprint

import pcapkit

# NOTE: ``reassembly=True`` is what turns reassembly on; ``tcp=True`` only selects
# which protocol to reassemble, and ``reasm_strict`` only tunes it. Without it the
# extraction runs to completion and then ``extraction.reassembly`` raises
# ``UnsupportedCall``, since the attribute is gated on the reassembly flag.
extraction = pcapkit.extract(
    fin='../captures/http6.cap',  # fout='../captures/http.txt', format='tree',
    store=False, tcp=True, verbose=True, nofile=True, reassembly=True,
    reasm_strict=True, extension=False
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
