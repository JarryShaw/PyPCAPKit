# -*- coding: utf-8 -*-


import io
import jspcap
import pprint


tree = jspcap.Extractor(fin='../sample/http1.pcap', tcp=True, verbose=True, nofile=True, strict=True)
# pprint.pprint(tree.reassembly.tcp)
print()
for packet in tree.reassembly.tcp:
    pprint.pprint(jspcap.analyse(io.BytesIO(packet['payload']), len(packet['payload'])).info)
    print()
