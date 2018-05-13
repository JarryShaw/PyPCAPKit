# -*- coding: utf-8 -*-


import io
import jspcap
import pprint


tree = jspcap.Extractor(
    fin='../sample/http6.cap',
    store=False, tcp=True, verbose=True, nofile=True, strict=True, extension=False
)
# pprint.pprint(tree.reassembly.tcp)
print()
for packet in tree.reassembly.tcp:
    payload = packet['payload']
    report = jspcap.analyse(io.BytesIO(payload), len(payload))
    if report.protochain and jspcap.HTTP in report.protochain:
        pprint.pprint(report.info)
    else:
        print(report)
    print()
