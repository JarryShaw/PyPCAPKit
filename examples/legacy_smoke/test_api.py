# -*- coding: utf-8 -*-

import pcapkit
from pcapkit.foundation.options import DumpOptions, ReassemblyOptions, TraceFlowOptions

json = pcapkit.extract(fin='../captures/http.pcap',
                       dump=DumpOptions(fout='../captures/http', format='json', files=True),
                       store=True, verbose=True,
                       reassembly=ReassemblyOptions(protocols=['ipv4', 'ipv6', 'tcp'], strict=False),
                       traceflow=TraceFlowOptions(protocols=['tcp'], fout='../captures/trace', format='json'))
