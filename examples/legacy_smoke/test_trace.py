# -*- coding: utf-8 -*-

import pprint

import pcapkit
from pcapkit.foundation.options import TraceFlowOptions

trace = pcapkit.extract('../captures/http.pcap', verbose=True,
                        engine=pcapkit.PCAPKit,  # type: ignore[arg-type]
                        traceflow=TraceFlowOptions(protocols=['tcp'], format='json', fout='../captures/trace'))
pprint.pprint(trace.traceflow)
