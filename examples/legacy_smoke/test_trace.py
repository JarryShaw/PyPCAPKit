# -*- coding: utf-8 -*-

import pprint

import pcapkit

trace = pcapkit.extract(fin='../captures/http.pcap', nofile=True, verbose=True,
                        engine=pcapkit.PCAPKit, tcp=True,  # type: ignore[arg-type]
                        trace=True, trace_format='json', trace_fout='../captures/trace')
pprint.pprint(trace.trace)
