# -*- coding: utf-8 -*-

import pprint

import pcapkit

trace = pcapkit.extract(fin='../sample/http.pcap', nofile=True, verbose=True,
                        trace=True, trace_format='json', trace_fout='../sample/trace')
pprint.pprint(trace.trace)
