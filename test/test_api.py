# -*- coding: utf-8 -*-

import pcapkit

json = pcapkit.extract(fin='../sample/http.pcap', fout='../sample/http', format='json', files=True,
                       store=True, verbose=True, ip=True, tcp=True, reasm_strict=False, trace=True,
                       trace_format='json', trace_fout='../sample/trace')
