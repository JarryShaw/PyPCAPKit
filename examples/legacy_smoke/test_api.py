# -*- coding: utf-8 -*-

import pcapkit

json = pcapkit.extract(fin='../captures/http.pcap', fout='../captures/http', format='json', files=True,
                       store=True, verbose=True, ip=True, tcp=True, reasm_strict=False, trace=True,
                       trace_format='json', trace_fout='../captures/trace')
