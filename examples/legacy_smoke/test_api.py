# -*- coding: utf-8 -*-

import pcapkit

# NOTE: ``ip``, ``tcp`` and ``reasm_strict`` are reassembly knobs and do nothing on
# their own -- ``reassembly=True`` is the flag that switches reassembly on, just as
# ``trace=True`` switches flow tracing on. ``tcp=True`` feeds both.
json = pcapkit.extract(fin='../captures/http.pcap', fout='../captures/http', format='json', files=True,
                       store=True, verbose=True, reassembly=True, ip=True, tcp=True,
                       reasm_strict=False, trace=True,
                       trace_format='json', trace_fout='../captures/trace')
