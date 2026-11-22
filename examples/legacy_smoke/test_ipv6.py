# -*- coding: utf-8 -*-

import pcapkit
from pcapkit.foundation.options import DumpOptions

extraction = pcapkit.extract(fin='../captures/ipv6.pcap',
                             dump=DumpOptions(fout='../captures/ipv6', format='tree', files=True),
                             verbose=True, store=False)
