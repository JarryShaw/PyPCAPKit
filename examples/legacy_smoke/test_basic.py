# -*- coding: utf-8 -*-

import pcapkit
from pcapkit.foundation.options import DumpOptions

plist = pcapkit.extract(fin='../captures/in.pcap',
                        dump=DumpOptions(fout='../captures/out.txt', format='tree'), verbose=True)
