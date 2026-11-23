# -*- coding: utf-8 -*-

import pcapkit
from pcapkit.foundation.options import DumpOptions

plist = pcapkit.extract(fin='../captures/tcp.pcap',
                        dump=DumpOptions(fout='../captures/tcp.txt', format='tree'), verbose=True)
