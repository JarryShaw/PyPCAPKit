# -*- coding: utf-8 -*-

import pcapkit
from pcapkit.foundation.options import DumpOptions

plist = pcapkit.extract(fin='../captures/dhcp.pcapng',
                        dump=DumpOptions(fout='../captures/pcapng.txt', format='tree'),
                        verbose=True)
