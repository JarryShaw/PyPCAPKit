# -*- coding: utf-8 -*-

import pcapkit

plist = pcapkit.extract(fin='../captures/dhcp.pcapng',
                        fout='../captures/pcapng.txt', format='tree', verbose=True)
