# -*- coding: utf-8 -*-

import pcapkit

plist = pcapkit.extract(fin='../sample/dhcp.pcapng',
                        fout='../sample/pcapng.txt', format='tree', verbose=True)
