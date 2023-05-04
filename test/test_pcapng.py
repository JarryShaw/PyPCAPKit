# -*- coding: utf-8 -*-

import pcapkit

plist = pcapkit.extract(fin='../sample/test.pcapng',
                        fout='../sample/pcapng.txt', format='tree', verbose=True)
