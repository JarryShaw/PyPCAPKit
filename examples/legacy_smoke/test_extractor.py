# -*- coding: utf-8 -*-

import pcapkit
from pcapkit.foundation.options import DumpOptions

plist = pcapkit.extract(fin='../captures/in.pcap',
                        dump=DumpOptions(fout='../captures/out.plist', format='plist'))
json = pcapkit.extract(fin='../captures/in.pcap',
                       dump=DumpOptions(fout='../captures/out.json', format='json'))
tree = pcapkit.extract(fin='../captures/in.pcap',
                       dump=DumpOptions(fout='../captures/out.txt', format='tree'))
