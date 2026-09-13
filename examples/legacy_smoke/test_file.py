# -*- coding: utf-8 -*-

import pcapkit

with open('../sample/in.pcap', 'rb') as file:
    pcapkit.extract(fin=file, nofile=True, verbose=True)
