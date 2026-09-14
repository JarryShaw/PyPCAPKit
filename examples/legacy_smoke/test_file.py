# -*- coding: utf-8 -*-

import pcapkit

with open('../captures/in.pcap', 'rb') as file:
    pcapkit.extract(fin=file, nofile=True, verbose=True)
