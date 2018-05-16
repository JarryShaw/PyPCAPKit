# -*- coding: utf-8 -*-


import chardet
import jspcap
import os
import pprint
import textwrap
import time


os.system('> ../sample/out')

extraction = jspcap.extract(
    fin='../sample/test.pcap',
    store=False, tcp=True, verbose=True, strict=True, nofile=True,
)
# pprint.pprint(extraction.frame)

with open('../sample/out', 'a') as file:
    # pprint.pprint(tcp.datagram)
    for datagram in extraction.reassembly.tcp:
        print(f'NotImplemented = {datagram.NotImplemented}')
        file.write(f'NotImplemented = {datagram.NotImplemented}')
        file.write('\n')
        print(f'index = {datagram.index}')
        file.write(f'index = {datagram.index}')
        file.write('\n')
        if isinstance(datagram.payload, tuple):
            for (index, payload) in enumerate(datagram.payload):
                file.write(f'Fragment No. {index}\n')
                for item in textwrap.wrap(payload.hex(), 64):
                    file.write(' '.join(textwrap.wrap(item, 2)))
                    file.write('\n')
        else:
            for item in textwrap.wrap(datagram.payload.hex(), 64):
                file.write(' '.join(textwrap.wrap(item, 2)))
                file.write('\n')
        for packet in datagram.packets:
            file.write(str(packet))
            file.write('\n')
        print()
        file.write('\n\n')
        file.write('—' * 80)
        file.write('\n\n')
