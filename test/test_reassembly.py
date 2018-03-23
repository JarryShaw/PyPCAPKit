#!/usr/bin/python3
# -*- coding: utf-8 -*-


import chardet
import jspcap
import os
import pprint
import textwrap


os.system('> ../sample/out')

tree = jspcap.Extractor(
    fin='../sample/test.pcap', fout='../sample/test', format='tree', ip=False, tcp=True, verbose=True, nofile=True,
)
# pprint.pprint(tree.frame)

with open('../sample/out', 'a') as file:
    tcp = jspcap.TCP_Reassembly(strict=True)
    tcp.run(tree.frame.tcp)
    # pprint.pprint(tcp.datagram)
    for datagram in tcp.datagram:
        print(f'NotImplemented = {datagram.NotImplemented}')
        file.write(f'NotImplemented = {datagram.NotImplemented}')
        file.write('\n')
        print(f'index = {datagram.index}')
        file.write(f'index = {datagram.index}')
        file.write('\n')
        if not datagram.NotImplemented:
            result = chardet.detect(datagram.payload)
            if result['encoding'] is not None:
                print(f"encoding = {result['encoding']} ({result['confidence']}, {result['language']})")
                file.write(f"encoding = {result['encoding']} ({result['confidence']}, {result['language']})")
                file.write('\n')
            try:
                file.write(datagram.payload.decode(result['encoding']))
                file.write('\n')
            except:
                print('/* encoding failed */')
                file.write('/* encoding failed */')
                file.write('\n')
                for item in textwrap.wrap(datagram.payload.hex(), 64):
                    file.write(' '.join(textwrap.wrap(item, 2)))
                    file.write('\n')
        else:
            for (index, payload) in enumerate(datagram.payload):
                file.write(f'Fragment No. {index}\n')
                for item in textwrap.wrap(payload.hex(), 64):
                    file.write(' '.join(textwrap.wrap(item, 2)))
                    file.write('\n')
        print()
        file.write('\n\n')
        file.write('—' * 80)
        file.write('\n\n')
