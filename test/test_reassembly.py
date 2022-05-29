# -*- coding: utf-8 -*-

import os
#import pprint
import textwrap

import pcapkit

os.system('> ../sample/out')  # nosec: B605 B607

extraction = pcapkit.extract(
    fin='../sample/test.pcap', engine=pcapkit.PCAPKit,  # type: ignore[arg-type]
    store=False, tcp=True, verbose=True, strict=True, nofile=True,
)
# pprint.pprint(extraction.frame)

with open('../sample/out', 'a') as file:
    # pprint.pprint(extraction.reassembly.tcp)
    for datagram in extraction.reassembly.tcp:  # type: ignore[union-attr]
        print(f'completed = {datagram.completed}')
        file.write(f'completed = {datagram.completed}')
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

                file.write(payload.decode(errors='replace'))
                file.write('\n')
        else:
            for item in textwrap.wrap(datagram.payload.hex(), 64):
                file.write(' '.join(textwrap.wrap(item, 2)))
                file.write('\n')

            file.write(datagram.payload.decode(errors='replace'))
            file.write('\n')
        # for packet in datagram.packets:
        #     file.write(str(packet))
        #     file.write('\n')
        print()
        file.write('\n\n')
        file.write('-' * 80)
        file.write('\n\n')
