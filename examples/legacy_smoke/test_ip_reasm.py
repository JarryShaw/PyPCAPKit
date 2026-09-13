# -*- coding: utf-8 -*-

import os
import textwrap

import pcapkit

os.system('> ../sample/out')  # nosec: B605 B607

extraction = pcapkit.extract(
    fin='../sample/ipv4.pcap', engine=pcapkit.PCAPKit,  # type: ignore[arg-type]
    store=False, ipv4=True, verbose=True, reasm_strict=True, #nofile=True,
    fout='../sample/ip_out.txt', format='tree', reassembly=True,
)
# pprint.pprint(extraction.frame)

with open('../sample/out', 'a') as file:  # pylint: disable=unspecified-encoding
    # pprint.pprint(extraction.reassembly.ipv4)
    for datagram in extraction.reassembly.ipv4:
        print(f'completed = {datagram.completed}')
        file.write(f'completed = {datagram.completed}')
        file.write('\n')

        print(f'index = {datagram.index}')
        file.write(f'index = {datagram.index}')
        file.write('\n\n')

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
        file.write('\n')

        print(repr(datagram.packet))
        print(repr(datagram.packet), file=file)

        file.write(str(datagram.packet))
        print()

        file.write('\n\n')
        file.write('-' * 80)
        file.write('\n\n')
