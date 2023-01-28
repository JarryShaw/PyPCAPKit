# -*- coding: utf-8 -*-

import cProfile

import pcapkit


def test() -> 'None':
    pcapkit.extract(fin='../sample/http.pcap', store=True,
                    nofile=True, engine='default', verbose=True)


if __name__ == '__main__':
    cProfile.run(
        'test()',
        'temp/parse_pcap.pstats',
    )
