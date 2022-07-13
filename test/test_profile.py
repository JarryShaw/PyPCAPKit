# -*- coding: utf-8 -*-

import cProfile

import pcapkit


def test() -> 'None':
    pcapkit.extract(fin='../sample/http.pcap', store=False, nofile=True, engine='default')


if __name__ == '__main__':
    cProfile.run(
        'test()',
        'temp/parse_pcap.pstats',
    )
