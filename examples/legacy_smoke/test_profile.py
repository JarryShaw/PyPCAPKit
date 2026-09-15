# -*- coding: utf-8 -*-
"""Profile a ``pcapkit.extract`` run and write cProfile stats for ``make profile``."""

import cProfile
import os

import pcapkit

#: Where cProfile writes its stats. ``make profile`` renders this into a call graph.
STATS = os.path.join('temp', 'parse_pcap.pstats')


def test() -> 'None':
    pcapkit.extract(fin='../captures/http.pcap', store=True,
                    nofile=True, engine='default', verbose=True)


if __name__ == '__main__':
    # cProfile will not create the directory it dumps into, so `python
    # test_profile.py` on a fresh checkout used to profile the whole run and then
    # die with FileNotFoundError. `make profile` does mkdir first; the script
    # should not need it to.
    os.makedirs(os.path.dirname(STATS), exist_ok=True)

    cProfile.run(
        'test()',
        STATS,
    )
    print(f'test_profile: wrote {STATS}')
