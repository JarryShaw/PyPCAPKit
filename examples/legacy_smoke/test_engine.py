# -*- coding: utf-8 -*-
"""Extract one capture with each of pcapkit's extraction engines.

Every engine is asked for the same tree-view dump of the same file, so the outputs
under ``../captures/engines/`` can be compared side by side.

An engine that is not available on this host is reported as skipped, with the
reason, and the rest of the demo carries on -- see :mod:`_engine_support` for what
counts as unavailable. Anything else is a real failure and is left to propagate.

Each line also names the driver that actually ran, because an engine whose package
is missing does not fail: ``Extractor`` warns and quietly uses pcapkit's own parser
instead, which would otherwise show up here as a healthy frame count.

"""

import os

import pcapkit
from _engine_support import ENGINES, ran_as_asked, report, unavailable

for engine in ENGINES:
    fout = f'../captures/engines/{engine}.txt'

    try:
        extraction = pcapkit.extract(fin='../captures/in.pcap', fout=fout,
                                     format='tree', engine=engine)  # type: ignore[arg-type]
    except Exception as exc:  # pylint: disable=broad-except
        reason = unavailable(exc)
        if reason is None:
            raise
        report(engine, f'skipped -- {reason}')

        # The dump file is opened before the engine runs, so a skipped engine
        # leaves an empty one behind. Drop it: a 0-byte engines/pyshark.txt next
        # to a full engines/default.txt reads as "pyshark parsed nothing".
        if os.path.exists(fout) and os.path.getsize(fout) == 0:
            os.remove(fout)
    else:
        driver, asked = ran_as_asked(engine, extraction)
        if asked:
            report(engine, f'{extraction.length} frames via {driver} -> {fout}')
        else:
            report(engine, f'its package is not installed -- pcapkit fell back to '
                           f'{driver}; {extraction.length} frames -> {fout}')
