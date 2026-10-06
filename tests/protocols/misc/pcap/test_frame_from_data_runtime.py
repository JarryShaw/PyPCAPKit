# -*- coding: utf-8 -*-
"""``Frame.from_data`` rebuilds a captured frame.

GitHub issue #1126: :meth:`~pcapkit.protocols.protocol.ProtocolBase.from_data`
took nothing but the data, so the ``num`` and ``header`` that
:class:`~pcapkit.protocols.misc.pcap.frame.Frame` requires could not reach it,
and every call raised :exc:`TypeError`. ``from_data`` now forwards extra
keywords to the construction, so the caller passes both alongside the data.

The frames are read from :file:`examples/captures/in.pcap`, so this belongs to
the runtime tier.

"""
from __future__ import annotations

import importlib.util
import os
import unittest

from tests._support import reimport_once_per_class, sample_path

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class FrameFromDataRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_from_data_round_trips_every_frame_byte_for_byte(self) -> None:
        from pcapkit.protocols.misc.pcap.frame import Frame
        from pcapkit.protocols.misc.pcap.header import Header

        path = sample_path('in.pcap')
        size = os.path.getsize(path)
        with open(path, 'rb') as file:
            header = Header(file)
            num = 0
            while file.tell() < size:
                num += 1
                start = file.tell()
                frame = Frame(file, num=num, header=header.info)
                end = start + 16 + frame.info.frame_info.incl_len
                file.seek(start)
                octets = file.read(end - start)

                with self.subTest(frame=num):
                    rebuilt = Frame.from_data(frame.info, num=num, header=header.info)
                    self.assertEqual(bytes(rebuilt), octets)
                    self.assertEqual(rebuilt.info.number, num)

        self.assertEqual(num, 6)

    def test_from_data_keyword_overrides_make_data(self) -> None:
        from pcapkit.protocols.misc.pcap.frame import Frame
        from pcapkit.protocols.misc.pcap.header import Header

        with open(sample_path('in.pcap'), 'rb') as file:
            header = Header(file)
            frame = Frame(file, num=1, header=header.info)

        rebuilt = Frame.from_data(frame.info, num=1, header=header.info, ts_sec=42)
        self.assertEqual(rebuilt.info.frame_info.ts_sec, 42)

    def test_from_data_rejects_a_misspelled_keyword(self) -> None:
        from pcapkit.protocols.misc.pcap.frame import Frame
        from pcapkit.protocols.misc.pcap.header import Header
        from pcapkit.utilities.exceptions import UnsupportedCall

        with open(sample_path('in.pcap'), 'rb') as file:
            header = Header(file)
            frame = Frame(file, num=1, header=header.info)

        with self.assertRaisesRegex(UnsupportedCall, "'heaedr'"):
            Frame.from_data(frame.info, num=1, heaedr=header.info)


if __name__ == '__main__':
    unittest.main()
