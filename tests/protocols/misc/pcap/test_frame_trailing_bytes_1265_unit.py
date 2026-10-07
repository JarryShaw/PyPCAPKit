# -*- coding: utf-8 -*-
"""A PCAP file ending in a partial record header stops cleanly at EOF.

GitHub issue #1265: with fewer than sixteen octets left after the last record,
:meth:`Frame.unpack <pcapkit.protocols.misc.pcap.frame.Frame.unpack>` parsed a
record header out of zero padding, and the payload read got a negative length
(``ValueError: read length must be non-negative or -1``). A tail that short now
raises :exc:`~pcapkit.utilities.exceptions.StreamEOFError`, which the extractor
treats as the end of the file, as it does for a truncated PCAP-NG block (#678).

Every case builds its own octets and reads no capture. Classes are imported
inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import io
import os
import tempfile
import unittest
import warnings

from tests._support import reimport_once_per_class

#: Little-endian global header: v2.4, Ethernet.
GLOBAL = bytes.fromhex('d4c3b2a1' '0200' '0400' '00000000' '00000000' 'ffff0000' '01000000')
#: One record: ts 1.000002, incl_len = orig_len = 4, four payload octets.
RECORD = bytes.fromhex('01000000' '02000000' '04000000' '04000000') + b'\xde\xad\xbe\xef'
TRAIL = b'\x00\x01\x02'


class TestFrameTrailingBytes(unittest.TestCase):
    """Pin the end-of-file signal for a tail shorter than a record header."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_short_tail_raises_stream_eof(self) -> None:
        from pcapkit.protocols.misc.pcap.header import Header
        from pcapkit.protocols.misc.pcap.frame import Frame
        from pcapkit.utilities.exceptions import StreamEOFError

        header = Header(GLOBAL)
        for size in range(16):
            with self.subTest(size=size):
                with self.assertRaises(StreamEOFError):
                    Frame(io.BytesIO(RECORD[:size]), num=1, header=header.info)

    def test_extract_keeps_frames_before_short_tail(self) -> None:
        import pcapkit

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'trail.pcap')
            with open(path, 'wb') as file:
                file.write(GLOBAL + RECORD + TRAIL)

            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                ext = pcapkit.extract(fin=path, nofile=True, store=True, auto=False,
                                      engine='default')
                frames = []
                # bounded, so that a reader which never reaches EOF fails
                # rather than spinning
                for _ in range(5):
                    try:
                        frames.append(next(ext))
                    except StopIteration:
                        break
                ext.close() if hasattr(ext, 'close') else None

        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].info.packet, b'\xde\xad\xbe\xef')


if __name__ == '__main__':
    unittest.main()
