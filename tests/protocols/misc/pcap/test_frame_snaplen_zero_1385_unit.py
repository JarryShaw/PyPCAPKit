# -*- coding: utf-8 -*-
"""Building a PCAP frame under a zero snaplen keeps the whole packet.

GitHub issue #1385: :meth:`Frame.make <pcapkit.protocols.misc.pcap.frame.Frame.make>`
defaulted ``incl_len`` to ``min(len(packet), snaplen)``, so a global header with
snaplen 0 produced a 16-octet record holding no packet data. The PCAP draft says
snaplen "MUST NOT be zero" (draft-ietf-opsawg-pcap, section 4), and libpcap reads
a zero value as the maximum for the link type (``pcapint_adjust_snapshot``), so
a zero snaplen is now no limit, as it already is for PCAP-NG.

Every case builds its own octets and reads no capture. Classes are imported
inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import io
import unittest

from tests._support import reimport_once_per_class

#: Little-endian global header: v2.4, snaplen 0, Ethernet.
GLOBAL_ZERO = bytes.fromhex('d4c3b2a1' '0200' '0400' '00000000' '00000000' '00000000' '01000000')
#: The same header with snaplen 2.
GLOBAL_TWO = bytes.fromhex('d4c3b2a1' '0200' '0400' '00000000' '00000000' '02000000' '01000000')
PACKET = b'\xde\xad\xbe\xef'


class TestFrameSnaplenZero(unittest.TestCase):
    """Pin the ``incl_len`` default of :meth:`Frame.make` against the snaplen."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _frame(self, ghdr: bytes) -> 'object':
        from pcapkit.protocols.misc.pcap.frame import Frame
        from pcapkit.protocols.misc.pcap.header import Header

        header = Header(ghdr)
        return Frame(num=1, header=header.info, ts_sec=1, ts_usec=2, packet=PACKET)

    def test_zero_snaplen_keeps_the_whole_packet(self) -> None:
        frame = self._frame(GLOBAL_ZERO)
        expected = bytes.fromhex('01000000' '02000000' '04000000' '04000000') + PACKET
        self.assertEqual(frame.data, expected)
        self.assertEqual(frame.info.frame_info.incl_len, 4)
        self.assertEqual(frame.info.frame_info.orig_len, 4)
        self.assertEqual(frame.info.cap_len, 4)

    def test_zero_snaplen_frame_parses_and_rebuilds_byte_exact(self) -> None:
        from pcapkit.protocols.misc.pcap.frame import Frame
        from pcapkit.protocols.misc.pcap.header import Header

        built = self._frame(GLOBAL_ZERO).data
        header = Header(GLOBAL_ZERO)
        parsed = Frame(io.BytesIO(built), num=1, header=header.info)
        self.assertEqual(parsed.info.frame_info.incl_len, 4)
        rebuilt = Frame.from_data(parsed.info, num=1, header=header.info)
        self.assertEqual(rebuilt.data, built)

    def test_nonzero_snaplen_still_truncates(self) -> None:
        frame = self._frame(GLOBAL_TWO)
        expected = bytes.fromhex('01000000' '02000000' '02000000' '04000000') + PACKET[:2]
        self.assertEqual(frame.data, expected)


if __name__ == '__main__':
    unittest.main()
