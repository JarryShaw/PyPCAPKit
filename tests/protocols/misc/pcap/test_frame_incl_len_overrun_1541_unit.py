# -*- coding: utf-8 -*-
"""A PCAP record claiming more octets than its file holds warns, and is kept as captured.

GitHub issue #1541. A record whose ``incl_len`` runs past the end of the file
parsed silently. It is now reported the way the PCAP-NG reader reports a
captured length running past its block (#1405), and is kept as captured in the
same way: ``incl_len`` and ``cap_len`` stay as declared, the packet is the octets
present, and the frame rebuilds as exactly the octets read, from ``info`` and
from ``info.to_dict()`` alike.

Every case builds its own octets and reads no capture. Classes are imported
inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import io
import struct
import unittest
import warnings

from tests._support import close_extractor, reimport_once_per_class

#: Little-endian global header: v2.4, Ethernet.
GLOBAL = bytes.fromhex('d4c3b2a1' '0200' '0400' '00000000' '00000000' 'ffff0000' '01000000')
#: Sixty octets of packet data, none of them zero.
PACKET = bytes(range(1, 61))


def _record(claim: 'int', packet: 'bytes' = PACKET) -> 'bytes':
    """A record whose header claims ``claim`` octets, followed by ``packet``."""
    return struct.pack('<IIII', 1_500_000_000, 7, claim, 86) + packet


class TestFrameInclLenOverrun(unittest.TestCase):
    """Pin how a record whose ``incl_len`` runs past the data parses and rebuilds."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def parse(self, octets: 'bytes') -> 'tuple[object, list[str]]':
        """The frame parsed from ``octets``, and the warnings it raised."""
        from pcapkit.protocols.misc.pcap.frame import Frame
        from pcapkit.protocols.misc.pcap.header import Header

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            frame = Frame(io.BytesIO(octets), num=4, header=Header(GLOBAL).info)
        return frame, [str(item.message) for item in caught]

    def test_overrun_warns_and_is_kept_as_captured(self) -> None:
        from pcapkit.protocols.misc.pcap.frame import Frame
        from pcapkit.protocols.misc.pcap.header import Header

        header = Header(GLOBAL).info
        for claim in (61, 1000, 0x7FFF_FFFF):
            with self.subTest(claim=claim):
                octets = _record(claim)
                frame, messages = self.parse(octets)
                self.assertIn(f'PCAP: [Frame 4] captured length {claim} runs past the data, '
                              f'which holds {len(PACKET)} octet(s); kept as captured', messages)

                info = frame.info  # type: ignore[attr-defined]
                self.assertEqual((info.frame_info.incl_len, info.cap_len, info.len), (claim, claim, 86))
                self.assertEqual(bytes(info.packet), PACKET)
                self.assertEqual(frame.data, octets)  # type: ignore[attr-defined]
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    for data in (info, info.to_dict()):
                        rebuilt = Frame.from_data(data, num=4, header=header)
                        self.assertEqual(rebuilt.data.hex(), octets.hex())

    def test_whole_record_does_not_warn(self) -> None:
        for packet in (PACKET, PACKET + b'\x00' * 16):
            with self.subTest(trailing=len(packet) - len(PACKET)):
                frame, messages = self.parse(_record(len(PACKET), packet))
                self.assertFalse([text for text in messages if 'runs past' in text], messages)
                self.assertEqual(bytes(frame.info.packet), PACKET)  # type: ignore[attr-defined]

    def test_extraction_keeps_the_cut_frame(self) -> None:
        import pcapkit

        octets = GLOBAL + _record(len(PACKET)) + _record(1000)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            extractor = pcapkit.extract(fin=io.BytesIO(octets), nofile=True, store=True, engine='default')
        close_extractor(extractor)
        frames = list(extractor.frame)
        self.assertEqual([bytes(frame.info.packet) for frame in frames], [PACKET, PACKET])
        self.assertEqual(sum('runs past the data' in str(item.message) for item in caught), 1)


if __name__ == '__main__':
    unittest.main()
