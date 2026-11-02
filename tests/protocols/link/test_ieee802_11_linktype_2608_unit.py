# -*- coding: utf-8 -*-
"""GitHub issue #2608: link types 105 and 127 reach the 802.11 and radiotap dissectors.

:class:`~pcapkit.protocols.misc.pcap.frame.Frame` and
:class:`~pcapkit.protocols.misc.pcapng.PCAPNG` bind
``LinkType.IEEE802_11`` (105) to
:class:`~pcapkit.protocols.link.ieee802_11.IEEE802_11` and
``LinkType.IEEE802_11_RADIOTAP`` (127) to
:class:`~pcapkit.protocols.link.radiotap.Radiotap`. A pcap and a pcapng capture
of each, built here octet by octet, parse to ``802.11`` and
``Radiotap:802.11``, and every frame and layer rebuilds byte-exactly.

Each test imports :mod:`pcapkit` itself, after
:func:`~tests._support.reimport_once_per_class`.

"""

import os
import struct
import tempfile
import unittest
import warnings

from tests._support import reimport_once_per_class

#: An 802.11 Ack: Frame Control type Control (1), subtype Ack (13), no flags;
#: Duration/ID 0; Address 1 only (IEEE Std 802.11-2020 §9.3.1.3).
ACK = bytes.fromhex('d400' '0000' '020000000001')

#: An 802.11 Data frame, no flags: Address 1 to 3, Sequence Control with
#: sequence number 1, then an LLC/SNAP body (§9.3.2.1).
DATA = (bytes.fromhex('0800' '0000' '020000000001' '020000000002' '020000000003' '1000')
        + bytes.fromhex('aaaa030000000800'))

#: A radiotap header whose one present bit, Flags (bit 1), selects a single
#: octet, so ``it_len`` is 9 and the 802.11 frame starts there.
RADIOTAP = bytes.fromhex('00' '00' '0900' '02000000' '00')


def _pcap(linktype: int, records: 'tuple[bytes, ...]') -> bytes:
    """A little-endian PCAP v2.4 file of ``records`` on ``linktype``."""
    data = struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 262144, linktype)
    for index, record in enumerate(records):
        data += struct.pack('<IIII', 1500000000 + index, 0, len(record), len(record)) + record
    return data


def _epb(record: bytes, index: int) -> bytes:
    """A little-endian Enhanced Packet Block of ``record`` on interface 0."""
    padded = record + bytes(-len(record) % 4)
    length = 32 + len(padded)
    return (struct.pack('<IIIIIII', 6, length, 0, 0, 1500000000 + index, len(record), len(record))
            + padded + struct.pack('<I', length))


def _pcapng(linktype: int, records: 'tuple[bytes, ...]') -> bytes:
    """A little-endian PCAP-NG file: one section, one interface on ``linktype``."""
    shb = struct.pack('<IIIHHqI', 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1, 28)
    idb = struct.pack('<IIHHII', 1, 20, linktype, 0, 262144, 20)
    return shb + idb + b''.join(_epb(record, index) for index, record in enumerate(records))


class TestIEEE802_11LinkTypes(unittest.TestCase):
    """Pin LinkType 105 and 127 in both capture formats."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _extract(self, data: bytes, suffix: str) -> 'list':  # type: ignore[type-arg]
        import pcapkit

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, f'wlan{suffix}')
            with open(path, 'wb') as file:
                file.write(data)
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                extractor = pcapkit.extract(fin=path, nofile=True, store=True)
        return list(extractor.frame)

    def _assert_rebuilds(self, layer, **kwargs) -> None:  # type: ignore[no-untyped-def]
        """``layer`` rebuilds byte-exactly from its info, and from ``info.to_dict()``."""
        for data in (layer.info, layer.info.to_dict()):
            with self.subTest(layer=type(layer).__name__, data=type(data).__name__):
                self.assertEqual(type(layer).from_data(data, **kwargs).data.hex(), layer.data.hex())

    def _assert_frames(self, frames: 'list', records: 'tuple[bytes, ...]',  # type: ignore[type-arg]
                       chains: 'list[str]', pcapng: bool) -> None:
        self.assertEqual([frame.protochain.chain for frame in frames], chains)
        for frame, record in zip(frames, records):
            self.assertEqual(bytes(frame.payload.data), record)
            if pcapng:
                self._assert_rebuilds(frame, num=frame._fnum, sct=frame._sect, ctx=frame._ctx)
            else:
                self._assert_rebuilds(frame, num=frame._fnum, header=frame._ghdr)
            layer = frame.payload
            while type(layer).__name__ not in ('Raw', 'NoPayload'):
                self._assert_rebuilds(layer)
                layer = layer.payload

    def test_registered_against_frame_and_pcapng(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.protocols.link.ieee802_11 import IEEE802_11
        from pcapkit.protocols.link.radiotap import Radiotap
        from pcapkit.protocols.misc.pcap.frame import Frame
        from pcapkit.protocols.misc.pcapng import PCAPNG

        for cls in (Frame, PCAPNG):
            for code, target in ((LinkType.IEEE802_11, IEEE802_11),
                                 (LinkType.IEEE802_11_RADIOTAP, Radiotap)):
                with self.subTest(table=cls.__name__, code=code.name):
                    self.assertEqual(cls.__proto__[code],
                                     ModuleDescriptor('pcapkit.protocols.link', target.__name__))
                    self.assertIs(cls._lookup_next_layer(cls.__proto__, code), target)
            with self.subTest(table=cls.__name__, index='IEEE802_11'):
                self.assertIs(cls._lookup_next_layer(cls.__proto__, IEEE802_11.__index__()), IEEE802_11)
        self.assertIs(IEEE802_11.__index__(), LinkType.IEEE802_11)
        self.assertEqual(IEEE802_11.__index__(), 105)
        self.assertEqual(int(LinkType.IEEE802_11_RADIOTAP), 127)

    def test_native_802_11_capture(self) -> None:
        """Link type 105 carries the MAC frame with no header in front of it."""
        from pcapkit.const.ieee802_11.control_subtype import ControlSubtype
        from pcapkit.const.ieee802_11.type import Type
        from pcapkit.const.reg.linktype import LinkType

        records = (ACK, DATA)
        for pcapng, (data, suffix) in enumerate(((_pcap(LinkType.IEEE802_11, records), '.pcap'),
                                                 (_pcapng(LinkType.IEEE802_11, records), '.pcapng'))):
            with self.subTest(format=suffix):
                frames = self._extract(data, suffix)
                self._assert_frames(frames, records, ['802.11', '802.11:Raw'], bool(pcapng))

                ack = frames[0].payload.info
                self.assertEqual((ack.frame_control.type, ack.frame_control.subtype),
                                 (Type.Control, ControlSubtype.ACK))
                self.assertEqual(ack.addr1, '02:00:00:00:00:01')
                self.assertIsNone(ack.addr2)
                body = frames[1].payload
                self.assertEqual(body.info.addr3, '02:00:00:00:00:03')
                self.assertEqual(body.info.seq_ctrl.sequence_number, 1)
                self.assertEqual(bytes(body.payload.data), DATA[24:])

    def test_radiotap_capture(self) -> None:
        """Link type 127 carries a radiotap header, then the MAC frame at ``it_len``."""
        from pcapkit.const.reg.linktype import LinkType

        records = (RADIOTAP + ACK, RADIOTAP + DATA)
        for pcapng, (data, suffix) in enumerate(((_pcap(LinkType.IEEE802_11_RADIOTAP, records), '.pcap'),
                                                 (_pcapng(LinkType.IEEE802_11_RADIOTAP, records), '.pcapng'))):
            with self.subTest(format=suffix):
                frames = self._extract(data, suffix)
                self._assert_frames(frames, records, ['Radiotap:802.11', 'Radiotap:802.11:Raw'], bool(pcapng))

                for frame, mac in zip(frames, (ACK, DATA)):
                    radiotap = frame.payload
                    self.assertEqual((radiotap.info.it_version, radiotap.info.it_len), (0, 9))
                    self.assertEqual(radiotap.length, 9)
                    self.assertEqual(bytes(radiotap.payload.data), mac)
                    self.assertEqual(radiotap.payload.info.addr1, '02:00:00:00:00:01')


if __name__ == '__main__':
    unittest.main()
