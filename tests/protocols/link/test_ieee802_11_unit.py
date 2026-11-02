# -*- coding: utf-8 -*-
"""GitHub issue #2575: the IEEE 802.11 MAC header behind radiotap.

:class:`~pcapkit.protocols.link.ieee802_11.IEEE802_11` decodes the MAC header
of IEEE Std 802.11-2020 §9.2 and keeps the frame body as
:class:`~pcapkit.protocols.misc.raw.Raw`. Covers data frames under each To
DS/From DS combination, management frames, the header length of every
control subtype, Control Frame Extension and Extension frames, the QoS and HT
Control fields, a refused protocol version, truncated input and ``make()``,
each with byte-exact round trips both ways. The Radiotap side of the dispatch
is covered in ``test_radiotap_unit.py``.

Each test imports :mod:`pcapkit` itself, after
:func:`~tests._support.reimport_once_per_class`.

"""

import unittest
import warnings

from tests._support import reimport_once_per_class

#: Six distinct addresses, ``01:01:01:01:01:01`` to ``06:06:06:06:06:06``.
ADDR = tuple(bytes([n]) * 6 for n in range(1, 7))


def _fc(type_: int, subtype: int, flags: int = 0, version: int = 0) -> bytes:
    """Frame Control, little-endian: B0-B1 version, B2-B3 type, B4-B7
    subtype, B8-B15 flags (IEEE Std 802.11-2020 §9.2.4.1.1)."""
    return bytes([version | type_ << 2 | subtype << 4, flags])


def _mac(n: int) -> str:
    return ':'.join([f'{n:02x}'] * 6)


#: Flag bits of the second Frame Control octet.
TO_DS, FROM_DS, MORE_FRAG, RETRY, PWR_MGT, MORE_DATA, PROTECTED, ORDER = (1 << i for i in range(8))


class TestIEEE802_11(unittest.TestCase):
    """Pin the IEEE 802.11 MAC header layer, alone."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _parse(self, raw: bytes):  # type: ignore[no-untyped-def]
        from pcapkit.protocols.link.ieee802_11 import IEEE802_11

        parsed = IEEE802_11(raw, len(raw))
        self.assertEqual(parsed.data, raw)
        for data in (parsed.info, parsed.info.to_dict()):
            with self.subTest(rebuild=type(data).__name__):
                self.assertEqual(IEEE802_11.from_data(data).data.hex(), raw.hex())
        return parsed

    def test_data_frame_addresses_follow_to_ds_and_from_ds(self) -> None:
        """Three addresses in every combination, and Address 4 only when To
        DS and From DS are both set (§9.2.4.3); Sequence Control sits
        between Address 3 and Address 4 (§9.3.2)."""
        from pcapkit.const.ieee802_11.data_subtype import DataSubtype
        from pcapkit.const.ieee802_11.type import Type

        body = b'\xaa\xaa\x03\x00\x00\x00\x08\x00'
        for flags, addr4 in ((0, False), (TO_DS, False), (FROM_DS, False),
                             (TO_DS | FROM_DS, True)):
            with self.subTest(flags=flags):
                raw = (_fc(2, 0, flags) + b'\x2c\x00' + ADDR[0] + ADDR[1] + ADDR[2]
                       + b'\x51\x34' + (ADDR[3] if addr4 else b'') + body)
                parsed = self._parse(raw)
                info = parsed.info
                self.assertIs(info.frame_control.type, Type.Data)
                self.assertIs(info.frame_control.subtype, DataSubtype.Data)
                self.assertEqual(info.frame_control.to_ds, bool(flags & TO_DS))
                self.assertEqual(info.frame_control.from_ds, bool(flags & FROM_DS))
                self.assertEqual(info.duration_id, 44)
                self.assertEqual((info.addr1, info.addr2, info.addr3), (_mac(1), _mac(2), _mac(3)))
                self.assertEqual(info.addr4, _mac(4) if addr4 else None)
                # 0x3451: fragment number 1, sequence number 0x345 (§9.2.4.4)
                self.assertEqual((info.seq_ctrl.fragment_number, info.seq_ctrl.sequence_number), (1, 0x345))
                self.assertIsNone(info.qos_control)
                self.assertIsNone(info.ht_control)
                self.assertEqual(parsed.length, 30 if addr4 else 24)
                self.assertEqual(type(parsed.payload).__name__, 'Raw')
                self.assertEqual(parsed.payload.data, body)
                self.assertEqual(parsed.protochain.chain, '802.11:Raw')

    def test_frame_control_flags(self) -> None:
        """Every flag of §9.2.4.1 lands on its own bit."""
        for bit, name in ((TO_DS, 'to_ds'), (FROM_DS, 'from_ds'), (MORE_FRAG, 'more_fragments'),
                          (RETRY, 'retry'), (PWR_MGT, 'power_management'),
                          (MORE_DATA, 'more_data'), (PROTECTED, 'protected'), (ORDER, 'order')):
            with self.subTest(name=name):
                raw = _fc(2, 0, bit) + bytes(2) + ADDR[0] + ADDR[1] + ADDR[2] + bytes(2) + bytes(6)
                info = self._parse(raw).info.frame_control
                for other in ('to_ds', 'from_ds', 'more_fragments', 'retry', 'power_management',
                              'more_data', 'protected', 'order'):
                    self.assertEqual(info[other], other == name)
                self.assertEqual(info.version, 0)
                self.assertIsNone(info.control_frame_extension)

    def test_protected_body_is_raw(self) -> None:
        """The Protected Frame bit leaves the body undecoded."""
        body = bytes.fromhex('0102030420000000') + b'ciphertext'
        raw = _fc(2, 0, PROTECTED) + bytes(2) + ADDR[0] + ADDR[1] + ADDR[2] + bytes(2) + body
        parsed = self._parse(raw)
        self.assertTrue(parsed.info.frame_control.protected)
        self.assertEqual(parsed.payload.data, body)

    def test_management_frame(self) -> None:
        """A Beacon is 24 octets of header whatever its DS bits say (§9.3.3).
        The bytes are the familiar ``80 00`` Beacon Frame Control."""
        from pcapkit.const.ieee802_11.management_subtype import ManagementSubtype
        from pcapkit.const.ieee802_11.type import Type

        body = bytes(8) + b'\x64\x00\x31\x04'
        for flags in (0, TO_DS | FROM_DS):
            with self.subTest(flags=flags):
                raw = (bytes([0x80, flags]) + bytes(2) + b'\xff' * 6 + ADDR[1] + ADDR[1]
                       + b'\x10\x00' + body)
                parsed = self._parse(raw)
                info = parsed.info
                self.assertIs(info.frame_control.type, Type.Management)
                self.assertIs(info.frame_control.subtype, ManagementSubtype.Beacon)
                self.assertEqual(info.addr1, 'ff:ff:ff:ff:ff:ff')
                self.assertIsNone(info.addr4)
                self.assertEqual((info.seq_ctrl.fragment_number, info.seq_ctrl.sequence_number), (0, 1))
                self.assertEqual(parsed.length, 24)
                self.assertEqual(parsed.payload.data, body)

    def test_management_frame_ht_control(self) -> None:
        """+HTC/Order in a Management frame adds HT Control (§9.2.4.1.10)."""
        raw = _fc(0, 0b1101, ORDER) + bytes(2) + ADDR[0] + ADDR[1] + ADDR[2] + bytes(2) + b'\x3c\x00\x00\x00' + b'\x7f'
        parsed = self._parse(raw)
        self.assertEqual(parsed.length, 28)
        self.assertEqual(parsed.info.ht_control.value, 0x3c)
        self.assertEqual(parsed.info.ht_control.variant, 'HT')
        self.assertEqual(parsed.payload.data, b'\x7f')

    def test_control_frame_header_length_per_subtype(self) -> None:
        """Every control subtype: RA and TA (16 octets); Control Frame
        Extension as the Linux kernel's ``ieee80211_hdrlen()`` reads it (16,
        whose Address 2 is NAV-SA in a DMG DTS); RA alone for CTS and Ack
        (10); and the minimal frame format of §9.2.3 (10) for the reserved
        subtypes and Control Wrapper, where the kernel gives 16."""
        from pcapkit.const.ieee802_11.control_subtype import ControlSubtype
        from pcapkit.const.ieee802_11.type import Type

        expected = {0b0000: 10, 0b0001: 10, 0b0010: 16, 0b0011: 16, 0b0100: 16, 0b0101: 16,
                    0b0110: 16, 0b0111: 10, 0b1000: 16, 0b1001: 16, 0b1010: 16, 0b1011: 16,
                    0b1100: 10, 0b1101: 10, 0b1110: 16, 0b1111: 16}
        rest = ADDR[1] + b'\x04\x00\x00\x00' + b'\xde\xad\xbe\xef'
        for subtype, hdr_len in expected.items():
            with self.subTest(subtype=subtype):
                raw = _fc(1, subtype) + b'\x02\x00' + ADDR[0] + rest
                parsed = self._parse(raw)
                info = parsed.info
                self.assertIs(info.frame_control.type, Type.Control)
                self.assertEqual(info.frame_control.subtype, ControlSubtype.get(subtype))
                self.assertEqual(parsed.length, hdr_len)
                self.assertEqual(info.addr2, _mac(2) if hdr_len == 16 else None)
                for absent in ('addr3', 'seq_ctrl', 'addr4', 'qos_control', 'ht_control'):
                    self.assertIsNone(info[absent])
                self.assertEqual(parsed.payload.data, raw[hdr_len:])

    def test_known_control_frames(self) -> None:
        """``d4 00`` is an Ack and ``b4 00`` an RTS; PS-Poll carries the AID in
        Duration/ID (§9.2.4.2)."""
        from pcapkit.const.ieee802_11.control_subtype import ControlSubtype

        fcs = b'\x11\x22\x33\x44'
        ack = self._parse(bytes.fromhex('d4000000') + ADDR[0] + fcs)
        self.assertIs(ack.info.frame_control.subtype, ControlSubtype.ACK)
        self.assertEqual((ack.length, ack.payload.data), (10, fcs))

        rts = self._parse(bytes.fromhex('b4002c01') + ADDR[0] + ADDR[1] + fcs)
        self.assertIs(rts.info.frame_control.subtype, ControlSubtype.RTS)
        self.assertEqual((rts.info.duration_id, rts.info.addr2, rts.length), (300, _mac(2), 16))

        ps_poll = self._parse(bytes.fromhex('a410' '05c0') + ADDR[0] + ADDR[1])
        self.assertIs(ps_poll.info.frame_control.subtype, ControlSubtype.PS_Poll)
        self.assertTrue(ps_poll.info.frame_control.power_management)
        self.assertEqual(ps_poll.info.duration_id, 0xc005)

    def test_control_frame_extension(self) -> None:
        """In a Control Frame Extension frame B8-B11 are the Control Frame
        Extension subfield, not To DS, From DS, More Fragments and Retry
        (§9.2.4.1.1); Address 2 follows Address 1."""
        raw = _fc(1, 0b0110, 0b0101 | PWR_MGT) + bytes(2) + ADDR[0] + ADDR[1] + b'\x00'
        parsed = self._parse(raw)
        info = parsed.info.frame_control
        self.assertEqual(info.control_frame_extension, 0b0101)
        for name in ('to_ds', 'from_ds', 'more_fragments', 'retry', 's1g_beacon_flags'):
            self.assertIsNone(info[name])
        self.assertTrue(info.power_management)
        self.assertEqual((parsed.length, parsed.info.addr2), (16, _mac(2)))
        self.assertEqual(parsed.payload.data, b'\x00')

        # DMG DTS (extension 6): RA, NAV-SA as Address 2, NAV-DA left in the body.
        dts = self._parse(_fc(1, 0b0110, 0b0110) + bytes(2) + ADDR[0] + ADDR[1] + ADDR[2])
        self.assertEqual(dts.info.frame_control.control_frame_extension, 6)
        self.assertEqual((dts.length, dts.info.addr2, dts.payload.data), (16, _mac(2), ADDR[2]))

    def test_s1g_beacon_frame_control(self) -> None:
        """In an S1G Beacon B8-B15 are the subfields Wireshark reads as
        ``wlan.fc.s1g.*``, kept whole; none of the eight flags is read."""
        from pcapkit.const.ieee802_11.extension_subtype import ExtensionSubtype

        raw = _fc(3, 0b0001, 0b1010_0101) + bytes(2) + ADDR[0] + bytes(8)
        parsed = self._parse(raw)
        info = parsed.info.frame_control
        self.assertIs(info.subtype, ExtensionSubtype.S1G_Beacon)
        self.assertEqual(info.s1g_beacon_flags, 0b1010_0101)
        for name in ('to_ds', 'from_ds', 'more_fragments', 'retry', 'power_management',
                     'more_data', 'protected', 'order', 'control_frame_extension'):
            self.assertIsNone(info[name])
        self.assertEqual(parsed.length, 10)

    def test_extension_frame_is_the_minimal_format(self) -> None:
        """A DMG Beacon reads as Frame Control, Duration and Address 1 (the
        BSSID); the rest stays in the body."""
        from pcapkit.const.ieee802_11.extension_subtype import ExtensionSubtype
        from pcapkit.const.ieee802_11.type import Type

        for subtype in (0b0000, 0b0001, 0b1111):
            with self.subTest(subtype=subtype):
                raw = _fc(3, subtype, ORDER) + bytes(2) + ADDR[0] + bytes(8)
                parsed = self._parse(raw)
                self.assertIs(parsed.info.frame_control.type, Type.Extension)
                self.assertEqual(parsed.info.frame_control.subtype, ExtensionSubtype.get(subtype))
                self.assertEqual(parsed.length, 10)
                self.assertIsNone(parsed.info.ht_control)

    def test_every_type_subtype_and_flag_round_trips(self) -> None:
        """Every (Type, Subtype) pair of the Table 9-1 registries, crossed with
        To DS, From DS and +HTC/Order, parses to the header length the layout
        rule gives and rebuilds byte for byte, and ``make()`` with the same
        values builds the same octets."""
        from pcapkit.const.ieee802_11.control_subtype import ControlSubtype
        from pcapkit.const.ieee802_11.type import Type
        from pcapkit.protocols.link.ieee802_11 import IEEE802_11

        ta_subtypes = {0b0010, 0b0011, 0b0100, 0b0101, 0b0110, 0b1000, 0b1001, 0b1010, 0b1011,
                       0b1110, 0b1111}
        body = b'\xaa\xbb\xcc'
        for type_ in Type:
            for subtype in range(16):
                for flags in (0, TO_DS, FROM_DS, TO_DS | FROM_DS, ORDER, TO_DS | FROM_DS | ORDER):
                    with self.subTest(type=type_.name, subtype=subtype, flags=flags):
                        qos = type_ == Type.Data and bool(subtype & 0b1000)
                        addr4 = type_ == Type.Data and bool(flags & TO_DS) and bool(flags & FROM_DS)
                        htc = (type_ == Type.Management or qos) and bool(flags & ORDER)
                        if type_ in (Type.Management, Type.Data):
                            hdr_len = 24 + 6 * addr4 + 2 * qos + 4 * htc
                        elif type_ == Type.Control:
                            hdr_len = 16 if subtype in ta_subtypes else 10
                        else:
                            hdr_len = 10
                        raw = _fc(type_, subtype, flags) + bytes([subtype, flags])
                        raw += bytes(range(1, hdr_len - 3)) + body
                        parsed = self._parse(raw)
                        self.assertEqual(parsed.length, hdr_len)
                        self.assertEqual(parsed.payload.data, body)

                        made = IEEE802_11(**IEEE802_11._make_data(parsed.info))
                        self.assertEqual(made.data.hex(), raw.hex())
                        self.assertEqual(IEEE802_11(made.data, len(made.data)).data, raw)
                        if type_ == Type.Control:
                            self.assertEqual(parsed.info.frame_control.subtype, ControlSubtype(subtype))

    def test_make_zero_fills_what_the_frame_carries(self) -> None:
        """Sequence Control, QoS Control and HT Control left out of ``make()``
        are written as zeros where the header carries them."""
        from pcapkit.protocols.link.ieee802_11 import IEEE802_11

        made = IEEE802_11(type='Data', subtype='QoS_Data', order=True)
        self.assertEqual(made.data, bytes.fromhex('8880') + bytes(2 + 18 + 2 + 2 + 4))
        info = made.info
        self.assertEqual((info.seq_ctrl.fragment_number, info.seq_ctrl.sequence_number), (0, 0))
        self.assertEqual(info.qos_control.tid, 0)
        self.assertEqual((info.ht_control.variant, info.ht_control.value), ('HT', 0))

    def test_qos_control(self) -> None:
        """The QoS bit (B7) of a Data subtype adds QoS Control (§9.2.4.5):
        TID in bits 0-3, EOSP bit 4, Ack Policy bits 5-6, A-MSDU Present bit
        7, and bits 8-15 kept whole."""
        from pcapkit.const.ieee802_11.data_subtype import DataSubtype

        for subtype in range(0b1000, 0b10000):
            with self.subTest(subtype=subtype):
                raw = (_fc(2, subtype, TO_DS) + bytes(2) + ADDR[0] + ADDR[1] + ADDR[2]
                       + bytes(2) + bytes([0b1011_0101, 0x7e]) + b'body')
                parsed = self._parse(raw)
                qos = parsed.info.qos_control
                self.assertEqual(parsed.info.frame_control.subtype, DataSubtype.get(subtype))
                self.assertEqual((qos.tid, qos.eosp, qos.ack_policy, qos.amsdu_present, qos.bits_8_15),
                                 (0b0101, True, 0b01, True, 0x7e))
                self.assertIsNone(parsed.info.ht_control)
                self.assertEqual(parsed.length, 26)
                self.assertEqual(parsed.payload.data, b'body')

    def test_ht_control_on_qos_data_only(self) -> None:
        """+HTC/Order adds HT Control to a QoS Data frame; on a non-QoS Data
        frame the bit is Order and adds nothing (§9.2.4.1.10)."""
        for subtype, hdr_len in ((0b1000, 30), (0b0000, 24)):
            with self.subTest(subtype=subtype):
                raw = (_fc(2, subtype, ORDER) + bytes(2) + ADDR[0] + ADDR[1] + ADDR[2]
                       + bytes(2) + (bytes(2) if subtype else b'') + bytes.fromhex('03000000') + b'xy')
                parsed = self._parse(raw)
                self.assertTrue(parsed.info.frame_control.order)
                self.assertEqual(parsed.length, hdr_len)
                self.assertEqual(parsed.info.ht_control is None, not subtype)

    def test_ht_control_variants_and_four_address_qos(self) -> None:
        """The variant follows bits 0 and 1 (§9.2.4.6); with Address 4, QoS
        and HT Control the header is its longest, 36 octets."""
        for value, variant in ((0x8000_0000, 'HT'), (0x0000_0001, 'VHT'), (0xffff_ffff, 'HE')):
            with self.subTest(variant=variant):
                raw = (_fc(2, 0b1000, TO_DS | FROM_DS | ORDER) + bytes(2) + ADDR[0] + ADDR[1]
                       + ADDR[2] + bytes(2) + ADDR[3] + bytes(2) + value.to_bytes(4, 'little'))
                parsed = self._parse(raw)
                self.assertEqual((parsed.info.ht_control.variant, parsed.info.ht_control.value),
                                 (variant, value))
                self.assertEqual(parsed.length, 36)
                self.assertEqual(type(parsed.payload).__name__, 'NoPayload')

    def test_protocol_version_other_than_zero_is_refused(self) -> None:
        """Version 1 is PV1 (§9.8) and versions 2-3 are reserved: never read
        as protocol version 0."""
        from pcapkit.protocols.link.ieee802_11 import IEEE802_11
        from pcapkit.utilities.exceptions import ProtocolError

        for version in (1, 2, 3):
            with self.subTest(version=version):
                raw = _fc(2, 0, 0, version) + bytes(22)
                with self.assertRaises(ProtocolError):
                    IEEE802_11(raw, len(raw))

    def test_truncated_header_rebuilds_as_captured(self) -> None:
        """A capture ending anywhere in the longest header parses without
        raising and rebuilds to exactly the octets captured."""
        from pcapkit.protocols.link.ieee802_11 import IEEE802_11

        raw = (_fc(2, 0b1000, TO_DS | FROM_DS | ORDER) + bytes(2) + ADDR[0] + ADDR[1]
               + ADDR[2] + b'\x10\x00' + ADDR[3] + b'\x05\x00' + b'\x01\x00\x00\x00' + b'body')
        for keep in range(1, len(raw) + 1):
            with self.subTest(keep=keep):
                cut = raw[:keep]
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    parsed = IEEE802_11(cut, len(cut))
                self.assertEqual(parsed.data, cut)
                self.assertEqual(IEEE802_11.from_data(parsed.info).data, cut)
                self.assertEqual(IEEE802_11.from_data(parsed.info.to_dict()).data, cut)

    def test_make_then_parse(self) -> None:
        """``make()`` lays out the fields Frame Control declares, zero-filling
        those not given, and parses back to the same octets."""
        from pcapkit.const.ieee802_11.data_subtype import DataSubtype
        from pcapkit.const.ieee802_11.type import Type
        from pcapkit.protocols.link.ieee802_11 import IEEE802_11

        made = IEEE802_11(type=Type.Data, subtype=DataSubtype.QoS_Data, to_ds=True, from_ds=True,
                          order=True, duration_id=0x2c, addr1=_mac(1), addr2=_mac(2), addr3=_mac(3),
                          seq_ctrl={'fragment_number': 1, 'sequence_number': 0x345}, addr4=_mac(4),
                          qos_control={'tid': 5, 'eosp': True, 'ack_policy': 1, 'amsdu_present': True,
                                       'bits_8_15': 0x7e},
                          ht_control=0x8000_0001, payload=b'body')
        expected = (bytes.fromhex('8883') + b'\x2c\x00' + ADDR[0] + ADDR[1] + ADDR[2] + b'\x51\x34'
                    + ADDR[3] + bytes([0b1011_0101, 0x7e]) + b'\x01\x00\x00\x80' + b'body')
        self.assertEqual(made.data.hex(), expected.hex())
        self._parse(made.data)

        self.assertEqual(IEEE802_11(type='Control', subtype='ACK', addr1=_mac(1)).data,
                         bytes.fromhex('d4000000') + ADDR[0])
        self.assertEqual(IEEE802_11(type=0, subtype=8).data,
                         bytes.fromhex('80000000') + bytes(20))
        self.assertEqual(IEEE802_11(type=1, subtype=6, control_frame_extension=0b0101).data,
                         bytes.fromhex('64050000') + bytes(12))
        self.assertEqual(IEEE802_11(type=3, subtype=1, s1g_beacon_flags=0b1010_0101).data,
                         bytes.fromhex('1ca50000') + bytes(6))

    def test_make_rejects_what_the_frame_does_not_carry(self) -> None:
        from pcapkit.protocols.link.ieee802_11 import IEEE802_11
        from pcapkit.utilities.exceptions import ProtocolError

        for kwargs in (
            {'type': 1, 'subtype': 0b1101, 'addr2': _mac(2)},
            {'type': 2, 'subtype': 0, 'addr4': _mac(4)},
            {'type': 2, 'subtype': 0, 'qos_control': {}},
            {'type': 2, 'subtype': 0b1000, 'ht_control': 0},
            {'type': 1, 'subtype': 0b1011, 'seq_ctrl': {}},
            {'type': 1, 'subtype': 0b0110, 'to_ds': True},
            {'type': 2, 'subtype': 0, 'control_frame_extension': 0},
            {'type': 3, 'subtype': 1, 'to_ds': True},
            {'type': 3, 'subtype': 1, 'order': True},
            {'type': 3, 'subtype': 1, 'control_frame_extension': 0},
            {'type': 3, 'subtype': 0, 's1g_beacon_flags': 0},
        ):
            with self.subTest(**{k: repr(v) for k, v in kwargs.items()}), self.assertRaises(ProtocolError):
                IEEE802_11(**kwargs)

    def test_make_rejects_what_does_not_fit(self) -> None:
        from pcapkit.protocols.link.ieee802_11 import IEEE802_11
        from pcapkit.utilities.exceptions import ProtocolError

        qos = {'tid': 0, 'eosp': False, 'ack_policy': 0, 'amsdu_present': False, 'bits_8_15': 0}
        for kwargs in (
            {'version': 1}, {'version': True}, {'type': 4}, {'type': True}, {'subtype': 16},
            {'to_ds': 2}, {'order': 'yes'}, {'duration_id': 0x1_0000}, {'duration_id': -1},
            {'addr1': 'not a mac'}, {'addr1': 1},
            {'seq_ctrl': {'fragment_number': 16, 'sequence_number': 0}},
            {'seq_ctrl': {'fragment_number': 0, 'sequence_number': 0x1000}},
            {'subtype': 8, 'qos_control': {**qos, 'tid': 16}},
            {'subtype': 8, 'qos_control': {**qos, 'bits_8_15': 0x100}},
            {'subtype': 8, 'order': True, 'ht_control': 0x1_0000_0000},
            {'type': 1, 'subtype': 6, 'control_frame_extension': 16},
            {'type': 3, 'subtype': 1, 's1g_beacon_flags': 0x100},
            {'more_data': 2},
        ):
            with self.subTest(**{k: repr(v) for k, v in kwargs.items()}), self.assertRaises(ProtocolError):
                IEEE802_11(**kwargs)

    def test_id_index_and_names(self) -> None:
        from pcapkit.protocols.link.ieee802_11 import IEEE802_11
        from pcapkit.utilities.exceptions import UnsupportedCall

        self.assertEqual(IEEE802_11.id(), ('IEEE802_11',))
        with self.assertRaises(UnsupportedCall):
            IEEE802_11.__index__()
        made = IEEE802_11()
        self.assertEqual((made.name, made.alias), ('IEEE 802.11 Wireless LAN', '802.11'))
        self.assertEqual(made.__length_hint__(), 36)


class TestIEEE802_11Registries(unittest.TestCase):
    """The Table 9-1 registries resolve a reserved value under its bare label."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_reserved_subtypes(self) -> None:
        from pcapkit.const.ieee802_11.control_subtype import ControlSubtype
        from pcapkit.const.ieee802_11.data_subtype import DataSubtype
        from pcapkit.const.ieee802_11.extension_subtype import ExtensionSubtype
        from pcapkit.const.ieee802_11.management_subtype import ManagementSubtype

        for registry, value in ((ControlSubtype, 0), (DataSubtype, 2), (DataSubtype, 6),
                                (ExtensionSubtype, 9)):
            with self.subTest(registry=registry.__name__, value=value):
                self.assertEqual(registry(value).name, 'Reserved')
        self.assertIs(ManagementSubtype(7), ManagementSubtype.Reserved_7)
        self.assertIs(DataSubtype(13), DataSubtype.Reserved_13)
        for registry in (ControlSubtype, DataSubtype, ExtensionSubtype, ManagementSubtype):
            with self.subTest(registry=registry.__name__), self.assertRaises(ValueError):
                registry(16)


if __name__ == '__main__':
    unittest.main()
