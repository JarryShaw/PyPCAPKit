# -*- coding: utf-8 -*-
"""GitHub issue #2936: IEEE 802.2 LLC, and the frames that carry it.

:class:`~pcapkit.protocols.link.llc.protocol.LLC` reads the DSAP, the SSAP and its
C/R bit, and the control field in its I, S and U formats, and dispatches the
information field of an I or UI PDU by DSAP. Ethernet hands it the payload
its Length/Type field bounds where that is a length (IEEE Std 802.3 §3.2.6),
an 802.11 data frame its MSDU, and PCAP and PCAP-NG the packets of
``LINKTYPE_ATM_RFC1483``. Every octet string here is built by hand, and every
layer rebuilds byte-exactly.

Each test imports :mod:`pcapkit` itself, after
:func:`~tests._support.reimport_once_per_class`.

"""

import os
import struct
import tempfile
import unittest
import warnings

from tests._support import reimport_once_per_class

#: Test tier (#1958): per-protocol field tests, interpreter-independent pure Python.
__tier__ = 'LATEST'

#: An option-less IPv4 header of protocol 59 and no payload, 192.0.2.1 to 198.51.100.1.
IPV4 = bytes.fromhex('4500001400000000403b0000c0000201c6336401')

#: A SNAP header under OUI 00-00-00 carrying EtherType 0x0800 (RFC 9542 Section 3).
SNAP_IPV4 = bytes.fromhex('000000' '0800') + IPV4

#: A UI command to the SNAP LSAP: DSAP 0xAA, SSAP 0xAA, control 0x03 (RFC 1042).
UI_SNAP = bytes.fromhex('aa' 'aa' '03') + SNAP_IPV4

#: Ethernet addresses: destination, then source.
MACS = bytes.fromhex('001122334455' '66778899aabb')


def _pcap(linktype: int, records: 'tuple[bytes, ...]') -> bytes:
    """A little-endian PCAP v2.4 file of ``records`` on ``linktype``."""
    data = struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 262144, linktype)
    for index, record in enumerate(records):
        data += struct.pack('<IIII', 1500000000 + index, 0, len(record), len(record)) + record
    return data


def _pcapng(linktype: int, records: 'tuple[bytes, ...]') -> bytes:
    """A little-endian PCAP-NG file: one section, one interface on ``linktype``."""
    shb = struct.pack('<IIIHHqI', 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1, 28)
    idb = struct.pack('<IIHHII', 1, 20, linktype, 0, 262144, 20)
    blocks = b''
    for index, record in enumerate(records):
        padded = record + bytes(-len(record) % 4)
        length = 32 + len(padded)
        blocks += (struct.pack('<IIIIIII', 6, length, 0, 0, 1500000000 + index, len(record), len(record))
                   + padded + struct.pack('<I', length))
    return shb + idb + blocks


def _wlan(fc: bytes, body: bytes, qos: 'bytes | None' = None) -> bytes:
    """An 802.11 frame of Frame Control ``fc``, three addresses, then ``body``."""
    addrs = bytes.fromhex('020000000001' '020000000002' '020000000003')
    return fc + bytes(2) + addrs + b'\x10\x00' + (qos or b'') + body


class _Base(unittest.TestCase):
    """Parsing and rebuilding helpers."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _llc(self, data: bytes):  # type: ignore[no-untyped-def]
        from pcapkit.protocols.link.llc.protocol import LLC
        return LLC(data, len(data))

    def _assert_rebuilds(self, layer) -> None:  # type: ignore[no-untyped-def]
        """``layer`` and each layer below it rebuild byte-exactly from their info and its dict."""
        while type(layer).__name__ not in ('Raw', 'NoPayload'):
            for data in (layer.info, layer.info.to_dict()):
                with self.subTest(layer=type(layer).__name__, data=type(data).__name__):
                    rebuilt = type(layer).from_data(data)
                    self.assertEqual(rebuilt.data.hex(), layer.data.hex())
                    self.assertEqual(rebuilt.info, layer.info)
            layer = layer.payload

    def _extract(self, data: bytes, suffix: str) -> 'list':  # type: ignore[type-arg]
        import pcapkit

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, f'llc{suffix}')
            with open(path, 'wb') as file:
                file.write(data)
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                extractor = pcapkit.extract(fin=path, store=True)
        return list(extractor.frame)


class TestLLC(_Base):
    """Pin the LLC PDU against IEEE Std 802.2."""

    ##########################################################################
    # The three formats.
    ##########################################################################

    def test_ui_pdu_to_snap_dispatches_by_dsap(self) -> None:
        from pcapkit.const.llc.lsap import LSAP
        from pcapkit.const.llc.modifier_function import ModifierFunction

        llc = self._llc(UI_SNAP)
        info = llc.info
        self.assertIs(info.dsap, LSAP.SNAP)
        self.assertIs(info.ssap, LSAP.SNAP)
        self.assertIs(info.cr, False)
        self.assertEqual((info.control.format, info.control.poll_final), ('U', False))
        self.assertIs(info.control.function, ModifierFunction.UI)
        self.assertEqual((info.control.send_seq, info.control.recv_seq, info.control.reserved),
                         (None, None, None))
        self.assertEqual((llc.name, llc.alias, llc.length), ('Logical Link Control', 'LLC', 3))
        self.assertEqual(llc.protochain.chain, 'LLC:SNAP:IPv4')
        self._assert_rebuilds(llc)

    def test_i_pdu_carries_its_sequence_numbers(self) -> None:
        """N(S) in bits 2-8 of the first octet, P/F and N(R) in the second."""
        data = bytes.fromhex('aa' 'aa' '0a' '0f') + SNAP_IPV4
        llc = self._llc(data)
        control = llc.info.control
        self.assertEqual((control.format, control.function, control.send_seq, control.recv_seq,
                          control.poll_final, control.reserved), ('I', None, 5, 7, True, None))
        self.assertEqual(llc.length, 4)
        self.assertEqual(llc.protochain.chain, 'LLC:SNAP:IPv4')
        self._assert_rebuilds(llc)

    def test_s_pdu_keeps_its_reserved_bits(self) -> None:
        """RNR (``0x04``) with bits 5-8 set, N(R) 3; its trailing octets are no service data."""
        from pcapkit.const.llc.supervisory_function import SupervisoryFunction

        data = bytes.fromhex('aa' 'ab' 'a5' '06') + SNAP_IPV4
        llc = self._llc(data)
        control = llc.info.control
        self.assertIs(control.function, SupervisoryFunction.RNR)
        self.assertEqual((control.format, control.send_seq, control.recv_seq, control.poll_final,
                          control.reserved), ('S', None, 3, False, 0xA))
        self.assertIs(llc.info.cr, True)
        self.assertEqual(llc.length, 4)
        self.assertEqual(type(llc.payload).__name__, 'Raw')
        self._assert_rebuilds(llc)

    def test_xid_information_is_llcs_own(self) -> None:
        """An XID command with P set, of the basic format, is not dispatched to SNAP."""
        from pcapkit.const.llc.modifier_function import ModifierFunction

        data = bytes.fromhex('aa' 'aa' 'bf' '810100')
        llc = self._llc(data)
        self.assertIs(llc.info.control.function, ModifierFunction.XID)
        self.assertIs(llc.info.control.poll_final, True)
        self.assertEqual(type(llc.payload).__name__, 'Raw')
        self.assertEqual(bytes(llc.payload.data), bytes.fromhex('810100'))
        self._assert_rebuilds(llc)

    def test_every_function_round_trips(self) -> None:
        from pcapkit.const.llc.lsap import LSAP
        from pcapkit.const.llc.modifier_function import ModifierFunction
        from pcapkit.const.llc.supervisory_function import SupervisoryFunction
        from pcapkit.protocols.link.llc.protocol import LLC

        cases = [('U', member, poll) for member in ModifierFunction for poll in (False, True)]
        cases += [('S', member, poll) for member in SupervisoryFunction for poll in (False, True)]
        for format_, function, poll in cases:
            with self.subTest(format=format_, function=function.name, poll=poll):
                made = bytes(LLC.from_fields(dsap=LSAP.Null, ssap=LSAP.Null, format=format_,
                                             function=function, poll_final=poll))
                llc = self._llc(made)
                self.assertEqual((llc.info.control.format, llc.info.control.function,
                                  llc.info.control.poll_final), (format_, function, poll))
                self._assert_rebuilds(llc)

    def test_an_unassigned_function_is_kept(self) -> None:
        """``0x2F`` is HDLC's SABM, which LLC does not define."""
        llc = self._llc(bytes.fromhex('fe' 'fe' '2f'))
        self.assertEqual((llc.info.control.function.name, int(llc.info.control.function)),
                         ('Unassigned', 0x2C))
        self._assert_rebuilds(llc)

    ##########################################################################
    # The address fields.
    ##########################################################################

    def test_dsap_keeps_its_ig_bit_and_ssap_loses_its_cr_bit(self) -> None:
        from pcapkit.const.llc.lsap import LSAP

        llc = self._llc(bytes.fromhex('ff' 'ff' 'e3') + b'test')
        self.assertIs(llc.info.dsap, LSAP.Global)
        self.assertIs(llc.info.ssap, LSAP.Network_Layer_Protocol_Identification)
        self.assertIs(llc.info.cr, True)
        self._assert_rebuilds(llc)

    def test_snap_needs_the_snap_ssap_too(self) -> None:
        """RFC 1042 sets both SAPs to 0xAA; a response, its C/R bit set, still reaches SNAP."""
        for ssap in (0x42, 0x00, 0xFE):
            with self.subTest(ssap=hex(ssap)):
                llc = self._llc(bytes((0xAA, ssap, 0x03)) + SNAP_IPV4)
                self.assertEqual(type(llc.payload).__name__, 'Raw')
                self.assertEqual(bytes(llc.payload.data), SNAP_IPV4)
                self._assert_rebuilds(llc)
        for data in (bytes.fromhex('aa' 'ab' '03') + SNAP_IPV4, bytes.fromhex('aa' 'ab' '0a0f') + SNAP_IPV4):
            with self.subTest(control=data[2:3].hex()):
                llc = self._llc(data)
                self.assertIs(llc.info.cr, True)
                self.assertEqual(llc.protochain.chain, 'LLC:SNAP:IPv4')
                self._assert_rebuilds(llc)

    def test_a_dsap_with_no_entry_is_kept_raw(self) -> None:
        llc = self._llc(bytes.fromhex('fe' 'fe' '03') + IPV4)
        self.assertEqual(type(llc.payload).__name__, 'Raw')
        self.assertEqual(bytes(llc.payload.data), IPV4)
        self._assert_rebuilds(llc)

    ##########################################################################
    # Construction.
    ##########################################################################

    def test_make_defaults_to_a_ui_command_to_snap(self) -> None:
        from pcapkit.protocols.link.llc.protocol import LLC

        self.assertEqual(bytes(LLC.from_fields()), bytes.fromhex('aaaa03'))
        made = LLC.from_fields(format='I', send_seq=5, recv_seq=7, poll_final=True, payload=SNAP_IPV4)
        self.assertEqual(bytes(made), bytes.fromhex('aaaa0a0f') + SNAP_IPV4)
        made = LLC.from_fields(cr=True, format='S', function=0x04, recv_seq=3, reserved=0xA)
        self.assertEqual(bytes(made), bytes.fromhex('aaaba506'))

    def test_make_refuses_what_would_not_read_back(self) -> None:
        from pcapkit.protocols.link.llc.protocol import LLC
        from pcapkit.utilities.exceptions import ProtocolError

        for fields in ({'ssap': 0xAB}, {'format': 'X'}, {'send_seq': 1}, {'recv_seq': 1},
                       {'reserved': 1}, {'format': 'I', 'function': 0x00}, {'format': 'U', 'reserved': 1},
                       {'format': 'S', 'send_seq': 1}, {'format': 'S', 'function': 0x01},
                       {'function': 0x10}, {'format': 'I', 'send_seq': 128}, {'dsap': 'SNAP'},
                       {'dsap': 0x100}, {'cr': 2}):
            with self.subTest(fields=fields):
                with self.assertRaises(ProtocolError):
                    LLC.from_fields(**fields)

    def test_index_and_registry(self) -> None:
        from pcapkit.const.llc.lsap import LSAP
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.protocols.link.llc.protocol import LLC
        from pcapkit.protocols.link.snap.protocol import SNAP

        self.assertIs(LLC.__index__(), LinkType.ATM_RFC1483)
        self.assertEqual(LLC.__proto__[LSAP.SNAP],
                         ModuleDescriptor('pcapkit.protocols.link.snap.protocol', 'SNAP'))
        self.assertIs(LLC._lookup_next_layer(LLC.__proto__, LSAP.SNAP), SNAP)
        self.assertEqual(LLC.__proto_key__, (LSAP, False))

    def test_register_lsap_dispatches_a_new_dsap(self) -> None:
        from pcapkit.const.llc.lsap import LSAP
        from pcapkit.foundation.registry import register_lsap
        from pcapkit.protocols.link.llc.protocol import LLC
        from pcapkit.protocols.link.snap.protocol import SNAP
        from pcapkit.utilities.exceptions import RegistryError

        try:
            register_lsap(LSAP.Network_Layer_Protocol_Identification, SNAP)
            llc = self._llc(bytes.fromhex('fe' 'fe' '03') + SNAP_IPV4)
            self.assertEqual(llc.protochain.chain, 'LLC:SNAP:IPv4')
        finally:
            LLC.__proto__.pop(LSAP.Network_Layer_Protocol_Identification, None)
        with self.assertRaises(RegistryError):
            register_lsap(0xFE, SNAP)  # type: ignore[arg-type]

    def test_a_dsap_registered_paired_needs_its_ssap(self) -> None:
        """A DSAP registered with ``paired=True`` is handed on only with the same SSAP, C/R masked."""
        from pcapkit.const.llc.lsap import LSAP
        from pcapkit.foundation.registry import register_lsap
        from pcapkit.protocols.link.llc.protocol import LLC
        from pcapkit.protocols.link.snap.protocol import SNAP
        from pcapkit.utilities.exceptions import RegistryError

        tables = dict(LLC.__proto__), dict(LLC.__paired__)
        try:
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                register_lsap(LSAP.Bridge_Spanning_Tree_Protocol, SNAP, paired=True)
            self.assertIs(LLC.__paired__[LSAP.Bridge_Spanning_Tree_Protocol], True)
            for ssap, chain in ((0x42, 'LLC:SNAP:IPv4'), (0x43, 'LLC:SNAP:IPv4'), (0xAA, None), (0x00, None)):
                with self.subTest(ssap=hex(ssap)):
                    llc = self._llc(bytes((0x42, ssap, 0x03)) + SNAP_IPV4)
                    if chain is None:
                        self.assertEqual(type(llc.payload).__name__, 'Raw')
                    else:
                        self.assertEqual(llc.protochain.chain, chain)
                    self._assert_rebuilds(llc)
            with self.assertRaises(RegistryError):
                register_lsap(LSAP.Bridge_Spanning_Tree_Protocol, SNAP, paired=1)  # type: ignore[arg-type]
        finally:
            for table, copy in zip((LLC.__proto__, LLC.__paired__), tables):
                table.clear()
                table.update(copy)

    def test_an_override_and_its_restore_keep_snap_paired(self) -> None:
        from pcapkit.const.llc.lsap import LSAP
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.foundation.registry import register_lsap
        from pcapkit.protocols.link.link import Link
        from pcapkit.protocols.link.llc.protocol import LLC

        shipped = LLC.__proto__[LSAP.SNAP]
        tables = dict(LLC.__proto__), dict(LLC.__paired__)
        custom = type('PairedRoundTrip', (Link,), {'__module__': __name__})
        try:
            for restore in (shipped, ModuleDescriptor('pcapkit.protocols.link.snap.protocol', 'SNAP')):
                with self.subTest(restore=type(restore).__name__):
                    with warnings.catch_warnings():
                        warnings.simplefilter('ignore')
                        register_lsap(LSAP.SNAP, custom)
                        self.assertNotIn(LSAP.SNAP, LLC.__paired__)
                        register_lsap(LSAP.SNAP, restore)
                    self.assertIs(LLC.__proto__[LSAP.SNAP], shipped)
                    self.assertEqual(LLC.__paired__, dict(LLC._shipped_paired))
                    self.assertEqual(type(self._llc(bytes.fromhex('aa' '42' '03') + SNAP_IPV4).payload).__name__,
                                     'Raw')
                    self.assertEqual(self._llc(UI_SNAP).protochain.chain, 'LLC:SNAP:IPv4')
            register_lsap(LSAP.SNAP, shipped)
            self.assertEqual(LLC.__paired__, dict(LLC._shipped_paired))
        finally:
            for table, copy in zip((LLC.__proto__, LLC.__paired__), tables):
                table.clear()
                table.update(copy)


class TestLLCCarriers(_Base):
    """Pin the frames that hand their payload to LLC."""

    ##########################################################################
    # IEEE 802.3: a Length/Type field that is a length.
    ##########################################################################

    def test_ethernet_length_bounds_the_llc_pdu(self) -> None:
        from pcapkit.protocols.link.ethernet.protocol import Ethernet

        pad = bytes(46 - len(UI_SNAP))
        data = MACS + struct.pack('!H', len(UI_SNAP)) + UI_SNAP + pad
        frame = Ethernet(data, len(data))
        self.assertEqual(int(frame.info.type), len(UI_SNAP))
        self.assertEqual(frame.info.trailer, pad)
        self.assertEqual(frame.protochain.chain, 'Ethernet:LLC:SNAP:IPv4')
        self.assertEqual(bytes(frame.payload.data), UI_SNAP)
        self._assert_rebuilds(frame)

        made = Ethernet.from_fields(dst='00:11:22:33:44:55', src='66:77:88:99:aa:bb',
                                    type=len(UI_SNAP), payload=UI_SNAP, trailer=pad)
        self.assertEqual(bytes(made), data)

    def test_ethernet_length_type_boundaries(self) -> None:
        """``0x05DC`` is a length, ``0x05DD`` to ``0x05FF`` are neither, ``0x0600`` is an EtherType."""
        from pcapkit.protocols.link.ethernet.protocol import Ethernet

        body = bytes.fromhex('fe' 'fe' '03') + bytes(0x05DC - 3)
        frame = Ethernet(MACS + b'\x05\xdc' + body, 14 + len(body))
        self.assertEqual(type(frame.payload).__name__, 'LLC')
        self.assertNotIn('trailer', frame.info)
        self._assert_rebuilds(frame)
        for value in (0x05DD, 0x05FF, 0x0600):
            with self.subTest(value=hex(value)):
                data = MACS + struct.pack('!H', value) + UI_SNAP
                frame = Ethernet(data, len(data))
                self.assertEqual(type(frame.payload).__name__, 'Raw')
                self.assertEqual(bytes(frame.payload.data), UI_SNAP)
                self._assert_rebuilds(frame)

    def test_ethernet_ii_keeps_its_payload_whole(self) -> None:
        """An EtherType frame has no trailer of its own; IPv4 keeps the link padding."""
        from pcapkit.protocols.link.ethernet.protocol import Ethernet

        data = MACS + b'\x08\x00' + IPV4 + bytes(26)
        frame = Ethernet(data, len(data))
        self.assertNotIn('trailer', frame.info)
        self.assertEqual(frame.protochain.chain, 'Ethernet:IPv4')
        self.assertEqual(frame.payload.info.trailer, bytes(26))
        self._assert_rebuilds(frame)

    def test_a_cut_8023_frame_rebuilds_as_captured(self) -> None:
        from pcapkit.protocols.link.ethernet.protocol import Ethernet

        data = MACS + struct.pack('!H', 46) + UI_SNAP[:10]
        frame = Ethernet(data, len(data))
        self.assertEqual(type(frame.payload).__name__, 'LLC')
        self.assertEqual(Ethernet.from_data(frame.info).data, data)
        cut = Ethernet(data[:13], 13)
        self.assertEqual(type(cut.payload).__name__, 'Raw')
        self.assertEqual(Ethernet.from_data(cut.info).data, data[:13])

    def test_ethernet_make_refuses_a_length_or_trailer_that_would_not_read_back(self) -> None:
        from pcapkit.protocols.link.ethernet.protocol import Ethernet
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaises(ProtocolError):
            Ethernet.from_fields(type=len(UI_SNAP) + 1, payload=UI_SNAP)
        with self.assertRaises(ProtocolError):
            Ethernet.from_fields(type=0x0800, payload=IPV4, trailer=b'\x00')

    ##########################################################################
    # IEEE 802.11: a data frame's MSDU.
    ##########################################################################

    def test_802_11_data_frames_carrying_an_msdu(self) -> None:
        from pcapkit.protocols.link.ieee802_11.protocol import IEEE802_11

        # Data (0b0000) and QoS Data (0b1000) with A-MSDU Present (bit 7 of QoS Control) clear.
        for data in (_wlan(b'\x08\x00', UI_SNAP), _wlan(b'\x88\x00', UI_SNAP, qos=b'\x00\x00')):
            with self.subTest(fc=data[:2].hex()):
                frame = IEEE802_11(data, len(data))
                self.assertEqual(frame.protochain.chain, '802.11:LLC:SNAP:IPv4')
                self._assert_rebuilds(frame)

    def test_802_11_bodies_that_are_no_msdu(self) -> None:
        from pcapkit.protocols.link.ieee802_11.protocol import IEEE802_11

        cases = {
            'protected': _wlan(b'\x08\x40', UI_SNAP),
            'A-MSDU': _wlan(b'\x88\x00', UI_SNAP, qos=b'\x80\x00'),
            'reserved subtype 1': _wlan(b'\x18\x00', UI_SNAP),
            'beacon': _wlan(b'\x80\x00', UI_SNAP),
        }
        for name, data in cases.items():
            with self.subTest(case=name):
                frame = IEEE802_11(data, len(data))
                self.assertEqual(type(frame.payload).__name__, 'Raw')
                self.assertEqual(bytes(frame.payload.data), UI_SNAP)
                self._assert_rebuilds(frame)
        null = _wlan(b'\x48\x00', b'')
        self.assertEqual(IEEE802_11(null, len(null)).protochain.chain, '802.11')

    def test_an_empty_msdu_or_a_stop_leaves_no_llc_layer(self) -> None:
        from pcapkit.protocols.link.ethernet.protocol import Ethernet
        from pcapkit.protocols.link.ieee802_11.protocol import IEEE802_11

        empty = _wlan(b'\x08\x00', b'')
        frame = IEEE802_11(empty, len(empty))
        self.assertEqual(type(frame.payload).__name__, 'NoPayload')
        self._assert_rebuilds(frame)

        data = MACS + struct.pack('!H', len(UI_SNAP)) + UI_SNAP
        stopped = Ethernet(data, len(data), protocol='Ethernet')
        self.assertEqual(type(stopped.payload).__name__, 'Raw')
        self.assertEqual(bytes(stopped.payload.data), UI_SNAP)

        # With no length given, the import reads the whole payload.
        frame = Ethernet(data, len(data))
        llc = frame._import_next_layer(frame.info.type)  # pylint: disable=protected-access
        self.assertEqual((type(llc).__name__, bytes(llc.data)), ('LLC', UI_SNAP))

    ##########################################################################
    # LINKTYPE_ATM_RFC1483.
    ##########################################################################

    def test_atm_rfc1483_captures(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.protocols.misc.pcap.frame.protocol import Frame
        from pcapkit.protocols.misc.pcapng.protocol import PCAPNG

        for cls in (Frame, PCAPNG):
            with self.subTest(table=cls.__name__):
                self.assertEqual(cls.__proto__[LinkType.ATM_RFC1483],
                                 ModuleDescriptor('pcapkit.protocols.link', 'LLC'))
        for data, suffix in ((_pcap(100, (UI_SNAP,)), '.pcap'), (_pcapng(100, (UI_SNAP,)), '.pcapng')):
            with self.subTest(format=suffix):
                frames = self._extract(data, suffix)
                self.assertEqual([frame.protochain.chain for frame in frames], ['LLC:SNAP:IPv4'])
                self._assert_rebuilds(frames[0].payload)


if __name__ == '__main__':
    unittest.main()
