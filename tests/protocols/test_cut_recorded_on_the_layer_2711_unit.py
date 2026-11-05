# -*- coding: utf-8 -*-
"""A layer whose octets the capture cut short records the cut, and rebuilds as cut.

GitHub issue #2711: inside a frame, a message whose captured octets fall short of the
length its context gives it reads ``TRUNCATED``, from the length an enclosing IP layer
declares or, where no layer declares one, from the frame's original length (#2653,
#2689). Nothing recorded the cut on the message's own header, though, so rebuilt on its
own from its data model the message verified the octets captured and read ``INVALID``
with a ``ChecksumWarning``. Ruled on the issue: the layer records the cut, so its parse
and its rebuild agree. ``Schema``'s own short read covers a payload the data ends
inside, and a layer running to the end of a frame the capture cut short records the cut
on the last of its fields holding octets.

Each frame below is cut at every octet inside its message and read from a PCAP
savefile: GRE behind IPv4 and behind a Linux cooked-capture header, ICMP and IGMPv2
behind an IPv4 Total Length of 0, IGMPv2 behind IPv4, and UDP behind IPv4 and IPv6. The
message must record the cut and read as its context reads it, and its rebuild from its
data model and its dict must give the octets captured, read the same, and report
nothing. Whole frames, a wrong checksum and a cut in the Ethernet padding past a
declared length are the controls.

The octets and captures are built here; this module is unit-tier and reads no capture file.

"""
from __future__ import annotations

import contextlib
import io
import itertools
import logging
import struct
import unittest
import warnings
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import reimport_once_per_class
from tests.foundation import _roundtrip as wire

if TYPE_CHECKING:
    from typing import Any, Iterator

#: Test tier (#1958): hand-picked parse -> rebuild round trips.
__tier__ = 'ALL'

#: ``LINKTYPE_ETHERNET`` and ``LINKTYPE_LINUX_SLL``.
ETHERNET, LINUX_SLL = 1, 113
#: An IPv4 header of its own 20 octets, protocol 253, as GRE's payload.
INNER = bytes.fromhex('450000141234000040fd7b83c0000201c6336401')


def message(head: bytes, rest: bytes) -> bytes:
    """``head``, then the checksum over the whole message, then ``rest``."""
    return head + wire.checksum(head + b'\x00\x00' + rest).to_bytes(2, 'big') + rest


def gre(payload: bytes) -> bytes:
    """A GRE message with C set, carrying IPv4 ``payload``, checksummed."""
    head = struct.pack('>HH', 0x8000, 0x0800)
    return head + struct.pack('>HH', wire.checksum(head + bytes(4) + payload), 0) + payload


def tso(packet: bytes) -> bytes:
    """IPv4 ``packet`` with its Total Length 0, as segmentation offload leaves it."""
    head = bytearray(packet[:20])
    head[2:4], head[10:12] = bytes(2), bytes(2)
    head[10:12] = wire.checksum(bytes(head)).to_bytes(2, 'big')
    return bytes(head) + packet[20:]


def sll(packet: bytes) -> bytes:
    """``packet`` behind a Linux cooked-capture header naming ``ARPHRD_IPGRE``."""
    return struct.pack('>HHH', 0, 778, 0) + bytes(8) + struct.pack('>H', 0x0800) + packet


def pcap(linktype: int, packet: bytes, original: int) -> bytes:
    """A PCAP savefile of one frame holding ``packet`` of ``original`` octets on the wire."""
    return (struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 0xFFFF, linktype)
            + struct.pack('<IIII', 1, 0, len(packet), original) + packet)


def udp(data: bytes, *, version: int) -> bytes:
    """A UDP datagram of ``data``, checksummed over the IPv4 or IPv6 pseudo-header."""
    src, dst, nxt = ((wire.IPV4_A, wire.IPV4_B, b'\x00\x11') if version == 4
                     else (wire.IPV6_A, wire.IPV6_B, b'\x00\x00\x00\x11'))
    head = struct.pack('>HHH', 40000, 9, 8 + len(data))
    length = (8 + len(data)).to_bytes(2 if version == 4 else 4, 'big')
    pseudo = src + dst + (nxt + length if version == 4 else length + nxt)
    value = wire.checksum(pseudo + head + bytes(2) + data) or 0xFFFF
    return head + value.to_bytes(2, 'big') + data


ICMP = message(b'\x08\x00', b'\x00\x01\x00\x01' + b'echo-data-octets')
IGMP = message(b'\x16\x00', bytes([239, 1, 2, 3]) + b'trailing')
GRE = gre(INNER)
#: A SETTINGS frame of three settings, then a connection-level WINDOW_UPDATE: each a
#: frame whose 3-octet Length counts its payload alone (RFC 9113, section 4.1).
SETTINGS = bytes.fromhex('000012' '04' '00' '00000000' '000100001000' '000300000064' '000400010000')
WINDOW_UPDATE = bytes.fromhex('000004' '08' '00' '00000000' '0000ffff')

#: Each frame: its link type, its octets, the layer holding its message, and the
#: octets of its message a cut must leave for the message to be its own layer.
FRAMES = {
    'GRE behind IPv4': (ETHERNET, wire.ethernet(wire.ipv4(GRE, proto=47), 0x0800), 'GRE', 8),
    'GRE behind LINUX_SLL': (LINUX_SLL, sll(GRE), 'GRE', 8),
    'GRE behind a Total Length of 0': (ETHERNET, wire.ethernet(tso(wire.ipv4(GRE, proto=47)), 0x0800), 'GRE', 8),
    'ICMP behind a Total Length of 0': (ETHERNET, wire.ethernet(tso(wire.ipv4(ICMP, proto=1)), 0x0800), 'ICMP', 8),
    'IGMPv2 behind IPv4': (ETHERNET, wire.ethernet(wire.ipv4(IGMP, proto=2), 0x0800), 'IGMPv2', 8),
    'IGMPv2 behind a Total Length of 0': (ETHERNET, wire.ethernet(tso(wire.ipv4(IGMP, proto=2)), 0x0800),
                                          'IGMPv2', 8),
}

#: Each UDP frame: its octets, and the octets of the datagram past its header.
DATAGRAMS = {
    'UDP behind IPv4': (wire.ethernet(wire.ipv4(udp(b'udp-payload-octets', version=4)), 0x0800), 18),
    'UDP behind IPv6': (wire.ethernet(wire.ipv6(udp(b'udp-payload-octets', version=6), nxt=17), 0x86DD), 18),
}


def checksums(messages: 'list[str]') -> 'list[str]':
    """The checksum warnings among ``messages``; the savefile's own end is reported too."""
    return [line for line in messages if 'checksum' in line]


class _Logged(logging.Handler):
    """Collect what the ``pcapkit`` logger reports."""

    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.messages = []  # type: list[str]

    def emit(self, record: 'logging.LogRecord') -> None:
        self.messages.append(f'logged: {record.getMessage()}')


@contextlib.contextmanager
def _reported() -> 'Iterator[list[str]]':
    """Collect what the block reports, on the :mod:`warnings` channel and the logger."""
    handler = _Logged()
    logger = logging.getLogger('pcapkit')
    logger.addHandler(handler)
    try:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            yield handler.messages
    finally:
        logger.removeHandler(handler)
    handler.messages.extend(f'warned: {item.message}' for item in caught)


class CutRecordedOnTheLayerTests(unittest.TestCase):
    """A message the capture cut short records it, and its rebuild reads as cut."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        import pcapkit
        from pcapkit.corekit.checksum.internet import ChecksumStatus
        from pcapkit.utilities import config

        self.pcapkit = pcapkit
        self.Status = ChecksumStatus
        patch = mock.patch.object(config, 'CHECKSUM_VERIFY', True)
        patch.start()
        self.addCleanup(patch.stop)

    def extract(self, linktype: int, packet: bytes, original: int) -> 'tuple[Any, list[str]]':
        """The frame a savefile of ``packet`` holds, and what reading it reported."""
        with _reported() as messages:
            frame = self.pcapkit.extract(fin=io.BytesIO(pcap(linktype, packet, original)), nofile=True).frame[0]
        return frame, messages

    def assertRebuildsAsCut(self, layer: 'Any') -> 'None':  # pylint: disable=invalid-name
        """``layer`` rebuilt from its data model and its dict: its octets and status, quietly."""
        for path, data in (('model', layer.info), ('dict', layer.info.to_dict())):
            with self.subTest(path=path), _reported() as messages:
                rebuilt = type(layer).from_data(data)
            self.assertEqual((rebuilt.data, rebuilt.info.get('checksum_status'), messages),
                             (layer.data, layer.info.get('checksum_status'), []))

    def test_a_cut_message_records_it_and_rebuilds_as_cut(self) -> None:
        for label, (linktype, whole, name, header) in FRAMES.items():
            span = len(whole) - whole.index(GRE if name == 'GRE' else ICMP if name == 'ICMP' else IGMP)
            for cut in range(1, span - header + 1):
                with self.subTest(frame=label, cut=cut):
                    frame, _ = self.extract(linktype, whole[:len(whole) - cut], len(whole))
                    layer = frame[name]
                    self.assertIsNotNone(layer.info.get('__short_read__'))
                    self.assertIs(layer.info.checksum_status, self.Status.TRUNCATED)
                    self.assertRebuildsAsCut(layer)
                    if 'Total Length of 0' in label:
                        # The cut is in the payload the IPv4 layer runs to the frame's end
                        # with, not in its empty trailer.
                        self.assertEqual(frame['IPv4'].info.get('__short_read__'),
                                         ('payload', span - cut))

    def test_a_layer_declaring_a_length_records_its_cut(self) -> None:
        for label, (whole, data) in DATAGRAMS.items():
            for cut in range(1, data + 1):
                with self.subTest(frame=label, cut=cut):
                    frame, _ = self.extract(ETHERNET, whole[:len(whole) - cut], len(whole))
                    layer = frame['UDP']
                    self.assertEqual(layer.info.get('__short_read__'), ('payload', data - cut))
                    self.assertEqual(type(layer).from_data(layer.info).data, layer.data)

    def test_a_whole_message_is_verified(self) -> None:
        for label, (linktype, whole, name, _) in FRAMES.items():
            with self.subTest(frame=label):
                frame, messages = self.extract(linktype, whole, len(whole))
                layer = frame[name]
                self.assertIsNone(layer.info.get('__short_read__'))
                self.assertEqual((layer.info.checksum_status, checksums(messages)), (self.Status.VALID, []))
                self.assertRebuildsAsCut(layer)

    def test_a_wrong_checksum_still_warns(self) -> None:
        bad = GRE[:4] + (int.from_bytes(GRE[4:6], 'big') ^ 0x0101).to_bytes(2, 'big') + GRE[6:]
        for label, linktype, whole in (('IPv4', ETHERNET, wire.ethernet(wire.ipv4(bad, proto=47), 0x0800)),
                                       ('LINUX_SLL', LINUX_SLL, sll(bad))):
            with self.subTest(frame=label):
                frame, messages = self.extract(linktype, whole, len(whole))
                self.assertIs(frame['GRE'].info.checksum_status, self.Status.INVALID)
                self.assertRegex(' '.join(messages), r'GRE: checksum 0x[0-9a-f]{4} is wrong;')

    def test_a_cut_past_a_declared_length_is_not_the_message(self) -> None:
        # The frame is padded past the datagram IPv4 declares, and cut in that padding only.
        whole = wire.ethernet(wire.ipv4(ICMP, proto=1), 0x0800) + bytes(8)
        frame, messages = self.extract(ETHERNET, whole[:-4], len(whole))
        layer = frame['ICMP']
        self.assertIsNone(layer.info.get('__short_read__'))
        self.assertEqual((layer.info.checksum_status, checksums(messages)), (self.Status.VALID, []))
        self.assertRebuildsAsCut(layer)

    def test_a_layer_declaring_its_length_records_no_frame_cut_past_it(self) -> None:
        # Behind an IPv4 Total Length of 0 the frame's cut reaches every layer, so
        # IPv4 and Ethernet, declaring no length, record it. UDP declares its Length
        # and an HTTP/2 frame its own, so a cut at or past those ends is none of theirs.
        datagram = wire.ethernet(tso(wire.ipv4(udp(b'hello', version=4))), 0x0800)
        whole = datagram + bytes(20)
        for where, keep in (('at its end', len(datagram)), ('3 into the padding', len(datagram) + 3),
                            ('19 into the padding', len(datagram) + 19), ('inside its data', len(datagram) - 2)):
            with self.subTest(layer='UDP', cut=where):
                frame, _ = self.extract(ETHERNET, whole[:keep], len(whole))
                record = ('payload', 3) if keep < len(datagram) else None
                self.assertEqual(frame['UDP'].info.get('__short_read__'), record)
                self.assertEqual(frame['IPv4'].info.get('__short_read__'), ('payload', keep - 34))
                self.assertEqual(frame['Ethernet'].info.get('__short_read__'), ('payload', keep - 14))
                self.assertEqual(type(frame['UDP']).from_data(frame['UDP'].info).data, frame['UDP'].data)

        segment = wire.ethernet(tso(wire.ipv4(wire.tcp(SETTINGS + WINDOW_UPDATE, seq=1, dport=80), proto=6)),
                                0x0800)
        for where, keep in (('at the first frame\'s end', len(segment) - len(WINDOW_UPDATE)),
                            ('inside the next frame', len(segment) - 1)):
            with self.subTest(layer='HTTP/2', cut=where):
                frame, _ = self.extract(ETHERNET, segment[:keep], len(segment))
                first = frame['TCP'].payload
                self.assertEqual((type(first).__name__, first.info.get('__short_read__')), ('HTTPv2', None))
                with _reported() as messages:
                    rebuilt = type(first).from_data(first.info)
                self.assertEqual((rebuilt.data, messages), (first.data, []))

    def test_a_layer_ending_in_a_list_records_no_frame_cut(self) -> None:
        # SCTP behind an IPv4 Total Length of 0 ends in its chunk list, whose buffer holds
        # only the chunks it took: a cut recorded there would drop the trailer a cut
        # chunk is kept in. So SCTP records nothing, and rebuilds as captured.
        packets = {
            # a DATA chunk of three octets and its pad octet
            'DATA': bytes.fromhex('13881389112233441eca615f0003001300000007000100020000000001020300'),
            # an INIT with four parameters, a DATA chunk of five octets, then a HEARTBEAT
            'INIT, DATA, HEARTBEAT': bytes.fromhex(
                '1388138911223344f8c903be0100003caabbccdd00010000000a000a0000000100050008c00002'
                '01000c000600050000000b000e6c6f63616c686f737400000000090008000003e8000300150000'
                '0007000100020000000061626364650000000400000c0001000778797a00'),
        }
        for (label, packet), (where, cut) in itertools.product(
                packets.items(), (('at its end', 0), ('3 into the padding', 3), ('2 inside the last chunk', -2))):
            segment = wire.ethernet(tso(wire.ipv4(packet, proto=132)), 0x0800)
            whole, keep = segment + bytes(20), len(segment) + cut
            with self.subTest(packet=label, cut=where):
                frame, _ = self.extract(ETHERNET, whole[:keep], len(whole))
                sctp = frame['SCTP']
                self.assertEqual(sctp.data, whole[34:keep])
                self.assertIsNone(sctp.info.get('__short_read__'))
                with _reported() as messages:
                    rebuilt = type(sctp).from_data(sctp.info)
                self.assertEqual((rebuilt.data, messages), (sctp.data, []))

    def test_an_ipv6_header_past_its_payload_length_stays_raw_in_a_cut_frame(self) -> None:
        # With #2694's capture-cut test on each header IPv6 walks: a padded frame cut at
        # the IP end or in the padding records nothing on IPv6, whose Payload Length
        # its octets cover, and a 16-octet Hop-by-Hop header under a Payload Length of 8
        # runs past it, so it stays Raw, quietly, whether or not the frame was cut.
        hop = bytes([59, 1, 0, 1, 4, 0, 0, 0, 1, 5, 0, 0, 0, 0, 0, 0])
        packet = wire.ethernet(b'\x60\x00\x00\x00\x00\x08\x00\x40' + wire.IPV6_A + wire.IPV6_B + hop[:8], 0x86DD)
        whole = packet + bytes(12)
        for where, keep in (('whole', len(whole)), ('at the packet end', len(packet)),
                            ('inside the padding', len(packet) + 4)):
            with self.subTest(cut=where):
                frame, messages = self.extract(ETHERNET, whole[:keep], len(whole))
                ipv6 = frame['IPv6']
                self.assertEqual(type(ipv6.payload).__name__, 'Raw')
                self.assertNotIn('hopopt', ipv6.info)
                self.assertIsNone(ipv6.info.get('__short_read__'))
                self.assertEqual([line for line in messages if 'EOF' not in line], [])
                with _reported() as rebuilt_messages:
                    rebuilt = type(ipv6).from_data(ipv6.info)
                self.assertEqual((rebuilt.data, rebuilt_messages), (ipv6.data, []))

    def test_an_ip_layer_covered_to_its_length_records_no_cut(self) -> None:
        # The frame is padded past the packet, and cut at the packet's end or inside
        # the padding: the IP layer, a Hop-by-Hop header it carries and its UDP
        # datagram are whole, while Ethernet, declaring no length, is cut with the frame.
        hop = bytes([17, 0, 1, 4, 0, 0, 0, 0])
        packets = {
            'IPv4': (wire.ethernet(wire.ipv4(udp(b'hello', version=4)), 0x0800), ()),
            'IPv6': (wire.ethernet(wire.ipv6(udp(b'hello', version=6), nxt=17), 0x86DD), ()),
            'IPv6 with HOPOPT': (wire.ethernet(wire.ipv6(hop + udp(b'hello', version=6), nxt=0), 0x86DD),
                                 ('HOPOPT',)),
        }
        for label, (packet, headers) in packets.items():
            whole = packet + bytes(max(60 - len(packet), 8))
            for where, keep in (('at the packet end', len(packet)), ('inside the padding', len(packet) + 2)):
                with self.subTest(packet=label, cut=where):
                    frame, _ = self.extract(ETHERNET, whole[:keep], len(whole))
                    names = ('IPv6' if 'IPv6' in label else 'IPv4', 'UDP')
                    self.assertEqual({name: frame[name].info.get('__short_read__') for name in names},
                                     dict.fromkeys(names))
                    # an IPv6 extension header is held in the IPv6 layer's info, not as a layer
                    self.assertEqual([frame['IPv6'].info[name.lower()].get('__short_read__') for name in headers],
                                     [None] * len(headers))
                    self.assertEqual(frame['Ethernet'].info.get('__short_read__'), ('payload', keep - 14))
                    for name in names:
                        # UDP rebuilt alone has no pseudo-header to verify against
                        with self.subTest(layer=name), _reported() as messages:
                            rebuilt = type(frame[name]).from_data(frame[name].info)
                        self.assertEqual((rebuilt.data, messages), (frame[name].data, []))


if __name__ == '__main__':
    unittest.main()
