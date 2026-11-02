# -*- coding: utf-8 -*-
"""A message behind an IPv4 Total Length of 0 the capture cut short reads ``TRUNCATED``.

GitHub issue #2689: :meth:`IPv4.read <pcapkit.protocols.internet.ipv4.IPv4.read>` reads
a Total Length of 0, as TCP segmentation offload leaves it, as the rest of the frame
(#1547), so the IPv4 layer declares no length and the frame's original length is the
only record of a snaplen cut. Cleared there by :meth:`Internet._decode_next_layer
<pcapkit.protocols.internet.internet.Internet._decode_next_layer>`, the cut is lost, and
GRE, ICMP and IGMP sum the octets captured and read ``INVALID`` with a false
``ChecksumWarning``. So the IPv4 layer leaves
:data:`~pcapkit.utilities.contextvars.frame_length` as it is, an AH between it and the
message hands it on, and :func:`~pcapkit.corekit.checksum.internet.verify_message`, which
all three share, counts the cut. A layer declaring its payload's length clears it, as
#2653 has it.

Each capture is built here and read through :func:`pcapkit.extract`. This module is
unit-tier and reads no capture file.

"""
from __future__ import annotations

import io
import struct
import unittest
import warnings
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import reimport_once_per_class
from tests.foundation import _roundtrip as wire

if TYPE_CHECKING:
    from typing import Any, Callable

    #: A writer of a capture: link type, the octets captured and the original length.
    Writer = Callable[[int, bytes, int], bytes]

#: Test tier (#1958): hand-picked parse -> rebuild round trips.
__tier__ = 'ALL'

#: ``LINKTYPE_ETHERNET`` and ``LINKTYPE_IPV4``.
ETHERNET, RAW_IPV4 = 1, 228
#: Octets of the fixed header of each message below, which a cut must leave whole
#: for the message to parse as its own layer.
HEADER = 8
#: The octets one cut takes off the end of a frame, where a test needs only one.
CUT = 4


def message(head: bytes, rest: bytes) -> bytes:
    """``head``, then the checksum over the whole message, then ``rest``."""
    return head + wire.checksum(head + b'\x00\x00' + rest).to_bytes(2, 'big') + rest


def wrong(msg: bytes, at: int) -> bytes:
    """``msg`` with the checksum field at ``at`` flipped in both octets."""
    field = int.from_bytes(msg[at:at + 2], 'big') ^ 0x0101
    return msg[:at] + field.to_bytes(2, 'big') + msg[at + 2:]


#: An IGMPv3 group record of type MODE_IS_INCLUDE for 239.1.2.3, with one source.
RECORD = bytes([1, 0, 0, 1, 239, 1, 2, 3, 192, 0, 2, 7])

#: Each message: its IP protocol number, its octets, where its checksum sits, and
#: the layer it parses as. GRE carries EtherType ``0x88B5``, local experimental,
#: so its payload is Raw; the IGMPv2 report carries trailing octets, so the cut
#: can end inside them as well as inside the message.
MESSAGES = {
    'GRE': (47, message(b'\x80\x00\x88\xb5', bytes(2) + b'payload-octets!!' * 2), 4, 'GRE'),
    'ICMP': (1, message(b'\x08\x00', b'\x00\x01\x00\x01' + b'echo-data-octets' * 2), 2, 'ICMP'),
    'IGMPv2': (2, message(b'\x16\x00', bytes([224, 0, 0, 9]) + b'trailing-octets!' * 2), 2, 'IGMPv2'),
    'IGMPv3': (2, message(b'\x22\x00', b'\x00\x00\x00\x02' + RECORD * 2), 2, 'IGMPv3'),
}


def ipv4(payload: bytes, proto: int, *, tso: bool) -> bytes:
    """An IPv4 packet carrying ``payload``, with a Total Length of 0 if ``tso``."""
    packet = bytearray(wire.ipv4(payload, proto=proto))
    if tso:
        packet[2:4] = packet[10:12] = b'\x00\x00'
        packet[10:12] = wire.checksum(bytes(packet[:20])).to_bytes(2, 'big')
    return bytes(packet)


def ah(nxt: int, payload: bytes) -> bytes:
    """An AH header of a 4-octet ICV, Payload Len 2 (RFC 4302 section 2.2), before ``payload``."""
    return bytes([nxt, 2, 0, 0]) + struct.pack('>II', 0x100, 1) + bytes(4) + payload


def frame(name: str, *, tso: bool = True, via_ah: bool = False, bad: bool = False,
          linktype: int = ETHERNET) -> bytes:
    """The frame of link type ``linktype`` carrying message ``name``."""
    proto, msg, at, _ = MESSAGES[name]
    if bad:
        msg = wrong(msg, at)
    packet = ipv4(ah(proto, msg), 51, tso=tso) if via_ah else ipv4(msg, proto, tso=tso)
    return wire.ethernet(packet, 0x0800) if linktype == ETHERNET else packet


def pcap(linktype: int, packet: bytes, original: int) -> bytes:
    """A PCAP savefile holding ``packet``, whose record says ``original`` octets were on the wire."""
    return (struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 0xFFFF, linktype)
            + struct.pack('<IIII', 1, 0, len(packet), original) + packet)


def block(kind: int, body: bytes) -> bytes:
    """A little-endian PCAP-NG block of ``kind`` around ``body``, padded to 32 bits."""
    body += bytes(-len(body) % 4)
    size = 12 + len(body)
    return struct.pack('<II', kind, size) + body + struct.pack('<I', size)


def pcapng(linktype: int, packet: bytes, original: int) -> bytes:
    """A PCAP-NG file of one interface and one Enhanced Packet Block holding ``packet``."""
    shb = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    idb = block(1, struct.pack('<HHI', linktype, 0, 0xFFFF))
    return shb + idb + block(6, struct.pack('<IIIII', 0, 0, 0, len(packet), original) + packet)


class TSOCutChecksumTests(unittest.TestCase):
    """The frame's original length tells a short TSO capture from a wrong checksum."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        import pcapkit
        from pcapkit.corekit.checksum.internet import ChecksumStatus
        from pcapkit.utilities import config
        from pcapkit.utilities.warnings import ChecksumWarning

        self.pcapkit = pcapkit
        self.Status = ChecksumStatus
        self.config = config
        self.ChecksumWarning = ChecksumWarning

    def extract(self, capture: bytes) -> 'tuple[Any, list[str]]':
        """The first frame of ``capture``, and the checksum warnings reading it gave."""
        with mock.patch.object(self.config, 'CHECKSUM_VERIFY', True), \
                warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            first = self.pcapkit.extract(fin=io.BytesIO(capture), nofile=True).frame[0]
        return first, [str(item.message) for item in caught
                       if issubclass(item.category, self.ChecksumWarning)]

    def status(self, packet: bytes, original: int, layer: str, *,
               write: 'Writer' = pcap, linktype: int = ETHERNET) -> 'tuple[Any, list[str]]':
        """The checksum status ``layer`` reads, :data:`None` if it did not parse, and the warnings."""
        first, caught = self.extract(write(linktype, packet, original))
        if layer not in first:
            return None, caught
        return first[layer].info.checksum_status, caught

    def test_every_cut_reads_truncated(self) -> None:
        for name, (_, msg, _, layer) in MESSAGES.items():
            for via_ah in (False, True):
                for bad in (False, True):
                    whole = frame(name, via_ah=via_ah, bad=bad)
                    for cut in range(1, len(msg)):
                        with self.subTest(message=name, ah=via_ah, bad=bad, cut=cut):
                            status, caught = self.status(whole[:-cut], len(whole), layer)
                            self.assertEqual(caught, [])
                            # A cut into the fixed header leaves the octets as Raw.
                            if cut <= len(msg) - HEADER:
                                self.assertIs(status, self.Status.TRUNCATED)
                            else:
                                self.assertIn(status, (None, self.Status.TRUNCATED))

    def test_pcapng_and_raw_ipv4_hand_the_cut_down_too(self) -> None:
        writers = {'pcap': pcap, 'pcapng': pcapng}
        for name, (_, _, _, layer) in MESSAGES.items():
            for (label, write), linktype in ((item, link) for item in writers.items()
                                             for link in (ETHERNET, RAW_IPV4)):
                for via_ah in (False, True):
                    whole = frame(name, via_ah=via_ah, bad=True, linktype=linktype)
                    with self.subTest(message=name, capture=label, linktype=linktype, ah=via_ah):
                        self.assertEqual(self.status(whole[:-CUT], len(whole), layer,
                                                     write=write, linktype=linktype),
                                         (self.Status.TRUNCATED, []))

    def test_complete_messages_are_verified(self) -> None:
        for name, (_, _, _, layer) in MESSAGES.items():
            for tso in (True, False):
                for via_ah in (False, True):
                    with self.subTest(message=name, tso=tso, ah=via_ah):
                        good = frame(name, tso=tso, via_ah=via_ah)
                        self.assertEqual(self.status(good, len(good), layer), (self.Status.VALID, []))
                        bad = frame(name, tso=tso, via_ah=via_ah, bad=True)
                        status, caught = self.status(bad, len(bad), layer)
                        self.assertIs(status, self.Status.INVALID)
                        self.assertEqual(len(caught), 1)
                        self.assertRegex(caught[0], rf'^{layer}: checksum 0x[0-9a-f]{{4}} is wrong;')

    def test_a_declared_total_length_reads_its_own_cut(self) -> None:
        # The control: the length IPv4 declares gives TRUNCATED on its own.
        for name, (_, _, _, layer) in MESSAGES.items():
            for via_ah in (False, True):
                whole = frame(name, tso=False, via_ah=via_ah, bad=True)
                with self.subTest(message=name, ah=via_ah):
                    self.assertEqual(self.status(whole[:-CUT], len(whole), layer),
                                     (self.Status.TRUNCATED, []))

    def test_only_a_layer_declaring_no_length_hands_the_cut_on(self) -> None:
        from pcapkit.corekit.checksum import internet as checksum
        from pcapkit.utilities.contextvars import frame_length

        seen = []  # type: list[object]
        verify = checksum.verify_message

        def spy(*args: 'Any', **kwargs: 'Any') -> 'Any':
            seen.append(frame_length.get())
            return verify(*args, **kwargs)

        _, msg, _, _ = MESSAGES['ICMP']
        cases = {
            'Total Length 0': (frame('ICMP'), True),
            'Total Length 0, then AH': (frame('ICMP', via_ah=True), True),
            'Total Length declared': (frame('ICMP', tso=False), False),
            'Total Length declared, then AH': (frame('ICMP', tso=False, via_ah=True), False),
            # The inner IPv4 declares the length, so it clears what the outer handed on.
            'Total Length 0, then IPv4 declaring one': (
                wire.ethernet(ipv4(ipv4(msg, 1, tso=False), 4, tso=True), 0x0800), False),
        }
        for name, (whole, kept) in cases.items():
            with self.subTest(case=name), mock.patch.object(checksum, 'verify_message', spy):
                seen.clear()
                self.extract(pcap(ETHERNET, whole[:-CUT], len(whole)))
                self.assertEqual(seen, [(len(whole) - CUT, len(whole)) if kept else None])
        self.assertIsNone(frame_length.get())

    def test_parse_rebuild_is_exact(self) -> None:
        from pcapkit.protocols.misc.pcap.frame import Frame

        for name, (_, msg, _, layer) in MESSAGES.items():
            for via_ah in (False, True):
                whole = frame(name, via_ah=via_ah, bad=True)
                for cut in (1, CUT, len(msg) - HEADER):
                    capture = pcap(ETHERNET, whole[:-cut], len(whole))
                    with self.subTest(message=name, ah=via_ah, cut=cut):
                        parsed, _ = self.extract(capture)
                        with mock.patch.object(self.config, 'CHECKSUM_VERIFY', True), \
                                warnings.catch_warnings(record=True) as caught:
                            warnings.simplefilter('always')
                            rebuilt = Frame.from_data(parsed.info, num=parsed.info.number,
                                                      header=parsed.header)
                        self.assertEqual(rebuilt.data, capture[24:])
                        # The rebuilt frame hands its lengths down as the parsed one did.
                        self.assertEqual(rebuilt[layer].info.checksum_status, self.Status.TRUNCATED)
                        self.assertEqual([item.category for item in caught
                                          if issubclass(item.category, self.ChecksumWarning)], [])


if __name__ == '__main__':
    unittest.main()
