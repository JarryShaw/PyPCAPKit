# -*- coding: utf-8 -*-
"""A GRE frame the capture cut short reads ``TRUNCATED``, not ``INVALID``.

GitHub issue #2653: neither the GRE header nor the Linux cooked-capture header in
front of it states a length, so :meth:`GRE.read <pcapkit.protocols.link.gre.GRE.read>`
cannot tell from its own octets a frame the snapshot length cut short from one whose
checksum is wrong. The record's original length tells them apart, as Wireshark's
captured length against its reported one does:
:class:`~pcapkit.protocols.misc.pcap.frame.Frame` and
:class:`~pcapkit.protocols.misc.pcapng.PCAPNG` set
:data:`~pcapkit.utilities.contextvars.frame_length` around the parse of their
payload, and GRE reads it. A complete frame whose checksum is wrong stays
``INVALID`` and warns.

Each capture is built here and read through :func:`pcapkit.extract`: PCAP, and
PCAP-NG's Enhanced, Simple and obsolete Packet Blocks, each over ``LINUX_SLL`` and
``LINUX_SLL2``. This module is unit-tier and reads no capture file.

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

#: ``LINKTYPE_LINUX_SLL`` and ``LINKTYPE_LINUX_SLL2``.
LINUX_SLL, LINUX_SLL2 = 113, 276
#: ``ARPHRD_IPGRE``, which both cooked-capture headers dispatch to GRE.
ARPHRD_IPGRE = 778
#: The octets the capture cuts off the end of each frame.
CUT = 4


def gre(payload: bytes, *, checksum: 'int | None' = None, protocol: int = 0x0800) -> bytes:
    """A GRE header with ``C`` set, carrying ``payload`` of EtherType ``protocol``, IPv4 by default.

    ``checksum`` is the field's value, the right one by default.

    """
    head = struct.pack('>HH', 0x8000, protocol)
    if checksum is None:
        checksum = wire.checksum(head + bytes(4) + payload)
    return head + struct.pack('>HH', checksum, 0) + payload


def sll(linktype: int, frame: bytes) -> bytes:
    """``frame`` behind a cooked-capture header of ``linktype`` naming ``ARPHRD_IPGRE``."""
    if linktype == LINUX_SLL:
        return struct.pack('>HHH', 0, ARPHRD_IPGRE, 0) + bytes(8) + struct.pack('>H', 0x0800) + frame
    return struct.pack('>HHIHBB', 0x0800, 0, 1, ARPHRD_IPGRE, 0, 0) + bytes(8) + frame


def pcap(linktype: int, packet: bytes, original: int) -> bytes:
    """A PCAP savefile holding ``packet``, whose record says ``original`` octets were on the wire."""
    return (struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 0xFFFF, linktype)
            + struct.pack('<IIII', 1, 0, len(packet), original) + packet)


def block(kind: int, body: bytes) -> bytes:
    """A little-endian PCAP-NG block of ``kind`` around ``body``, padded to 32 bits."""
    body += bytes(-len(body) % 4)
    size = 12 + len(body)
    return struct.pack('<II', kind, size) + body + struct.pack('<I', size)


def epb(packet: bytes, original: int) -> bytes:
    """An Enhanced Packet Block holding ``packet`` of ``original`` octets on the wire."""
    return block(6, struct.pack('<IIIII', 0, 0, 0, len(packet), original) + packet)


def spb(packet: bytes, original: int) -> bytes:
    """A Simple Packet Block holding ``packet`` of ``original`` octets on the wire."""
    return block(3, struct.pack('<I', original) + packet)


def packet_block(packet: bytes, original: int) -> bytes:
    """An obsolete Packet Block holding ``packet`` of ``original`` octets on the wire."""
    return block(2, struct.pack('<HHIIII', 0, 0, 0, 0, len(packet), original) + packet)


def pcapng(maker: 'Callable[[bytes, int], bytes]') -> 'Writer':
    """A writer of PCAP-NG files of one interface and one packet block that ``maker`` builds."""
    def write(linktype: int, packet: bytes, original: int) -> bytes:
        shb = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        idb = block(1, struct.pack('<HHI', linktype, 0, 0xFFFF))
        return shb + idb + maker(packet, original)
    return write


#: The datagram GRE carries: IPv4 and UDP, whose eight octets of data the cut ends inside.
DATAGRAM = wire.ipv4(wire.udp(b'payload!'))
#: GRE with a right checksum, and with one that is wrong.
GOOD = gre(DATAGRAM)
BAD = gre(DATAGRAM, checksum=int.from_bytes(GOOD[4:6], 'big') ^ 0x0101)
#: The warning :data:`BAD` gives when it is complete.
WRONG = (f'GRE: checksum {int.from_bytes(BAD[4:6], "big"):#06x} is wrong; '
         f'{int.from_bytes(GOOD[4:6], "big"):#06x} expected')

#: GRE short enough that IPv4 carrying it needs Ethernet padding: four octets of
#: EtherType ``0x88B5``, local experimental, which no layer is registered for.
SHORT_GOOD = gre(b'tiny', protocol=0x88B5)
SHORT_BAD = gre(b'tiny', protocol=0x88B5, checksum=int.from_bytes(SHORT_GOOD[4:6], 'big') ^ 0x0101)
#: The warning :data:`SHORT_BAD` gives when it is complete.
SHORT_WRONG = (f'GRE: checksum {int.from_bytes(SHORT_BAD[4:6], "big"):#06x} is wrong; '
               f'{int.from_bytes(SHORT_GOOD[4:6], "big"):#06x} expected')


def behind_ip(version: int, message: bytes) -> 'tuple[bytes, int]':
    """``message`` in an IPv4 or IPv6 datagram in an Ethernet frame, and where the datagram ends.

    The frame is padded to the 60-octet minimum, or given a 4-octet trailer when
    it is longer, so that octets follow the datagram for a capture to cut.

    """
    if version == 4:
        frame = wire.ethernet(wire.ipv4(message, proto=47), 0x0800)
    else:
        frame = wire.ethernet(wire.ipv6(message, nxt=47), 0x86DD)
    return frame + bytes(max(60 - len(frame), 4)), len(frame)


class GRESnaplenCutTests(unittest.TestCase):
    """A frame's original length tells GRE a short capture from a wrong checksum."""

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

    def extract(self, capture: bytes, *, verify: bool = True) -> 'tuple[Any, list[str]]':
        """The first frame of ``capture``, and the checksum warnings reading it gave."""
        with mock.patch.object(self.config, 'CHECKSUM_VERIFY', verify), \
                warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            frame = self.pcapkit.extract(fin=io.BytesIO(capture), nofile=True).frame[0]
        return frame, [str(item.message) for item in caught
                       if issubclass(item.category, self.ChecksumWarning)]

    def assertCutReadsTruncated(self, write: 'Writer') -> None:  # pylint: disable=invalid-name
        """Every case over both cooked-capture headers, as ``write`` puts them in a capture."""
        for linktype, link in ((LINUX_SLL, 'LINUX_SLL1'), (LINUX_SLL2, 'LINUX_SLL2')):
            good, bad = sll(linktype, GOOD), sll(linktype, BAD)
            cases = {
                'cut, right checksum': (good[:-CUT], len(good), self.Status.TRUNCATED, []),
                'cut, wrong checksum': (bad[:-CUT], len(bad), self.Status.TRUNCATED, []),
                'complete, right checksum': (good, len(good), self.Status.VALID, []),
                'complete, wrong checksum': (bad, len(bad), self.Status.INVALID, [WRONG]),
            }
            for name, (packet, original, status, messages) in cases.items():
                with self.subTest(linktype=linktype, case=name):
                    frame, caught = self.extract(write(linktype, packet, original))
                    # The payload parses whatever the status; UDP port 9 leaves its data as Raw.
                    self.assertEqual(frame.protochain.chain, f'{link}:GRE:IPv4:UDP:Raw')
                    self.assertEqual((frame['GRE'].info.checksum_status, caught), (status, messages))
                    # Off, nothing is verified, cut or not.
                    frame, caught = self.extract(write(linktype, packet, original), verify=False)
                    self.assertEqual((frame['GRE'].info.get('checksum_status'), caught), (None, []))

    def test_pcap(self) -> None:
        self.assertCutReadsTruncated(pcap)

    def test_pcapng_enhanced_packet_block(self) -> None:
        self.assertCutReadsTruncated(pcapng(epb))

    def test_pcapng_simple_packet_block(self) -> None:
        self.assertCutReadsTruncated(pcapng(spb))

    def test_pcapng_obsolete_packet_block(self) -> None:
        self.assertCutReadsTruncated(pcapng(packet_block))

    def test_an_original_length_below_the_captured_one_cuts_nothing(self) -> None:
        # An ``orig_len`` smaller than ``incl_len`` is malformed, not a cut.
        packet = sll(LINUX_SLL, GOOD)
        for name, write in (('pcap', pcap), ('epb', pcapng(epb)), ('pb', pcapng(packet_block))):
            with self.subTest(capture=name):
                frame, caught = self.extract(write(LINUX_SLL, packet, len(packet) - CUT))
                self.assertEqual((frame['GRE'].info.checksum_status, caught), (self.Status.VALID, []))
        # A cut one reads as cut.
        frame, caught = self.extract(pcap(LINUX_SLL, packet[:-CUT], len(packet)))
        self.assertEqual((frame['GRE'].info.checksum_status, caught), (self.Status.TRUNCATED, []))

    def test_the_lengths_reach_the_layers_below_the_frame_only(self) -> None:
        from pcapkit.protocols.link.gre import GRE
        from pcapkit.utilities.contextvars import frame_length

        seen = []  # type: list[object]
        read = GRE.read

        def spy(layer: 'Any', *args: 'Any', **kwargs: 'Any') -> 'Any':
            seen.append(frame_length.get())
            return read(layer, *args, **kwargs)

        packet = sll(LINUX_SLL2, BAD)
        with mock.patch.object(GRE, 'read', spy):
            self.extract(pcap(LINUX_SLL2, packet[:-CUT], len(packet)))
            self.extract(pcapng(epb)(LINUX_SLL2, packet[:-CUT], len(packet)))
            self.extract(pcapng(spb)(LINUX_SLL2, packet[:-CUT], len(packet)))
        self.assertEqual(seen, [(len(packet) - CUT, len(packet))] * 3)
        self.assertIsNone(frame_length.get())

        # Outside a frame, GRE verifies the octets it holds.
        with mock.patch.object(self.config, 'CHECKSUM_VERIFY', True), \
                warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            layer = GRE(BAD[:-CUT])
        self.assertIs(layer.info.checksum_status, self.Status.INVALID)
        self.assertEqual([item.category for item in caught], [self.ChecksumWarning])

    def test_parse_rebuild_is_exact(self) -> None:
        from pcapkit.protocols.misc.pcap.frame import Frame

        def rebuild(frame: 'Any') -> 'tuple[Any, list[type]]':
            """``frame`` rebuilt from its data model, and the checksum warnings that gave."""
            if isinstance(frame, Frame):
                kwargs = {'num': frame.info.number, 'header': frame.header}  # type: dict[str, Any]
            else:
                kwargs = {'num': frame.info.number, 'sct': frame.info.section_number,
                          'ctx': frame._ctx}  # pylint: disable=protected-access
            with mock.patch.object(self.config, 'CHECKSUM_VERIFY', True), \
                    warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter('always')
                rebuilt = type(frame).from_data(frame.info, **kwargs)
            return rebuilt, [item.category for item in caught
                             if issubclass(item.category, self.ChecksumWarning)]

        for linktype in (LINUX_SLL, LINUX_SLL2):
            packet = sll(linktype, BAD)
            capture = pcap(linktype, packet[:-CUT], len(packet))
            cases = {'pcap': (capture, capture[24:]),
                     'pcapng': (pcapng(epb)(linktype, packet[:-CUT], len(packet)),
                                epb(packet[:-CUT], len(packet)))}
            for name, (capture, record) in cases.items():
                with self.subTest(linktype=linktype, capture=name):
                    self.assertTrue(capture.endswith(record))
                    frame, _ = self.extract(capture)
                    rebuilt, caught = rebuild(frame)
                    self.assertEqual(rebuilt.data, record)
                    # The rebuilt frame hands its lengths down as the parsed one did.
                    self.assertEqual((rebuilt['GRE'].info.checksum_status, caught),
                                     (self.Status.TRUNCATED, []))


class GREBehindIPTests(GRESnaplenCutTests):
    """Behind IP, GRE verifies over the length the IP layer declares, not the frame's.

    :class:`~pcapkit.protocols.internet.internet.Internet` clears
    :data:`~pcapkit.utilities.contextvars.frame_length` around its payload's parse,
    so octets the capture cut off past the datagram are none of GRE's. No shipped
    registry binds IP protocol 47 to GRE, so each test registers it with
    :func:`~pcapkit.foundation.registry.protocols.internet.register_transtype` and
    puts the registry back afterwards.

    """

    # NOTE: The inherited tests run here too, with GRE also bound under IP; they
    # carry no IP layer, so they read as they do on the class above.

    def setUp(self) -> None:
        super().setUp()
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.foundation.registry import register_transtype
        from pcapkit.protocols.internet.internet import Internet
        from pcapkit.protocols.link.gre import GRE

        previous = Internet.__proto__.get(TransType.GRE)
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            register_transtype(TransType.GRE, GRE)

        def restore() -> None:
            if previous is None:
                Internet.__proto__.pop(TransType.GRE, None)
            else:
                Internet.__proto__[TransType.GRE] = previous
        self.addCleanup(restore)

    def assertBehindIPReads(self, write: 'Writer') -> None:  # pylint: disable=invalid-name
        """Every case behind IPv4 and IPv6, as ``write`` puts them in an Ethernet capture."""
        for version, network in ((4, 'IPv4'), (6, 'IPv6')):
            good, end = behind_ip(version, SHORT_GOOD)
            bad, _ = behind_ip(version, SHORT_BAD)
            cases = {
                'padding cut in part': (good[:end + 2], len(good), self.Status.VALID, []),
                'padding cut whole': (good[:end], len(good), self.Status.VALID, []),
                'cut inside the datagram': (good[:end - 2], len(good), self.Status.TRUNCATED, []),
                'cut inside, wrong checksum': (bad[:end - 2], len(bad), self.Status.TRUNCATED, []),
                'complete': (good, len(good), self.Status.VALID, []),
                'complete, wrong checksum': (bad, len(bad), self.Status.INVALID, [SHORT_WRONG]),
            }
            for name, (packet, original, status, messages) in cases.items():
                with self.subTest(network=network, case=name):
                    frame, caught = self.extract(write(1, packet, original))
                    # GRE's payload is Raw, named after its EtherType.
                    self.assertEqual(frame.protochain.chain.split(':')[:3], ['Ethernet', network, 'GRE'])
                    self.assertEqual((frame['GRE'].info.checksum_status, caught), (status, messages))

    def test_pcap_behind_ip(self) -> None:
        self.assertBehindIPReads(pcap)

    def test_pcapng_behind_ip(self) -> None:
        self.assertBehindIPReads(pcapng(epb))

    def test_the_lengths_are_cleared_behind_ip(self) -> None:
        from pcapkit.protocols.link.gre import GRE
        from pcapkit.utilities.contextvars import frame_length

        seen = []  # type: list[object]
        read = GRE.read

        def spy(layer: 'Any', *args: 'Any', **kwargs: 'Any') -> 'Any':
            seen.append(frame_length.get())
            return read(layer, *args, **kwargs)

        packet, end = behind_ip(4, SHORT_GOOD)
        with mock.patch.object(GRE, 'read', spy):
            self.extract(pcap(1, packet[:end], len(packet)))
            self.extract(pcap(LINUX_SLL, sll(LINUX_SLL, GOOD)[:-CUT], len(sll(LINUX_SLL, GOOD))))
        self.assertEqual(seen, [None, (len(sll(LINUX_SLL, GOOD)) - CUT, len(sll(LINUX_SLL, GOOD)))])
        self.assertIsNone(frame_length.get())


if __name__ == '__main__':
    unittest.main()
