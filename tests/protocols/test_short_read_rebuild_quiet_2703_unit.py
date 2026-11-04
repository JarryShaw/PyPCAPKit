# -*- coding: utf-8 -*-
"""A layer rebuilt from a short read verifies as its capture did, quietly.

GitHub issue #2703: were :meth:`Protocol.from_data
<pcapkit.protocols.protocol.Protocol.from_data>` to parse and verify a header the capture cut
short at full width, the missing octets as the zeros they were read as, before cutting it
back to what was captured, a layer that verifies a checksum during its parse would read the
zero-filled one as ``INVALID`` and warn, where its capture read ``TRUNCATED`` and did not.
So the header is cut back through its own ``__short_read__`` before it is read, at the
width it declares, as its capture was.

Each layer below that verifies during its parse is cut at every octet that leaves it a
short read: GRE, IGMPv1, IGMPv2, IGMPv3 and OSPF built on the octets, and ICMP and IGMPv3
read from a PCAP savefile, since a capture keeps the cut header of the others as raw
octets. Its rebuild from the data model and from the :obj:`dict` must give the octets
captured and the checksum status read, and report nothing, on the :mod:`warnings` channel
or the ``pcapkit`` logger. Whole messages are the control: they verify on rebuild, and one
with a wrong checksum warns as its parse did.

The octets and captures are built here; this module is unit-tier and reads no capture file.

"""
from __future__ import annotations

import contextlib
import io
import logging
import struct
import unittest
import warnings
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import reimport_once_per_class
from tests.foundation import _roundtrip as wire

if TYPE_CHECKING:
    from typing import Any, Callable, Iterator

#: Test tier (#1958): hand-picked parse -> rebuild round trips.
__tier__ = 'ALL'


def message(head: bytes, rest: bytes) -> bytes:
    """``head``, then the checksum over the whole message, then ``rest``."""
    return head + wire.checksum(head + b'\x00\x00' + rest).to_bytes(2, 'big') + rest


def gre(flags: int, extra: bytes) -> bytes:
    """A GRE message with ``flags`` and the Key and Sequence Number ``extra``, checksummed."""
    head, body = struct.pack('>HH', flags, 0x88B5), extra + b'twenty-octet-payload'
    value = wire.checksum(head + bytes(4) + body)
    return head + struct.pack('>HH', value, 0) + body


def ospf() -> bytes:
    """An OSPFv2 packet of its 24-octet header alone, with Null authentication.

    The checksum covers the packet but its 8-octet Authentication field (:rfc:`2328`).

    """
    head = struct.pack('>BBH4s4s', 2, 1, 24, bytes([192, 0, 2, 1]), bytes(4))
    tail = struct.pack('>H', 0) + b'auth-key'
    return head + wire.checksum(head + b'\x00\x00' + tail[:2]).to_bytes(2, 'big') + tail


def wrong(msg: bytes, at: int) -> bytes:
    """``msg`` with the checksum at ``at`` flipped in both octets."""
    return msg[:at] + (int.from_bytes(msg[at:at + 2], 'big') ^ 0x0101).to_bytes(2, 'big') + msg[at + 2:]


#: A group record of type MODE_IS_INCLUDE for 239.1.1.1 with one source, 10.0.0.1.
RECORD = bytes.fromhex('01000001ef0101010a000001')

#: Each message built on its octets: the module and class it is read as, its octets,
#: where its checksum sits, and the cuts that leave its header a short read. Shorter
#: than eight octets, an IGMPv3 Query is refused by its class, which classifies a
#: Query by its length. A Report cut after its header or its first group record ends
#: on a whole field, before the records its count declares, which reads short (#2711).
DIRECT = {
    'GRE C': ('link.gre.protocol', 'GRE', gre(0x8000, b''), 4, range(1, 8)),
    'GRE C, K, S': ('link.gre.protocol', 'GRE', gre(0xB000, struct.pack('>II', 0x11223344, 7)), 4, range(1, 16)),
    'IGMPv1 report': ('internet.igmpv1.protocol', 'IGMPv1', message(b'\x12\x00', bytes([224, 0, 0, 1])), 2, range(1, 8)),
    'IGMPv2 leave': ('internet.igmpv2.protocol', 'IGMPv2', message(b'\x17\x00', bytes([239, 1, 2, 3])), 2, range(1, 8)),
    'IGMPv3 report': ('internet.igmpv3.protocol', 'IGMPv3', message(b'\x22\x00', bytes.fromhex('00000002') + RECORD * 2),
                      2, range(1, 32)),
    'IGMPv3 query': ('internet.igmpv3.protocol', 'IGMPv3', message(b'\x11\x64', bytes(4) + bytes.fromhex('027d00010a000001')),
                     2, range(12, 16)),
    'OSPFv2': ('application.ospf.protocol', 'OSPF', ospf(), 12, range(1, 24)),
}  # type: dict[str, tuple[str, str, bytes, int, Any]]

#: Each message read from a capture, behind Ethernet and IPv4: its IP protocol number,
#: its octets, where its checksum sits, and the name it is looked up by in the frame.
#: IPv4 declares the length, so a cut ends the message inside its own data.
CAPTURED = {
    'ICMP echo': (1, message(b'\x08\x00', b'\x00\x01\x00\x01' + b'echo-data-octets'), 2, 'ICMP'),
    'IGMPv3 report': (2, message(b'\x22\x00', bytes.fromhex('00000002') + RECORD * 2), 2, 'IGMPv3'),
}

#: Octets of the fixed header of each captured message, which a cut must leave
#: whole for the capture to keep it as its own layer.
HEADER = 8


def pcap(packet: bytes, original: int) -> bytes:
    """A PCAP savefile of one Ethernet frame holding ``packet`` of ``original`` octets on the wire."""
    return (struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 0xFFFF, 1)
            + struct.pack('<IIII', 1, 0, len(packet), original) + packet)


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


class ShortReadRebuildTests(unittest.TestCase):
    """A rebuilt short read is read and verified as its capture was."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        import importlib

        import pcapkit
        from pcapkit.corekit.checksum.internet import ChecksumStatus
        from pcapkit.utilities import config

        self.pcapkit = pcapkit
        self.Status = ChecksumStatus
        self.classes = {
            label: getattr(importlib.import_module(f'pcapkit.protocols.{module}'), name)
            for label, (module, name, *_) in DIRECT.items()
        }
        patch = mock.patch.object(config, 'CHECKSUM_VERIFY', True)
        patch.start()
        self.addCleanup(patch.stop)

    def parse(self, build: 'Callable[[], Any]') -> 'tuple[Any, list[str]]':
        """What ``build`` returns, and what it reported."""
        with _reported() as messages:
            layer = build()
        return layer, messages

    def direct(self, label: str, data: bytes) -> 'tuple[Any, list[str]]':
        """``data`` read as the class of message ``label``."""
        return self.parse(lambda: self.classes[label](data, len(data)))

    def captured(self, label: str, cut: int) -> 'tuple[Any, list[str]]':
        """Message ``label`` read from a capture that holds all but ``cut`` octets of its frame."""
        proto, msg, _, name = CAPTURED[label]
        whole = wire.ethernet(wire.ipv4(msg, proto=proto), 0x0800)
        frame, messages = self.parse(lambda: self.pcapkit.extract(
            fin=io.BytesIO(pcap(whole[:len(whole) - cut], len(whole))), nofile=True).frame[0])
        return frame[name], messages

    def assertRebuildsAsParsed(self, layer: 'Any') -> 'None':  # pylint: disable=invalid-name
        """``layer`` rebuilt from its data model and its dict: its octets, its status, and nothing reported."""
        for path, data in (('model', layer.info), ('dict', layer.info.to_dict())):
            with self.subTest(path=path):
                rebuilt, messages = self.parse(lambda: type(layer).from_data(data))  # pylint: disable=cell-var-from-loop
                self.assertEqual((rebuilt.data.hex(), rebuilt.info.checksum_status, messages),
                                 (layer.data.hex(), layer.info.checksum_status, []))

    def test_a_cut_header_built_on_its_octets_rebuilds_quietly(self) -> None:
        for label, (_, _, msg, _, cuts) in DIRECT.items():
            for count in cuts:
                with self.subTest(message=label, captured=count):
                    layer, _ = self.direct(label, msg[:count])
                    self.assertIsNotNone(layer.info.get('__short_read__'))
                    self.assertEqual(layer.data, msg[:count])
                    self.assertRebuildsAsParsed(layer)

    def test_a_cut_message_read_from_a_capture_rebuilds_quietly(self) -> None:
        for label, (_, msg, _, _) in CAPTURED.items():
            for cut in range(1, len(msg) - HEADER + 1):
                with self.subTest(message=label, cut=cut):
                    layer, messages = self.captured(label, cut)
                    self.assertIsNotNone(layer.info.get('__short_read__'))
                    self.assertIs(layer.info.checksum_status, self.Status.TRUNCATED)
                    self.assertNotRegex(' '.join(messages), r'checksum 0x[0-9a-f]{4} is wrong;')
                    self.assertRebuildsAsParsed(layer)

    def test_a_cut_header_still_reads_truncated(self) -> None:
        # Where the cut leaves part of what the checksum covers uncaptured; an
        # OSPF header cut in its Authentication field leaves all of it captured.
        for label, (_, _, msg, _, cuts) in DIRECT.items():
            for count in cuts:
                with self.subTest(message=label, captured=count):
                    layer, _ = self.direct(label, msg[:count])
                    expected = self.Status.VALID if label == 'OSPFv2' and count >= 16 else self.Status.TRUNCATED
                    self.assertIs(layer.info.checksum_status, expected)

    def test_a_whole_message_rebuilds_verified(self) -> None:
        for label, (_, _, msg, _, _) in DIRECT.items():
            with self.subTest(message=label):
                layer, messages = self.direct(label, msg)
                self.assertIsNone(layer.info.get('__short_read__'))
                self.assertEqual((layer.info.checksum_status, messages), (self.Status.VALID, []))
                self.assertRebuildsAsParsed(layer)
        for label in CAPTURED:
            with self.subTest(message=label, captured=True):
                layer, _ = self.captured(label, 0)
                self.assertIs(layer.info.checksum_status, self.Status.VALID)
                self.assertRebuildsAsParsed(layer)

    def test_a_wrong_checksum_warns_on_rebuild_as_on_parse(self) -> None:
        for label, (_, _, msg, at, _) in DIRECT.items():
            with self.subTest(message=label):
                layer, parsed = self.direct(label, wrong(msg, at))
                self.assertIs(layer.info.checksum_status, self.Status.INVALID)
                for path, data in (('model', layer.info), ('dict', layer.info.to_dict())):
                    with self.subTest(path=path):
                        rebuilt, messages = self.parse(lambda: type(layer).from_data(data))  # pylint: disable=cell-var-from-loop
                        self.assertEqual((rebuilt.data, rebuilt.info.checksum_status), (layer.data, self.Status.INVALID))
                        self.assertEqual(messages, parsed)
                        self.assertRegex(' '.join(messages), r'checksum 0x[0-9a-f]{4} is wrong;')

    def test_a_rebuilt_instance_keeps_no_short_read_of_its_own(self) -> None:
        # The record is handed to the construction alone, so afterwards the
        # instance reads the class-level None, as one built directly does.
        msg = DIRECT['GRE C'][2]
        for count in (6, len(msg)):
            layer, _ = self.direct('GRE C', msg[:count])
            for path, data in (('model', layer.info), ('dict', layer.info.to_dict())):
                with self.subTest(captured=count, path=path):
                    rebuilt, _ = self.parse(lambda: type(layer).from_data(data))  # pylint: disable=cell-var-from-loop
                    self.assertEqual(rebuilt.data, msg[:count])
                    self.assertEqual({'__short_read__', '_uncaptured'} & set(vars(rebuilt)), set())
                    self.assertIsNone(rebuilt.__short_read__)

    def test_a_failed_rebuild_keeps_no_short_read_either(self) -> None:
        from pcapkit.utilities.exceptions import CaughtByCaller, ProtocolError

        gre, msg = self.classes['GRE C'], DIRECT['GRE C'][2]
        layer, _ = self.direct('GRE C', msg[:6])
        self.assertIsNotNone(layer.info.get('__short_read__'))
        built = []  # type: list[Any]
        pack = gre.pack

        def recorded(proto: 'Any', **kwargs: 'Any') -> bytes:
            built.append(proto)
            return pack(proto, **kwargs)

        broken = {
            # a count that is no count, which fails the cut in ``pack``
            'malformed record': ({**layer.info.to_dict(), '__short_read__': ('reserved1', 'two')}, TypeError),
            # a version GRE refuses, which fails ``read`` after the cut
            'parse error': ({**layer.info.to_dict(), 'version': 1}, ProtocolError),
        }
        for label, (data, error) in broken.items():
            with self.subTest(case=label), mock.patch.object(gre, 'pack', recorded), \
                    CaughtByCaller(ProtocolError), self.assertRaises(error):
                del built[:]
                gre.from_data(data)
            with self.subTest(case=label, check='instance'):
                self.assertEqual(len(built), 1)
                self.assertEqual({'__short_read__', '_uncaptured'} & set(vars(built[0])), set())
                self.assertIsNone(built[0].__short_read__)


if __name__ == '__main__':
    unittest.main()
