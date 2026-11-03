# -*- coding: utf-8 -*-
"""A rebuilt frame reports nothing its parse did not, and a new problem once.

GitHub issue #2711: rebuilding an outer layer with ``from_data`` rebuilds its payload
the same way, whose own parse went over the payload's octets and reported what they
carry; the outer layer then parsed those octets again and reported it all once more.
So Ethernet over IPv4 over a cut IGMPv3 Report logged every message of the Report
twice, where IPv4 alone logged it once. The payload's parse is now quiet, warnings and
the errors a next-layer fallback absorbs alike, since the outer layer's own parse
reports them.

Ethernet frames carrying an IGMPv3 Report over IPv4 and over IPv6 are cut at every
offset, read from their octets and from a PCAP savefile, and every layer is rebuilt
from its data model and its dict: it must give the octets parsed and report nothing
beyond what the parse reported, on the :mod:`warnings` channel or the ``pcapkit``
logger. A zero-fill ceiling low enough that the Report's in-frame parse raises gives
the errors. The controls are a wrong checksum, reported once on rebuild as on parse,
and a problem the parse never had, which the rebuild reports once.

The octets and captures are built here; this module is unit-tier and reads no capture file.

"""
from __future__ import annotations

import collections
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

#: A group record of type MODE_IS_INCLUDE for 239.1.1.1 with one source, 10.0.0.1.
RECORD = bytes.fromhex('01000001ef0101010a000001')


def message(head: bytes, rest: bytes) -> bytes:
    """``head``, then the checksum over the whole message, then ``rest``."""
    return head + wire.checksum(head + b'\x00\x00' + rest).to_bytes(2, 'big') + rest


#: An IGMPv3 Report of two group records.
REPORT = message(b'\x22\x00', bytes.fromhex('00000002') + RECORD * 2)

#: Each frame: Ethernet over IPv4, then over IPv6, carrying the Report as IP protocol 2.
FRAMES = {
    'IPv4': wire.ethernet(wire.ipv4(REPORT, proto=2), 0x0800),
    'IPv6': wire.ethernet(wire.ipv6(REPORT, nxt=2), 0x86DD),
}


def pcap(packet: bytes, original: int) -> bytes:
    """A PCAP savefile of one Ethernet frame holding ``packet`` of ``original`` octets on the wire."""
    return (struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 0xFFFF, 1)
            + struct.pack('<IIII', 1, 0, len(packet), original) + packet)


class _Logged(logging.Handler):
    """Collect what the ``pcapkit`` logger reports, with its level."""

    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.messages = []  # type: list[str]

    def emit(self, record: 'logging.LogRecord') -> None:
        self.messages.append(f'{record.levelname}: {record.getMessage()}')


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


def _layers(frame: 'Any') -> 'Iterator[Any]':
    """``frame`` and every layer it carries, NoPayload excluded."""
    layer = frame
    while type(layer).__name__ != 'NoPayload':
        yield layer
        layer = layer.payload


class RebuildReportsOnceTests(unittest.TestCase):
    """A rebuild reports what its octets carry once, and nothing the parse did not."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        import pcapkit
        from pcapkit.protocols.link.ethernet import Ethernet
        from pcapkit.utilities import config

        self.pcapkit = pcapkit
        self.Ethernet = Ethernet
        self.config = config
        patch = mock.patch.object(config, 'CHECKSUM_VERIFY', True)
        patch.start()
        self.addCleanup(patch.stop)

    def parse(self, build: 'Callable[[], Any]') -> 'tuple[Any, list[str]]':
        """What ``build`` returns, and what it reported."""
        with _reported() as messages:
            layer = build()
        return layer, messages

    def cuts(self) -> 'Iterator[tuple[str, str, Any, list[str]]]':
        """Every frame cut at every offset, read from its octets and from a savefile."""
        for label, whole in FRAMES.items():
            for cut in range(len(whole)):
                data = whole[:len(whole) - cut]
                frame, messages = self.parse(lambda: self.Ethernet(data, len(data)))  # pylint: disable=cell-var-from-loop
                yield label, f'octets, cut {cut}', frame, messages
                frame, messages = self.parse(lambda: self.pcapkit.extract(  # pylint: disable=cell-var-from-loop
                    fin=io.BytesIO(pcap(data, len(whole))), nofile=True).frame[0].payload)
                yield label, f'savefile, cut {cut}', frame, messages

    def assertRebuildsWithin(self, frame: 'Any', parsed: 'list[str]') -> 'None':  # pylint: disable=invalid-name
        """Every layer of ``frame`` rebuilds its octets, reporting nothing ``parsed`` lacks."""
        for layer in _layers(frame):
            for path, data in (('model', layer.info), ('dict', layer.info.to_dict())):
                with self.subTest(layer=type(layer).__name__, path=path):
                    rebuilt, messages = self.parse(lambda: type(layer).from_data(data))  # pylint: disable=cell-var-from-loop
                    self.assertEqual(rebuilt.data, layer.data)
                    beyond = collections.Counter(messages) - collections.Counter(parsed)
                    self.assertEqual(sorted(beyond.elements()), [])

    def test_a_cut_frame_rebuilds_within_its_parse(self) -> None:
        for label, how, frame, parsed in self.cuts():
            with self.subTest(frame=label, read=how):
                self.assertRebuildsWithin(frame, parsed)

    def test_errors_a_fallback_absorbs_are_reported_once(self) -> None:
        # Too low a ceiling for the Report's records, zero-filled to the length IP
        # declares, so its parse inside the frame raises and becomes Raw.
        with mock.patch.object(self.config, 'MAX_ZERO_PAD_LENGTH', 8):
            seen = 0
            for label, how, frame, parsed in self.cuts():
                with self.subTest(frame=label, read=how):
                    self.assertRebuildsWithin(frame, parsed)
                seen += any(line.startswith('CRITICAL: FieldValueError') for line in parsed)
            self.assertTrue(seen)

    def test_a_wrong_checksum_is_reported_once_on_rebuild(self) -> None:
        bad = REPORT[:2] + (int.from_bytes(REPORT[2:4], 'big') ^ 0x0101).to_bytes(2, 'big') + REPORT[4:]
        for label, whole in (('IPv4', wire.ethernet(wire.ipv4(bad, proto=2), 0x0800)),
                             ('IPv6', wire.ethernet(wire.ipv6(bad, nxt=2), 0x86DD))):
            frame, parsed = self.parse(lambda: self.Ethernet(whole, len(whole)))  # pylint: disable=cell-var-from-loop
            self.assertRegex(' '.join(parsed), r'IGMPv3: checksum 0x[0-9a-f]{4} is wrong;')
            for layer in list(_layers(frame))[:2]:
                with self.subTest(frame=label, layer=type(layer).__name__):
                    rebuilt, messages = self.parse(lambda: type(layer).from_data(layer.info))  # pylint: disable=cell-var-from-loop
                    self.assertEqual((rebuilt.data, messages), (layer.data, parsed))

    def test_a_problem_new_to_the_rebuild_is_reported_once(self) -> None:
        for label, whole in FRAMES.items():
            frame, parsed = self.parse(lambda: self.Ethernet(whole, len(whole)))  # pylint: disable=cell-var-from-loop
            self.assertEqual(parsed, [])
            edited = frame.info.to_dict()
            report = edited[edited['__next_name__']]
            report = report[report['__next_name__']]
            report['checksum'] = b'\xbe\xef'
            with self.subTest(frame=label, problem='checksum'):
                _, messages = self.parse(lambda: self.Ethernet.from_data(edited))  # pylint: disable=cell-var-from-loop
                self.assertEqual(len(messages), 2)
                self.assertRegex(' '.join(messages), r'IGMPv3: checksum 0xbeef is wrong;')

            cut = whole[:len(whole) - 8]
            frame, parsed = self.parse(lambda: self.Ethernet(cut, len(cut)))  # pylint: disable=cell-var-from-loop
            self.assertNotRegex(' '.join(parsed), 'FieldValueError')
            with self.subTest(frame=label, problem='zero-fill ceiling'), \
                    mock.patch.object(self.config, 'MAX_ZERO_PAD_LENGTH', 8):
                _, messages = self.parse(lambda: self.Ethernet.from_data(frame.info))  # pylint: disable=cell-var-from-loop
                self.assertEqual([line.split(':')[0] for line in messages], ['CRITICAL', 'WARNING'])
                self.assertRegex(messages[0], r'^CRITICAL: FieldValueError: Field records declares')


if __name__ == '__main__':
    unittest.main()
