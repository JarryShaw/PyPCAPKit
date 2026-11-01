# -*- coding: utf-8 -*-
"""DTLS reassembly takes the IP/TCP shape (#2531).

``reassembly-integration.rst`` listed the ways DTLS reassembly still differed from
IP and TCP once #2528 routed it through the toolkit and the analysis:

* a reassembled message carried no ``packet``, where an IP or TCP datagram's is a
  :class:`~pcapkit.foundation.reassembly.data.data.Deferred` parse run on first
  read -- for DTLS, the decoding
  :func:`~pcapkit.foundation.analysis.dtls.dtls_handshake` does;
* :class:`~pcapkit.foundation.reassembly.dtls.DTLS` set no ``__protocol_type__``,
  so its protocol was looked up in the protocol registry by name.

Each case runs the default engine over a capture built in memory, as PCAP and as
PCAP-NG, and reads no sample capture.

"""

from __future__ import annotations

import pickle
import unittest
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import reimport_once_per_class
from tests.foundation.reassembly.test_dtls_handshake_reassembly_2440_unit import (
    _client_hello_body, _dtls_handshake, _dtls_record, _extract, _frame, _pcap, _pcapng, _split)

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): pickling, whose protocols differ by interpreter.
__tier__ = 'ALL'

#: A ``ClientHello`` body, the message the captures below fragment.
BODY = _client_hello_body(cookie=b'\xab\xcd\xef\x01')
#: Its message sequence number.
MESSAGE_SEQ = 4
#: The containers each case runs over.
CONTAINERS = (('pcap', _pcap), ('pcapng', _pcapng))


def _records(frags: 'list[tuple[int, int]]') -> 'list[bytes]':
    """One ``handshake`` record per ``(offset, length)`` fragment of :data:`BODY`."""
    return [_dtls_record(22, _dtls_handshake(1, BODY[fo:fo + length], message_seq=MESSAGE_SEQ,
                                             fragment_offset=fo, fragment_length=length,
                                             total_length=len(BODY)), seq=num)
            for num, (fo, length) in enumerate(frags, 1)]


#: The whole message, in two fragments.
COMPLETE = _records(_split(BODY, (len(BODY) // 2,)))
#: The first and last thirds only; the middle one is lost.
INCOMPLETE = [record for num, record in
              enumerate(_records(_split(BODY, (len(BODY) // 3, 2 * len(BODY) // 3)))) if num != 1]


def _held(datagram: 'Any') -> 'Any':
    """``datagram``'s ``packet`` as stored, without resolving it."""
    return datagram.__dict__[datagram.__map__.get('packet', 'packet')]


class DeferredPacketTests(unittest.TestCase):
    """A reassembled message's ``packet`` is ``dtls_handshake``'s result, deferred."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _datagram(self, write: 'Any', records: 'list[bytes]', **kwargs: 'Any') -> 'Any':
        extractor = _extract(self, write([_frame(record) for record in records]),
                             reassembly=True, dtls=True, **kwargs)
        datagram, = extractor.reassembly.dtls
        return datagram

    def test_a_complete_message_holds_a_deferred_decode(self) -> None:
        from pcapkit.const.tls.handshake_type import HandshakeType
        from pcapkit.foundation.reassembly.data.data import Deferred

        for container, write in CONTAINERS:
            with self.subTest(container=container):
                held = _held(self._datagram(write, COMPLETE))
                self.assertIsInstance(held, Deferred)
                self.assertEqual(held.proto, (HandshakeType.client_hello, len(BODY), MESSAGE_SEQ))
                self.assertEqual(held.payload, BODY)

    def test_reading_packet_decodes_as_dtls_handshake_does(self) -> None:
        from pcapkit.foundation.analysis import dtls_handshake
        from pcapkit.protocols.data.application.tls import ClientHello

        for container, write in CONTAINERS:
            with self.subTest(container=container):
                datagram = self._datagram(write, COMPLETE)
                packet = datagram.packet
                self.assertEqual(packet, dtls_handshake(datagram))
                self.assertIsInstance(packet.body, ClientHello)
                self.assertEqual(packet.body.cookie, b'\xab\xcd\xef\x01')
                self.assertEqual((packet.message_seq, packet.fragment_offset, packet.fragment_length,
                                  packet.is_fragmented), (MESSAGE_SEQ, 0, len(BODY), False))
                self.assertIs(datagram.packet, packet)
                self.assertEqual(datagram.to_dict()['packet'], packet.to_dict())

    def test_the_decode_runs_on_first_read_and_only_once(self) -> None:
        from pcapkit.protocols.application.dtls import DTLS

        for container, write in CONTAINERS:
            with self.subTest(container=container):
                with mock.patch.object(DTLS, 'read_handshake', wraps=DTLS.read_handshake) as decode:
                    datagram = self._datagram(write, COMPLETE)
                    self.assertIn('packet', datagram)
                    self.assertEqual(decode.call_count, 0)
                    datagram.packet  # pylint: disable=pointless-statement
                    datagram['packet']  # pylint: disable=pointless-statement
                    repr(datagram)
                self.assertEqual(decode.call_count, 1)

    def test_an_incomplete_message_has_no_packet(self) -> None:
        from pcapkit.foundation.analysis import dtls_handshake

        for container, write in CONTAINERS:
            for strict in (True, False):
                with self.subTest(container=container, strict=strict):
                    datagram = self._datagram(write, INCOMPLETE, reasm_strict=strict)
                    self.assertEqual(datagram.completed.name, 'PARTIAL')
                    self.assertIsInstance(datagram.body, tuple if strict else bytes)
                    self.assertIsNone(_held(datagram))
                    self.assertIsNone(datagram.packet)
                    self.assertIsNone(dtls_handshake(datagram))

    def test_a_deferred_datagram_pickles_and_still_decodes(self) -> None:
        from pcapkit.foundation.analysis import dtls_handshake
        from pcapkit.foundation.reassembly.data.data import Deferred

        for container, write in CONTAINERS:
            for protocol in range(pickle.HIGHEST_PROTOCOL + 1):
                with self.subTest(container=container, protocol=protocol):
                    datagram = self._datagram(write, COMPLETE)
                    restored = pickle.loads(pickle.dumps(datagram, protocol=protocol))
                    self.assertIsInstance(_held(restored), Deferred)
                    self.assertEqual(restored.packet, dtls_handshake(datagram))


class ProtocolTypeTests(unittest.TestCase):
    """The engine names its protocol itself, as the IP and TCP engines do."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_the_engine_declares_the_dtls_protocol(self) -> None:
        from pcapkit.protocols.application.dtls import DTLS

        for container, write in CONTAINERS:
            with self.subTest(container=container):
                extractor = _extract(self, write([_frame(record) for record in COMPLETE]),
                                     reassembly=True, dtls=True)
                engine = type(extractor._reasm.dtls)
                self.assertIs(vars(engine).get('__protocol_type__'), DTLS)
                self.assertIs(engine.protocol, DTLS)

    def test_the_protocol_survives_a_registry_without_it(self) -> None:
        """With no ``'DTLS'`` registered, a name lookup would answer ``Raw``."""
        import pcapkit.protocols
        from pcapkit.protocols.application.dtls import DTLS

        for container, write in CONTAINERS:
            with self.subTest(container=container):
                extractor = _extract(self, write([_frame(record) for record in COMPLETE]),
                                     reassembly=True, ip=True, tcp=True, dtls=True)
                with mock.patch.dict(pcapkit.protocols.__proto__):
                    for name in ('IPV4', 'TCP', 'DTLS'):
                        del pcapkit.protocols.__proto__[name]
                    for name in ('ipv4', 'tcp', 'dtls'):
                        engine = getattr(extractor._reasm, name)
                        self.assertIs(engine.protocol, type(engine).__protocol_type__, name)
                    self.assertIs(extractor._reasm.dtls.protocol, DTLS)


if __name__ == '__main__':
    unittest.main()
