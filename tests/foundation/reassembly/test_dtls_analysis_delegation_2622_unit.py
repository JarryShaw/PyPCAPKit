# -*- coding: utf-8 -*-
"""DTLS handshake analysis is a method of the DTLS protocol (#2622).

The owner ruled on #2622 that the protocol class owns the parse of a reassembled
outcome, and that :mod:`pcapkit.foundation.analysis` and the reassembly's deferred
``packet`` only call it. For DTLS that method is
:meth:`DTLS.analyze_handshake <pcapkit.protocols.application.dtls.DTLS.analyze_handshake>`:

* :func:`~pcapkit.foundation.analysis.dtls.dtls_handshake` returns what the method
  returns, called on :class:`~pcapkit.protocols.application.dtls.DTLS` itself;
* a datagram's ``packet`` is the method bound to the reassembly's own
  ``__protocol_type__``, so a DTLS subclass overriding it decodes the ``packet``, a
  protocol without it raises :exc:`AttributeError` once a message completes, and the
  binding survives every pickle protocol;
* a body that does not decode stays raw quietly, as a handled refusal is (#2588),
  while :meth:`DTLS.read_handshake` on the same octets stays loud.

Every capture is built in memory, as PCAP and as PCAP-NG; no sample capture is read.

"""

from __future__ import annotations

import operator
import pickle
import sys
import threading
import unittest
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import reimport_once_per_class
from tests.foundation.reassembly.test_dtls_handshake_reassembly_2440_unit import (
    _client_hello_body, _dtls_handshake, _dtls_record, _extract, _frame, _pcap, _pcapng, _split)
from tests.utilities._harness import capture

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): pickling and the exception hooks, which differ by interpreter.
__tier__ = 'ALL'

#: A ``ClientHello`` body, which decodes.
BODY = _client_hello_body(cookie=b'\x01\x02\x03')
#: A ``ClientHello`` body cut short inside ``random``, which does not.
BAD_BODY = b'\xfe\xfd' + bytes(7)
#: Their message sequence number.
MESSAGE_SEQ = 6
#: The containers each case runs over.
CONTAINERS = (('pcap', _pcap), ('pcapng', _pcapng))


def _records(body: 'bytes') -> 'list[bytes]':
    """``body`` as a ``ClientHello`` in two ``handshake`` records."""
    return [_dtls_record(22, _dtls_handshake(1, body[fo:fo + length], message_seq=MESSAGE_SEQ,
                                             fragment_offset=fo, fragment_length=length,
                                             total_length=len(body)), seq=num)
            for num, (fo, length) in enumerate(_split(body, (len(body) // 2,)), 1)]


def _held(datagram: 'Any') -> 'Any':
    """``datagram``'s ``packet`` as stored, without resolving it."""
    return datagram.__dict__[datagram.__map__.get('packet', 'packet')]


def _header(body: 'bytes') -> 'tuple[Any, int, int]':
    """The ``(msg_type, length, message_seq)`` of :func:`_records` ``(body)``."""
    from pcapkit.const.tls.handshake_type import HandshakeType

    return (HandshakeType.client_hello, len(body), MESSAGE_SEQ)


class _Reassembled(unittest.TestCase):
    """Builds the one message a capture of :func:`_records` reassembles."""

    def _datagram(self, write: 'Any', body: 'bytes' = BODY) -> 'Any':
        extractor = _extract(self, write([_frame(record) for record in _records(body)]),
                             reassembly=True, dtls=True)
        datagram, = extractor.reassembly.dtls
        self.assertTrue(datagram.completed)
        return datagram


class DelegationTests(_Reassembled):
    """``dtls_handshake`` and the deferred ``packet`` both call the protocol method."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_dtls_handshake_returns_the_protocol_methods_result(self) -> None:
        from pcapkit.foundation.analysis import dtls_handshake
        from pcapkit.protocols.application.dtls import DTLS

        result = object()
        for container, write in CONTAINERS:
            with self.subTest(container=container):
                datagram = self._datagram(write)
                with mock.patch.object(DTLS, 'analyze_handshake', return_value=result) as analyze:
                    self.assertIs(dtls_handshake(datagram), result)
                analyze.assert_called_once_with(_header(BODY), BODY)

    def test_a_dtls_subclass_overriding_the_method_decodes_the_packet(self) -> None:
        from pcapkit.foundation.analysis import dtls_handshake
        from pcapkit.foundation.reassembly.dtls import DTLS as DTLS_Reassembly
        from pcapkit.protocols.application.dtls import DTLS
        from pcapkit.protocols.data.application.dtls import DTLS as Data_DTLS
        from pcapkit.protocols.data.application.tls import ClientHello
        from pcapkit.protocols.schema.application.dtls import DTLS as Schema_DTLS

        class TaggedDTLS(DTLS, schema=Schema_DTLS, data=Data_DTLS):
            """A DTLS protocol whose handshake analysis is tagged as its own."""

            @classmethod
            def analyze_handshake(cls, header: 'Any', body: 'bytes') -> 'Any':  # type: ignore[override]
                return ('tagged', header, body)

        for container, write in CONTAINERS:
            with self.subTest(container=container):
                with mock.patch.object(DTLS_Reassembly, '__protocol_type__', TaggedDTLS):
                    datagram = self._datagram(write)
                self.assertEqual(datagram.packet, ('tagged', _header(BODY), BODY))
                # the public function decodes with DTLS itself
                self.assertIsInstance(dtls_handshake(datagram).body, ClientHello)

    def test_a_protocol_type_without_the_method_fails_when_a_message_completes(self) -> None:
        from pcapkit.const.tls.handshake_type import HandshakeType
        from pcapkit.foundation.reassembly.data.dtls import Packet
        from pcapkit.foundation.reassembly.dtls import DTLS as DTLS_Reassembly

        class Unrelated:  # pylint: disable=too-few-public-methods
            """A ``__protocol_type__`` with no ``analyze_handshake``."""

        class Engine(DTLS_Reassembly):
            __protocol_type__ = Unrelated

        half = len(BODY) // 2
        engine = Engine()
        for num, (offset, fragment) in enumerate(((0, BODY[:half]), (half, BODY[half:])), 1):
            info = Packet(bufid=('192.0.2.1', 1234, '198.51.100.1', 5684, 0), num=num,
                          msg_type=HandshakeType.client_hello, length=len(BODY),
                          message_seq=MESSAGE_SEQ, fragment_offset=offset,
                          fragment_length=len(fragment), payload=fragment, timestamp=float(num))
            if num == 1:
                engine(info)  # the first half completes nothing, so nothing is read
                continue
            with self.assertRaisesRegex(AttributeError, 'analyze_handshake'):
                engine(info)

    def test_the_packet_is_the_bound_method_across_pickling(self) -> None:
        from pcapkit.foundation.reassembly.data.data import Deferred
        from pcapkit.protocols.application.dtls import DTLS

        for container, write in CONTAINERS:
            for protocol in range(pickle.HIGHEST_PROTOCOL + 1):
                with self.subTest(container=container, protocol=protocol):
                    datagram = self._datagram(write)
                    restored = pickle.loads(pickle.dumps(datagram, protocol=protocol))
                    for held in (_held(datagram), _held(restored)):
                        self.assertIsInstance(held, Deferred)
                        self.assertEqual(held.analyze, DTLS.analyze_handshake)
                    self.assertEqual(restored.packet, datagram.packet)


class QuietRefusalTests(_Reassembled):
    """A body that does not decode stays raw, and its refusal logs and hooks nothing."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        # NOTE: imported before the sentinels go in, since importing pcapkit
        # outside development mode installs tbtrim's hook itself.
        import pcapkit  # pylint: disable=import-outside-toplevel,unused-import
        saved = sys.excepthook, threading.excepthook

        def restore() -> None:
            sys.excepthook, threading.excepthook = saved

        self.addCleanup(restore)

        def sentinel(*args: 'object') -> None:
            sys.__excepthook__(*args)  # type: ignore[arg-type]

        def thread_sentinel(args: 'object') -> None:  # pylint: disable=unused-argument
            pass

        self.sentinels = sentinel, thread_sentinel
        sys.excepthook, threading.excepthook = self.sentinels

    def _quietly(self, decode: 'Any', *args: 'Any') -> 'Any':
        """``decode(*args)``, asserting it logs nothing and leaves both hooks alone."""
        from pcapkit.utilities.logging import logger

        with capture(logger) as recorder:
            result = decode(*args)
        self.assertEqual(recorder.messages, [])
        self.assertIs(sys.excepthook, self.sentinels[0])
        self.assertIs(threading.excepthook, self.sentinels[1])
        return result

    def test_an_undecodable_body_stays_raw_quietly(self) -> None:
        from pcapkit.foundation.analysis import dtls_handshake
        from pcapkit.protocols.application.dtls import DTLS
        from pcapkit.utilities.exceptions import ProtocolError
        from pcapkit.utilities.logging import logger

        for container, write in CONTAINERS:
            with self.subTest(container=container):
                datagram = self._datagram(write, BAD_BODY)
                results = (self._quietly(operator.attrgetter('packet'), datagram),
                           self._quietly(dtls_handshake, datagram),
                           self._quietly(DTLS.analyze_handshake, _header(BAD_BODY), BAD_BODY))
                for message in results:
                    self.assertEqual((message.body, message.message_seq, message.fragment_offset,
                                      message.fragment_length, message.is_fragmented),
                                     (BAD_BODY, MESSAGE_SEQ, 0, len(BAD_BODY), False))

        # reading the same octets directly, with nothing to handle the refusal, stays loud
        octets = _dtls_handshake(1, BAD_BODY, message_seq=MESSAGE_SEQ, fragment_offset=0,
                                 fragment_length=len(BAD_BODY))
        with capture(logger) as recorder:
            with self.assertRaises(ProtocolError):
                DTLS.read_handshake(octets)
        self.assertEqual([level for level, _ in recorder.messages], ['CRITICAL'])


if __name__ == '__main__':
    unittest.main()
