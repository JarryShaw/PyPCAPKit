# -*- coding: utf-8 -*-
"""``ip_datagram`` and ``tcp_datagram`` take ``layer``, ``protocol`` and ``context`` (#2947).

Each takes them keyword-only, as the parse it wraps does, and forwards only those
set, as the engine hands them to a reassembly's deferred ``packet`` (#2933). So
called with the stops and context an extraction was given, each returns what the
extraction's datagram holds as ``packet``.

Every capture is built in memory, as PCAP and as PCAP-NG; no sample capture is read.

"""

from __future__ import annotations

import inspect
import unittest
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import reimport_once_per_class
from tests.foundation.reassembly.test_dtls_handshake_reassembly_2440_unit import _extract
from tests.foundation.reassembly.test_reassembly_parse_options_2933_unit import (
    CONTAINERS, DNS, ESP, INNER, REQUEST, SEGMENTS, V4_DST, V4_SRC, V6_DST, V6_SRC, _context,
    _fragments)

if TYPE_CHECKING:
    from typing import Any, Callable

#: The options the functions take, in order.
OPTIONS = ('layer', 'protocol', 'context')


def _ip(payload: bytes, proto: int, *, v6: bool = False) -> 'Any':
    """A complete IP datagram carrying ``payload`` as protocol ``proto``."""
    from pcapkit.const.reg.transtype import TransType
    from pcapkit.foundation.reassembly.data import Completion
    from pcapkit.foundation.reassembly.ip.data import Datagram, DatagramID

    src, dst = (V6_SRC, V6_DST) if v6 else (V4_SRC, V4_DST)
    return Datagram(completed=Completion.COMPLETE,
                    id=DatagramID(src=src, dst=dst, id=1, proto=TransType(proto)),
                    index=(1, 2), header=b'', payload=payload, packet=None, conflict=())


def _tcp(payload: bytes) -> 'Any':
    """A complete TCP datagram carrying ``payload`` from port 1234 to port 80."""
    from pcapkit.foundation.reassembly.data import Completion
    from pcapkit.foundation.reassembly.tcp.data import Datagram, DatagramID

    return Datagram(completed=Completion.COMPLETE,
                    id=DatagramID(src=(V4_SRC, 1234), dst=(V4_DST, 80), ack=1),
                    index=(1, 2), header=b'', payload=payload, packet=None, conflict=())


def _parsed(packet: 'Any') -> 'Any':
    """What a parse produced, comparable by value."""
    return type(packet), str(packet.protochain), packet.info


class SignatureTests(unittest.TestCase):
    """The options are keyword-only, off by default, and a closed set."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _functions(self) -> 'tuple[tuple[Callable[..., Any], Any], ...]':
        from pcapkit.foundation.analysis import ip_datagram, tcp_datagram

        return ((ip_datagram, _ip(DNS, 17)), (tcp_datagram, _tcp(b''.join(REQUEST))))

    def test_options_are_keyword_only_off_by_default_and_closed(self) -> None:
        for function, datagram in self._functions():
            with self.subTest(function=function.__name__):
                first, *rest = inspect.signature(function).parameters.values()
                self.assertEqual((first.name, first.kind),
                                 ('datagram', inspect.Parameter.POSITIONAL_OR_KEYWORD))
                self.assertEqual([(param.name, param.kind, param.default) for param in rest],
                                 [(name, inspect.Parameter.KEYWORD_ONLY, None) for name in OPTIONS])
                with self.assertRaises(TypeError):
                    function(datagram, _layer='Transport')
                with self.assertRaises(TypeError):
                    function(datagram, 'Transport')

    def test_both_take_the_same_options_and_extract_s_context(self) -> None:
        from pcapkit.foundation.analysis import ip_datagram, tcp_datagram
        from pcapkit.foundation.extraction import Extractor

        ip_options = list(inspect.signature(ip_datagram).parameters.values())[1:]
        tcp_options = list(inspect.signature(tcp_datagram).parameters.values())[1:]
        self.assertEqual(ip_options, tcp_options)
        self.assertEqual(inspect.signature(ip_datagram).parameters['context'],
                         inspect.signature(Extractor.__init__).parameters['context'])


class StopTests(unittest.TestCase):
    """A payload stops as the parse ``analyze`` runs stops it."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_ip_stop_inside_the_payload(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.foundation.analysis import ip_datagram
        from pcapkit.protocols.internet.ipv4.protocol import IPv4
        from pcapkit.protocols.internet.ipv6.protocol import IPv6

        for v6, klass in ((False, IPv4), (True, IPv6)):
            for stop in ({'layer': 'Transport'}, {'protocol': 'UDP'}):
                with self.subTest(version=klass.__name__, **stop):
                    packet = ip_datagram(_ip(DNS, 17, v6=v6), **stop)
                    self.assertEqual(str(packet.protochain), 'UDP:Raw')
                    self.assertEqual(_parsed(packet), _parsed(klass.analyze(TransType.UDP, DNS, **stop)))

    def test_ip_stop_at_the_reassembled_layer_keeps_the_payload_raw(self) -> None:
        from pcapkit.foundation.analysis import ip_datagram
        from pcapkit.protocols.internet.ipv4.protocol import IPv4
        from pcapkit.protocols.internet.ipv6.protocol import IPv6
        from pcapkit.protocols.misc.raw.protocol import Raw

        for v6, klass in ((False, IPv4), (True, IPv6)):
            for stop in ({'layer': 'Internet'}, {'protocol': klass.__name__}, {'protocol': klass}):
                with self.subTest(version=klass.__name__, stop=stop):
                    packet = ip_datagram(_ip(DNS, 17, v6=v6), **stop)
                    self.assertIs(type(packet), Raw)
                    self.assertEqual(bytes(packet), DNS)

    def test_tcp_stop_at_the_transport_layer_keeps_the_payload_raw(self) -> None:
        from pcapkit.foundation.analysis import tcp_datagram
        from pcapkit.protocols.misc.raw.protocol import Raw

        for stop in ({'layer': 'Transport'}, {'protocol': 'TCP'}):
            with self.subTest(**stop):
                packet = tcp_datagram(_tcp(b''.join(REQUEST)), **stop)
                self.assertIs(type(packet), Raw)
                self.assertEqual(bytes(packet), b''.join(REQUEST))

    def test_no_stop_parses_the_whole_payload(self) -> None:
        from pcapkit.foundation.analysis import ip_datagram, tcp_datagram
        from pcapkit.protocols.application.httpv1.protocol import HTTPv1

        for stop in ({}, dict.fromkeys(OPTIONS), {'layer': 'Application'}):
            with self.subTest(stop=stop):
                self.assertEqual(str(ip_datagram(_ip(DNS, 17), **stop).protochain), 'UDP:DNS')
                self.assertIs(type(tcp_datagram(_tcp(b''.join(REQUEST)), **stop)), HTTPv1)

    def test_only_the_options_set_reach_the_parse(self) -> None:
        from pcapkit.foundation.analysis import ip_datagram, tcp_datagram
        from pcapkit.protocols.internet.ipv4.protocol import IPv4
        from pcapkit.protocols.transport.tcp.protocol import TCP

        for function, klass, datagram in ((ip_datagram, IPv4, _ip(DNS, 17)),
                                          (tcp_datagram, TCP, _tcp(b''.join(REQUEST)))):
            for options in ({}, dict.fromkeys(OPTIONS)):
                with self.subTest(function=function.__name__, options=options):
                    with mock.patch.object(klass, 'analyze', wraps=klass.analyze) as analyze:
                        function(datagram, **options)
                    # NOTE: An IP payload's next-layer state takes the private route (#2840, #2945).
                    self.assertEqual(set(analyze.call_args.kwargs), set())


class ContextTests(unittest.TestCase):
    """A reassembled ESP datagram finds the SA it is given, in any shape ``extract`` takes."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_the_context_opens_esp(self) -> None:
        from pcapkit.corekit.context import ContextRegistry
        from pcapkit.foundation.analysis import ip_datagram
        from pcapkit.protocols.internet.esp.protocol import ESPStatus

        shapes = {'context': _context, 'list': lambda: [_context()],
                  'registry': lambda: ContextRegistry.make(_context())}
        for v6 in (False, True):
            datagram = _ip(ESP, 50, v6=v6)
            self.assertIs(ip_datagram(datagram).info.status, ESPStatus.NO_SA)
            for shape, make in shapes.items():
                with self.subTest(v6=v6, shape=shape):
                    packet = ip_datagram(datagram, context=make())
                    self.assertIs(packet.info.status, ESPStatus.DECRYPTED)
                    self.assertEqual(packet.info.plaintext, INNER)


class PacketParityTests(unittest.TestCase):
    """Given an extraction's options, each function returns its datagram's ``packet``."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_the_extraction_s_options_give_its_packet(self) -> None:
        from pcapkit.foundation.analysis import ip_datagram, tcp_datagram

        cases = (
            ('ipv4', _fragments('ipv4', ESP, 50), lambda: {'context': _context()}),
            ('ipv6', _fragments('ipv6', ESP, 50), lambda: {'context': _context()}),
            ('ipv4', _fragments('ipv4', DNS, 17), lambda: {'layer': 'Transport'}),
            ('ipv6', _fragments('ipv6', DNS, 17), lambda: {'protocol': 'UDP'}),
            ('ipv4', _fragments('ipv4', DNS, 17), lambda: {'layer': 'Internet'}),
            ('tcp', SEGMENTS, lambda: {'layer': 'Transport'}),
            ('tcp', SEGMENTS, lambda: {'protocol': 'TCP'}),
        )
        for kind, frames, options in cases:
            function = tcp_datagram if kind == 'tcp' else ip_datagram
            for container, build in CONTAINERS:
                with self.subTest(kind=kind, options=sorted(options()), container=container):
                    extractor = _extract(self, build(frames), reassembly=[kind], **options())
                    datagram, = getattr(extractor.reassembly, kind)
                    packet = datagram.packet
                    self.assertEqual(_parsed(function(datagram, **options())), _parsed(packet))
                    self.assertNotEqual(_parsed(function(datagram)), _parsed(packet))


if __name__ == '__main__':
    unittest.main()
