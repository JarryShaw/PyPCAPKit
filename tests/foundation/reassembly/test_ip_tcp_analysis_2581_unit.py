# -*- coding: utf-8 -*-
"""IP and TCP reassembly parse through their own analysis modules (#2581).

:func:`pcapkit.foundation.analysis.ip.ip_datagram` parses a reassembled IPv4 or
IPv6 datagram's payload, and :func:`pcapkit.foundation.analysis.tcp.tcp_datagram`
a reassembled TCP datagram's, as
:func:`pcapkit.foundation.analysis.dtls.dtls_handshake` decodes a DTLS message.
A reassembled datagram's deferred ``packet`` runs the same parse, bound to the
reassembly's own protocol: it holds what the analysis function returns for the
default protocol, and what a custom ``__protocol_type__`` returns otherwise.

Every capture is built in memory, as PCAP and as PCAP-NG; no sample capture is
read.

"""

from __future__ import annotations

import ipaddress
import pickle
import struct
import unittest
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import reimport_once_per_class
from tests.foundation.reassembly.test_dtls_handshake_reassembly_2440_unit import (
    _extract, _pcap, _pcapng)

if TYPE_CHECKING:
    from typing import Any, Callable

#: Test tier (#1958): pickling, whose protocols differ by interpreter.
__tier__ = 'ALL'

#: The containers each case runs over.
CONTAINERS = (('pcap', _pcap), ('pcapng', _pcapng))

V4_SRC, V4_DST = ipaddress.ip_address('192.0.2.1'), ipaddress.ip_address('198.51.100.2')
V6_SRC, V6_DST = ipaddress.ip_address('2001:db8::1'), ipaddress.ip_address('2001:db8::2')

#: A UDP datagram, the payload both IP captures fragment in two.
UDP = struct.pack('!HHHH', 1234, 9, 32, 0) + bytes(range(24))
#: An HTTP request, which the TCP captures carry in two segments.
REQUEST = (b'GET / HTTP/1.1\r\n', b'Host: example\r\n\r\n')


def _ether(packet: bytes, ethertype: int) -> bytes:
    return b'\xbb' * 6 + b'\xaa' * 6 + ethertype.to_bytes(2, 'big') + packet


def _ipv4(payload: bytes, *, offset: int, mf: bool, protocol: int = 17, df: bool = False) -> bytes:
    flags = (0x4000 if df else 0) | (0x2000 if mf else 0) | offset // 8
    return _ether(struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 0x1234, flags, 64,
                              protocol, 0, V4_SRC.packed, V4_DST.packed) + payload, 0x0800)


def _ipv6(payload: bytes, *, offset: int, mf: bool) -> bytes:
    fragment = struct.pack('!BBHI', 17, 0, offset | int(mf), 0x5678) + payload
    return _ether(struct.pack('!IHBB16s16s', 6 << 28, len(fragment), 44, 64,
                              V6_SRC.packed, V6_DST.packed) + fragment, 0x86DD)


def _tcp(payload: bytes, *, seq: int, fin: bool = False) -> bytes:
    flags = 0x18 | (0x01 if fin else 0)  # PSH, ACK, and FIN if asked
    segment = struct.pack('!HHIIBBHHH', 1234, 80, seq, 1, 5 << 4, flags, 0xFFFF, 0, 0) + payload
    return _ipv4(segment, offset=0, mf=False, protocol=6, df=True)


#: Each engine's frames: whole, and with a fragment or segment lost.
FRAMES = {
    'ipv4': ([_ipv4(UDP[:16], offset=0, mf=True), _ipv4(UDP[16:], offset=16, mf=False)],
             [_ipv4(UDP[:16], offset=0, mf=True)]),
    'ipv6': ([_ipv6(UDP[:16], offset=0, mf=True), _ipv6(UDP[16:], offset=16, mf=False)],
             [_ipv6(UDP[:16], offset=0, mf=True)]),
    'tcp': ([_tcp(REQUEST[0], seq=1000), _tcp(REQUEST[1], seq=1000 + len(REQUEST[0]), fin=True)],
            [_tcp(REQUEST[0], seq=1000), _tcp(REQUEST[1], seq=1008 + len(REQUEST[0]), fin=True)]),
}


def _held(datagram: 'Any') -> 'Any':
    """``datagram``'s ``packet`` as stored, without resolving it."""
    return datagram.__dict__[datagram.__map__.get('packet', 'packet')]


def _parsed(packet: 'Any') -> 'Any':
    """What a parse produced, comparable by value."""
    return None if packet is None else (type(packet), packet.info)


class CustomProtocol:
    """A custom engine's ``__protocol_type__``, whose parse is tagged as its own.

    Module-level, so a datagram whose ``packet`` it is bound to still pickles.

    """

    @classmethod
    def analyze(cls, proto: 'Any', payload: bytes) -> 'tuple[str, Any, bytes]':
        return ('custom', proto, payload)


def _analysis(kind: str) -> 'tuple[Callable[[Any], Any], Any, Any]':
    """The public function, the default protocol and the engine for ``kind``."""
    from pcapkit.foundation.analysis import ip_datagram, tcp_datagram
    from pcapkit.foundation.reassembly import ipv4, ipv6, tcp
    from pcapkit.protocols.internet.ipv4 import IPv4
    from pcapkit.protocols.internet.ipv6 import IPv6
    from pcapkit.protocols.transport.tcp import TCP

    return {
        'ipv4': (ip_datagram, IPv4, ipv4.IPv4),
        'ipv6': (ip_datagram, IPv6, ipv6.IPv6),
        'tcp': (tcp_datagram, TCP, tcp.TCP),
    }[kind]


def _expected(kind: str) -> 'Any':
    """The class the default protocol parses ``kind``'s whole payload to."""
    from pcapkit.protocols.application.httpv1 import HTTPv1
    from pcapkit.protocols.transport.udp import UDP as UDP_Protocol

    return HTTPv1 if kind == 'tcp' else UDP_Protocol


def _key(kind: str, proto: 'Any') -> 'Any':
    """What the parse of ``kind``'s datagram dispatches on, comparable by value."""
    return [port.port for port in proto] if kind == 'tcp' else proto


class AnalysisFunctionTests(unittest.TestCase):
    """``ip_datagram`` and ``tcp_datagram``, called on a datagram built directly."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @staticmethod
    def _ip(payload: 'bytes | tuple[bytes, ...]', *, v6: bool = False,
            completed: str = 'COMPLETE') -> 'Any':
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.foundation.reassembly.data.data import Completion
        from pcapkit.foundation.reassembly.data.ip import Datagram, DatagramID

        src, dst = (V6_SRC, V6_DST) if v6 else (V4_SRC, V4_DST)
        return Datagram(completed=Completion[completed],
                        id=DatagramID(src=src, dst=dst, id=1, proto=TransType.UDP),
                        index=(1, 2), header=b'', payload=payload, packet=None, conflict=())

    @staticmethod
    def _tcp(payload: 'bytes | tuple[bytes, ...]', *, dport: int = 80,
             completed: str = 'COMPLETE') -> 'Any':
        from pcapkit.foundation.reassembly.data.data import Completion
        from pcapkit.foundation.reassembly.data.tcp import Datagram, DatagramID

        return Datagram(completed=Completion[completed],
                        id=DatagramID(src=(V4_SRC, 1234), dst=(V4_DST, dport), ack=1),
                        index=(1, 2), header=b'', payload=payload, packet=None, conflict=())

    def test_ip_datagram_parses_by_the_payload_protocol_type(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.foundation.analysis import ip_datagram
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.transport.udp import UDP as UDP_Protocol

        packet = ip_datagram(self._ip(UDP))
        self.assertIsInstance(packet, UDP_Protocol)
        self.assertEqual(_parsed(packet), _parsed(IPv4.analyze(TransType.UDP, UDP)))
        self.assertEqual((packet.info.srcport, packet.info.dstport), (1234, 9))

    def test_ip_datagram_takes_the_protocol_its_addresses_belong_to(self) -> None:
        from pcapkit.foundation.analysis import ip_datagram
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.internet.ipv6 import IPv6

        for v6, called, idle in ((False, IPv4, IPv6), (True, IPv6, IPv4)):
            with self.subTest(v6=v6):
                with mock.patch.object(called, 'analyze', wraps=called.analyze) as used, \
                        mock.patch.object(idle, 'analyze', wraps=idle.analyze) as unused:
                    ip_datagram(self._ip(UDP, v6=v6))
                used.assert_called_once()
                self.assertEqual(used.call_args.args[1], UDP)
                unused.assert_not_called()

    def test_tcp_datagram_parses_by_its_ports(self) -> None:
        from pcapkit.const.reg.apptype import TCP as AppType_TCP
        from pcapkit.foundation.analysis import tcp_datagram
        from pcapkit.protocols.application.httpv1 import HTTPv1 as HTTP
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.protocols.transport.tcp import TCP

        payload = b''.join(REQUEST)
        with mock.patch.object(TCP, 'analyze', wraps=TCP.analyze) as analyze:
            self.assertIsInstance(tcp_datagram(self._tcp(payload)), HTTP)
        ports, = {call.args[0] for call in analyze.call_args_list}
        self.assertEqual([type(port) for port in ports], [AppType_TCP, AppType_TCP])
        self.assertEqual([port.port for port in ports], [1234, 80])
        self.assertIsInstance(tcp_datagram(self._tcp(b'not a protocol', dport=50000)), Raw)

    def test_a_contiguous_incomplete_payload_is_parsed(self) -> None:
        from pcapkit.foundation.analysis import ip_datagram, tcp_datagram
        from pcapkit.protocols.application.httpv1 import HTTPv1 as HTTP
        from pcapkit.protocols.transport.udp import UDP as UDP_Protocol

        request = b''.join(REQUEST)
        for completed in ('PARTIAL', 'TIMEOUT'):
            with self.subTest(completed=completed):
                self.assertIsInstance(ip_datagram(self._ip(UDP, completed=completed)), UDP_Protocol)
                self.assertIsInstance(tcp_datagram(self._tcp(request, completed=completed)), HTTP)

    def test_received_runs_are_not_parsed(self) -> None:
        from pcapkit.foundation.analysis import ip_datagram, tcp_datagram

        runs = (UDP[:8], UDP[16:])
        self.assertIsNone(ip_datagram(self._ip(runs, completed='PARTIAL')))
        self.assertIsNone(ip_datagram(self._ip(runs, v6=True, completed='TIMEOUT')))
        self.assertIsNone(tcp_datagram(self._tcp(REQUEST, completed='PARTIAL')))

    def test_the_functions_are_exported_as_reassembly_names_are(self) -> None:
        import pcapkit.all
        import pcapkit.foundation
        import pcapkit.foundation.analysis
        from pcapkit.foundation.analysis.ip import ip_datagram
        from pcapkit.foundation.analysis.tcp import tcp_datagram

        for module in (pcapkit.foundation.analysis, pcapkit.foundation, pcapkit.all):
            for name, function in (('ip_datagram', ip_datagram), ('tcp_datagram', tcp_datagram)):
                with self.subTest(module=module.__name__, name=name):
                    self.assertIn(name, module.__all__)
                    self.assertIs(getattr(module, name), function)


class ExtractorReassemblyTests(unittest.TestCase):
    """A reassembled datagram's ``packet`` is the analysis function's result, deferred."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _datagram(self, kind: str, write: 'Any', *, whole: bool = True, **kwargs: 'Any') -> 'Any':
        frames = FRAMES[kind][0 if whole else 1]
        extractor = _extract(self, write(frames), reassembly=True, ip=True, tcp=True, **kwargs)
        datagram, = getattr(extractor.reassembly, kind)
        return datagram

    def test_reading_packet_parses_as_the_analysis_function_does(self) -> None:
        for kind in FRAMES:
            function, _, _ = _analysis(kind)
            for container, write in CONTAINERS:
                with self.subTest(kind=kind, container=container):
                    datagram = self._datagram(kind, write)
                    self.assertTrue(datagram.completed)
                    packet = datagram.packet
                    self.assertIsInstance(packet, _expected(kind))
                    self.assertEqual(_parsed(packet), _parsed(function(datagram)))
                    self.assertIs(datagram.packet, packet)

    def test_a_custom_protocol_type_parses_the_packet(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.foundation.reassembly.data.data import Deferred

        for kind in FRAMES:
            function, _, engine = _analysis(kind)
            key = [1234, 80] if kind == 'tcp' else TransType.UDP
            for container, write in CONTAINERS:
                with self.subTest(kind=kind, container=container):
                    with mock.patch.object(engine, '__protocol_type__', CustomProtocol):
                        datagram = self._datagram(kind, write)
                    self.assertIsInstance(_held(datagram), Deferred)
                    tag, proto, payload = datagram.packet
                    self.assertEqual((tag, _key(kind, proto), payload),
                                     ('custom', key, datagram.payload))
                    # the analysis function parses with the default protocol
                    self.assertIsInstance(function(datagram), _expected(kind))

    def test_the_parse_runs_on_first_read_and_only_once(self) -> None:
        for kind in FRAMES:
            function, protocol, _ = _analysis(kind)
            for container, write in CONTAINERS:
                with self.subTest(kind=kind, container=container):
                    with mock.patch.object(protocol, 'analyze', wraps=protocol.analyze) as analyze:
                        datagram = self._datagram(kind, write)
                        self.assertEqual(analyze.call_count, 0)
                        packet = datagram.packet
                        datagram['packet']  # pylint: disable=pointless-statement
                        repr(datagram)
                        self.assertEqual(analyze.call_count, 1)
                        self.assertEqual(_parsed(packet), _parsed(function(datagram)))

    def test_an_incomplete_datagram_is_parsed_unless_strict(self) -> None:
        from pcapkit.foundation.reassembly.data.data import Deferred

        for kind in FRAMES:
            function, _, _ = _analysis(kind)
            for container, write in CONTAINERS:
                for strict in (True, False):
                    with self.subTest(kind=kind, container=container, strict=strict):
                        datagram = self._datagram(kind, write, whole=False, reasm_strict=strict)
                        self.assertEqual(datagram.completed.name, 'PARTIAL')
                        self.assertIsInstance(datagram.payload, tuple if strict else bytes)
                        self.assertIsInstance(_held(datagram), type(None) if strict else Deferred)
                        self.assertEqual(_parsed(datagram.packet), _parsed(function(datagram)))
                        self.assertEqual(datagram.packet is None, strict)

    def test_a_deferred_datagram_pickles_and_still_parses(self) -> None:
        from pcapkit.foundation.reassembly.data.data import Deferred

        for kind in FRAMES:
            function, _, engine = _analysis(kind)
            for container, write in CONTAINERS:
                default = self._datagram(kind, write)
                with mock.patch.object(engine, '__protocol_type__', CustomProtocol):
                    custom = self._datagram(kind, write)
                for name, datagram in (('default', default), ('custom', custom)):
                    restored = []
                    for number in range(pickle.HIGHEST_PROTOCOL + 1):
                        with self.subTest(kind=kind, container=container, engine=name,
                                          protocol=number):
                            copy = pickle.loads(pickle.dumps(datagram, protocol=number))
                            self.assertIsInstance(_held(datagram), Deferred)
                            self.assertIsInstance(_held(copy), Deferred)
                            restored.append(copy.packet)
                    with self.subTest(kind=kind, container=container, engine=name):
                        if name == 'default':
                            expected = _parsed(function(datagram))
                            self.assertEqual([_parsed(packet) for packet in restored],
                                             [expected] * len(restored))
                            self.assertEqual(_parsed(datagram.packet), expected)
                        else:
                            self.assertEqual(datagram.packet[0], 'custom')
                            self.assertEqual(restored, [datagram.packet] * len(restored))


if __name__ == '__main__':
    unittest.main()
