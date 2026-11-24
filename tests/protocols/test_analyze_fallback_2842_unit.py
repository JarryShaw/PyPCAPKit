# -*- coding: utf-8 -*-
"""A payload ``analyze`` fails to parse is kept whole, its failure as ``error`` (#2842).

``Protocol.analyze`` and ``Transport.analyze`` retry a failed parse as ``Raw`` on
the stream that parse read. Each entry point must keep what the per-frame path's
``Raw`` keeps for the same octets -- all of them, and the failure's message -- and
rebuild them byte for byte: the two methods, ``ip_datagram`` for IPv4 and IPv6,
``tcp_datagram``, and the ``Deferred`` packet IP and TCP reassembly store.

Every packet is built in memory; no sample capture is read.

"""

from __future__ import annotations

import ipaddress
import struct
import unittest
import warnings
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any, Callable

#: Test tier (#1958): stream semantics, and hand-picked parse -> rebuild round trips.
__tier__ = 'ALL'

V4_SRC, V4_DST = ipaddress.ip_address('192.0.2.1'), ipaddress.ip_address('198.51.100.2')
V6_SRC, V6_DST = ipaddress.ip_address('2001:db8::1'), ipaddress.ip_address('2001:db8::2')

#: A TCP segment whose Data Offset is 0, under the 5 words RFC 9293 section 3.1
#: requires, which TCP refuses.
SEGMENT = bytes(range(30))
#: An HTTP request, which TLS on port 443 refuses: ``G`` is no TLS content type.
REQUEST = b'GET / HTTP/1.1\r\nHost: example\r\n\r\n'
#: The ports ``REQUEST`` is carried between; only 443 is registered.
SPORT, DPORT = 1234, 443


def _ipv4(payload: bytes) -> bytes:
    """An IPv4 header, DF set, carrying ``payload`` as TCP."""
    return struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0x4000, 64, 6, 0,
                       V4_SRC.packed, V4_DST.packed) + payload


def _ipv6(payload: bytes) -> bytes:
    """An IPv6 header carrying ``payload`` as TCP."""
    return struct.pack('!IHBB16s16s', 6 << 28, len(payload), 6, 64,
                       V6_SRC.packed, V6_DST.packed) + payload


def _tcp(payload: bytes) -> bytes:
    """A TCP header from :data:`SPORT` to :data:`DPORT` carrying ``payload``."""
    return struct.pack('!HHIIBBHHH', SPORT, DPORT, 1, 1, 5 << 4, 0x18, 0xFFFF, 0, 0) + payload


def _parse(func: 'Callable[..., Any]', *args: 'Any') -> 'Any':
    """``func(*args)``, whatever the failed parse warns."""
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        return func(*args)


def _ports() -> 'tuple[Any, Any]':
    """:data:`SPORT` and :data:`DPORT` as TCP application types."""
    from pcapkit.const.reg.apptype import TCP as AppType_TCP

    return AppType_TCP.get(SPORT), AppType_TCP.get(DPORT)


class AnalyzeFallbackTests(unittest.TestCase):
    """Every entry point to the fallback keeps the payload as a frame's ``Raw`` does."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def assertKeptWhole(self, result: 'Any', payload: bytes, frame: 'Any') -> None:
        """``result`` holds ``payload`` and ``frame``'s failure, and rebuilds it."""
        from pcapkit.protocols.misc.raw.protocol import Raw

        self.assertIs(type(frame), Raw)
        self.assertEqual(bytes(frame), payload)
        self.assertTrue(frame.info.error)

        self.assertIs(type(result), Raw)
        self.assertEqual(bytes(result), payload)
        self.assertEqual(result.info.packet, payload)
        self.assertEqual(result.info.error, frame.info.error)
        self.assertEqual(bytes(Raw.from_data(result.info)), payload)

    def _ip_frames(self) -> 'Any':
        """Each IP protocol, with the ``Raw`` its per-frame parse keeps of :data:`SEGMENT`."""
        from pcapkit.protocols.internet.ipv4.protocol import IPv4
        from pcapkit.protocols.internet.ipv6.protocol import IPv6

        for protocol, build in ((IPv4, _ipv4), (IPv6, _ipv6)):
            yield protocol, _parse(protocol, build(SEGMENT)).payload

    def test_protocol_analyze(self) -> None:
        from pcapkit.const.reg.transtype import TransType

        for protocol, frame in self._ip_frames():
            with self.subTest(protocol=protocol.__name__):
                result = _parse(protocol.analyze, TransType.TCP, SEGMENT)
                self.assertKeptWhole(result, SEGMENT, frame)

    def test_transport_analyze(self) -> None:
        from pcapkit.protocols.transport.tcp.protocol import TCP

        frame = _parse(TCP, _tcp(REQUEST)).payload
        self.assertKeptWhole(_parse(TCP.analyze, _ports(), REQUEST), REQUEST, frame)

    def test_ip_datagram(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.foundation.analysis import ip_datagram
        from pcapkit.foundation.reassembly.data import Completion
        from pcapkit.foundation.reassembly.ip.data import Datagram, DatagramID
        from pcapkit.protocols.internet.ipv6.protocol import IPv6

        for protocol, frame in self._ip_frames():
            with self.subTest(protocol=protocol.__name__):
                src, dst = (V6_SRC, V6_DST) if protocol is IPv6 else (V4_SRC, V4_DST)
                datagram = Datagram(completed=Completion.COMPLETE,
                                    id=DatagramID(src=src, dst=dst, id=1, proto=TransType.TCP),
                                    index=(1,), header=b'', payload=SEGMENT, packet=None, conflict=())
                self.assertKeptWhole(_parse(ip_datagram, datagram), SEGMENT, frame)

    def test_tcp_datagram(self) -> None:
        from pcapkit.foundation.analysis import tcp_datagram
        from pcapkit.foundation.reassembly.data import Completion
        from pcapkit.foundation.reassembly.tcp.data import Datagram, DatagramID
        from pcapkit.protocols.transport.tcp.protocol import TCP

        frame = _parse(TCP, _tcp(REQUEST)).payload
        datagram = Datagram(completed=Completion.COMPLETE,
                            id=DatagramID(src=(V4_SRC, SPORT), dst=(V4_DST, DPORT), ack=1),
                            index=(1,), header=b'', payload=REQUEST, packet=None, conflict=())
        self.assertKeptWhole(_parse(tcp_datagram, datagram), REQUEST, frame)

    def test_deferred_ip_packet(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.foundation.reassembly.data import Deferred
        from pcapkit.foundation.reassembly.ip.data import Packet
        from pcapkit.foundation.reassembly.ipv4.reassembly import IPv4 as IPv4_Reassembly
        from pcapkit.foundation.reassembly.ipv6.reassembly import IPv6 as IPv6_Reassembly
        from pcapkit.protocols.internet.ipv6.protocol import IPv6

        engines = {'IPv4': IPv4_Reassembly, 'IPv6': IPv6_Reassembly}
        for protocol, frame in self._ip_frames():
            with self.subTest(protocol=protocol.__name__):
                src, dst = (V6_SRC, V6_DST) if protocol is IPv6 else (V4_SRC, V4_DST)
                reassembly = engines[protocol.__name__]()
                for num, (fo, mf, part) in enumerate(((0, True, SEGMENT[:16]),
                                                      (16, False, SEGMENT[16:])), 1):
                    reassembly(Packet((src, dst, 1, TransType.TCP), num, fo, 20, mf,
                                      20 + len(part), b'', bytearray(part), float(num)))
                datagram, = reassembly.datagram
                self.assertIsInstance(datagram.__dict__[datagram.__map__.get('packet', 'packet')],
                                      Deferred)
                self.assertKeptWhole(_parse(getattr, datagram, 'packet'), SEGMENT, frame)

    def test_deferred_tcp_packet(self) -> None:
        from functools import partial

        from pcapkit.foundation.analysis.tcp import _analyze_payload
        from pcapkit.foundation.reassembly.data import Deferred
        from pcapkit.protocols.transport.tcp.protocol import TCP

        frame = _parse(TCP, _tcp(REQUEST)).payload
        deferred = Deferred(partial(_analyze_payload, TCP), _ports(), REQUEST)
        self.assertKeptWhole(_parse(deferred), REQUEST, frame)


if __name__ == '__main__':
    unittest.main()
