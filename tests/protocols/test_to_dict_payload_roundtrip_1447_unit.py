# -*- coding: utf-8 -*-
"""``from_data(info.to_dict())`` rebuilds the payload, byte for byte.

GitHub issue #1447: :meth:`Info.to_dict <pcapkit.corekit.infoclass.Info.to_dict>`
leaves out ``__next_type__`` and ``__next_name__``, which
:meth:`~pcapkit.protocols.protocol.ProtocolBase._make_payload` dispatched on, so
a layer rebuilt from its dict lost its payload: an Ethernet frame came back as
its 14-octet header. IPv6 lost its extension headers the same way, with
``__exthdr__``, and HTTP raised ``ProtocolError('invalid HTTP data: Raw')``.

The dict itself is left as it was, since the dumps are written from it; the
payload is found from the dict's structure instead.

Every case builds its own octets and reads no capture. Classes are imported
inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import io
import struct
import unittest
import warnings

from tests._support import reimport_once_per_class

MAC = bytes.fromhex('0123456789ab' 'fedcba987654')
SRC4, DST4 = bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])
SRC6 = bytes.fromhex('20010db8' + '00' * 11 + '01')
DST6 = bytes.fromhex('20010db8' + '00' * 11 + '02')


def ipv4(proto: int, payload: bytes) -> bytes:
    """An IPv4 header carrying ``payload`` as protocol ``proto``."""
    return struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 0, 0x4000, 64, proto, 0,
                       SRC4, DST4) + payload


def tcp(dport: int, payload: bytes) -> bytes:
    """A TCP header with no options, to ``dport``."""
    return struct.pack('!HHIIBBHHH', 49152, dport, 1, 1, 0x50, 0x18, 0xffff, 0, 0) + payload


def udp(payload: bytes, port: int = 40000) -> bytes:
    """A UDP header from ``port`` to itself; the default is unregistered, so the payload is Raw."""
    return struct.pack('!HHHH', port, port, 8 + len(payload), 0) + payload


HTTP1 = b'GET / HTTP/1.1\r\nHost: example\r\n\r\n'
#: The HTTP/2 connection preface and an empty SETTINGS frame.
HTTP2 = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n' + bytes.fromhex('000000' '04' '00' '00000000')
#: An L2TPv2 control header (T and L set): length 12, tunnel 1, session 2.
#: Its info is under ``l2tp``, the ``info_name`` every L2TP version shares,
#: not under its lowercased class name.
L2TPV2 = bytes.fromhex('c802' '000c' '0001' '0002' '0000' '0000')
ARP = bytes.fromhex('0001' '0800' '06' '04' '0001') + MAC[6:] + SRC4 + bytes(6) + DST4
#: Hop-by-Hop Options, then Destination Options, then UDP; each a lone PadN.
EXTHDR = bytes.fromhex('3c' '00' '0104' '00000000') + bytes.fromhex('11' '00' '0104' '00000000')
IPV6_PAYLOAD = EXTHDR + udp(b'ping')
IPV6 = struct.pack('!IHBB16s16s', 6 << 28, len(IPV6_PAYLOAD), 0, 64, SRC6, DST6) + IPV6_PAYLOAD

#: Link-layer frames, each carried in a PCAP record.
FRAMES = {
    'ipv4-tcp-http1': MAC + b'\x08\x00' + ipv4(6, tcp(80, HTTP1)),
    'ipv4-tcp-http2': MAC + b'\x08\x00' + ipv4(6, tcp(80, HTTP2)),
    'ipv4-udp': MAC + b'\x08\x00' + ipv4(17, udp(b'pong')),
    'ipv4-udp-l2tpv2': MAC + b'\x08\x00' + ipv4(17, udp(L2TPV2, port=1701)),
    'arp-padded': MAC + b'\x08\x06' + ARP + bytes(18),
    'ipv6-exthdr-udp': MAC + b'\x86\xdd' + IPV6,
}

#: Little-endian global header: v2.4, Ethernet.
GLOBAL = bytes.fromhex('d4c3b2a1' '0200' '0400' '00000000' '00000000' 'ffff0000' '01000000')

#: Every layer type #1447 names, each of which these frames must exercise, and
#: L2TPv2, whose ``info_name`` is not its lowercased class name.
LAYERS = {'Frame', 'Ethernet', 'ARP', 'IPv4', 'IPv6', 'TCP', 'UDP', 'HTTP', 'L2TPv2'}


class TestToDictPayloadRoundTrip(unittest.TestCase):
    """Pin the rebuild of a layer from its dict."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        quiet = warnings.catch_warnings()
        quiet.__enter__()  # pylint: disable=unnecessary-dunder-call
        self.addCleanup(quiet.__exit__, None, None, None)
        warnings.simplefilter('ignore')

    def frame(self, name: str):  # type: ignore[no-untyped-def]
        """Parse ``FRAMES[name]`` as the first record of a PCAP file."""
        from pcapkit.protocols.misc.pcap.frame import Frame
        from pcapkit.protocols.misc.pcap.header import Header

        packet = FRAMES[name]
        record = struct.pack('<IIII', 1, 2, len(packet), len(packet)) + packet
        self.header = Header(GLOBAL).info
        return Frame(io.BytesIO(record), num=1, header=self.header)

    def layers(self, name: str):  # type: ignore[no-untyped-def]
        """Yield every layer of ``FRAMES[name]``, from the frame down."""
        from pcapkit.protocols.misc.null import NoPayload

        layer = self.frame(name)
        while not isinstance(layer, NoPayload):
            yield layer
            layer = layer.payload

    def rebuild(self, layer):  # type: ignore[no-untyped-def]
        """``type(layer).from_data(layer.info.to_dict())``."""
        from pcapkit.protocols.misc.pcap.frame import Frame

        kwargs = {'num': 1, 'header': self.header} if isinstance(layer, Frame) else {}
        return type(layer).from_data(layer.info.to_dict(), **kwargs)

    def test_every_layer_rebuilds_from_its_dict(self) -> None:
        seen = set()
        for name in FRAMES:
            for layer in self.layers(name):
                seen.add(type(layer).__name__)
                with self.subTest(frame=name, layer=type(layer).__name__):
                    self.assertEqual(self.rebuild(layer).data, layer.data)
        self.assertLessEqual(LAYERS, seen)

    def test_rebuilt_payload_has_the_parsed_type(self) -> None:
        for name in FRAMES:
            for layer in self.layers(name):
                with self.subTest(frame=name, layer=type(layer).__name__):
                    self.assertIs(type(self.rebuild(layer).payload), type(layer.payload))

    def test_ipv6_extension_headers_rebuild_from_its_dict(self) -> None:
        from pcapkit.protocols.internet.ipv6 import IPv6

        ipv6 = self.frame('ipv6-exthdr-udp')[IPv6]
        dict_ = ipv6.info.to_dict()
        self.assertNotIn('__exthdr__', dict_)

        rebuilt = IPv6.from_data(dict_)
        self.assertEqual(rebuilt.data, ipv6.data)
        self.assertEqual(
            [type(ext).__name__ for ext in rebuilt._exthdr.values()],  # pylint: disable=protected-access
            ['HOPOPT', 'IPv6_Opts'],
        )

    def test_payload_is_found_by_info_name_not_class_name(self) -> None:
        from pcapkit.protocols.link.l2tpv2 import L2TPv2
        from pcapkit.protocols.transport.udp import UDP

        udp_ = self.frame('ipv4-udp-l2tpv2')[UDP]
        self.assertIsInstance(udp_.payload, L2TPv2)
        self.assertIn('l2tp', udp_.info.to_dict())

        rebuilt = UDP.from_data(udp_.info.to_dict())
        self.assertIsInstance(rebuilt.payload, L2TPv2)
        self.assertEqual(rebuilt.data, udp_.data)
        self.assertEqual(len(rebuilt.data), 8 + len(L2TPV2))

    def test_http_dict_keeps_its_version(self) -> None:
        from pcapkit.protocols.application.http import HTTP

        for name, alias in (('ipv4-tcp-http1', 'HTTP/1.1'), ('ipv4-tcp-http2', 'HTTP/2')):
            with self.subTest(frame=name):
                http = self.frame(name)[HTTP]
                self.assertEqual(http.alias, alias)
                self.assertEqual(HTTP.from_data(http.info.to_dict()).alias, alias)

    def test_dict_without_a_payload_key_rebuilds_the_header_alone(self) -> None:
        from pcapkit.protocols.link.ethernet import Ethernet
        from pcapkit.protocols.misc.null import NoPayload

        eth = Ethernet(FRAMES['ipv4-udp'])
        dict_ = eth.info.to_dict()
        del dict_['ipv4']

        rebuilt = Ethernet.from_data(dict_)
        self.assertIsInstance(rebuilt.payload, NoPayload)
        self.assertEqual(rebuilt.data, FRAMES['ipv4-udp'][:14])

    def test_to_dict_still_leaves_the_dispatch_keys_out(self) -> None:
        # The dumps are written from ``to_dict``, so the fix must not add to it.
        for name in FRAMES:
            for layer in self.layers(name):
                with self.subTest(frame=name, layer=type(layer).__name__):
                    dict_ = layer.info.to_dict()
                    for key in ('__next_type__', '__next_name__', '__exthdr__'):
                        self.assertNotIn(key, dict_)


if __name__ == '__main__':
    unittest.main()
