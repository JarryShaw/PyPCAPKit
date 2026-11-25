# -*- coding: utf-8 -*-
"""``analyze`` dispatches a reassembled payload as the frame path dispatches a next layer (#2945).

* ``Transport.analyze`` looks the payload up by the port ``_decode_next_layer`` does: the
  lower one, unless only the higher one is registered.
* A reassembled IP payload gets the datagram's addresses and IP version, as a frame's IP
  layer hands its next layer, through ``_from_parent``; so does a payload ``analyze`` is
  also given a keyword for its constructor.
* ``IPv6.analyze`` keeps a payload raw past a stop at the Fragment header it follows.

Every capture is built in memory, as PCAP and as PCAP-NG; no sample capture is read.

"""

from __future__ import annotations

import contextlib
import ipaddress
import struct
import unittest
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import reimport_once_per_class
from tests.foundation.reassembly.test_dtls_handshake_reassembly_2440_unit import _extract, _pcap
from tests.foundation.reassembly.test_reassembly_parse_options_2933_unit import (
    CONTAINERS, DNS, ESP, INNER, V4_DST, V6_DST, V6_SRC, _ether, _fragments, _ipv4)

if TYPE_CHECKING:
    from typing import Any, Iterator

#: An address neither capture sends to.
ELSEWHERE = {'ipv4': ipaddress.ip_address('203.0.113.9'), 'ipv6': ipaddress.ip_address('2001:db8::9')}
#: Each capture's destination.
DESTINATION = {'ipv4': V4_DST, 'ipv6': V6_DST}
#: An HTTP request, which the TCP captures carry in two segments.
REQUEST = (b'GET / HTTP/1.1\r\n', b'Host: example\r\n\r\n')


def _tcp(payload: bytes, sport: int, dport: int, *, seq: int, fin: bool = False) -> bytes:
    flags = 0x18 | (0x01 if fin else 0)  # PSH, ACK, and FIN if asked
    segment = struct.pack('!HHIIBBHHH', sport, dport, seq, 1, 5 << 4, flags, 0xFFFF, 0, 0) + payload
    return _ipv4(segment, 6, df=True)


def _segments(sport: int, dport: int) -> 'list[bytes]':
    """:data:`REQUEST` from ``sport`` to ``dport``, the last segment closing the flow."""
    return [_tcp(REQUEST[0], sport, dport, seq=1000),
            _tcp(REQUEST[1], sport, dport, seq=1000 + len(REQUEST[0]), fin=True)]


def _ipv6(payload: bytes, nxt: int) -> bytes:
    """An unfragmented IPv6 packet, as :func:`_ipv4` builds an IPv4 one."""
    return struct.pack('!IHBB16s16s', 6 << 28, len(payload), nxt, 64,
                       V6_SRC.packed, V6_DST.packed) + payload


def _context(*destinations: 'Any') -> 'Any':
    """ESP-NULL SAs for :data:`ESP`'s SPI, the first an HMAC one that no ICV of it verifies."""
    from pcapkit.protocols.internet.esp.protocol import ESPContext, SecurityAssociation

    decoy, *rest = destinations
    return ESPContext(SecurityAssociation(spi=7, destination=decoy, integrity='HMAC-SHA2-256-128',
                                          integrity_key=bytes(32)),
                      *(SecurityAssociation(spi=7, destination=address) for address in rest))


@contextlib.contextmanager
def _spy(cls: type) -> 'Iterator[list[dict[str, Any]]]':
    """Record the next-layer state every ``cls.read`` is given; the read still runs."""
    calls = []  # type: list[dict[str, Any]]
    original = cls.read

    def read(self: 'Any', *args: 'Any', **kwargs: 'Any') -> 'Any':
        calls.append(kwargs)
        return original(self, *args, **kwargs)

    with mock.patch.object(cls, 'read', read):
        yield calls


class _Case(unittest.TestCase):

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def reassembled(self, kind: str, frames: 'list[bytes]', **kwargs: 'Any') -> 'list[tuple[str, Any]]':
        """Each container's name, and its one ``kind`` datagram."""
        datagrams = []
        for name, build in CONTAINERS:
            extractor = _extract(self, build(frames), reassembly=[kind], **kwargs)
            found = getattr(extractor.reassembly, kind)
            self.assertEqual(len(found), 1, name)
            datagrams.append((name, found[0]))
        return datagrams


class PortTests(_Case):
    """``Transport.analyze`` takes the port a frame's next layer is looked up by."""

    def test_neither_port_registered_records_the_lower(self) -> None:
        from pcapkit.protocols.misc.raw.protocol import Raw

        whole = _extract(self, _pcap(_segments(22, 51774)[:1])).frame[0]['TCP'].payload
        self.assertEqual((type(whole), whole.info.protocol), (Raw, 22))
        for container, datagram in self.reassembled('tcp', _segments(22, 51774)):
            with self.subTest(container=container):
                self.assertIs(type(datagram.packet), Raw)
                self.assertEqual(datagram.packet.info.protocol, 22)

    def test_both_ports_registered_take_the_lower(self) -> None:
        from pcapkit.const.reg.apptype import AppType, TransportProtocol
        from pcapkit.protocols.transport.tcp.protocol import TCP

        # NOTE: 443 is TLS's and 80 HTTP's, so the source port no longer wins.
        whole = TCP(_tcp(b''.join(REQUEST), 443, 80, seq=1000)[34:]).payload
        self.assertEqual(type(whole).__name__, 'HTTPv1')
        for container, datagram in self.reassembled('tcp', _segments(443, 80)):
            with self.subTest(container=container):
                self.assertEqual(type(datagram.packet).__name__, 'HTTPv1')
        ports = tuple(AppType.get(port, proto=TransportProtocol.tcp) for port in (443, 80))
        self.assertEqual(type(TCP.analyze(ports, b''.join(REQUEST))).__name__, 'HTTPv1')

    def test_a_port_that_is_not_a_number_is_passed_over(self) -> None:
        """A missing or non-int port still falls back rather than raising."""
        from pcapkit.protocols.misc.raw.protocol import Raw
        from pcapkit.protocols.transport.tcp.protocol import TCP

        request = b''.join(REQUEST)
        self.assertEqual(type(TCP.analyze((None, 80), request)).__name__, 'HTTPv1')
        for ports, protocol in (((None, None), None), (('80', 443), 443)):
            with self.subTest(ports=ports):
                packet = TCP.analyze(ports, request)
                self.assertIs(type(packet), Raw)
                self.assertEqual(packet.info.protocol, protocol)


class StateTests(_Case):
    """A reassembled IP payload gets the addresses and version a frame's IP layer hands on."""

    def test_an_sa_keyed_by_destination_matches_by_it(self) -> None:
        from pcapkit.foundation.analysis.ip import ip_datagram
        from pcapkit.protocols.internet.esp.protocol import ESPStatus

        whole = _extract(self, _pcap([_ipv4(ESP, 50, df=True)]),
                         context=_context(ELSEWHERE['ipv4'], V4_DST)).frame[0]['IPv4'].payload
        self.assertIs(whole.info.status, ESPStatus.DECRYPTED)
        for kind in ('ipv4', 'ipv6'):
            context = _context(ELSEWHERE[kind], DESTINATION[kind])
            for container, datagram in self.reassembled(kind, _fragments(kind, ESP, 50),
                                                        context=context):
                with self.subTest(kind=kind, container=container):
                    self.assertIs(datagram.packet.info.status, ESPStatus.DECRYPTED)
                    self.assertEqual(datagram.packet.info.plaintext, INNER)
                    self.assertIs(ip_datagram(datagram, context=context).info.status,
                                  ESPStatus.DECRYPTED)

    def test_an_sa_for_another_destination_does_not_apply(self) -> None:
        from pcapkit.protocols.internet.esp.protocol import ESPContext, ESPStatus, SecurityAssociation

        for kind in ('ipv4', 'ipv6'):
            context = ESPContext(SecurityAssociation(spi=7, destination=ELSEWHERE[kind]))
            for container, datagram in self.reassembled(kind, _fragments(kind, ESP, 50),
                                                        context=context):
                with self.subTest(kind=kind, container=container):
                    self.assertIs(datagram.packet.info.status, ESPStatus.NO_SA)

    def test_the_payload_gets_the_frame_s_addresses_and_version(self) -> None:
        from pcapkit.protocols.internet.esp.protocol import ESP as ESP_Protocol

        for kind, frame in (('ipv4', _ipv4(ESP, 50, df=True)), ('ipv6', _ether(_ipv6(ESP, 50), 0x86DD))):
            with self.subTest(kind=kind), _spy(ESP_Protocol) as calls:
                _extract(self, _pcap([frame]))
                whole = calls[-1]
                for _, datagram in self.reassembled(kind, _fragments(kind, ESP, 50)):
                    del calls[:]
                    datagram.packet  # pylint: disable=pointless-statement
                    state = calls[-1]
                    self.assertEqual(state['version'], whole['version'])
                    self.assertEqual({key: state['packet'][key] for key in ('src', 'dst')},
                                     {key: whole['packet'][key] for key in ('src', 'dst')})

    def test_the_state_takes_the_channel_beside_a_constructor_keyword(self) -> None:
        """``IGMP.__new__`` does not read the enclosing IP ``version`` as its own (#2840)."""
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.igmpv2.protocol import IGMPv2
        from pcapkit.protocols.internet.ipv4.protocol import IPv4

        # NOTE: An IGMPv2 Membership Report for 224.0.0.251.
        octets = bytes([0x16, 0, 0, 0, 224, 0, 0, 251])
        whole = IPv4(_ipv4(octets, 2, df=True)[14:]).payload
        self.assertIs(type(whole), IGMPv2)
        with _spy(IGMPv2) as calls:
            packet = IPv4.analyze(TransType.IGMP, octets, version=4, unread=True)
        self.assertIs(type(packet), IGMPv2)
        self.assertEqual(packet.info, whole.info)
        self.assertEqual((calls[0]['version'], calls[0]['unread']), (4, True))


class StopTests(_Case):
    """``IPv6.analyze`` stops at the Fragment header a reassembled payload follows."""

    def test_a_stop_at_the_fragment_header_keeps_the_payload_raw(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ipv6.protocol import IPv6
        from pcapkit.protocols.internet.ipv6_frag.protocol import IPv6_Frag
        from pcapkit.protocols.misc.raw.protocol import Raw

        at_ipv6 = IPv6.analyze(TransType.UDP, DNS, protocol='IPv6')
        self.assertIs(type(at_ipv6), Raw)
        for stop in ('IPv6_Frag', IPv6_Frag):
            with self.subTest(stop=stop):
                packet = IPv6.analyze(TransType.UDP, DNS, protocol=stop)
                self.assertIs(type(packet), Raw)
                self.assertEqual(packet.info, at_ipv6.info)
                for container, datagram in self.reassembled('ipv6', _fragments('ipv6', DNS, 17),
                                                            protocol=stop):
                    with self.subTest(container=container):
                        self.assertIs(type(datagram.packet), Raw)
                        self.assertEqual(bytes(datagram.packet), DNS)
                        self.assertEqual(datagram.packet.info.protocol, TransType.UDP)
                # NOTE: An IPv4 datagram has no Fragment header to stop at.
                for container, datagram in self.reassembled('ipv4', _fragments('ipv4', DNS, 17),
                                                            protocol=stop):
                    with self.subTest(kind='ipv4', container=container):
                        self.assertEqual(str(datagram.packet.protochain), 'UDP:DNS')


if __name__ == '__main__':
    unittest.main()
