# -*- coding: utf-8 -*-
"""IPv4 computes a pending upper-layer checksum behind its Authentication Headers.

GitHub issue #2861: an upper layer whose ``make()`` left its checksum pending is
computed by the enclosing IPv4 layer behind one or more Authentication Headers,
as well as when it follows the IPv4 header. AH sits between the two in transport
mode (RFC 4302 section 3.1.1) and moves no address, so the pseudo-header is
IPv4's own (RFC 793 section 3.1, RFC 768), with a source route's final
destination (RFC 791). A fragment's checksum covers the reassembled datagram, so
it stays pending, as does one the packet gives no pseudo-header for, quietly.

The upper layers are every class ``Internet.__proto__`` dispatches that verifies
over a pseudo-header, so one registered later gets its cases with no edit here.
Each checksum is checked by summing a pseudo-header built by hand with the upper
layer's octets, which comes to zero once the checksum is right (RFC 1071).

"""
from __future__ import annotations

import ipaddress
import sys
import threading
import unittest
import warnings
from unittest import mock

from tests._support import install_hook_sentinels, reimport_once_per_class
from tests.foundation import _roundtrip as wire
from tests.utilities._harness import capture

#: Test tier (#1958): make -> parse round trips, and the warning and exception hooks,
#: which differ by interpreter.
__tier__ = 'ALL'

SRC, DST = ipaddress.ip_address('192.0.2.1'), ipaddress.ip_address('198.51.100.2')
#: The last address of a source route still to be visited, which the pseudo-header takes
#: as the destination (RFC 791).
FINAL = ipaddress.ip_address('203.0.113.9')
#: The AH Protocol number (RFC 4302 section 2.2).
AH_PROTO = 51
#: An AH with a 96-bit ICV (RFC 2404) is 24 octets.
AH_LEN = 24

#: Upper layers whose checksum the RFC defines over the IPv6 pseudo-header alone, so an
#: IPv4 pseudo-header gives none: their checksum is left as given, directly or behind AH.
IPV6_ONLY = {
    'MH': 'RFC 6275 section 6.1.1 defines the checksum over the IPv6 pseudo-header',
}

#: Arguments giving an upper layer octets of its own to cover; the defaults otherwise.
ARGS = {
    'TCP': {'srcport': 40000, 'dstport': 80, 'payload': b'signed'},
    'UDP': {'srcport': 40000, 'dstport': 40001, 'payload': b'signed'},
}


def pseudo4(src: object, dst: object, protocol: int, length: int) -> bytes:
    """An IPv4 pseudo-header (RFC 793 section 3.1, RFC 768)."""
    return src.packed + dst.packed + bytes([0, protocol]) + length.to_bytes(2, 'big')


class PendingChecksumTestCase(unittest.TestCase):
    """Imports, the upper layers from the registry, and helpers the tests share."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        from pcapkit.const.ipv4.option_number import OptionNumber
        from pcapkit.corekit.checksum.internet import ChecksumStatus
        from pcapkit.protocols.internet.ah.protocol import AH
        from pcapkit.protocols.internet.internet import Internet
        from pcapkit.protocols.internet.ipv4.protocol import IPv4
        from pcapkit.utilities import config
        from pcapkit.utilities.warnings import ProtocolWarning

        self.OptionNumber, self.Status, self.AH, self.IPv4 = OptionNumber, ChecksumStatus, AH, IPv4
        self.config, self.ProtocolWarning = config, ProtocolWarning

        #: Every upper layer ``Internet.__proto__`` dispatches that verifies its checksum
        #: over the pseudo-header of the IP layer, by protocol number.
        self.uppers = {}  # type: dict[int, type]
        for code, target in dict(Internet.__proto__).items():
            klass = getattr(target, 'klass', target)
            if hasattr(klass, '_verify_pseudo_checksum'):
                self.uppers[int(code)] = klass

    def upper(self, klass: type, **kwargs: object) -> object:
        """An instance of ``klass`` as the tests construct it."""
        return klass.from_fields(**ARGS.get(klass.__name__, {}), **kwargs)

    def behind(self, code: int, upper: object, depth: int) -> object:
        """``upper`` behind ``depth`` Authentication Headers, the innermost naming ``code``."""
        layer = upper
        for level in range(depth):
            layer = self.AH.from_fields(next=code if level == 0 else AH_PROTO, spi=0x1234 + level, seq=1,
                                        icv=bytes(AH_LEN - 12), payload=layer)
        return layer

    def ipv4(self, protocol: int, payload: object, **kwargs: object) -> bytes:
        """The octets of an IPv4 packet from SRC to DST carrying ``payload``."""
        return self.IPv4.from_fields(src=SRC, dst=DST, protocol=protocol, payload=payload, **kwargs).data

    def parse(self, octets: bytes) -> 'tuple[object, list[tuple[type, str]]]':
        """``octets`` parsed as IPv4, verified, and its ProtocolWarnings as ``(category, message)``."""
        with mock.patch.object(self.config, 'CHECKSUM_VERIFY', True), \
                warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            layer = self.IPv4(octets)
        return layer, [(item.category, str(item.message))
                       for item in caught if issubclass(item.category, self.ProtocolWarning)]

    def assertRoundTrips(self, octets: bytes) -> object:
        """``octets`` rebuild byte for byte from their parse; returns the layer parsed."""
        ip, _ = self.parse(octets)
        for info in (ip.info, ip.info.to_dict()):
            self.assertEqual(self.IPv4.from_data(info).data, octets)
        return ip

    def assertVerifies(self, octets: bytes, klass: type, status: object) -> None:
        """``octets`` record ``status`` on their ``klass`` layer with no warning, and round-trip."""
        ip, messages = self.parse(octets)
        layer = ip
        while not isinstance(layer, klass):
            layer = layer.payload
        self.assertEqual((layer.info.checksum_status, messages), (status, []))
        self.assertRoundTrips(octets)

    def assertComputed(self, octets: bytes, code: int, *, dst: object = DST) -> None:
        """``octets``, an upper layer of ``code``, sum to zero over their IPv4 pseudo-header."""
        self.assertEqual(wire.checksum(pseudo4(SRC, dst, code, len(octets)) + octets), 0)


class ComputedTests(PendingChecksumTestCase):
    """The checksum computed behind AH, over IPv4's own pseudo-header."""

    def test_behind_authentication_headers(self) -> None:
        names = {klass.__name__ for klass in self.uppers.values()}
        self.assertLessEqual({'TCP', 'UDP'}, names)
        # The tables name only upper layers the registry gives.
        self.assertLessEqual(set(IPV6_ONLY) | set(ARGS), names)

        for code, klass in self.uppers.items():
            direct = self.ipv4(code, self.upper(klass))
            for depth in (1, 2):
                with self.subTest(klass.__name__, depth=depth):
                    made = self.ipv4(AH_PROTO, self.behind(code, self.upper(klass), depth))
                    octets = made[20 + depth * AH_LEN:]
                    # AH moves no address, so the upper layer reads as it does directly.
                    self.assertEqual(octets, direct[20:])
                    if klass.__name__ in IPV6_ONLY:
                        self.assertEqual(octets, self.upper(klass).data)
                        self.assertVerifies(made, klass, self.Status.NO_PSEUDO_HEADER)
                    else:
                        self.assertComputed(octets, code)
                        self.assertVerifies(made, klass, self.Status.VALID)

    def test_behind_a_source_route(self) -> None:
        # RFC 791: while the route has addresses left, the destination is its last one.
        route = [(self.OptionNumber.LSR, {'counts': 2, 'route': ['198.51.100.7'], 'remaining': [str(FINAL)]})]
        for code, klass in self.uppers.items():
            if klass.__name__ in IPV6_ONLY:
                continue
            with self.subTest(klass.__name__):
                made = self.ipv4(AH_PROTO, self.behind(code, self.upper(klass), 1), options=route)
                header = (made[0] & 0x0F) * 4
                self.assertComputed(made[header + AH_LEN:], code, dst=FINAL)
                self.assertVerifies(made, klass, self.Status.VALID)


class LeftPendingTests(PendingChecksumTestCase):
    """What is written as given: an explicit checksum, and one no pseudo-header covers."""

    def test_an_explicit_checksum_is_kept(self) -> None:
        for code, klass in self.uppers.items():
            for depth in (1, 2):
                with self.subTest(klass.__name__, depth=depth):
                    explicit = self.upper(klass, checksum=b'\xbe\xef')
                    made = self.ipv4(AH_PROTO, self.behind(code, explicit, depth))
                    self.assertEqual(made[20 + depth * AH_LEN:], explicit.data)
                    self.assertRoundTrips(made)

                    with mock.patch.object(self.config, 'CHECKSUM_COMPUTE', False):
                        pending = self.upper(klass)
                        made = self.ipv4(AH_PROTO, self.behind(code, pending, depth))
                    self.assertEqual(made[20 + depth * AH_LEN:], pending.data)
                    self.assertRoundTrips(made)

                    # Left out, it is computed.
                    if klass.__name__ not in IPV6_ONLY:
                        made = self.ipv4(AH_PROTO, self.behind(code, self.upper(klass), depth))
                        self.assertComputed(made[20 + depth * AH_LEN:], code)

    def test_a_fragment_waits_for_reassembly(self) -> None:
        # The checksum covers the whole datagram, which a fragment holds only part of (#2471).
        tcp = self.upper(self.uppers[6])
        for kwargs in ({'mf': True}, {'offset': 1}):
            with self.subTest(**kwargs):
                payload = self.behind(6, tcp, 1)
                made = self.ipv4(AH_PROTO, payload, **kwargs)
                self.assertEqual(made[20:], payload.data)
                self.assertRoundTrips(made)
        # The whole datagram beside them is computed.
        self.assertComputed(self.ipv4(AH_PROTO, self.behind(6, tcp, 1))[20 + AH_LEN:], 6)

    def test_a_layer_the_packet_does_not_reach(self) -> None:
        from pcapkit.protocols.internet.esp.protocol import ESP
        from pcapkit.protocols.internet.hopopt.protocol import HOPOPT

        tcp = self.upper(self.uppers[6])
        cases = {
            # The AH names UDP, so the segment behind it is read as UDP.
            'next header': (AH_PROTO, self.AH.from_fields(next=17, icv=bytes(12), payload=tcp)),
            # IPv4 walks no IPv6 extension header (RFC 8200 section 4).
            'hop-by-hop options': (0, HOPOPT.from_fields(next=6, payload=tcp)),
            # The upper layer of ESP is encrypted (RFC 4303).
            'ESP': (50, ESP.from_fields(spi=1, seq=1, payload=tcp)),
            'AH behind ESP': (50, ESP.from_fields(spi=1, seq=1, payload=self.behind(6, tcp, 1))),
        }
        for name, (protocol, payload) in cases.items():
            with self.subTest(name):
                made = self.ipv4(protocol, payload)
                self.assertEqual(made[20:], payload.data)
                self.assertRoundTrips(made)
        # The AH that names the segment computes it.
        self.assertComputed(self.ipv4(AH_PROTO, self.behind(6, tcp, 1))[20 + AH_LEN:], 6)


class QuietRefusalTests(PendingChecksumTestCase):
    """A pseudo-header the packet parsed back does not give is refused quietly (#2588)."""

    def setUp(self) -> None:
        super().setUp()
        self.sentinels = install_hook_sentinels(self)

    def test_nothing_is_logged_or_hooked(self) -> None:
        from pcapkit.utilities.logging import logger

        tcp = self.upper(self.uppers[6])
        # A Total Length short of the AH, so the packet parsed back has no upper layer: ending
        # at the IPv4 header, inside the AH's fixed fields, and inside its ICV.
        for total_length in (20, 20 + 8, 20 + 16):
            with self.subTest(total_length=total_length), capture(logger) as recorder:
                payload = self.behind(6, tcp, 1)
                made = self.ipv4(AH_PROTO, payload, total_length=total_length)
                self.assertEqual(made[20:], payload.data)
                self.assertEqual(recorder.messages, [])
                self.assertIs(sys.excepthook, self.sentinels[0])
                self.assertIs(threading.excepthook, self.sentinels[1])
        # The Total Length the packet's own octets give computes it.
        self.assertComputed(self.ipv4(AH_PROTO, self.behind(6, tcp, 1))[20 + AH_LEN:], 6)


if __name__ == '__main__':
    unittest.main()
