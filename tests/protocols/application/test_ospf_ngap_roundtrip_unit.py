# -*- coding: utf-8 -*-
"""OSPF and NGAP rebuild what they parsed, or refuse it.

GitHub issues:

* #1249: :meth:`OSPF.make <pcapkit.protocols.application.ospf.OSPF.make>`
  recomputed Packet Length from the payload and ``_make_data`` dropped the
  parsed one, so the 16-octet digest that cryptographic authentication appends
  outside the packet (:rfc:`2328#appendix-D.4.3`) was counted in it.
* #1250: ``OSPF(auth_type=2, auth_data=<bytes>)`` raised
  :exc:`AttributeError`.
* #1251 (OSPF half): an ``auth_data`` that is not 8 octets was padded or cut.
* #1252: octets after the aligned PER ``NGAP-PDU`` were dropped on rebuild.

Every case builds its own octets in memory and reads no capture. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`,
c.f. ``tests/protocols/link/test_ethernet_mac_roundtrip_unit.py``.

"""

import importlib.util
import unittest

from tests._support import reimport_once_per_class

HAS_PYCRATE = importlib.util.find_spec('pycrate_asn1dir') is not None

#: Cryptographic authentication: Key ID 1, Auth Data Len 16, sequence 7.
CRYPTO_AUTH = bytes.fromhex('0000011000000007')
#: A 20-octet Hello body.
HELLO_BODY = bytes.fromhex('ffffff00000a020100000028c0a8000100000000')


def ospf_header(length: int, auth_type: int, auth: bytes) -> bytes:
    """OSPFv2 Hello header with the given Packet Length and authentication."""
    return (bytes.fromhex('0201') + length.to_bytes(2, 'big')
            + bytes.fromhex('c0a8000100000000' '0000')
            + auth_type.to_bytes(2, 'big') + auth)


#: Packets whose Packet Length is not ``24 + len(payload)``.
OSPF_PACKETS = {
    'crypto auth, digest outside Length': ospf_header(0x2c, 2, CRYPTO_AUTH) + HELLO_BODY + bytes(range(16)),
    'Length zero': ospf_header(0x00, 0, bytes(8)) + HELLO_BODY,
    'Length short of the payload': ospf_header(0x1e, 0, bytes(8)) + HELLO_BODY,
    'Length matching the payload': ospf_header(0x2c, 0, bytes(8)) + HELLO_BODY,
}

#: ``NGSetupRequest`` in aligned PER, c.f. ``test_ngap_unit.NGSETUP_REQUEST``.
NGSETUP_REQUEST = bytes.fromhex(
    '00150036000004001b00080002f839100001020052400d0500706361706b69742d676e62'
    '0066000d00000000010002f839000000080015400140'
)


class TestOSPFRoundTrip(unittest.TestCase):
    """Pin Packet Length and the 8-octet Authentication field."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_from_data_keeps_parsed_packet_length(self) -> None:
        from pcapkit.protocols.application.ospf import OSPF

        for name, packet in OSPF_PACKETS.items():
            with self.subTest(packet=name):
                parsed = OSPF(packet, len(packet))
                self.assertEqual(bytes(OSPF.from_data(parsed.info)), packet)

    def test_make_packet_length_default_and_explicit(self) -> None:
        from pcapkit.protocols.application.ospf import OSPF

        self.assertEqual(bytes(OSPF(payload=HELLO_BODY))[2:4], b'\x00\x2c')
        self.assertEqual(bytes(OSPF(packet_length=0x1e, payload=HELLO_BODY))[2:4], b'\x00\x1e')

    def test_from_data_without_len_computes_packet_length(self) -> None:
        from ipaddress import ip_address

        from pcapkit.protocols.application.ospf import OSPF
        from pcapkit.protocols.data.application.ospf import OSPF as Data_OSPF

        data = Data_OSPF.from_dict({
            'version': 2, 'type': 1, 'router_id': ip_address('192.168.0.1'),
            'area_id': ip_address('0.0.0.0'), 'chksum': b'\x00\x00', 'autype': 0,
            'auth': bytes(8),
        })
        self.assertNotIn('len', data)
        self.assertEqual(bytes(OSPF.from_data(data)), ospf_header(24, 0, bytes(8)))

    def test_make_rejects_invalid_packet_length(self) -> None:
        from pcapkit.protocols.application.ospf import OSPF
        from pcapkit.utilities.exceptions import ProtocolError

        for packet_length in (-1, 0x10000, True, 24.0, '24'):
            with self.subTest(packet_length=packet_length):
                with self.assertRaises(ProtocolError) as caught:
                    OSPF(packet_length=packet_length)
                self.assertIn('invalid packet length', str(caught.exception))
        self.assertEqual(bytes(OSPF(packet_length=0xFFFF))[2:4], b'\xff\xff')

    def test_make_crypto_auth_from_bytes(self) -> None:
        from pcapkit.protocols.application.ospf import OSPF

        packet = bytes(OSPF(auth_type=2, auth_data=CRYPTO_AUTH))
        self.assertEqual(packet[16:24], CRYPTO_AUTH)

        info = OSPF(packet, len(packet)).info
        self.assertEqual((info.auth.key_id, info.auth.len, info.auth.seq), (1, 16, 7))
        self.assertEqual(bytes(OSPF.from_data(info)), packet)

    def test_make_rejects_wrong_width_auth_data(self) -> None:
        from pcapkit.protocols.application.ospf import OSPF
        from pcapkit.utilities.exceptions import ProtocolError

        for auth_type in (0, 1, 2):
            for auth_data in (b'abc', b'0123456789', b''):
                with self.subTest(auth_type=auth_type, auth_data=auth_data):
                    with self.assertRaises(ProtocolError) as caught:
                        OSPF(auth_type=auth_type, auth_data=auth_data)
                    self.assertIn('8 octets', str(caught.exception))


@unittest.skipUnless(HAS_PYCRATE, 'pycrate not installed')
class TestNGAPTrailingOctets(unittest.TestCase):
    """Octets after the ``NGAP-PDU`` are refused rather than dropped."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_exact_pdu_rebuilds_byte_for_byte(self) -> None:
        from pcapkit.protocols.application.ngap import NGAP

        parsed = NGAP(NGSETUP_REQUEST, len(NGSETUP_REQUEST))
        self.assertEqual(bytes(NGAP.from_data(parsed.info)), NGSETUP_REQUEST)

    def test_trailing_octets_raise_protocol_error(self) -> None:
        from pcapkit.protocols.application.ngap import NGAP
        from pcapkit.utilities.exceptions import ProtocolError

        for suffix in (b'\x00', b'\xff\xff', b'\xde\xad\xbe\xef'):
            with self.subTest(suffix=suffix):
                packet = NGSETUP_REQUEST + suffix
                with self.assertRaises(ProtocolError) as caught:
                    NGAP(packet, len(packet))
                self.assertIn(f'{len(suffix)} octet(s) after the NGAP-PDU', str(caught.exception))


if __name__ == '__main__':
    unittest.main()
