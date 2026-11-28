# -*- coding: utf-8 -*-
"""HIP verifies RVS_HMAC and RELAY_HMAC with a registration's keys.

GitHub issue #3187: given a ``HIPContext`` holding a ``HIPRegistration``, HIP verifies
``RVS_HMAC`` (RFC 8004 section 4.2.1) and ``RELAY_HMAC`` (RFC 5770 section 5.8, RFC 9028
section 5.8) as #2939 verifies ``HIP_MAC``, and records the outcome as the parameter's
``hmac_status``. Each is an HMAC over the packet before it, its Checksum zeroed and its
Header Length counting only that, keyed with the integrity key of the association the
client holds with its rendezvous server or relay, under the sending side's key (RFC 7401
section 6.5). The packets follow the RFCs' relaying figures and are written out by
hand, and the HMACs computed here with :mod:`hmac`, not with pcapkit.

"""
from __future__ import annotations

import hmac
import ipaddress
import struct
import unittest
import warnings

from tests._support import reimport_once_per_class

#: The Initiator's, the Responder's and the server's HITs: ORCHIDs whose OGA ID is 1,
#: RSA,DSA/SHA-256. The Responder is the server's client, and the server HOST_g.
HIT_I = ipaddress.IPv6Address('2001:21::1')
HIT_R = ipaddress.IPv6Address('2001:21::2')
HIT_S = ipaddress.IPv6Address('2001:21::3')
#: A second server, whose HIT is below the Responder's, so it is HOST_l.
HIT_S2 = ipaddress.IPv6Address('2001:21::')
#: HIP-gl and HIP-lg integrity keys of the registration, of SHA-256's length.
KEY_GL, KEY_LG = bytes(range(32)), bytes(range(32, 64))
#: Those of a second registration.
KEY2_GL, KEY2_LG = bytes(range(128, 160)), bytes(range(160, 192))
#: Those of the association of HIT_I and HIT_R, whose HOST_g is HIT_R.
PEER_GL, PEER_LG = bytes(range(64, 96)), bytes(range(96, 128))

#: Packet types (RFC 7401 section 5.3).
I1, R1, I2, UPDATE = 1, 2, 3, 16
#: Parameter types (RFC 7401 section 5.2, RFC 8004 section 4.2, RFC 9028 section 5.7).
SEQ, HIP_MAC = 385, 61505
RELAY_FROM, RELAY_TO, FROM, RVS_HMAC, VIA_RVS, RELAY_HMAC = 63998, 64002, 65498, 65500, 65502, 65520
#: Registration Types (RFC 8003 section 6, RFC 8004 section 4.1, RFC 9028 section 5.9).
RENDEZVOUS, RELAY_UDP_HIP, RELAY_UDP_ESP, CANDIDATE_DISCOVERY = 1, 2, 3, 4

#: The Initiator's address, IPv4 in IPv6 as FROM carries it (RFC 8004 section 4.2.2).
ADDR_I = ipaddress.IPv6Address('::ffff:192.0.2.1')
#: A SEQ parameter, Update ID 7.
SEQ_TLV = struct.pack('!HHI', SEQ, 4, 7)


def tlv(code: int, value: bytes) -> bytes:
    """A parameter of type ``code`` holding ``value``, padded to 8 octets."""
    record = struct.pack('!HH', code, len(value)) + value
    return record + bytes(-len(record) % 8)


def packet(ptype: int, sender: object, receiver: object, *params: bytes, version: int = 2) -> bytes:
    """A HIP packet, its Checksum non-zero as on the wire."""
    body = b''.join(params)
    return (bytes([59, (40 + len(body)) // 8 - 1, ptype, version << 4 | 1]) + b'\x5a\xa5'
            + b'\x00\x00' + sender.packed + receiver.packed + body)  # type: ignore[attr-defined]


def covered(octets: bytes) -> bytes:
    """``octets`` as RFC 8004 section 4.2.1 covers them: Checksum zeroed, Header Length
    counting them."""
    scope = bytearray(octets)
    scope[1] = len(scope) // 8 - 1
    scope[4:6] = b'\x00\x00'
    return bytes(scope)


def mac(key: bytes, octets: bytes) -> bytes:
    """The HMAC over what ``octets`` covers, with SHA-256, RHASH of the HITs' suite."""
    return hmac.new(key, covered(octets), 'sha256').digest()


def relay_addr(code: int, port: int = 50500) -> bytes:
    """A RELAY_FROM or RELAY_TO parameter: the Initiator's UDP address (RFC 9028 section 5.7)."""
    return tlv(code, struct.pack('!HBB', port, 17, 0) + ADDR_I.packed)


def flip(octets: bytes, at: int) -> bytes:
    """``octets`` with a bit of octet ``at`` flipped."""
    return octets[:at] + bytes([octets[at] ^ 1]) + octets[at + 1:]


class RegistrationTestCase(unittest.TestCase):
    """Imports and helpers every test here shares."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.const.hip.registration import Registration
        from pcapkit.protocols.internet.hip.protocol import (HIP, HIPAssociation, HIPAuthStatus,
                                                             HIPContext, HIPRegistration)
        from pcapkit.utilities.exceptions import ProtocolError
        from pcapkit.utilities.warnings import ProtocolWarning

        self.HIP, self.Parameter, self.Registration = HIP, Parameter, Registration
        self.Association, self.Context, self.Reg = HIPAssociation, HIPContext, HIPRegistration
        self.Status, self.ProtocolError, self.ProtocolWarning = HIPAuthStatus, ProtocolError, ProtocolWarning

    def parse(self, octets: bytes, *keys: object, context: object = ...) -> 'tuple[object, list[str]]':
        """``octets`` parsed as HIP with ``keys``, and the ProtocolWarnings it raised."""
        if context is ...:
            context = self.Context(*keys)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            layer = self.HIP(octets, context=context)
        return layer, [str(item.message) for item in caught
                       if issubclass(item.category, self.ProtocolWarning)]

    def status(self, octets: bytes, code: int, *keys: object) -> 'tuple[object, list[str]]':
        """The status the parameter ``code`` of ``octets`` records, and the warnings."""
        layer, messages = self.parse(octets, *keys)
        return layer.info.parameters[self.Parameter(code)].get('hmac_status'), messages

    def registration(self, *reg_type: int, gl: bytes = KEY_GL, lg: bytes = KEY_LG) -> object:
        """The Responder's registration with the server (RFC 8004 section 3.2)."""
        association = self.Association(HIT_R, HIT_S, integrity_gl=gl, integrity_lg=lg)
        return self.Reg(association, registrar=HIT_S, reg_type=reg_type)

    def peer(self) -> object:
        """The association of the Initiator and the Responder."""
        return self.Association(HIT_I, HIT_R, integrity_gl=PEER_GL, integrity_lg=PEER_LG)


class RVSHMACTests(RegistrationTestCase):
    """RVS_HMAC, RFC 8004 section 4.2.1."""

    def relayed_i1(self, key: bytes = KEY_GL, *after: bytes) -> bytes:
        """I1(RVS, R, HIT-I, HIT-R, FROM:I, RVS_HMAC), as the RVS relays it (RFC 8004
        section 3.3), its RVS_HMAC under ``key`` and ``after`` following it."""
        head = packet(I1, HIT_I, HIT_R, tlv(FROM, ADDR_I.packed))
        return packet(I1, HIT_I, HIT_R, tlv(FROM, ADDR_I.packed), tlv(RVS_HMAC, mac(key, head)), *after)

    def test_relayed_i1_is_under_the_servers_key(self) -> None:
        octets = self.relayed_i1()
        self.assertEqual(self.status(octets, RVS_HMAC, self.registration(RENDEZVOUS)),
                         (self.Status.VALID, []))
        # The server's HIT is the greater, so it sends under HIP-gl; HIP-lg is the client's.
        status, messages = self.status(self.relayed_i1(KEY_LG), RVS_HMAC, self.registration(RENDEZVOUS))
        self.assertIs(status, self.Status.INVALID)
        self.assertEqual(messages, ['HIPv2: RVS_HMAC: the HMAC does not verify'])

    def test_covers_the_header_and_the_from_before_it(self) -> None:
        octets = self.relayed_i1()
        # Packet Type, Version, Controls, and FROM's type and address: "especially the IP
        # address included in the FROM parameter" (RFC 8004 section 4.2.2).
        for at in (2, 3, 6, 40, 44, 59):
            with self.subTest(at=at):
                status, messages = self.status(flip(octets, at), RVS_HMAC, self.registration(RENDEZVOUS))
                self.assertIs(status, self.Status.INVALID)
                self.assertEqual(messages, ['HIPv2: RVS_HMAC: the HMAC does not verify'])
        # Not the Checksum, the HMAC's own padding, nor a parameter after it.
        octets = self.relayed_i1(KEY_GL, tlv(VIA_RVS, ADDR_I.packed))
        for at in (4, 5, 103, 115, len(octets) - 1):
            with self.subTest(at=at):
                self.assertEqual(self.status(flip(octets, at), RVS_HMAC, self.registration(RENDEZVOUS)),
                                 (self.Status.VALID, []))

    def test_header_length_and_checksum_as_the_rfc_sets_them(self) -> None:
        # "The HIP 'checksum' field MUST be set to zero, and the HIP header length ...
        # MUST be calculated not to cover any excluded parameter."
        head = bytearray(packet(I1, HIT_I, HIT_R, tlv(FROM, ADDR_I.packed)))
        on_wire = bytes(head[:1]) + bytes([head[1] + 5]) + bytes(head[2:4]) + bytes(2) + bytes(head[6:])
        with_checksum = bytes(head[:1]) + bytes([len(head) // 8 - 1]) + bytes(head[2:])
        for name, scope in (('header length', on_wire), ('checksum', with_checksum)):
            with self.subTest(name=name):
                digest = hmac.new(KEY_GL, scope, 'sha256').digest()
                octets = packet(I1, HIT_I, HIT_R, tlv(FROM, ADDR_I.packed), tlv(RVS_HMAC, digest))
                self.assertIs(self.status(octets, RVS_HMAC, self.registration(RENDEZVOUS))[0],
                              self.Status.INVALID)

    def test_packets_between_the_client_and_its_server(self) -> None:
        # "both SHOULD protect packets with an added RVS_HMAC": each under its own key,
        # covering the HIP_MAC of their association before it.
        association = self.Association(HIT_R, HIT_S, integrity_gl=KEY_GL, integrity_lg=KEY_LG)
        registration = self.Reg(association, registrar=HIT_S, reg_type=[RENDEZVOUS])
        for sender, receiver, key in ((HIT_R, HIT_S, KEY_LG), (HIT_S, HIT_R, KEY_GL)):
            with self.subTest(sender=str(sender)):
                hip_mac = tlv(HIP_MAC, mac(key, packet(UPDATE, sender, receiver, SEQ_TLV)))
                with_mac = packet(UPDATE, sender, receiver, SEQ_TLV, hip_mac)
                octets = packet(UPDATE, sender, receiver, SEQ_TLV, hip_mac, tlv(RVS_HMAC, mac(key, with_mac)))
                layer, messages = self.parse(octets, association, registration)
                params = layer.info.parameters
                self.assertEqual((params[self.Parameter.HIP_MAC].hmac_status,
                                  params[self.Parameter.RVS_HMAC].hmac_status, messages),
                                 (self.Status.VALID, self.Status.VALID, []))
                # Under the other side's key, it does not verify.
                other = KEY_GL if key == KEY_LG else KEY_LG
                swapped = packet(UPDATE, sender, receiver, SEQ_TLV, hip_mac,
                                 tlv(RVS_HMAC, mac(other, with_mac)))
                self.assertIs(self.status(swapped, RVS_HMAC, registration)[0], self.Status.INVALID)

    def test_no_registration_is_quiet_and_no_context_records_nothing(self) -> None:
        octets = self.relayed_i1()
        stranger = self.Reg(self.Association('2001:21::4', HIT_S, integrity_gl=KEY_GL, integrity_lg=KEY_LG),
                            registrar=HIT_S, reg_type=[RENDEZVOUS])
        # The peer's keys, a relay registration and another host's registration key no RVS_HMAC.
        for keys in ((), (self.peer(),), (self.registration(RELAY_UDP_HIP, RELAY_UDP_ESP),), (stranger,)):
            with self.subTest(keys=keys):
                self.assertEqual(self.status(octets, RVS_HMAC, *keys), (self.Status.NO_KEY, []))
        layer, messages = self.parse(octets, context=None)
        self.assertNotIn('hmac_status', layer.info.parameters[self.Parameter.RVS_HMAC])
        self.assertEqual(messages, [])

    def test_hip_version_1_is_not_verified(self) -> None:
        head = packet(I1, HIT_I, HIT_R, tlv(FROM, ADDR_I.packed), version=1)
        octets = packet(I1, HIT_I, HIT_R, tlv(FROM, ADDR_I.packed), tlv(RVS_HMAC, mac(KEY_GL, head)),
                        version=1)
        self.assertEqual(self.status(octets, RVS_HMAC, self.registration(RENDEZVOUS)),
                         (self.Status.UNSUPPORTED, ['HIPv1: RVS_HMAC: only HIP version 2 is verified']))

    def test_rebuilds_byte_for_byte_and_reports_the_status(self) -> None:
        octets = self.relayed_i1()
        layer, _ = self.parse(octets, self.registration(RENDEZVOUS))
        self.assertEqual(self.HIP.from_data(layer.info).data, octets)
        self.assertEqual(layer.info.to_dict()['parameters'][self.Parameter.RVS_HMAC]['hmac_status'],
                         self.Status.VALID)


class RelayHMACTests(RegistrationTestCase):
    """RELAY_HMAC, RFC 5770 section 5.8 and RFC 9028 section 5.8."""

    def relayed(self, ptype: int, key: bytes = KEY_GL, *params: bytes) -> bytes:
        """A packet of the Initiator's with ``params``, as the Control Relay Server relays
        it with RELAY_FROM and RELAY_HMAC (RFC 9028 section 4.5, steps 2 and 6)."""
        head = packet(ptype, HIT_I, HIT_R, *params, relay_addr(RELAY_FROM))
        return packet(ptype, HIT_I, HIT_R, *params, relay_addr(RELAY_FROM), tlv(RELAY_HMAC, mac(key, head)))

    def test_relayed_i1_under_either_relay_service(self) -> None:
        octets = self.relayed(I1)
        # A Data Relay Server relays control packets as a Control Relay Server does
        # (RFC 9028 section 4.12.2).
        for reg_type in (RELAY_UDP_HIP, RELAY_UDP_ESP):
            with self.subTest(reg_type=reg_type):
                self.assertEqual(self.status(octets, RELAY_HMAC, self.registration(reg_type)),
                                 (self.Status.VALID, []))
        self.assertEqual(self.status(octets, RELAY_HMAC, self.registration(RENDEZVOUS, CANDIDATE_DISCOVERY)),
                         (self.Status.NO_KEY, []))

    def test_covers_the_senders_hit_and_relay_from(self) -> None:
        octets = self.relayed(I1)
        # The Sender's HIT, which is not the registration's, and RELAY_FROM's port,
        # protocol and address.
        for at in (23, 44, 46, 63):
            with self.subTest(at=at):
                status, messages = self.status(flip(octets, at), RELAY_HMAC, self.registration(RELAY_UDP_HIP))
                self.assertIs(status, self.Status.INVALID)
                self.assertEqual(messages, ['HIPv2: RELAY_HMAC: the HMAC does not verify'])
        status, _ = self.status(self.relayed(I1, KEY_LG), RELAY_HMAC, self.registration(RELAY_UDP_HIP))
        self.assertIs(status, self.Status.INVALID)

    def test_relayed_i2_carries_both_keys(self) -> None:
        # The Initiator's HIP_MAC is under the peer association's key, which the relay's
        # RELAY_HMAC after it covers under the relay's.
        octets = self.relayed(I2, KEY_GL, tlv(HIP_MAC, mac(PEER_LG, packet(I2, HIT_I, HIT_R))))
        layer, messages = self.parse(octets, self.peer(), self.registration(RELAY_UDP_HIP))
        params = layer.info.parameters
        self.assertEqual((params[self.Parameter.HIP_MAC].hmac_status,
                          params[self.Parameter.RELAY_HMAC].hmac_status, messages),
                         (self.Status.VALID, self.Status.VALID, []))
        self.assertEqual(self.HIP.from_data(layer.info).data, octets)
        # Each key verifies only its own parameter.
        layer, _ = self.parse(octets, self.registration(RELAY_UDP_HIP))
        self.assertEqual((layer.info.parameters[self.Parameter.HIP_MAC].hmac_status,
                          layer.info.parameters[self.Parameter.RELAY_HMAC].hmac_status),
                         (self.Status.NO_KEY, self.Status.VALID))

    def test_the_clients_r1_to_the_relay_is_under_its_own_key(self) -> None:
        # R1(RELAY_TO) on its way to the relay is the client's packet, under HIP-lg: RFC
        # 8004 section 4.2.1 has both sides protect what they exchange.
        head = packet(R1, HIT_R, HIT_I, relay_addr(RELAY_TO))
        octets = packet(R1, HIT_R, HIT_I, relay_addr(RELAY_TO), tlv(RELAY_HMAC, mac(KEY_LG, head)))
        self.assertEqual(self.status(octets, RELAY_HMAC, self.registration(RELAY_UDP_HIP)),
                         (self.Status.VALID, []))
        self.assertIs(self.status(flip(octets, 63), RELAY_HMAC, self.registration(RELAY_UDP_HIP))[0],
                      self.Status.INVALID)
        # Under the relay's key, it does not verify.
        swapped = packet(R1, HIT_R, HIT_I, relay_addr(RELAY_TO), tlv(RELAY_HMAC, mac(KEY_GL, head)))
        self.assertIs(self.status(swapped, RELAY_HMAC, self.registration(RELAY_UDP_HIP))[0],
                      self.Status.INVALID)


class AmbiguousRegistrationTests(RegistrationTestCase):
    """Registrations a packet's HITs do not tell apart are each tried, in either order."""

    def test_two_clients_of_one_registrar(self) -> None:
        # I and R are both clients of S, which relays I's I1 to R under its key for R;
        # I's registration matches the packet too, by its Sender's HIT.
        reg_i = self.Reg(self.Association(HIT_I, HIT_S, integrity_gl=KEY2_GL, integrity_lg=KEY2_LG),
                         registrar=HIT_S, reg_type=[RENDEZVOUS])
        head = packet(I1, HIT_I, HIT_R, tlv(FROM, ADDR_I.packed))
        octets = packet(I1, HIT_I, HIT_R, tlv(FROM, ADDR_I.packed), tlv(RVS_HMAC, mac(KEY_GL, head)))
        for keys in ((reg_i, self.registration(RENDEZVOUS)), (self.registration(RENDEZVOUS), reg_i)):
            with self.subTest(first=str(keys[0].requester)):
                self.assertEqual(self.status(octets, RVS_HMAC, *keys), (self.Status.VALID, []))
                self.assertEqual(self.status(flip(octets, 59), RVS_HMAC, *keys),
                                 (self.Status.INVALID, ['HIPv2: RVS_HMAC: the HMAC does not verify']))

    def test_two_relay_clients_answering_each_other(self) -> None:
        # R answers I's relayed I1 with an R1 through their common relay, under R's key;
        # I's registration matches it too, by its Receiver's HIT.
        reg_i = self.Reg(self.Association(HIT_I, HIT_S, integrity_gl=KEY2_GL, integrity_lg=KEY2_LG),
                         registrar=HIT_S, reg_type=[RELAY_UDP_HIP])
        head = packet(R1, HIT_R, HIT_I, relay_addr(RELAY_TO))
        octets = packet(R1, HIT_R, HIT_I, relay_addr(RELAY_TO), tlv(RELAY_HMAC, mac(KEY_LG, head)))
        for keys in ((reg_i, self.registration(RELAY_UDP_HIP)), (self.registration(RELAY_UDP_HIP), reg_i)):
            with self.subTest(first=str(keys[0].requester)):
                self.assertEqual(self.status(octets, RELAY_HMAC, *keys), (self.Status.VALID, []))

    def test_two_registrars_of_one_requester(self) -> None:
        # R is registered with S and with S2, which relays under HIP-lg as HOST_l (RFC
        # 7401 section 6.5); the packet names neither server. The requester's own keys
        # verify nothing it receives.
        reg_s2 = self.Reg(self.Association(HIT_R, HIT_S2, integrity_gl=KEY2_GL, integrity_lg=KEY2_LG),
                          registrar=HIT_S2, reg_type=[RENDEZVOUS])
        head = packet(I1, HIT_I, HIT_R, tlv(FROM, ADDR_I.packed))
        for key, expected in ((KEY2_LG, self.Status.VALID), (KEY_GL, self.Status.VALID),
                              (KEY2_GL, self.Status.INVALID), (KEY_LG, self.Status.INVALID)):
            octets = packet(I1, HIT_I, HIT_R, tlv(FROM, ADDR_I.packed), tlv(RVS_HMAC, mac(key, head)))
            for keys in ((self.registration(RENDEZVOUS), reg_s2), (reg_s2, self.registration(RENDEZVOUS))):
                with self.subTest(key=key[0], first=str(keys[0].registrar)):
                    status, messages = self.status(octets, RVS_HMAC, *keys)
                    self.assertIs(status, expected)
                    self.assertEqual(len(messages), int(expected is self.Status.INVALID))


class RegistrationKeyTests(RegistrationTestCase):
    """HIPRegistration, its HIPContext lookup, and REGISTRATION_HMAC."""

    def test_registration_types_key_the_rfcs_parameters(self) -> None:
        from pcapkit.protocols.internet.hip.const import REGISTRATION_HMAC

        self.assertEqual(REGISTRATION_HMAC, {
            self.Parameter.RVS_HMAC: (self.Registration.RENDEZVOUS,),
            self.Parameter.RELAY_HMAC: (self.Registration.RELAY_UDP_HIP, self.Registration.RELAY_UDP_ESP),
        })

    def test_properties_and_repr_hold_no_key(self) -> None:
        registration = self.registration(RENDEZVOUS, self.Registration.RELAY_UDP_HIP)
        self.assertEqual((registration.requester, registration.registrar), (HIT_R, HIT_S))
        self.assertEqual(registration.reg_type, (self.Registration.RENDEZVOUS, self.Registration.RELAY_UDP_HIP))
        self.assertIs(type(registration.reg_type[0]), self.Registration)
        self.assertEqual(int(registration.association.responder), int(HIT_S))
        self.assertEqual(repr(registration), '<HIPRegistration requester=2001:21::2 '
                                             'registrar=2001:21::3 reg_type=RENDEZVOUS,RELAY_UDP_HIP>')
        # The registrar may have been the Initiator, registering over an UPDATE.
        by_update = self.Reg(self.Association(HIT_S, HIT_R, integrity_gl=KEY_GL, integrity_lg=KEY_LG),
                             registrar=HIT_S.packed, reg_type=[RENDEZVOUS])
        self.assertEqual((by_update.requester, by_update.registrar), (HIT_R, HIT_S))

    def test_matches_and_computes_under_the_sending_side(self) -> None:
        registration = self.registration(RENDEZVOUS)
        for sender, receiver, matched, key in ((HIT_I, HIT_R, True, KEY_GL), (HIT_S, HIT_R, True, KEY_GL),
                                               (HIT_R, HIT_S, True, KEY_LG), (HIT_R, HIT_I, True, KEY_LG),
                                               (HIT_I, HIT_S, False, None), (HIT_S, HIT_I, False, None)):
            with self.subTest(sender=str(sender), receiver=str(receiver)):
                self.assertIs(registration.matches(sender, receiver), matched)
                if key is None:
                    with self.assertRaises(self.ProtocolError):
                        registration.compute_hmac(sender, receiver, b'data')
                else:
                    self.assertEqual(registration.compute_hmac(str(sender), int(receiver), b'data'),
                                     hmac.new(key, b'data', 'sha256').digest())

    def test_refuses_bad_arguments(self) -> None:
        association = self.Association(HIT_R, HIT_S, integrity_gl=KEY_GL, integrity_lg=KEY_LG)
        cases = [
            ((b'key',), {'registrar': HIT_S, 'reg_type': [RENDEZVOUS]}),
            ((association,), {'registrar': HIT_I, 'reg_type': [RENDEZVOUS]}),
            ((association,), {'registrar': True, 'reg_type': [RENDEZVOUS]}),
            ((association,), {'registrar': HIT_S, 'reg_type': [True]}),
            ((association,), {'registrar': HIT_S, 'reg_type': ['RENDEZVOUS']}),
            ((association,), {'registrar': HIT_S, 'reg_type': [256]}),
        ]
        for args, kwargs in cases:
            with self.subTest(args=args, kwargs=kwargs), self.assertRaises(self.ProtocolError):
                self.Reg(*args, **kwargs)

    def test_context_registers_and_matches(self) -> None:
        rendezvous, relay = self.registration(RENDEZVOUS), self.registration(RELAY_UDP_ESP)
        context = self.Context(self.peer(), rendezvous, relay)
        self.assertEqual(context.registrations, (rendezvous, relay))
        self.assertEqual(repr(context), '<HIPContext identities=0 associations=1 registrations=2>')
        self.assertEqual(context.match_registrations(HIT_I, HIT_R, reg_type=[RENDEZVOUS]), (rendezvous,))
        self.assertEqual(context.match_registrations(HIT_I, HIT_R, reg_type=(RENDEZVOUS, RELAY_UDP_ESP)),
                         (rendezvous, relay))
        self.assertEqual(context.match_registrations(HIT_I, HIT_R, reg_type=[RELAY_UDP_HIP]), ())
        self.assertEqual(context.match_registrations(HIT_I, HIT_S, reg_type=[RENDEZVOUS]), ())
        with self.assertRaises(self.ProtocolError):
            context.register(rendezvous.association.integrity_gl)


if __name__ == '__main__':
    unittest.main()
