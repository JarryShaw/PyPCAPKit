from __future__ import annotations

import datetime
import importlib.util
import types
from ipaddress import ip_address
import unittest
from unittest import mock

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


class DummyDict(dict):
    __getattr__ = dict.__getitem__


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class HIPUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_hip_index_length_alias_and_make_data(self) -> None:
        from pcapkit.const.hip.packet import Packet
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.hip import HIP

        data = DummyDict(
            next=TransType.TCP,
            type=Packet.I1,
            version=2,
            chksum=b'\x12\x34',
            control=DummyDict(anonymous=True),
            shit=b'source-hit',
            rhit=b'recv-hit',
            parameters=['param'],
            length=40,
            __next_type__=None,
        )
        proto = object.__new__(HIP)
        proto._info = data
        proto._extf = False
        proto._next = 'payload'
        proto._protos = ['TCP']

        self.assertEqual(HIP.__index__(), TransType.HIP)
        self.assertEqual(proto.__length_hint__(), 40)
        self.assertEqual(proto.name, 'Host Identity Protocol')
        self.assertEqual(proto.alias, 'HIPv2')
        self.assertEqual(proto.length, 40)
        self.assertEqual(proto.payload, 'payload')
        self.assertEqual(proto.protocol, 'TCP')
        self.assertEqual(proto.protochain, ['TCP'])
        values = HIP._make_data(data)
        self.assertEqual(values['next'], TransType.TCP)
        self.assertEqual(values['packet'], Packet.I1)
        self.assertEqual(values['version'], 2)
        self.assertEqual(values['checksum'], b'\x12\x34')
        self.assertEqual(values['controls_anonymous'], True)
        self.assertEqual(values['shit'], b'source-hit')
        self.assertEqual(values['rhit'], b'recv-hit')
        self.assertEqual(values['parameters'], ['param'])
        self.assertIn('payload', values)

    def test_hip_read_make_post_init_and_parameter_list_edges(self) -> None:
        from pcapkit.const.hip.packet import Packet
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.data.internet import hip as hip_data
        from pcapkit.protocols.internet.hip import HIP
        from pcapkit.protocols.internet.internet import Internet
        from pcapkit.protocols.schema.internet import hip as hip_schema
        from pcapkit.utilities.exceptions import ProtocolError, UnsupportedCall

        proto = object.__new__(HIP)
        proto._info = DummyDict(version=2, length=40)
        proto._extf = False
        proto._next = 'payload'
        proto._protos = ['UDP']
        proto._data = b'\x00' * 40
        proto.__cached__ = {}
        proto.__header__ = hip_schema.HIP(
            next=TransType.UDP,
            len=4,
            pkt={'bit_0': 0, 'type': Packet.I1},
            ver={'bit_1': 1, 'version': 2},
            checksum=b'\x12\x34',
            control={'anonymous': 1},
            shit=1,
            rhit=2,
            param=[],
            payload=b'data',
        )

        parsed = proto.read(length=40, extension=True)
        self.assertEqual(parsed.next, TransType.UDP)
        self.assertEqual(parsed.length, 40)
        self.assertEqual(parsed.type, Packet.I1)
        self.assertTrue(parsed.control.anonymous)

        with mock.patch.object(HIP, '_decode_next_layer', return_value='decoded') as decode:
            self.assertEqual(proto.read(length=40), 'decoded')
        decode.assert_called_once()

        with self.assertRaises(ProtocolError):
            proto.__header__ = hip_schema.HIP(
                next=TransType.UDP,
                len=4,
                pkt={'bit_0': 1, 'type': Packet.I1},
                ver={'bit_1': 1, 'version': 2},
                checksum=b'\x00\x00',
                control={'anonymous': 0},
                shit=0,
                rhit=0,
                param=[],
                payload=b'',
            )
            proto.read(length=40, extension=True)

        with self.assertRaises(ProtocolError):
            proto.__header__ = hip_schema.HIP(
                next=TransType.UDP,
                len=4,
                pkt={'bit_0': 0, 'type': Packet.I1},
                ver={'bit_1': 0, 'version': 2},
                checksum=b'\x00\x00',
                control={'anonymous': 0},
                shit=0,
                rhit=0,
                param=[],
                payload=b'',
            )
            proto.read(length=40, extension=True)

        proto._extf = True
        with self.assertRaises(UnsupportedCall):
            _ = proto.payload
        with self.assertRaises(UnsupportedCall):
            _ = proto.protocol
        with self.assertRaises(UnsupportedCall):
            _ = proto.protochain

        made = proto.make(
            next=TransType.TCP,
            packet=Packet.I2,
            version=2,
            checksum=b'\xab\xcd',
            controls_anonymous=True,
            shit=3,
            rhit=4,
            parameters=[(Parameter.ESP_INFO, {'index': 1, 'old_spi': 2, 'new_spi': 3})],
            payload=b'tcp',
        )
        self.assertEqual(made.next, TransType.TCP)
        self.assertEqual(made.pkt['type'], Packet.I2)
        self.assertTrue(made.control['anonymous'])
        self.assertGreater(made.len, 4)

        unassigned = hip_schema.UnassignedParameter(
            type=Parameter.Unassigned_65499,
            len=3,
            value=b'raw',
        )
        params, total = proto._make_hip_param([
            b'\x00' * 8,
            unassigned,
            (Parameter.ESP_INFO, {'index': 5, 'old_spi': 6, 'new_spi': 7}),
        ], version=2)
        self.assertEqual(params[0], b'\x00' * 8)
        self.assertIsInstance(params[1], bytes)
        self.assertGreater(total, 16)

        param_dict = OrderedMultiDict([
            (Parameter.ESP_INFO, hip_data.ESPInfoParameter(
                type=Parameter.ESP_INFO,
                critical=True,
                length=16,
                index=8,
                old_spi=9,
                new_spi=10,
            )),
        ])
        dict_params, dict_total = proto._make_hip_param(param_dict, version=2)
        self.assertEqual(dict_params[0].index, 8)
        self.assertGreaterEqual(dict_total, 16)

        proto.__header__ = DummyDict(param=[unassigned])
        parsed_params = proto._read_hip_param(len(unassigned), version=2)
        self.assertEqual(parsed_params[Parameter.Unassigned_65499].contents, b'raw')
        with self.assertRaises(ProtocolError):
            proto._read_hip_param(len(unassigned) + 1, version=2)

        with mock.patch.object(Internet, '__post_init__', return_value=None) as post_init:
            post_proto = object.__new__(HIP)
            post_proto.__post_init__(extension=True, custom=True)
        self.assertTrue(post_proto._extf)
        post_init.assert_called_once()

        param_options = OrderedMultiDict([
            (Parameter.ESP_INFO, hip_data.ESPInfoParameter(
                type=Parameter.ESP_INFO,
                critical=True,
                length=16,
                index=1,
                old_spi=2,
                new_spi=3,
            )),
        ])
        proto.__header__ = hip_schema.HIP(
            next=TransType.UDP,
            len=5,
            pkt={'bit_0': 0, 'type': Packet.I1},
            ver={'bit_1': 1, 'version': 2},
            checksum=b'\x12\x34',
            control={'anonymous': 1},
            shit=1,
            rhit=2,
            param=[],
            payload=b'data',
        )
        proto._data = b'\x00' * 48
        with mock.patch.object(proto, '_read_hip_param', return_value=param_options) as read_params:
            parsed_with_param = proto.read(extension=True)
        read_params.assert_called_once_with(8, version=2)
        self.assertEqual(parsed_with_param.parameters[Parameter.ESP_INFO].index, 1)
        self.assertEqual(proto.make(parameters=None).len, 0)

    def test_hip_register_parameter_warns_on_overwrite(self) -> None:
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.data.internet import hip as hip_data
        from pcapkit.protocols.internet.hip import HIP
        from pcapkit.protocols.schema.internet import hip as hip_schema

        read_name = f'_read_param_{Parameter.ESP_INFO.name.lower()}'
        make_name = f'_make_param_{Parameter.ESP_INFO.name.lower()}'
        original_read = getattr(HIP, read_name)
        original_make = getattr(HIP, make_name)
        try:
            with mock.patch('pcapkit.protocols.internet.hip.warn') as warn:
                HIP.register_parameter(Parameter.ESP_INFO, 'esp_info')
            warn.assert_called_once()
            self.assertIs(getattr(HIP, read_name), original_read)
            self.assertIs(getattr(HIP, make_name), original_make)
        finally:
            setattr(HIP, read_name, original_read)
            setattr(HIP, make_name, original_make)

        custom = Parameter.Unassigned_65501
        custom_read_name = f'_read_param_{custom.name.lower()}'
        custom_make_name = f'_make_param_{custom.name.lower()}'
        original_custom_read = getattr(HIP, custom_read_name, None)
        original_custom_make = getattr(HIP, custom_make_name, None)

        def read_param(packet, *, version, options):
            return hip_data.UnassignedParameter(type=packet.type, critical=False,
                                                length=4, contents=packet.value)

        def make_param(code, param=None, *, version, contents=b'', **kwargs):
            return hip_schema.UnassignedParameter(type=code, len=len(contents),
                                                  value=contents)

        try:
            with mock.patch('pcapkit.protocols.internet.hip.warn') as warn:
                HIP.register_parameter(custom, (read_param, make_param))
            warn.assert_not_called()
            self.assertIs(getattr(HIP, custom_read_name), read_param)
            self.assertIs(getattr(HIP, custom_make_name), make_param)
        finally:
            if original_custom_read is None:
                delattr(HIP, custom_read_name)
            else:
                setattr(HIP, custom_read_name, original_custom_read)
            if original_custom_make is None:
                delattr(HIP, custom_make_name)
            else:
                setattr(HIP, custom_make_name, original_custom_make)

    def test_hip_parameter_readers_cover_simple_models_and_guards(self) -> None:
        from pcapkit.const.hip.certificate import Certificate
        from pcapkit.const.hip.cipher import Cipher
        from pcapkit.const.hip.di import DITypes
        from pcapkit.const.hip.ecdsa_curve import ECDSACurve
        from pcapkit.const.hip.ecdsa_low_curve import ECDSALowCurve
        from pcapkit.const.hip.eddsa_curve import EdDSACurve
        from pcapkit.const.hip.esp_transform_suite import ESPTransformSuite
        from pcapkit.const.hip.group import Group
        from pcapkit.const.hip.hi_algorithm import HIAlgorithm
        from pcapkit.const.hip.hit_suite import HITSuite
        from pcapkit.const.hip.nat_traversal import NATTraversal
        from pcapkit.const.hip.notify_message import NotifyMessage
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.const.hip.registration import Registration
        from pcapkit.const.hip.registration_failure import RegistrationFailure
        from pcapkit.const.hip.suite import Suite
        from pcapkit.const.hip.transport import Transport
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.internet.hip import HIP
        from pcapkit.protocols.schema.internet import hip as hip_schema
        from pcapkit.utilities.exceptions import ProtocolError

        proto = object.__new__(HIP)
        options = OrderedMultiDict()

        self.assertEqual(proto._read_param_unassigned(
            hip_schema.UnassignedParameter(type=Parameter.Unassigned_65499, len=3, value=b'raw'),
            version=2,
            options=options,
        ).contents, b'raw')
        self.assertEqual(proto._read_param_esp_info(
            hip_schema.ESPInfoParameter(type=Parameter.ESP_INFO, len=12,
                                        index=1, old_spi=2, new_spi=3),
            version=2,
            options=options,
        ).new_spi, 3)
        with self.assertRaises(ProtocolError):
            proto._read_param_esp_info(
                hip_schema.ESPInfoParameter(type=Parameter.ESP_INFO, len=8,
                                            index=1, old_spi=2, new_spi=3),
                version=2,
                options=options,
            )

        self.assertEqual(proto._read_param_r1_counter(
            hip_schema.R1CounterParameter(type=Parameter.R1_COUNTER, len=12, counter=9),
            version=1,
            options=options,
        ).counter, 9)
        with self.assertRaises(ProtocolError):
            proto._read_param_r1_counter(
                hip_schema.R1CounterParameter(type=Parameter.R1_Counter, len=12, counter=9),
                version=2,
                options=options,
            )

        locator_set = proto._read_param_locator_set(
            hip_schema.LocatorSetParameter(
                type=Parameter.LOCATOR_SET,
                len=48,
                locators=[
                    hip_schema.Locator(traffic=1, type=0, len=4,
                                       flags={'preferred': 1}, lifetime=5,
                                       value=ip_address('2001:db8::1')),
                    hip_schema.Locator(traffic=2, type=1, len=5,
                                       flags={'preferred': 0}, lifetime=6,
                                       value=hip_schema.LocatorData(
                                           spi=7,
                                           ip=ip_address('2001:db8::2'),
                                       )),
                ],
            ),
            version=2,
            options=options,
        )
        self.assertEqual(len(locator_set.locator_set), 2)
        self.assertEqual(locator_set.locator_set[1].locator.spi, 7)
        with self.assertRaises(ProtocolError):
            proto._read_param_locator_set(
                hip_schema.LocatorSetParameter(
                    type=Parameter.LOCATOR_SET,
                    len=8,
                    locators=[hip_schema.Locator(traffic=1, type=3, len=4,
                                                 flags={'preferred': 0}, lifetime=1,
                                                 value=ip_address('2001:db8::1'))],
                ),
                version=2,
                options=options,
            )

        self.assertEqual(proto._read_param_puzzle(
            hip_schema.PuzzleParameter(type=Parameter.PUZZLE, len=8, index=1,
                                       lifetime=32, opaque=b'op', random=5),
            version=2,
            options=options,
        ).lifetime, datetime.timedelta(seconds=1))
        with self.assertRaises(ProtocolError):
            proto._read_param_puzzle(
                hip_schema.PuzzleParameter(type=Parameter.PUZZLE, len=8, index=1,
                                           lifetime=32, opaque=b'op', random=5),
                version=1,
                options=options,
            )
        self.assertEqual(proto._read_param_solution(
            hip_schema.SolutionParameter(type=Parameter.SOLUTION, len=8, index=1,
                                         lifetime=32, opaque=b'op', random=5, solution=6),
            version=2,
            options=options,
        ).solution, 6)
        with self.assertRaises(ProtocolError):
            proto._read_param_solution(
                hip_schema.SolutionParameter(type=Parameter.SOLUTION, len=9, index=1,
                                             lifetime=32, opaque=b'op', random=5, solution=6),
                version=2,
                options=options,
            )

        self.assertEqual(proto._read_param_seq(
            hip_schema.SEQParameter(type=Parameter.SEQ, len=4, update_id=11),
            version=2,
            options=options,
        ).id, 11)
        self.assertEqual(proto._read_param_ack(
            hip_schema.ACKParameter(type=Parameter.ACK, len=8, update_id=[11, 12]),
            version=2,
            options=options,
        ).update_id, (11, 12))
        self.assertEqual(proto._read_param_dh_group_list(
            hip_schema.DHGroupListParameter(type=Parameter.DH_GROUP_LIST, len=1,
                                            groups=[Group.NIST_P_256]),
            version=2,
            options=options,
        ).group_id, (Group.NIST_P_256,))
        self.assertEqual(proto._read_param_diffie_hellman(
            hip_schema.DiffieHellmanParameter(type=Parameter.DIFFIE_HELLMAN, len=4,
                                              group=Group.NIST_P_256,
                                              pub_len=1, pub_val=5),
            version=2,
            options=options,
        ).pub_val, 5)

        self.assertEqual(proto._read_param_hip_transform(
            hip_schema.HIPTransformParameter(type=Parameter.HIP_TRANSFORM, len=2,
                                             suites=[Suite.AES_CBC_with_HMAC_SHA1]),
            version=1,
            options=options,
        ).suite_id, (Suite.AES_CBC_with_HMAC_SHA1,))
        with self.assertRaises(ProtocolError):
            proto._read_param_hip_transform(
                hip_schema.HIPTransformParameter(type=Parameter.HIP_TRANSFORM, len=2,
                                                 suites=[Suite.AES_CBC_with_HMAC_SHA1]),
                version=2,
                options=options,
            )
        with mock.patch('pcapkit.protocols.internet.hip.warn') as warn:
            hip_cipher = proto._read_param_hip_cipher(
                hip_schema.HIPCipherParameter(type=Parameter.HIP_CIPHER, len=12,
                                              ciphers=[Cipher.NULL_ENCRYPT] * 6),
                version=2,
                options=options,
            )
        self.assertEqual(len(hip_cipher.cipher_id), 6)
        warn.assert_called_once()
        self.assertEqual(proto._read_param_nat_traversal_mode(
            hip_schema.NATTraversalModeParameter(type=Parameter.NAT_TRAVERSAL_MODE, len=4,
                                                 modes=[NATTraversal.UDP_ENCAPSULATION]),
            version=2,
            options=options,
        ).mode_id, (NATTraversal.UDP_ENCAPSULATION,))
        self.assertEqual(proto._read_param_transaction_pacing(
            hip_schema.TransactionPacingParameter(type=Parameter.TRANSACTION_PACING,
                                                  len=4, min_ta=10),
            version=2,
            options=options,
        ).min_ta, 10)
        encrypted_schema = hip_schema.EncryptedParameter(type=Parameter.ENCRYPTED, len=8,
                                                         iv=b'iv', data=b'data')
        encrypted_schema.cipher = Cipher.NULL_ENCRYPT
        self.assertEqual(proto._read_param_encrypted(
            encrypted_schema,
            version=2,
            options=options,
        ).data, b'data')

        for algorithm, identity in [
            (HIAlgorithm.ECDSA, hip_schema.ECDSACurveHostIdentity(
                curve=ECDSACurve.NIST_P_256, pub_key=b'ec')),
            (HIAlgorithm.ECDSA_LOW, hip_schema.ECDSALowCurveHostIdentity(
                curve=ECDSALowCurve.SECP160R1, pub_key=b'lo')),
            (HIAlgorithm.EdDSA, hip_schema.EdDSACurveHostIdentity(
                curve=EdDSACurve.EdDSA25519, pub_key=b'ed')),
            (HIAlgorithm.RSA, b'rsa'),
        ]:
            host_id = proto._read_param_host_id(
                hip_schema.HostIDParameter(type=Parameter.HOST_ID, len=12,
                                           hi_len=3, di_data={'type': DITypes.FQDN, 'len': 2},
                                           algorithm=algorithm, hi=identity, di=b'id'),
                version=2,
                options=options,
            )
            self.assertEqual(host_id.algorithm, algorithm)

        self.assertEqual(proto._read_param_hit_suite_list(
            hip_schema.HITSuiteListParameter(type=Parameter.HIT_SUITE_LIST, len=1,
                                             suites=[HITSuite.ECDSA_SHA_384]),
            version=2,
            options=options,
        ).suite_id, (HITSuite.ECDSA_SHA_384,))
        self.assertEqual(proto._read_param_cert(
            hip_schema.CertParameter(type=Parameter.CERT, len=8,
                                     cert_group=Group.NIST_P_256,
                                     cert_count=1, cert_id=2,
                                     cert_type=Certificate.X_509_v3,
                                     cert=b'cert'),
            version=2,
            options=options,
        ).cert, b'cert')
        self.assertEqual(proto._read_param_notification(
            hip_schema.NotificationParameter(type=Parameter.NOTIFICATION, len=6,
                                             msg_type=NotifyMessage.INVALID_SYNTAX,
                                             msg=b'no'),
            version=2,
            options=options,
        ).msg, b'no')
        self.assertEqual(proto._read_param_echo_request_signed(
            hip_schema.EchoRequestSignedParameter(type=Parameter.ECHO_REQUEST_SIGNED,
                                                  len=2, opaque=b'er'),
            version=2,
            options=options,
        ).opaque, b'er')
        self.assertEqual(proto._read_param_echo_response_signed(
            hip_schema.EchoResponseSignedParameter(type=Parameter.ECHO_RESPONSE_SIGNED,
                                                   len=2, opaque=b'es'),
            version=2,
            options=options,
        ).opaque, b'es')
        self.assertEqual(proto._read_param_echo_request_unsigned(
            hip_schema.EchoRequestUnsignedParameter(type=Parameter.ECHO_REQUEST_UNSIGNED,
                                                    len=2, opaque=b'ur'),
            version=2,
            options=options,
        ).opaque, b'ur')
        self.assertEqual(proto._read_param_echo_response_unsigned(
            hip_schema.EchoResponseUnsignedParameter(type=Parameter.ECHO_RESPONSE_UNSIGNED,
                                                     len=2, opaque=b'us'),
            version=2,
            options=options,
        ).opaque, b'us')

        self.assertEqual(proto._read_param_reg_info(
            hip_schema.RegInfoParameter(type=Parameter.REG_INFO, len=3,
                                        min_lifetime=1, max_lifetime=2,
                                        reg_info=[Registration.RENDEZVOUS]),
            version=2,
            options=options,
        ).lifetime.max, datetime.timedelta(seconds=2))
        self.assertEqual(proto._read_param_reg_request(
            hip_schema.RegRequestParameter(type=Parameter.REG_REQUEST, len=2,
                                           lifetime=3,
                                           reg_request=[Registration.RELAY_UDP_HIP]),
            version=2,
            options=options,
        ).reg_type, (Registration.RELAY_UDP_HIP,))
        self.assertEqual(proto._read_param_reg_response(
            hip_schema.RegResponseParameter(type=Parameter.REG_RESPONSE, len=2,
                                            lifetime=4,
                                            reg_response=[Registration.RELAY_UDP_ESP]),
            version=2,
            options=options,
        ).lifetime, datetime.timedelta(seconds=4))
        self.assertEqual(proto._read_param_reg_failed(
            hip_schema.RegFailedParameter(type=Parameter.REG_FAILED, len=2,
                                          lifetime=5,
                                          reg_failed=[RegistrationFailure.Insufficient_resources]),
            version=2,
            options=options,
        ).reg_type, (RegistrationFailure.Insufficient_resources,))

        self.assertEqual(proto._read_param_reg_from(
            hip_schema.RegFromParameter(type=Parameter.REG_FROM, len=20,
                                        port=10500, protocol=TransType.UDP,
                                        address=ip_address('2001:db8::10')),
            version=2,
            options=options,
        ).port, 10500)
        self.assertEqual(proto._read_param_transport_format_list(
            hip_schema.TransportFormatListParameter(type=Parameter.TRANSPORT_FORMAT_LIST,
                                                    len=2,
                                                    formats=[Parameter.ESP_INFO]),
            version=2,
            options=options,
        ).tf_type, (Parameter.ESP_INFO,))
        self.assertEqual(proto._read_param_esp_transform(
            hip_schema.ESPTransformParameter(type=Parameter.ESP_TRANSFORM, len=2,
                                             suites=[ESPTransformSuite.AES_128_CBC_with_HMAC_SHA1]),
            version=2,
            options=options,
        ).suite_id, (ESPTransformSuite.AES_128_CBC_with_HMAC_SHA1,))
        self.assertEqual(proto._read_param_seq_data(
            hip_schema.SeqDataParameter(type=Parameter.SEQ_DATA, len=4, seq=77),
            version=2,
            options=options,
        ).seq, 77)
        self.assertEqual(proto._read_param_ack_data(
            hip_schema.AckDataParameter(type=Parameter.ACK_DATA, len=8, ack=[1, 2]),
            version=2,
            options=options,
        ).ack, (1, 2))
        self.assertEqual(proto._read_param_payload_mic(
            hip_schema.PayloadMICParameter(type=Parameter.PAYLOAD_MIC, len=8,
                                           next=TransType.TCP,
                                           payload=b'payload',
                                           mic=b'mic'),
            version=2,
            options=options,
        ).next, TransType.TCP)
        self.assertEqual(proto._read_param_transaction_id(
            hip_schema.TransactionIDParameter(type=Parameter.TRANSACTION_ID, len=4, id=88),
            version=2,
            options=options,
        ).id, 88)
        self.assertEqual(proto._read_param_overlay_id(
            hip_schema.OverlayIDParameter(type=Parameter.OVERLAY_ID, len=4, id=99),
            version=2,
            options=options,
        ).id, 99)
        self.assertTrue(proto._read_param_route_dst(
            hip_schema.RouteDstParameter(type=Parameter.ROUTE_DST, len=20,
                                         flags={'symmetric': 1, 'must_follow': 1},
                                         hit=[ip_address('2001:db8::20')]),
            version=2,
            options=options,
        ).flags.symmetric)
        self.assertEqual(proto._read_param_hip_transport_mode(
            hip_schema.HIPTransportModeParameter(type=Parameter.HIP_TRANSPORT_MODE,
                                                 len=4, port=5050,
                                                 mode=[Transport.DEFAULT]),
            version=2,
            options=options,
        ).mode_id, (Transport.DEFAULT,))
        self.assertEqual(proto._read_param_hip_mac(
            hip_schema.HIPMACParameter(type=Parameter.HIP_MAC, len=4, hmac=b'hmac'),
            version=2,
            options=options,
        ).hmac, b'hmac')
        self.assertEqual(proto._read_param_hip_mac_2(
            hip_schema.HIPMAC2Parameter(type=Parameter.HIP_MAC_2, len=5, hmac=b'hmac2'),
            version=2,
            options=options,
        ).hmac, b'hmac2')
        self.assertEqual(proto._read_param_hip_signature_2(
            hip_schema.HIPSignature2Parameter(type=Parameter.HIP_SIGNATURE_2,
                                              len=5, algorithm=HIAlgorithm.RSA,
                                              signature=b'sig'),
            version=2,
            options=options,
        ).signature, b'sig')
        self.assertEqual(proto._read_param_hip_signature(
            hip_schema.HIPSignatureParameter(type=Parameter.HIP_SIGNATURE,
                                             len=5, algorithm=HIAlgorithm.RSA,
                                             signature=b'sig'),
            version=2,
            options=options,
        ).signature, b'sig')
        self.assertEqual(proto._read_param_relay_from(
            hip_schema.RelayFromParameter(type=Parameter.RELAY_FROM, len=20,
                                          port=10501, protocol=TransType.UDP,
                                          address=ip_address('2001:db8::30')),
            version=2,
            options=options,
        ).port, 10501)
        self.assertEqual(proto._read_param_relay_to(
            hip_schema.RelayToParameter(type=Parameter.RELAY_TO, len=20,
                                        port=10502, protocol=TransType.UDP,
                                        address=ip_address('2001:db8::31')),
            version=2,
            options=options,
        ).port, 10502)
        self.assertEqual(proto._read_param_overlay_ttl(
            hip_schema.OverlayTTLParameter(type=Parameter.OVERLAY_TTL, len=4, ttl=30),
            version=2,
            options=options,
        ).ttl, datetime.timedelta(seconds=30))
        self.assertTrue(proto._read_param_route_via(
            hip_schema.RouteViaParameter(type=Parameter.ROUTE_VIA, len=20,
                                         flags={'symmetric': 1, 'must_follow': 0},
                                         hit=[ip_address('2001:db8::40')]),
            version=2,
            options=options,
        ).flags.symmetric)
        self.assertEqual(proto._read_param_from(
            hip_schema.FromParameter(type=Parameter.FROM, len=16,
                                     address=ip_address('2001:db8::50')),
            version=2,
            options=options,
        ).address, ip_address('2001:db8::50'))
        self.assertEqual(proto._read_param_rvs_hmac(
            hip_schema.RVSHMACParameter(type=Parameter.RVS_HMAC, len=4, hmac=b'rvsh'),
            version=2,
            options=options,
        ).hmac, b'rvsh')
        self.assertEqual(proto._read_param_via_rvs(
            hip_schema.ViaRVSParameter(type=Parameter.VIA_RVS, len=16,
                                       address=[ip_address('2001:db8::60')]),
            version=2,
            options=options,
        ).address, (ip_address('2001:db8::60'),))
        self.assertEqual(proto._read_param_relay_hmac(
            hip_schema.RelayHMACParameter(type=Parameter.RELAY_HMAC, len=4, hmac=b'relh'),
            version=2,
            options=options,
        ).hmac, b'relh')

        guard_cases = [
            (proto._read_param_r1_counter,
             hip_schema.R1CounterParameter(type=Parameter.R1_COUNTER, len=8, counter=9)),
            (proto._read_param_solution,
             hip_schema.SolutionParameter(type=Parameter.SOLUTION, len=8, index=1,
                                          lifetime=32, opaque=b'op', random=5, solution=6),
             1),
            (proto._read_param_seq,
             hip_schema.SEQParameter(type=Parameter.SEQ, len=3, update_id=11)),
            (proto._read_param_ack,
             hip_schema.ACKParameter(type=Parameter.ACK, len=5, update_id=[11])),
            (proto._read_param_hip_transform,
             hip_schema.HIPTransformParameter(type=Parameter.HIP_TRANSFORM, len=3,
                                              suites=[Suite.AES_CBC_with_HMAC_SHA1]),
             1),
            (proto._read_param_hip_cipher,
             hip_schema.HIPCipherParameter(type=Parameter.HIP_CIPHER, len=3,
                                           ciphers=[Cipher.NULL_ENCRYPT])),
            (proto._read_param_nat_traversal_mode,
             hip_schema.NATTraversalModeParameter(type=Parameter.NAT_TRAVERSAL_MODE,
                                                  len=3,
                                                  modes=[NATTraversal.UDP_ENCAPSULATION])),
            (proto._read_param_transaction_pacing,
             hip_schema.TransactionPacingParameter(type=Parameter.TRANSACTION_PACING,
                                                   len=3, min_ta=10)),
            (proto._read_param_reg_from,
             hip_schema.RegFromParameter(type=Parameter.REG_FROM, len=19,
                                         port=10500, protocol=TransType.UDP,
                                         address=ip_address('2001:db8::10'))),
            (proto._read_param_transport_format_list,
             hip_schema.TransportFormatListParameter(type=Parameter.TRANSPORT_FORMAT_LIST,
                                                     len=3, formats=[Parameter.ESP_INFO])),
            (proto._read_param_esp_transform,
             hip_schema.ESPTransformParameter(type=Parameter.ESP_TRANSFORM, len=3,
                                              suites=[ESPTransformSuite.AES_128_CBC_with_HMAC_SHA1])),
            (proto._read_param_seq_data,
             hip_schema.SeqDataParameter(type=Parameter.SEQ_DATA, len=3, seq=77)),
            (proto._read_param_ack_data,
             hip_schema.AckDataParameter(type=Parameter.ACK_DATA, len=5, ack=[1])),
            (proto._read_param_route_dst,
             hip_schema.RouteDstParameter(type=Parameter.ROUTE_DST, len=5,
                                          flags={'symmetric': 1, 'must_follow': 1},
                                          hit=[])),
            (proto._read_param_hip_transport_mode,
             hip_schema.HIPTransportModeParameter(type=Parameter.HIP_TRANSPORT_MODE,
                                                  len=3, port=5050,
                                                  mode=[Transport.DEFAULT])),
            (proto._read_param_relay_from,
             hip_schema.RelayFromParameter(type=Parameter.RELAY_FROM, len=19,
                                           port=10501, protocol=TransType.UDP,
                                           address=ip_address('2001:db8::30'))),
            (proto._read_param_relay_to,
             hip_schema.RelayToParameter(type=Parameter.RELAY_TO, len=19,
                                         port=10502, protocol=TransType.UDP,
                                         address=ip_address('2001:db8::31'))),
            (proto._read_param_overlay_ttl,
             hip_schema.OverlayTTLParameter(type=Parameter.OVERLAY_TTL, len=3, ttl=30)),
            (proto._read_param_route_via,
             hip_schema.RouteViaParameter(type=Parameter.ROUTE_VIA, len=5,
                                          flags={'symmetric': 1, 'must_follow': 0},
                                          hit=[])),
            (proto._read_param_from,
             hip_schema.FromParameter(type=Parameter.FROM, len=15,
                                      address=ip_address('2001:db8::50'))),
            (proto._read_param_via_rvs,
             hip_schema.ViaRVSParameter(type=Parameter.VIA_RVS, len=15,
                                        address=[ip_address('2001:db8::60')])),
        ]
        for case in guard_cases:
            reader, packet = case[0], case[1]
            version = case[2] if len(case) > 2 else 2
            with self.assertRaises(ProtocolError):
                reader(packet, version=version, options=options)

        with mock.patch('pcapkit.protocols.internet.hip.warn') as warn:
            self.assertEqual(proto._read_param_hip_cipher(
                hip_schema.HIPCipherParameter(type=Parameter.HIP_CIPHER, len=2,
                                              ciphers=[Cipher.NULL_ENCRYPT]),
                version=2,
                options=options,
            ).cipher_id, (Cipher.NULL_ENCRYPT,))
        warn.assert_not_called()

    def test_hip_parameter_constructors_cover_keyword_paths(self) -> None:
        from pcapkit.const.hip.certificate import Certificate
        from pcapkit.const.hip.cipher import Cipher
        from pcapkit.const.hip.di import DITypes
        from pcapkit.const.hip.ecdsa_curve import ECDSACurve
        from pcapkit.const.hip.ecdsa_low_curve import ECDSALowCurve
        from pcapkit.const.hip.eddsa_curve import EdDSACurve
        from pcapkit.const.hip.esp_transform_suite import ESPTransformSuite
        from pcapkit.const.hip.group import Group
        from pcapkit.const.hip.hi_algorithm import HIAlgorithm
        from pcapkit.const.hip.hit_suite import HITSuite
        from pcapkit.const.hip.nat_traversal import NATTraversal
        from pcapkit.const.hip.notify_message import NotifyMessage
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.const.hip.registration import Registration
        from pcapkit.const.hip.registration_failure import RegistrationFailure
        from pcapkit.const.hip.suite import Suite
        from pcapkit.const.hip.transport import Transport
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.data.internet import hip as hip_data
        from pcapkit.protocols.internet.hip import HIP
        from pcapkit.protocols.schema.internet import hip as hip_schema
        from pcapkit.utilities.exceptions import ProtocolError

        proto = object.__new__(HIP)

        self.assertEqual(proto._make_param_unassigned(
            Parameter.Unassigned_65499,
            version=2,
            contents=b'raw',
        ).value, b'raw')
        self.assertEqual(proto._make_param_esp_info(
            Parameter.ESP_INFO,
            version=2,
            index=1,
            old_spi=2,
            new_spi=3,
        ).new_spi, 3)
        self.assertEqual(proto._make_param_r1_counter(
            Parameter.R1_COUNTER,
            version=2,
            counter=4,
        ).counter, 4)
        with self.assertRaises(ProtocolError):
            proto._make_param_r1_counter(Parameter.R1_Counter, version=2)

        locators = proto._make_param_locator_set(
            Parameter.LOCATOR_SET,
            version=2,
            locator_set=[
                {'traffic': 1, 'type': 0, 'preferred': True,
                 'lifetime': datetime.timedelta(seconds=5),
                 'ip': '2001:db8::1'},
                {'traffic': 2, 'type': 1, 'preferred': False,
                 'lifetime': 6, 'ip': '2001:db8::2', 'spi': 7},
            ],
        )
        self.assertEqual(len(locators.locators), 2)
        self.assertEqual(locators.locators[1].value.spi, 7)

        self.assertEqual(proto._make_param_puzzle(
            Parameter.PUZZLE,
            version=2,
            index=1,
            lifetime=1,
            opaque=b'op',
            random=5,
        ).lifetime, 32)
        self.assertEqual(proto._make_param_solution(
            Parameter.SOLUTION,
            version=2,
            index=1,
            lifetime=datetime.timedelta(seconds=1),
            opaque=b'op',
            random=5,
            solution=6,
        ).solution, 6)
        self.assertEqual(proto._make_param_seq(
            Parameter.SEQ,
            version=2,
            update_id=7,
        ).update_id, 7)
        self.assertEqual(proto._make_param_ack(
            Parameter.ACK,
            version=2,
            update_id=[7, 8],
        ).update_id, [7, 8])
        self.assertEqual(proto._make_param_dh_group_list(
            Parameter.DH_GROUP_LIST,
            version=2,
            groups=[Group.NIST_P_256],
        ).groups, [Group.NIST_P_256])
        self.assertEqual(proto._make_param_diffie_hellman(
            Parameter.DIFFIE_HELLMAN,
            version=2,
            group=Group.NIST_P_256,
            pub_val=9,
        ).pub_val, 9)
        self.assertEqual(proto._make_param_hip_transform(
            Parameter.HIP_TRANSFORM,
            version=1,
            suites=[Suite.AES_CBC_with_HMAC_SHA1],
        ).suites, [Suite.AES_CBC_with_HMAC_SHA1])
        self.assertEqual(proto._make_param_hip_cipher(
            Parameter.HIP_CIPHER,
            version=2,
            ciphers=[Cipher.NULL_ENCRYPT],
        ).ciphers, [Cipher.NULL_ENCRYPT])
        self.assertEqual(proto._make_param_nat_traversal_mode(
            Parameter.NAT_TRAVERSAL_MODE,
            version=2,
            modes=[NATTraversal.UDP_ENCAPSULATION],
        ).modes, [NATTraversal.UDP_ENCAPSULATION])
        self.assertEqual(proto._make_param_transaction_pacing(
            Parameter.TRANSACTION_PACING,
            version=2,
            min_ta=10,
        ).min_ta, 10)

        self.assertEqual(proto._make_param_encrypted(
            Parameter.ENCRYPTED,
            version=2,
            cipher=Cipher.NULL_ENCRYPT,
            data=b'data',
        ).data, b'data')
        self.assertEqual(proto._make_param_encrypted(
            Parameter.ENCRYPTED,
            version=2,
            cipher=Cipher.AES_128_CBC,
            iv=b'\x00' * 16,
            data=b'data',
        ).iv, b'\x00' * 16)
        with self.assertRaises(ProtocolError):
            proto._make_param_encrypted(Parameter.ENCRYPTED, version=2,
                                        cipher=Cipher.AES_128_CBC)
        with self.assertRaises(ProtocolError):
            proto._make_param_encrypted(Parameter.ENCRYPTED, version=2,
                                        cipher=Cipher.AES_128_CBC,
                                        iv=b'short')

        self.assertEqual(proto._make_param_host_id(
            Parameter.HOST_ID,
            version=2,
            hi_curve=ECDSACurve.NIST_P_256,
            hi_pub_key=b'ec',
            di=b'id',
            di_type=DITypes.FQDN,
        ).algorithm, HIAlgorithm.ECDSA)
        self.assertEqual(proto._make_param_host_id(
            Parameter.HOST_ID,
            version=2,
            hi_curve=ECDSALowCurve.SECP160R1,
            hi_pub_key=b'lo',
        ).algorithm, HIAlgorithm.ECDSA_LOW)
        self.assertEqual(proto._make_param_host_id(
            Parameter.HOST_ID,
            version=2,
            hi_curve=EdDSACurve.EdDSA25519,
            hi_pub_key=b'ed',
        ).algorithm, HIAlgorithm.EdDSA)
        with self.assertRaises(ProtocolError):
            proto._make_param_host_id(Parameter.HOST_ID, version=2)
        self.assertEqual(proto._make_param_host_id(
            Parameter.HOST_ID,
            version=2,
            hi=hip_data.HostIdentity(curve=ECDSACurve.NIST_P_256, pubkey=b'data'),
        ).algorithm, HIAlgorithm.ECDSA)
        self.assertEqual(proto._make_param_host_id(
            Parameter.HOST_ID,
            version=2,
            hi=hip_schema.ECDSACurveHostIdentity(curve=ECDSACurve.NIST_P_256,
                                                 pub_key=b'schema'),
        ).hi.pub_key, b'schema')
        self.assertEqual(proto._make_param_host_id(
            Parameter.HOST_ID,
            version=2,
            hi=b'bytes',
            hi_algorithm=HIAlgorithm.RSA,
        ).hi, b'bytes')

        self.assertEqual(proto._make_param_hit_suite_list(
            Parameter.HIT_SUITE_LIST,
            version=2,
            suites=[HITSuite.ECDSA_SHA_384],
        ).suites, [HITSuite.ECDSA_SHA_384])
        self.assertEqual(proto._make_param_cert(
            Parameter.CERT,
            version=2,
            cert_group=Group.NIST_P_256,
            cert_count=1,
            cert_id=2,
            cert_type=Certificate.X_509_v3,
            cert=b'cert',
        ).cert, b'cert')
        self.assertEqual(proto._make_param_notification(
            Parameter.NOTIFICATION,
            version=2,
            msg_type=NotifyMessage.INVALID_SYNTAX,
            msg=b'bad',
        ).msg, b'bad')
        self.assertEqual(proto._make_param_echo_request_signed(
            Parameter.ECHO_REQUEST_SIGNED,
            version=2,
            opaque=b'ers',
        ).opaque, b'ers')
        self.assertEqual(proto._make_param_reg_info(
            Parameter.REG_INFO,
            version=2,
            min_lifetime=datetime.timedelta(seconds=1),
            max_lifetime=datetime.timedelta(seconds=2),
            reg_info=[Registration.RENDEZVOUS],
        ).reg_info, [Registration.RENDEZVOUS])
        self.assertEqual(proto._make_param_reg_request(
            Parameter.REG_REQUEST,
            version=2,
            lifetime=datetime.timedelta(seconds=3),
            reg_request=[Registration.RELAY_UDP_HIP],
        ).reg_request, [Registration.RELAY_UDP_HIP])
        self.assertEqual(proto._make_param_reg_response(
            Parameter.REG_RESPONSE,
            version=2,
            lifetime=4,
            reg_response=[Registration.RELAY_UDP_ESP],
        ).reg_response, [Registration.RELAY_UDP_ESP])
        self.assertEqual(proto._make_param_reg_failed(
            Parameter.REG_FAILED,
            version=2,
            lifetime=datetime.timedelta(seconds=5),
            reg_failed=[RegistrationFailure.Insufficient_resources],
        ).reg_failed, [RegistrationFailure.Insufficient_resources])
        self.assertEqual(proto._make_param_reg_from(
            Parameter.REG_FROM,
            version=2,
            port=10500,
            protocol=TransType.UDP,
            address='2001:db8::10',
        ).port, 10500)
        self.assertEqual(proto._make_param_echo_response_signed(
            Parameter.ECHO_RESPONSE_SIGNED,
            version=2,
            opaque=b'es',
        ).opaque, b'es')
        self.assertEqual(proto._make_param_transport_format_list(
            Parameter.TRANSPORT_FORMAT_LIST,
            version=2,
            formats=[Parameter.ESP_INFO],
        ).formats, [Parameter.ESP_INFO])
        self.assertEqual(proto._make_param_esp_transform(
            Parameter.ESP_TRANSFORM,
            version=2,
            suites=[ESPTransformSuite.AES_128_CBC_with_HMAC_SHA1],
        ).suites, [ESPTransformSuite.AES_128_CBC_with_HMAC_SHA1])
        self.assertEqual(proto._make_param_seq_data(
            Parameter.SEQ_DATA,
            version=2,
            seq=77,
        ).seq, 77)
        self.assertEqual(proto._make_param_ack_data(
            Parameter.ACK_DATA,
            version=2,
            ack=[1, 2],
        ).ack, [1, 2])
        self.assertEqual(proto._make_param_payload_mic(
            Parameter.PAYLOAD_MIC,
            version=2,
            next=TransType.TCP,
            payload=b'payload',
            mic=b'mic',
        ).next, TransType.TCP)
        self.assertEqual(proto._make_param_transaction_id(
            Parameter.TRANSACTION_ID,
            version=2,
            id=88,
        ).id, 88)
        self.assertEqual(proto._make_param_overlay_id(
            Parameter.OVERLAY_ID,
            version=2,
            id=99,
        ).id, 99)
        self.assertTrue(proto._make_param_route_dst(
            Parameter.ROUTE_DST,
            version=2,
            symmetric=True,
            must_follow=True,
            hit=[ip_address('2001:db8::20')],
        ).flags['symmetric'])
        self.assertEqual(proto._make_param_hip_transport_mode(
            Parameter.HIP_TRANSPORT_MODE,
            version=2,
            port=5050,
            modes=[Transport.DEFAULT],
        ).mode, [Transport.DEFAULT])
        self.assertEqual(proto._make_param_hip_mac(
            Parameter.HIP_MAC,
            version=2,
            hmac=b'hmac',
        ).hmac, b'hmac')
        self.assertEqual(proto._make_param_hip_mac_2(
            Parameter.HIP_MAC_2,
            version=2,
            hmac=b'hmac2',
        ).hmac, b'hmac2')
        self.assertEqual(proto._make_param_hip_signature_2(
            Parameter.HIP_SIGNATURE_2,
            version=2,
            algorithm=HIAlgorithm.RSA,
            signature=b'sig2',
        ).signature, b'sig2')
        self.assertEqual(proto._make_param_hip_signature(
            Parameter.HIP_SIGNATURE,
            version=2,
            algorithm=HIAlgorithm.RSA,
            signature=b'sig',
        ).signature, b'sig')
        self.assertEqual(proto._make_param_echo_request_unsigned(
            Parameter.ECHO_REQUEST_UNSIGNED,
            version=2,
            opaque=b'eur',
        ).opaque, b'eur')
        self.assertEqual(proto._make_param_echo_response_unsigned(
            Parameter.ECHO_RESPONSE_UNSIGNED,
            version=2,
            opaque=b'eus',
        ).opaque, b'eus')
        self.assertEqual(proto._make_param_relay_from(
            Parameter.RELAY_FROM,
            version=2,
            port=10501,
            protocol=TransType.UDP,
            address='2001:db8::30',
        ).port, 10501)
        self.assertEqual(proto._make_param_relay_to(
            Parameter.RELAY_TO,
            version=2,
            port=10502,
            protocol=TransType.UDP,
            address='2001:db8::31',
        ).port, 10502)
        self.assertEqual(proto._make_param_overlay_ttl(
            Parameter.OVERLAY_TTL,
            version=2,
            ttl=datetime.timedelta(seconds=30),
        ).ttl, 30)
        self.assertTrue(proto._make_param_route_via(
            Parameter.ROUTE_VIA,
            version=2,
            symmetric=True,
            hit=[ip_address('2001:db8::40')],
        ).flags['symmetric'])
        self.assertEqual(proto._make_param_from(
            Parameter.FROM,
            version=2,
            address='2001:db8::50',
        ).address, '2001:db8::50')
        self.assertEqual(proto._make_param_rvs_hmac(
            Parameter.RVS_HMAC,
            version=2,
            hmac=b'rvsh',
        ).hmac, b'rvsh')
        self.assertEqual(proto._make_param_via_rvs(
            Parameter.VIA_RVS,
            version=2,
            address=[ip_address('2001:db8::60')],
        ).address, [ip_address('2001:db8::60')])
        self.assertEqual(proto._make_param_relay_hmac(
            Parameter.RELAY_HMAC,
            version=2,
            hmac=b'relh',
        ).hmac, b'relh')

    def test_hip_parameter_constructors_cover_data_model_and_default_paths(self) -> None:
        from pcapkit.const.hip.certificate import Certificate
        from pcapkit.const.hip.cipher import Cipher
        from pcapkit.const.hip.di import DITypes
        from pcapkit.const.hip.ecdsa_curve import ECDSACurve
        from pcapkit.const.hip.ecdsa_low_curve import ECDSALowCurve
        from pcapkit.const.hip.eddsa_curve import EdDSACurve
        from pcapkit.const.hip.esp_transform_suite import ESPTransformSuite
        from pcapkit.const.hip.group import Group
        from pcapkit.const.hip.hi_algorithm import HIAlgorithm
        from pcapkit.const.hip.hit_suite import HITSuite
        from pcapkit.const.hip.nat_traversal import NATTraversal
        from pcapkit.const.hip.notify_message import NotifyMessage
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.const.hip.registration import Registration
        from pcapkit.const.hip.registration_failure import RegistrationFailure
        from pcapkit.const.hip.suite import Suite
        from pcapkit.const.hip.transport import Transport
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.data.internet import hip as hip_data
        from pcapkit.protocols.internet.hip import HIP
        from pcapkit.utilities.exceptions import ProtocolError

        proto = object.__new__(HIP)
        dt1 = datetime.timedelta(seconds=1)
        dt2 = datetime.timedelta(seconds=2)

        self.assertEqual(proto._make_param_unassigned(
            Parameter.Unassigned_65499,
            hip_data.UnassignedParameter(type=Parameter.Unassigned_65499,
                                         critical=False, length=8,
                                         contents=b'data'),
            version=2,
        ).value, b'data')
        self.assertEqual(proto._make_param_r1_counter(
            Parameter.R1_COUNTER,
            hip_data.R1CounterParameter(type=Parameter.R1_COUNTER,
                                        critical=False, length=16,
                                        counter=2),
            version=2,
        ).counter, 2)

        locator_ipv6 = hip_data.Locator(traffic=1, type=0, length=16,
                                        preferred=True, lifetime=dt1,
                                        locator=ip_address('2001:db8::1'))
        locator_data = hip_data.Locator(traffic=2, type=1, length=20,
                                        preferred=False, lifetime=dt2,
                                        locator=hip_data.LocatorData(
                                            spi=7,
                                            ip=ip_address('2001:db8::2'),
                                        ))
        self.assertEqual(len(proto._make_param_locator_set(
            Parameter.LOCATOR_SET,
            hip_data.LocatorSetParameter(type=Parameter.LOCATOR_SET,
                                         critical=False, length=48,
                                         locator_set=(locator_ipv6, locator_data)),
            version=2,
        ).locators), 2)
        self.assertEqual(proto._make_param_locator_set(Parameter.LOCATOR_SET,
                                                       version=2).locators, [])
        with self.assertRaises(ProtocolError):
            proto._make_param_locator_set(
                Parameter.LOCATOR_SET,
                hip_data.LocatorSetParameter(
                    type=Parameter.LOCATOR_SET,
                    critical=False,
                    length=8,
                    locator_set=(hip_data.Locator(
                        traffic=1, type=0, length=4, preferred=False,
                        lifetime=dt1, locator=b'bad',
                    ),),
                ),
                version=2,
            )

        self.assertEqual(proto._make_param_puzzle(
            Parameter.PUZZLE,
            hip_data.PuzzleParameter(type=Parameter.PUZZLE, critical=False,
                                     length=16, index=1, lifetime=dt1,
                                     opaque=b'op', random=5),
            version=2,
        ).random, 5)
        self.assertEqual(proto._make_param_solution(
            Parameter.SOLUTION,
            hip_data.SolutionParameter(type=Parameter.SOLUTION, critical=False,
                                       length=24, index=1, lifetime=dt1,
                                       opaque=b'op', random=5, solution=6),
            version=2,
        ).solution, 6)
        self.assertEqual(proto._make_param_seq(
            Parameter.SEQ,
            hip_data.SEQParameter(type=Parameter.SEQ, critical=False,
                                  length=8, id=10),
            version=2,
        ).update_id, 10)
        self.assertEqual(proto._make_param_ack(
            Parameter.ACK,
            hip_data.ACKParameter(type=Parameter.ACK, critical=False,
                                  length=12, update_id=(1, 2)),
            version=2,
        ).update_id, (1, 2))
        self.assertEqual(proto._make_param_ack(Parameter.ACK, version=2).update_id, [])
        self.assertEqual(proto._make_param_dh_group_list(
            Parameter.DH_GROUP_LIST,
            hip_data.DHGroupListParameter(type=Parameter.DH_GROUP_LIST,
                                          critical=False, length=8,
                                          group_id=(Group.NIST_P_256,)),
            version=2,
        ).groups, (Group.NIST_P_256,))
        self.assertEqual(proto._make_param_dh_group_list(
            Parameter.DH_GROUP_LIST,
            version=2,
        ).groups, [])
        self.assertEqual(proto._make_param_diffie_hellman(
            Parameter.DIFFIE_HELLMAN,
            hip_data.DiffieHellmanParameter(type=Parameter.DIFFIE_HELLMAN,
                                            critical=False, length=8,
                                            group_id=Group.NIST_P_256,
                                            pub_len=1, pub_val=9),
            version=2,
        ).pub_val, 9)

        self.assertEqual(proto._make_param_hip_transform(
            Parameter.HIP_TRANSFORM,
            hip_data.HIPTransformParameter(type=Parameter.HIP_TRANSFORM,
                                           critical=False, length=8,
                                           suite_id=(Suite.AES_CBC_with_HMAC_SHA1,)),
            version=1,
        ).suites, (Suite.AES_CBC_with_HMAC_SHA1,))
        self.assertEqual(proto._make_param_hip_transform(
            Parameter.HIP_TRANSFORM,
            version=1,
        ).suites, [])
        self.assertEqual(proto._make_param_hip_cipher(
            Parameter.HIP_CIPHER,
            hip_data.HIPCipherParameter(type=Parameter.HIP_CIPHER,
                                        critical=False, length=8,
                                        cipher_id=(Cipher.NULL_ENCRYPT,)),
            version=2,
        ).ciphers, (Cipher.NULL_ENCRYPT,))
        self.assertEqual(proto._make_param_hip_cipher(
            Parameter.HIP_CIPHER,
            version=2,
        ).ciphers, [])
        self.assertEqual(proto._make_param_nat_traversal_mode(
            Parameter.NAT_TRAVERSAL_MODE,
            hip_data.NATTraversalModeParameter(type=Parameter.NAT_TRAVERSAL_MODE,
                                               critical=False, length=8,
                                               mode_id=(NATTraversal.UDP_ENCAPSULATION,)),
            version=2,
        ).modes, (NATTraversal.UDP_ENCAPSULATION,))
        self.assertEqual(proto._make_param_nat_traversal_mode(
            Parameter.NAT_TRAVERSAL_MODE,
            version=2,
        ).modes, [])
        self.assertEqual(proto._make_param_transaction_pacing(
            Parameter.TRANSACTION_PACING,
            hip_data.TransactionPacingParameter(type=Parameter.TRANSACTION_PACING,
                                                critical=False, length=8,
                                                min_ta=11),
            version=2,
        ).min_ta, 11)
        self.assertEqual(proto._make_param_encrypted(
            Parameter.ENCRYPTED,
            hip_data.EncryptedParameter(type=Parameter.ENCRYPTED,
                                        critical=False, length=8,
                                        cipher=Cipher.NULL_ENCRYPT,
                                        iv=b'iv', data=b'data'),
            version=2,
        ).data, b'data')

        self.assertEqual(proto._make_param_host_id(
            Parameter.HOST_ID,
            hip_data.HostIDParameter(type=Parameter.HOST_ID, critical=False,
                                     length=16, hi_len=4,
                                     di_type=DITypes.FQDN, di_len=2,
                                     algorithm=HIAlgorithm.RSA,
                                     hi=b'host', di=b'id'),
            version=2,
        ).hi, b'host')
        self.assertEqual(proto._make_param_host_id(
            Parameter.HOST_ID,
            version=2,
            hi=hip_data.HostIdentity(curve=ECDSALowCurve.SECP160R1,
                                     pubkey=b'low'),
        ).algorithm, HIAlgorithm.ECDSA_LOW)
        self.assertEqual(proto._make_param_host_id(
            Parameter.HOST_ID,
            version=2,
            hi=hip_data.HostIdentity(curve=EdDSACurve.EdDSA25519,
                                     pubkey=b'ed'),
        ).algorithm, HIAlgorithm.EdDSA)
        with self.assertRaises(ProtocolError):
            proto._make_param_host_id(
                Parameter.HOST_ID,
                version=2,
                hi=hip_data.HostIdentity(curve=object(), pubkey=b'bad'),
            )

        self.assertEqual(proto._make_param_hit_suite_list(
            Parameter.HIT_SUITE_LIST,
            hip_data.HITSuiteListParameter(type=Parameter.HIT_SUITE_LIST,
                                           critical=False, length=8,
                                           suite_id=(HITSuite.ECDSA_SHA_384,)),
            version=2,
        ).suites, (HITSuite.ECDSA_SHA_384,))
        self.assertEqual(proto._make_param_hit_suite_list(
            Parameter.HIT_SUITE_LIST,
            version=2,
        ).suites, [])
        self.assertEqual(proto._make_param_cert(
            Parameter.CERT,
            hip_data.CertParameter(type=Parameter.CERT, critical=False,
                                   length=12, cert_group=Group.NIST_P_256,
                                   cert_count=1, cert_id=2,
                                   cert_type=Certificate.X_509_v3,
                                   cert=b'cert'),
            version=2,
        ).cert, b'cert')
        self.assertEqual(proto._make_param_notification(
            Parameter.NOTIFICATION,
            hip_data.NotificationParameter(type=Parameter.NOTIFICATION,
                                           critical=False, length=8,
                                           msg_type=NotifyMessage.INVALID_SYNTAX,
                                           msg=b'bad'),
            version=2,
        ).msg, b'bad')
        self.assertEqual(proto._make_param_echo_request_signed(
            Parameter.ECHO_REQUEST_SIGNED,
            hip_data.EchoRequestSignedParameter(type=Parameter.ECHO_REQUEST_SIGNED,
                                                critical=False, length=8,
                                                opaque=b'ers'),
            version=2,
        ).opaque, b'ers')

        lifetime = hip_data.Lifetime(min=dt1, max=dt2)
        self.assertEqual(proto._make_param_reg_info(
            Parameter.REG_INFO,
            hip_data.RegInfoParameter(type=Parameter.REG_INFO, critical=False,
                                      length=8, lifetime=lifetime,
                                      reg_type=(Registration.RENDEZVOUS,)),
            version=2,
        ).max_lifetime, 2)
        self.assertEqual(proto._make_param_reg_info(Parameter.REG_INFO,
                                                    version=2).reg_info, [])
        self.assertEqual(proto._make_param_reg_request(
            Parameter.REG_REQUEST,
            hip_data.RegRequestParameter(type=Parameter.REG_REQUEST,
                                         critical=False, length=8,
                                         lifetime=dt1,
                                         reg_type=(Registration.RELAY_UDP_HIP,)),
            version=2,
        ).lifetime, 1)
        self.assertEqual(proto._make_param_reg_request(Parameter.REG_REQUEST,
                                                       version=2).reg_request, [])
        self.assertEqual(proto._make_param_reg_response(
            Parameter.REG_RESPONSE,
            hip_data.RegResponseParameter(type=Parameter.REG_RESPONSE,
                                          critical=False, length=8,
                                          lifetime=dt1,
                                          reg_type=(Registration.RELAY_UDP_ESP,)),
            version=2,
        ).lifetime, 1)
        self.assertEqual(proto._make_param_reg_response(Parameter.REG_RESPONSE,
                                                        version=2).reg_response, [])
        self.assertEqual(proto._make_param_reg_failed(
            Parameter.REG_FAILED,
            hip_data.RegFailedParameter(type=Parameter.REG_FAILED,
                                        critical=False, length=8,
                                        lifetime=dt1,
                                        reg_type=(RegistrationFailure.Insufficient_resources,)),
            version=2,
        ).lifetime, 1)
        self.assertEqual(proto._make_param_reg_failed(Parameter.REG_FAILED,
                                                      version=2).reg_failed, [])
        self.assertEqual(proto._make_param_reg_from(
            Parameter.REG_FROM,
            hip_data.RegFromParameter(type=Parameter.REG_FROM, critical=False,
                                      length=24, port=10500,
                                      protocol=TransType.UDP,
                                      address=ip_address('2001:db8::10')),
            version=2,
        ).port, 10500)
        self.assertEqual(proto._make_param_echo_response_signed(
            Parameter.ECHO_RESPONSE_SIGNED,
            hip_data.EchoResponseSignedParameter(type=Parameter.ECHO_RESPONSE_SIGNED,
                                                 critical=False, length=8,
                                                 opaque=b'es'),
            version=2,
        ).opaque, b'es')
        self.assertEqual(proto._make_param_transport_format_list(
            Parameter.TRANSPORT_FORMAT_LIST,
            hip_data.TransportFormatListParameter(type=Parameter.TRANSPORT_FORMAT_LIST,
                                                  critical=False, length=8,
                                                  tf_type=(Parameter.ESP_INFO,)),
            version=2,
        ).formats, (Parameter.ESP_INFO,))
        self.assertEqual(proto._make_param_transport_format_list(
            Parameter.TRANSPORT_FORMAT_LIST,
            version=2,
        ).formats, [])
        self.assertEqual(proto._make_param_esp_transform(
            Parameter.ESP_TRANSFORM,
            hip_data.ESPTransformParameter(type=Parameter.ESP_TRANSFORM,
                                           critical=False, length=8,
                                           suite_id=(ESPTransformSuite.AES_128_CBC_with_HMAC_SHA1,)),
            version=2,
        ).suites, (ESPTransformSuite.AES_128_CBC_with_HMAC_SHA1,))
        self.assertEqual(proto._make_param_esp_transform(
            Parameter.ESP_TRANSFORM,
            version=2,
        ).suites, [])
        self.assertEqual(proto._make_param_seq_data(
            Parameter.SEQ_DATA,
            hip_data.SeqDataParameter(type=Parameter.SEQ_DATA, critical=False,
                                      length=8, seq=77),
            version=2,
        ).seq, 77)
        self.assertEqual(proto._make_param_ack_data(
            Parameter.ACK_DATA,
            hip_data.AckDataParameter(type=Parameter.ACK_DATA, critical=False,
                                      length=12, ack=(1, 2)),
            version=2,
        ).ack, (1, 2))
        self.assertEqual(proto._make_param_ack_data(Parameter.ACK_DATA,
                                                    version=2).ack, [])
        self.assertEqual(proto._make_param_payload_mic(
            Parameter.PAYLOAD_MIC,
            hip_data.PayloadMICParameter(type=Parameter.PAYLOAD_MIC,
                                         critical=False, length=16,
                                         next=TransType.TCP,
                                         payload=b'payload', mic=b'mic'),
            version=2,
        ).payload, b'payload')
        self.assertEqual(proto._make_param_transaction_id(
            Parameter.TRANSACTION_ID,
            hip_data.TransactionIDParameter(type=Parameter.TRANSACTION_ID,
                                            critical=False, length=8, id=88),
            version=2,
        ).id, 88)
        self.assertEqual(proto._make_param_overlay_id(
            Parameter.OVERLAY_ID,
            hip_data.OverlayIDParameter(type=Parameter.OVERLAY_ID,
                                        critical=False, length=8, id=99),
            version=2,
        ).id, 99)
        flags = hip_data.Flags(symmetric=True, must_follow=True)
        self.assertTrue(proto._make_param_route_dst(
            Parameter.ROUTE_DST,
            hip_data.RouteDstParameter(type=Parameter.ROUTE_DST,
                                       critical=False, length=24,
                                       flags=flags,
                                       hit=(ip_address('2001:db8::20'),)),
            version=2,
        ).flags['must_follow'])
        self.assertEqual(proto._make_param_hip_transport_mode(
            Parameter.HIP_TRANSPORT_MODE,
            hip_data.HIPTransportModeParameter(type=Parameter.HIP_TRANSPORT_MODE,
                                               critical=False, length=8,
                                               port=5050,
                                               mode_id=(Transport.DEFAULT,)),
            version=2,
        ).mode, (Transport.DEFAULT,))
        self.assertEqual(proto._make_param_hip_transport_mode(
            Parameter.HIP_TRANSPORT_MODE,
            version=2,
        ).mode, [])
        self.assertEqual(proto._make_param_hip_mac(
            Parameter.HIP_MAC,
            hip_data.HIPMACParameter(type=Parameter.HIP_MAC,
                                     critical=False, length=8, hmac=b'hmac'),
            version=2,
        ).hmac, b'hmac')
        self.assertEqual(proto._make_param_hip_mac_2(
            Parameter.HIP_MAC_2,
            hip_data.HIPMAC2Parameter(type=Parameter.HIP_MAC_2,
                                      critical=False, length=8, hmac=b'hmac2'),
            version=2,
        ).hmac, b'hmac2')
        self.assertEqual(proto._make_param_hip_signature_2(
            Parameter.HIP_SIGNATURE_2,
            hip_data.HIPSignature2Parameter(type=Parameter.HIP_SIGNATURE_2,
                                            critical=False, length=8,
                                            algorithm=HIAlgorithm.RSA,
                                            signature=b'sig2'),
            version=2,
        ).signature, b'sig2')
        self.assertEqual(proto._make_param_hip_signature(
            Parameter.HIP_SIGNATURE,
            hip_data.HIPSignatureParameter(type=Parameter.HIP_SIGNATURE,
                                           critical=False, length=8,
                                           algorithm=HIAlgorithm.RSA,
                                           signature=b'sig'),
            version=2,
        ).signature, b'sig')
        self.assertEqual(proto._make_param_echo_request_unsigned(
            Parameter.ECHO_REQUEST_UNSIGNED,
            hip_data.EchoRequestUnsignedParameter(type=Parameter.ECHO_REQUEST_UNSIGNED,
                                                  critical=False, length=8,
                                                  opaque=b'eur'),
            version=2,
        ).opaque, b'eur')
        self.assertEqual(proto._make_param_echo_response_unsigned(
            Parameter.ECHO_RESPONSE_UNSIGNED,
            hip_data.EchoResponseUnsignedParameter(type=Parameter.ECHO_RESPONSE_UNSIGNED,
                                                   critical=False, length=8,
                                                   opaque=b'eus'),
            version=2,
        ).opaque, b'eus')
        self.assertEqual(proto._make_param_relay_from(
            Parameter.RELAY_FROM,
            hip_data.RelayFromParameter(type=Parameter.RELAY_FROM,
                                        critical=False, length=24,
                                        port=10501, protocol=TransType.UDP,
                                        address=ip_address('2001:db8::30')),
            version=2,
        ).port, 10501)
        self.assertEqual(proto._make_param_relay_to(
            Parameter.RELAY_TO,
            hip_data.RelayToParameter(type=Parameter.RELAY_TO,
                                      critical=False, length=24,
                                      port=10502, protocol=TransType.UDP,
                                      address=ip_address('2001:db8::31')),
            version=2,
        ).port, 10502)
        self.assertEqual(proto._make_param_overlay_ttl(
            Parameter.OVERLAY_TTL,
            hip_data.OverlayTTLParameter(type=Parameter.OVERLAY_TTL,
                                         critical=False, length=8, ttl=dt1),
            version=2,
        ).ttl, 1)
        self.assertTrue(proto._make_param_route_via(
            Parameter.ROUTE_VIA,
            hip_data.RouteViaParameter(type=Parameter.ROUTE_VIA,
                                       critical=False, length=24,
                                       flags=flags,
                                       hit=(ip_address('2001:db8::40'),)),
            version=2,
        ).flags['symmetric'])
        self.assertEqual(proto._make_param_from(
            Parameter.FROM,
            hip_data.FromParameter(type=Parameter.FROM, critical=False,
                                   length=20,
                                   address=ip_address('2001:db8::50')),
            version=2,
        ).address, ip_address('2001:db8::50'))
        self.assertEqual(proto._make_param_rvs_hmac(
            Parameter.RVS_HMAC,
            hip_data.RVSHMACParameter(type=Parameter.RVS_HMAC,
                                      critical=False, length=8,
                                      hmac=b'rvsh'),
            version=2,
        ).hmac, b'rvsh')
        self.assertEqual(proto._make_param_via_rvs(
            Parameter.VIA_RVS,
            hip_data.ViaRVSParameter(type=Parameter.VIA_RVS,
                                     critical=False, length=20,
                                     address=(ip_address('2001:db8::60'),)),
            version=2,
        ).address, (ip_address('2001:db8::60'),))
        self.assertEqual(proto._make_param_via_rvs(Parameter.VIA_RVS,
                                                   version=2).address, [])
        self.assertEqual(proto._make_param_relay_hmac(
            Parameter.RELAY_HMAC,
            hip_data.RelayHMACParameter(type=Parameter.RELAY_HMAC,
                                        critical=False, length=8,
                                        hmac=b'relh'),
            version=2,
        ).hmac, b'relh')

    def test_hip_schema_selectors_and_encrypted_parameter_branches(self) -> None:
        from pcapkit.const.hip.cipher import Cipher
        from pcapkit.const.hip.hi_algorithm import HIAlgorithm
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.schema.internet import hip as hip_schema
        from pcapkit.utilities.exceptions import FieldValueError

        ipv6_field = hip_schema.locator_value_selector({'type': 0, 'len': 4})
        self.assertEqual(type(ipv6_field).__name__, 'IPv6AddressField')
        locator_field = hip_schema.locator_value_selector({'type': 1, 'len': 5})
        self.assertIs(locator_field.schema, hip_schema.LocatorData)
        self.assertEqual(locator_field.length, 20)
        with self.assertRaises(FieldValueError):
            hip_schema.locator_value_selector({'type': 2, 'len': 1})

        host_field = hip_schema.host_id_hi_selector({
            'algorithm': HIAlgorithm.ECDSA,
            'hi_len': 8,
        })
        self.assertIs(host_field.schema, hip_schema.ECDSACurveHostIdentity)
        unknown_host_field = hip_schema.host_id_hi_selector({
            'algorithm': HIAlgorithm.RSA,
            'hi_len': 6,
        })
        self.assertEqual(type(unknown_host_field).__name__, 'BytesField')
        self.assertEqual(unknown_host_field.length, 6)

        missing_packet: dict[str, object] = {}
        with mock.patch('pcapkit.protocols.schema.internet.hip.warn') as warn:
            hip_schema.EncryptedParameter.pre_unpack(missing_packet)
        self.assertEqual(missing_packet['__cipher__'], Cipher.get(0xffff))
        warn.assert_called_once()

        empty_options = OrderedMultiDict()
        no_cipher_packet = {'options': empty_options}
        with mock.patch('pcapkit.protocols.schema.internet.hip.warn') as warn:
            hip_schema.EncryptedParameter.pre_unpack(no_cipher_packet)
        self.assertEqual(no_cipher_packet['__cipher__'], Cipher.get(0xffff))
        warn.assert_called_once()

        cipher_options = OrderedMultiDict()
        cipher_options.add(Parameter.HIP_CIPHER, types.SimpleNamespace(
            cipher_id=(Cipher.AES_128_CBC, Cipher.NULL_ENCRYPT),
        ))
        cipher_packet = {'options': cipher_options}
        with mock.patch('pcapkit.protocols.schema.internet.hip.warn') as warn:
            hip_schema.EncryptedParameter.pre_unpack(cipher_packet)
        self.assertIs(cipher_packet['__cipher__'], Cipher.AES_128_CBC)
        warn.assert_not_called()

        cipher_options.add(Parameter.ENCRYPTED, object())
        next_cipher_packet = {'options': cipher_options}
        hip_schema.EncryptedParameter.pre_unpack(next_cipher_packet)
        self.assertIs(next_cipher_packet['__cipher__'], Cipher.NULL_ENCRYPT)

        cipher_options.add(Parameter.ENCRYPTED, object())
        too_many_packet = {'options': cipher_options}
        with mock.patch('pcapkit.protocols.schema.internet.hip.warn') as warn:
            hip_schema.EncryptedParameter.pre_unpack(too_many_packet)
        self.assertEqual(too_many_packet['__cipher__'], Cipher.get(0xfffe))
        warn.assert_called_once()

        encrypted = hip_schema.EncryptedParameter(
            type=Parameter.ENCRYPTED,
            len=4,
            data=b'data',
        )
        self.assertIs(encrypted.post_process({'__cipher__': Cipher.NULL_ENCRYPT}), encrypted)
        self.assertIs(encrypted.cipher, Cipher.NULL_ENCRYPT)


if __name__ == '__main__':
    unittest.main()
