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
        from pcapkit.protocols.internet.hip import HIP

        registry = HIP.__dict__['__parameter__']

        original = registry[Parameter.ESP_INFO]
        try:
            with mock.patch('pcapkit.protocols.internet.hip.warn') as warn:
                HIP.register_parameter(Parameter.ESP_INFO, 'esp_info')
            warn.assert_called_once()
            self.assertEqual(registry[Parameter.ESP_INFO], 'esp_info')
        finally:
            registry[Parameter.ESP_INFO] = original

        # An unregistered code carries no entry, so registering one is not an
        # overwrite. The setattr form could not tell the two apart: it keyed the
        # warning on ``hasattr(cls, f'_read_param_{name}')``, which is true of
        # every shipped handler as well as of anything a user had installed.
        custom = Parameter.Unassigned_65501
        self.assertNotIn(custom, registry)
        try:
            with mock.patch('pcapkit.protocols.internet.hip.warn') as warn:
                HIP.register_parameter(custom, 'unassigned')
            warn.assert_not_called()
            self.assertEqual(registry[custom], 'unassigned')

            with mock.patch('pcapkit.protocols.internet.hip.warn') as warn:
                HIP.register_parameter(custom, 'unassigned')
            warn.assert_called_once()
        finally:
            registry.pop(custom, None)

    def test_hip_register_parameter_dispatches_a_registered_callable_pair(self) -> None:
        """A ``(parser, constructor)`` pair must reach both dispatch directions.

        The pair is called with the signatures :data:`ParameterParser` and
        :data:`ParameterConstructor` declare -- ``(schema, *, version, options)``
        and ``(code, param=None, *, version, **kwargs)`` -- i.e. as plain
        callables rather than as methods with an implicit ``self``. That is the
        calling convention every other dispatch family uses, and the reason the
        registry form replaced ``setattr``: installing the callable on the class
        made it a descriptor, so dispatch passed ``self`` as the first positional
        argument and a handler written to the declared signature could not be
        called at all.

        """
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.data.internet import hip as hip_data
        from pcapkit.protocols.internet.hip import HIP
        from pcapkit.protocols.schema.internet import hip as hip_schema

        registry = HIP.__dict__['__parameter__']
        custom = Parameter.Unassigned_65501
        seen = []  # type: list[str]

        def read_param(schema, *, version, options):
            seen.append(f'read/v{version}')
            return hip_data.UnassignedParameter(type=schema.type, critical=False,
                                                length=4 + schema.len,
                                                contents=schema.value)

        def make_param(code, param=None, *, version, contents=b'', **kwargs):
            seen.append(f'make/v{version}')
            if param is not None:
                contents = param.contents
            return hip_schema.UnassignedParameter(type=code, len=len(contents),
                                                  value=contents)

        self.assertNotIn(custom, registry)
        try:
            HIP.register_parameter(custom, (read_param, make_param))
            self.assertEqual(registry[custom], (read_param, make_param))

            schema = hip_schema.UnassignedParameter(type=custom, len=4,
                                                    value=b'abcd')
            proto = object.__new__(HIP)
            proto.__header__ = types.SimpleNamespace(param=[schema])
            parsed = proto._read_hip_param(len(schema), version=2)
            self.assertEqual(seen, ['read/v2'])
            self.assertEqual(parsed[custom].contents, b'abcd')

            # the list-of-tuples branch of the constructor
            seen.clear()
            made_list, list_len = proto._make_hip_param(
                [(custom, {'contents': b'wxyz'})], version=2)
            self.assertEqual(seen, ['make/v2'])
            self.assertEqual(made_list[0].value, b'wxyz')
            # 4 octets of type and length plus 4 of value is already a multiple
            # of 8, so RFC 7401 5.2.1 asks for no padding at all:
            # 11 + 4 - (4 + 3) % 8 == 8.
            self.assertEqual(list_len, 8)

            # ... and the OrderedMultiDict branch, which the two halves of an
            # issue like this are equally easy to fix one of and forget the other
            seen.clear()
            made_dict, dict_len = proto._make_hip_param(
                OrderedMultiDict([(custom, parsed[custom])]), version=2)
            self.assertEqual(seen, ['make/v2'])
            self.assertEqual(made_dict[0].value, b'abcd')
            self.assertEqual(dict_len, 8)
        finally:
            registry.pop(custom, None)

    def test_hip_parameter_registry_covers_every_shipped_handler(self) -> None:
        """Every ``_read_param_*`` / ``_make_param_*`` pair must be reachable.

        The setattr form derived the handler name from ``code.name.lower()``, so
        a handler was reachable by construction and "what is registered?" had no
        direct answer. Under the registry the mapping is explicit data, which
        means a handler added without its registry entry becomes dead code --
        this pins the two sides together.

        """
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.internet.hip import HIP

        registry = HIP.__dict__['__parameter__']
        fallback = registry.default_factory()
        self.assertEqual(fallback, 'unassigned')

        registered = set(registry.values()) | {fallback}
        self.assertEqual(
            {name[len('_read_param_'):] for name in vars(HIP)
             if name.startswith('_read_param_')},
            registered,
        )
        self.assertEqual(
            {name[len('_make_param_'):] for name in vars(HIP)
             if name.startswith('_make_param_')},
            registered,
        )

        # ``R1_Counter`` (128, HIPv1) and ``R1_COUNTER`` (129, HIPv2) are distinct
        # codes whose names differ only in case, so both have to be keyed
        # explicitly -- ``code.name.lower()`` collapsed them for free.
        self.assertEqual(registry[Parameter.R1_Counter], 'r1_counter')
        self.assertEqual(registry[Parameter.R1_COUNTER], 'r1_counter')

        # every key is a real parameter code, and every value names real methods
        for code, name in registry.items():
            with self.subTest(code=code):
                self.assertIsInstance(code, Parameter)
                self.assertTrue(hasattr(HIP, f'_read_param_{name}'))
                self.assertTrue(hasattr(HIP, f'_make_param_{name}'))

    def test_hip_unregistered_parameter_code_does_not_mutate_the_registry(self) -> None:
        """Parsing must not write to the shared HIP parameter registry.

        :attr:`HIP.__parameter__ <pcapkit.protocols.internet.hip.HIP.__parameter__>`
        is a :class:`collections.defaultdict` on a class attribute shared by
        every instance in the process, so ``registry[code]`` would insert each
        code it missed -- the leak #428 swept out of the sixteen registries that
        already existed. This one is new, so the guard has to be pinned here too:
        the reads go through
        :meth:`~pcapkit.protocols.protocol.ProtocolBase._lookup_registry`.

        Code 65499 is unassigned in IANA's registry and 4650 is
        ``RELAYED_ADDRESS``, which is assigned but has no parser, so both take
        the fallback.

        """
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.internet.hip import HIP
        from pcapkit.protocols.schema.internet import hip as hip_schema

        registry = HIP.__dict__['__parameter__']
        proto = object.__new__(HIP)

        for code in (Parameter.Unassigned_65499, Parameter.RELAYED_ADDRESS):
            with self.subTest(code=code):
                before = set(registry)
                self.assertNotIn(code, before)

                schema = hip_schema.UnassignedParameter(type=code, len=4,
                                                        value=b'abcd')
                proto.__header__ = types.SimpleNamespace(param=[schema])
                proto._read_hip_param(len(schema), version=2)
                self.assertEqual(set(registry), before)

                # both constructor branches, since either can leak on its own
                proto._make_hip_param([(code, {'contents': b'abcd'})], version=2)
                self.assertEqual(set(registry), before)
                proto._make_hip_param(
                    OrderedMultiDict([(code, types.SimpleNamespace(contents=b'abcd'))]),
                    version=2)
                self.assertEqual(set(registry), before)

                # a leak would make the next genuine registration warn
                with mock.patch('pcapkit.protocols.internet.hip.warn') as warn:
                    try:
                        HIP.register_parameter(code, 'unassigned')
                        warn.assert_not_called()
                    finally:
                        registry.pop(code, None)

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
                                         reserved=0, opaque=b'op', random=5, solution=6),
            version=2,
            options=options,
        ).solution, 6)
        with self.assertRaises(ProtocolError):
            proto._read_param_solution(
                hip_schema.SolutionParameter(type=Parameter.SOLUTION, len=9, index=1,
                                             reserved=0, opaque=b'op', random=5, solution=6),
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
                                          reserved=0, opaque=b'op', random=5, solution=6),
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
            reserved=0,
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

    def test_hip_make_param_encrypted_preserves_iv_on_pack(self) -> None:
        # #556: ``_make_param_encrypted`` used to pass ``cipher=`` to
        # ``Schema_EncryptedParameter``, a keyword the schema does not
        # accept (the packing-time cipher lookup keys off ``__cipher__``,
        # a packet-context key -- not a constructible field), so the value
        # was dropped with an ``UnknownFieldWarning`` and the schema's own
        # ``pre_unpack`` fallback then always treated the parameter as
        # cipher-less, silently packing an AES-cipher ``ENCRYPTED``
        # parameter without its IV. Building one through ``make`` and
        # packing it must retain the IV.
        import warnings

        from pcapkit.const.hip.cipher import Cipher
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.internet.hip import HIP

        proto = object.__new__(HIP)
        iv = b'\x11' * 16

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            schema = proto._make_param_encrypted(
                Parameter.ENCRYPTED,
                version=2,
                cipher=Cipher.AES_128_CBC,
                iv=iv,
                data=b'DATA',
            )
            packed = bytes(schema)
        # constructing and packing must not have drawn an
        # ``UnknownFieldWarning`` for an unrecognised ``cipher`` keyword, nor
        # the ``pre_unpack`` fallback's "missing HIP_CIPHER parameter" one.
        self.assertEqual(caught, [])

        self.assertIn(iv, packed)
        self.assertEqual(schema.cipher, Cipher.AES_128_CBC)

        # a cipher that needs no IV (e.g. ``NULL_ENCRYPT``) still packs
        # cleanly, with no IV octets and no "missing HIP_CIPHER" warning
        # (the resolved cipher is known directly; there is nothing to
        # infer from a sibling parameter this schema was never given).
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            schema_null = proto._make_param_encrypted(
                Parameter.ENCRYPTED,
                version=2,
                cipher=Cipher.NULL_ENCRYPT,
                data=b'DATA',
            )
            packed_null = bytes(schema_null)
        self.assertEqual(caught, [])
        self.assertEqual(packed_null, b'\x02\x81\x00\x08\x00\x00\x00\x00DATA\x00\x00\x00\x00')

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
                                     opaque=b'op', random=5, rhash_len=64),
            version=2,
        ).random, 5)
        self.assertEqual(proto._make_param_solution(
            Parameter.SOLUTION,
            hip_data.SolutionParameter(type=Parameter.SOLUTION, critical=False,
                                       length=24, index=1, reserved=0,
                                       opaque=b'op', random=5, solution=6,
                                       rhash_len=64),
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

    def test_hip_registration_parameters_reject_underflowing_length(self) -> None:
        """#438: a registration parameter's ``Length`` too small for its own
        ``lifetime`` octet must raise, not silently drop the registration list.

        ``reg_request``, ``reg_response`` and ``reg_failed`` each size their
        list of registration-type octets as ``Length - 1``. Nothing floored
        that at zero, so a peer declaring ``Length = 0`` drove the list length
        to ``-1``. Unlike a :class:`~pcapkit.corekit.fields.strings.BytesField`,
        :class:`~pcapkit.corekit.fields.collections.ListField` never reaches
        :func:`struct.calcsize` for a negative length -- its own ``while length
        > 0`` loop just returns an empty list instead -- so this parsed to an
        empty ``reg_type`` with no exception and no diagnostic, rather than
        rejecting the malformed ``Length``.

        """
        from pcapkit.protocols.internet.hip import HIP
        from pcapkit.utilities.exceptions import FieldValueError

        # next(1) len(1)=5 pkt(1) ver(1)=0x01 (the reserved bit that must be 1)
        # checksum(2) control(2) shit(16) rhit(16) -- the fixed 40-octet header,
        # declaring one 8-octet parameter to follow: (5 - 4) * 8 == 8.
        fixed = bytes([0x3b, 0x05, 0x00, 0x01]) + bytes(2) + bytes(2) + bytes(16) + bytes(16)
        self.assertEqual(len(fixed), 40)

        for name, code in (
            ('REG_REQUEST', 932),
            ('REG_RESPONSE', 934),
            ('REG_FAILED', 936),
        ):
            with self.subTest(parameter=name):
                # type(2) len(2)=0 lifetime(1), then 3 octets padding out the
                # 8-octet parameter area the outer header declared.
                param = code.to_bytes(2, 'big') + (0).to_bytes(2, 'big') + bytes(4)
                raw = fixed + param

                with self.assertRaisesRegex(FieldValueError, 'invalid parameter length'):
                    HIP(raw, len(raw), extension=True)

    def test_hip_reg_info_parameter_rejects_underflowing_length(self) -> None:
        """#455: a ``REG_INFO`` parameter's ``Length`` too small for its own
        ``min_lifetime``/``max_lifetime`` octets must raise, not silently
        drop the registration list.

        ``reg_info`` sizes its list of registration-type octets as
        ``Length - 2`` -- the two octets are ``min_lifetime`` and
        ``max_lifetime``, which ``REG_INFO`` carries in place of the single
        ``lifetime`` octet #438 fixed for ``reg_request``/``reg_response``/
        ``reg_failed``. Nothing floored that at zero either, so a peer
        declaring ``Length = 0`` drove the list length to ``-2``. Unlike a
        :class:`~pcapkit.corekit.fields.strings.BytesField`,
        :class:`~pcapkit.corekit.fields.collections.ListField` never reaches
        :func:`struct.calcsize` for a negative length -- its own ``while
        length > 0`` loop just returns an empty list instead -- so this
        parsed to an empty ``reg_type`` with no exception and no diagnostic:
        ``proto.info.parameters[930].reg_type == ()``, confirmed against the
        pre-fix tree at ``da2422728``, rather than rejecting the malformed
        ``Length``.

        """
        from pcapkit.protocols.internet.hip import HIP
        from pcapkit.utilities.exceptions import FieldValueError

        # next(1) len(1)=5 pkt(1) ver(1)=0x01 (the reserved bit that must be 1)
        # checksum(2) control(2) shit(16) rhit(16) -- the fixed 40-octet header,
        # declaring one 8-octet parameter to follow: (5 - 4) * 8 == 8.
        fixed = bytes([0x3b, 0x05, 0x00, 0x01]) + bytes(2) + bytes(2) + bytes(16) + bytes(16)
        self.assertEqual(len(fixed), 40)

        # type(2)=930 (REG_INFO) len(2)=0, min_lifetime(1) max_lifetime(1),
        # then 2 octets padding out the 8-octet parameter area the outer
        # header declared.
        param = (930).to_bytes(2, 'big') + (0).to_bytes(2, 'big') + bytes(2) + bytes(2)
        raw = fixed + param

        with self.assertRaisesRegex(FieldValueError, 'invalid parameter length'):
            HIP(raw, len(raw), extension=True)

    def test_hip_nat_traversal_mode_parameter_rejects_underflowing_length(self) -> None:
        """#463: a ``NAT_TRAVERSAL_MODE`` parameter's ``Length`` too small
        for its own two-octet ``reserved`` field must raise, not silently
        drop the NAT traversal mode list.

        ``modes`` sizes its list of NAT traversal mode entries as
        ``Length - 2``, the ``- 2`` accounting for the ``reserved`` field
        read unconditionally ahead of it. Nothing floored that at zero, so a
        peer declaring ``Length = 0`` drove the list length to ``-2``.
        Unlike a :class:`~pcapkit.corekit.fields.strings.BytesField`,
        :class:`~pcapkit.corekit.fields.collections.ListField` never reaches
        :func:`struct.calcsize` for a negative length -- its own ``while
        length > 0`` loop just returns an empty list instead -- so this
        parsed to an empty ``modes`` with no exception and no diagnostic,
        rather than rejecting the malformed ``Length``.

        """
        from pcapkit.protocols.internet.hip import HIP
        from pcapkit.utilities.exceptions import FieldValueError

        # next(1) len(1)=5 pkt(1) ver(1)=0x01 (the reserved bit that must be 1)
        # checksum(2) control(2) shit(16) rhit(16) -- the fixed 40-octet header,
        # declaring one 8-octet parameter to follow: (5 - 4) * 8 == 8.
        fixed = bytes([0x3b, 0x05, 0x00, 0x01]) + bytes(2) + bytes(2) + bytes(16) + bytes(16)
        self.assertEqual(len(fixed), 40)

        # type(2)=608 (NAT_TRAVERSAL_MODE) len(2)=0, reserved(2), then 2
        # octets padding out the 8-octet parameter area the outer header
        # declared.
        param = (608).to_bytes(2, 'big') + (0).to_bytes(2, 'big') + bytes(2) + bytes(2)
        raw = fixed + param

        with self.assertRaisesRegex(FieldValueError, 'invalid parameter length'):
            HIP(raw, len(raw), extension=True)

    def test_hip_transport_format_list_parameter_accepts_an_empty_list_at_length_zero(self) -> None:
        """#463/#466: ``TRANSPORT_FORMAT_LIST`` has no two-octet prefix, so
        ``Length = 0`` is a legitimate empty list, not a malformed one.

        A first pass at #463 applied the same ``pkt['len'] - 2`` guard used
        by :class:`NATTraversalModeParameter`, :class:`ESPTransformParameter`
        and :class:`HIPTransportModeParameter` to this parameter's ``formats``
        field too, on the assumption that the expression was byte-identical
        across all four sites for the same reason. It is not: :rfc:`7401`
        Section 5.2.11 defines ``Length`` as literally "2x number of TF
        types", with nothing between ``Length`` and the list to account for.
        So ``Length = 0`` with an empty ``formats`` list -- which packs
        correctly on ``main`` as ``08010000`` -- was turned into a raise by
        that first pass, a regression rather than a declined fix. This
        parses it back to confirm the corrected :func:`~pcapkit.protocols.
        schema.internet.hip.transport_format_list_len` accepts it again.

        Two copies, and since #651 not because one is unrepresentable -- one
        now is -- but because two consecutive parameters are what prove the
        reader's *stride*. A parser that pads by the wrong amount still reads
        a lone parameter correctly and only lands in the wrong place at the
        start of the next one, so a single-parameter fixture cannot tell a
        correct padding rule from any other.

        """
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.internet.hip import HIP

        # next(1) len(1)=6 pkt(1) ver(1)=0x01 (the reserved bit that must be 1)
        # checksum(2) control(2) shit(16) rhit(16) -- the fixed 40-octet header,
        # declaring one 16-octet parameter area to follow: (6 - 4) * 8 == 16.
        fixed = bytes([0x3b, 0x06, 0x00, 0x01]) + bytes(2) + bytes(2) + bytes(16) + bytes(16)
        self.assertEqual(len(fixed), 40)

        # Two copies of: type(2)=2049 (TRANSPORT_FORMAT_LIST) len(2)=0, no
        # formats, then the four octets of padding RFC 7401 5.2.1 requires of a
        # parameter with no contents at all -- 11 + 0 - (0 + 3) % 8 == 8, so 8
        # octets each and 16 together.
        empty = (2049).to_bytes(2, 'big') + (0).to_bytes(2, 'big') + bytes(4)
        self.assertEqual(len(empty), 8)
        raw = fixed + empty * 2

        proto = HIP(raw, len(raw), extension=True)
        copies = proto.info.parameters.getlist(Parameter.TRANSPORT_FORMAT_LIST)
        self.assertEqual(len(copies), 2)
        self.assertEqual(copies[0].tf_type, ())
        self.assertEqual(copies[1].tf_type, ())

    def test_hip_transport_format_list_parameter_parses_the_full_declared_length(self) -> None:
        """#463/#466: a since-corrected revision's ``- 2`` under-read every
        *non-empty* ``TRANSPORT_FORMAT_LIST``, silently dropping trailing
        entries; this proves the fully declared list now survives.

        Pre-#463, on ``main``, with the then-one-octet ``item_type`` still in
        place: ``Length = 4`` and four one-octet transport format entries
        underflowed to ``pkt['len'] - 2 == 2``, sizing the list at only two
        entries and silently dropping the last two octets. That bug is
        independent of the item-width defect fixed alongside it below --
        confirmed directly against a ``main``-shaped schema object:
        ``TransportFormatListParameter(type=..., len=4, formats=[10, 20, 30,
        40])`` packs to twelve octets and reads back as ``formats ==
        [Unassigned_10, Unassigned_20]``.

        Each ``TF type`` entry is two octets, not one -- :rfc:`7401` Section
        5.2.11 fixes it at "2x number of TF types" and the diagram shows two
        16-bit ``TF type`` fields per 32-bit row, matching
        :class:`HIPTransportModeParameter`'s ``mode`` field rather than the
        one-octet items :func:`two_octet_prefix_list_len`'s other two call
        sites use. So this test's four entries are four *two*-octet values
        (``Length = 8``), and with both defects fixed --
        :func:`~pcapkit.protocols.schema.internet.hip.
        transport_format_list_len` returning ``Length`` unchanged, and
        ``item_type=EnumField(length=2, ...)`` -- all four survive the round
        trip rather than being dropped or double-counted.

        """
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.internet.hip import HIP

        # next(1) len(1)=8 pkt(1) ver(1)=0x01 (the reserved bit that must be 1)
        # checksum(2) control(2) shit(16) rhit(16) -- the fixed 40-octet header,
        # declaring one 32-octet parameter area to follow: (8 - 4) * 8 == 32.
        fixed = bytes([0x3b, 0x08, 0x00, 0x01]) + bytes(2) + bytes(2) + bytes(16) + bytes(16)
        self.assertEqual(len(fixed), 40)

        # Two copies of: type(2)=2049 len(2)=8, four two-octet format entries
        # (10, 20, 30, 40), then four octets of padding. Eight octets of
        # contents are 8-aligned on their own, which is exactly the residue at
        # which the pre-#651 rule (align the contents, ignore the four-octet
        # type-and-length header) appended nothing and left the record four
        # octets short; RFC 7401 5.2.1 asks for 11 + 8 - (8 + 3) % 8 == 16 --
        # so 16 octets each and 32 together.
        one = (2049).to_bytes(2, 'big') + (8).to_bytes(2, 'big') + b''.join(
            n.to_bytes(2, 'big') for n in (10, 20, 30, 40)) + bytes(4)
        self.assertEqual(len(one), 16)
        raw = fixed + one * 2

        proto = HIP(raw, len(raw), extension=True)
        copies = proto.info.parameters.getlist(Parameter.TRANSPORT_FORMAT_LIST)
        self.assertEqual(len(copies), 2)
        for copy in copies:
            self.assertEqual(len(copy.tf_type), 4)
            self.assertEqual([int(tf) for tf in copy.tf_type], [10, 20, 30, 40])

    def test_hip_transport_format_list_parameter_round_trips_through_the_maker(self) -> None:
        """#463/#466: the public maker and the schema's own read path must
        agree on the entry width, or a hand-built test cannot catch either
        one being wrong -- which is exactly what happened here.

        ``_make_param_transport_format_list`` computes ``len=2 *
        len(tf_type)``, already assuming two-octet entries, independently of
        whatever ``item_type`` the ``formats`` field declares. A hand-built
        ``TransportFormatListParameter(type=..., len=..., formats=...)``
        picks a self-consistent ``len`` by hand and so cannot expose a
        maker/schema disagreement -- which is why the one-octet
        ``item_type`` survived review once already. Building through the
        maker instead pins the two to agree: with one-octet items and two
        real entries, the maker's ``len=4`` reads back as ``len // 1 == 4``
        entries -- ``[10, 20, 0, 0]``, two spurious trailing zeros -- while
        with two-octet items it reads back as ``len // 2 == 2`` entries,
        matching what went in.

        Includes ``Parameter.ESP_TRANSFORM`` (4095) and
        ``Parameter.HIP_TRANSPORT_MODE`` (7680), both real HIP parameter
        type numbers over 255 and so within :rfc:`7401`'s own TF type range
        (2050-4095) -- and both exactly the values a one-octet ``item_type``
        cannot pack at all (``struct.error: 'B' format requires 0 <= number
        <= 255``), so the one-octet assumption cannot pass this test
        silently by falling back to small integers.

        """
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.internet.hip import HIP
        from pcapkit.protocols.schema.internet import hip as hip_schema

        proto = object.__new__(HIP)
        cases = (
            [],
            [Parameter.ESP_TRANSFORM],
            [Parameter.ESP_TRANSFORM, Parameter.HIP_TRANSPORT_MODE],
            [Parameter.ESP_TRANSFORM, Parameter.HIP_TRANSPORT_MODE, Parameter.HIP_CIPHER],
        )
        for formats in cases:
            with self.subTest(formats=formats):
                schema = proto._make_param_transport_format_list(
                    Parameter.TRANSPORT_FORMAT_LIST, version=2, formats=list(formats))
                self.assertEqual(schema.len, 2 * len(formats))

                packed = bytes(schema)
                reparsed = hip_schema.TransportFormatListParameter.unpack(packed)
                self.assertEqual(list(reparsed.formats), list(formats))

    def test_hip_esp_transform_parameter_rejects_underflowing_length(self) -> None:
        """#463: an ``ESP_TRANSFORM`` parameter's ``Length`` too small for
        its own two-octet ``reserved`` field must raise, not silently drop
        the ESP transform suite list.

        ``suites`` sizes its list of ESP transform suite entries as
        ``Length - 2``, the ``- 2`` accounting for the ``reserved`` field
        read unconditionally ahead of it. Nothing floored that at zero, so a
        peer declaring ``Length = 0`` drove the list length to ``-2``.
        Unlike a :class:`~pcapkit.corekit.fields.strings.BytesField`,
        :class:`~pcapkit.corekit.fields.collections.ListField` never reaches
        :func:`struct.calcsize` for a negative length -- its own ``while
        length > 0`` loop just returns an empty list instead -- so this
        parsed to an empty ``suites`` with no exception and no diagnostic,
        rather than rejecting the malformed ``Length``.

        """
        from pcapkit.protocols.internet.hip import HIP
        from pcapkit.utilities.exceptions import FieldValueError

        # next(1) len(1)=5 pkt(1) ver(1)=0x01 (the reserved bit that must be 1)
        # checksum(2) control(2) shit(16) rhit(16) -- the fixed 40-octet header,
        # declaring one 8-octet parameter to follow: (5 - 4) * 8 == 8.
        fixed = bytes([0x3b, 0x05, 0x00, 0x01]) + bytes(2) + bytes(2) + bytes(16) + bytes(16)
        self.assertEqual(len(fixed), 40)

        # type(2)=4095 (ESP_TRANSFORM) len(2)=0, reserved(2), then 2 octets
        # padding out the 8-octet parameter area the outer header declared.
        param = (4095).to_bytes(2, 'big') + (0).to_bytes(2, 'big') + bytes(2) + bytes(2)
        raw = fixed + param

        with self.assertRaisesRegex(FieldValueError, 'invalid parameter length'):
            HIP(raw, len(raw), extension=True)

    def test_hip_transport_mode_parameter_rejects_underflowing_length(self) -> None:
        """#463: a ``HIP_TRANSPORT_MODE`` parameter's ``Length`` too small
        for its own two-octet ``port`` field must raise, not silently drop
        the transport mode list.

        ``mode`` sizes its list of transport mode entries as ``Length - 2``,
        the ``- 2`` accounting for the ``port`` field read unconditionally
        ahead of it. Nothing floored that at zero, so a peer declaring
        ``Length = 0`` drove the list length to ``-2``. Unlike a
        :class:`~pcapkit.corekit.fields.strings.BytesField`,
        :class:`~pcapkit.corekit.fields.collections.ListField` never reaches
        :func:`struct.calcsize` for a negative length -- its own ``while
        length > 0`` loop just returns an empty list instead -- so this
        parsed to an empty ``mode`` with no exception and no diagnostic,
        rather than rejecting the malformed ``Length``.

        """
        from pcapkit.protocols.internet.hip import HIP
        from pcapkit.utilities.exceptions import FieldValueError

        # next(1) len(1)=5 pkt(1) ver(1)=0x01 (the reserved bit that must be 1)
        # checksum(2) control(2) shit(16) rhit(16) -- the fixed 40-octet header,
        # declaring one 8-octet parameter to follow: (5 - 4) * 8 == 8.
        fixed = bytes([0x3b, 0x05, 0x00, 0x01]) + bytes(2) + bytes(2) + bytes(16) + bytes(16)
        self.assertEqual(len(fixed), 40)

        # type(2)=7680 (HIP_TRANSPORT_MODE) len(2)=0, port(2), then 2 octets
        # padding out the 8-octet parameter area the outer header declared.
        param = (7680).to_bytes(2, 'big') + (0).to_bytes(2, 'big') + bytes(2) + bytes(2)
        raw = fixed + param

        with self.assertRaisesRegex(FieldValueError, 'invalid parameter length'):
            HIP(raw, len(raw), extension=True)

    def test_hip_nat_traversal_mode_parameter_round_trips_through_the_maker(self) -> None:
        """#472: the public maker and the schema's own read path must agree
        on the entry width, or a hand-built test cannot catch either one
        being wrong -- the same class of defect #463/#466 fixed for
        ``TRANSPORT_FORMAT_LIST``, at a site that fix did not cover.

        ``_make_param_nat_traversal_mode`` computes ``len=2 + 2 *
        len(mode_id)``, already assuming two-octet Mode ID entries --
        :rfc:`5770` Section 5.4 places a 16-bit Mode ID field per entry,
        after the two-octet ``Reserved`` field, exactly like
        :class:`HIPTransportModeParameter`'s ``mode``. A hand-built
        ``NATTraversalModeParameter(type=..., len=..., modes=...)`` picks a
        self-consistent ``len`` by hand and so cannot expose a maker/schema
        disagreement. Building through the maker instead pins the two to
        agree: with the one-octet ``item_type`` this module carried before
        this fix, one entry's maker-computed ``len=4`` reversed through
        :func:`~pcapkit.protocols.schema.internet.hip.
        two_octet_prefix_list_len` back to ``(len - 2) // 1 == 2`` items --
        ``[1, 0]``, one spurious trailing entry -- while with the corrected
        two-octet ``item_type`` it reverses to ``(len - 2) // 2 == 1``,
        matching what went in.

        Measured directly against this defect before this fix, byte for
        byte: ``modes=[1]`` packed to ``0260000400000100000000`` (11 octets,
        declared ``len=4``) and read back as ``modes == [1, 0]``.

        """
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.internet.hip import HIP
        from pcapkit.protocols.schema.internet import hip as hip_schema

        proto = object.__new__(HIP)
        cases = ([], [1], [1, 2], [1, 2, 3])
        for modes in cases:
            with self.subTest(modes=modes):
                schema = proto._make_param_nat_traversal_mode(
                    Parameter.NAT_TRAVERSAL_MODE, version=2, modes=list(modes))
                self.assertEqual(schema.len, 2 + 2 * len(modes))

                packed = bytes(schema)
                reparsed = hip_schema.NATTraversalModeParameter.unpack(packed)
                self.assertEqual([int(mode) for mode in reparsed.modes], list(modes))

    def test_hip_esp_transform_parameter_round_trips_through_the_maker(self) -> None:
        """#472: the public maker and the schema's own read path must agree
        on the entry width, or a hand-built test cannot catch either one
        being wrong -- the same class of defect #463/#466 fixed for
        ``TRANSPORT_FORMAT_LIST``, at a second site that fix did not cover.

        ``_make_param_esp_transform`` computes ``len=2 + 2 * len(suite_id)``,
        already assuming two-octet Suite ID entries -- :rfc:`7402` Section
        5.1.2 places a 16-bit Suite ID field per entry, after the two-octet
        ``Reserved`` field, exactly like :class:`HIPTransportModeParameter`'s
        ``mode``. A hand-built ``ESPTransformParameter(type=..., len=...,
        suites=...)`` picks a self-consistent ``len`` by hand and so cannot
        expose a maker/schema disagreement. Building through the maker
        instead pins the two to agree: with the one-octet ``item_type`` this
        module carried before this fix, one entry's maker-computed ``len=4``
        reversed through :func:`~pcapkit.protocols.schema.internet.hip.
        two_octet_prefix_list_len` back to ``(len - 2) // 1 == 2`` items --
        ``[1, 0]``, one spurious trailing entry -- while with the corrected
        two-octet ``item_type`` it reverses to ``(len - 2) // 2 == 1``,
        matching what went in.

        Measured directly against this defect before this fix, byte for
        byte: ``suites=[1]`` packed to ``0fff000400000100000000`` (11
        octets, declared ``len=4``) and read back as ``suites == [1, 0]``.

        """
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.internet.hip import HIP
        from pcapkit.protocols.schema.internet import hip as hip_schema

        proto = object.__new__(HIP)
        cases = ([], [1], [1, 2], [1, 2, 3])
        for suites in cases:
            with self.subTest(suites=suites):
                schema = proto._make_param_esp_transform(
                    Parameter.ESP_TRANSFORM, version=2, suites=list(suites))
                self.assertEqual(schema.len, 2 + 2 * len(suites))

                packed = bytes(schema)
                reparsed = hip_schema.ESPTransformParameter.unpack(packed)
                self.assertEqual([int(suite) for suite in reparsed.suites], list(suites))

    def test_hip_nat_traversal_mode_and_esp_transform_survive_the_full_parser(self) -> None:
        """#472: both parameters must also round-trip through the full
        ``HIP()`` parser, not just through a direct schema ``pack``/
        ``unpack`` -- the maker/schema agreement the two tests above check
        is necessary but not sufficient, since the full parser is what a
        real caller actually uses.

        Before this fix, feeding a maker-built ``modes=[1]`` parameter
        through the full parser did not reproduce the *same* phantom-entry
        symptom the direct schema round trip shows -- the single 11-octet
        parameter this module's ``len`` arithmetic produced was not a
        multiple of eight, so :meth:`HIP.make` raised ``ProtocolError:
        HIPv2: invalid format`` before a packet even existed to parse, and a
        hand-built two-copy packet instead corrupted the second copy and
        emitted ``SchemaWarning: packet length < 0``. Either way the full
        parser did not silently return a wrong value; it failed outright,
        which is what this test pins now that the fix makes it succeed
        instead.

        Since #651 both parameters are 8-aligned on their own -- ``len = 4``
        (two ``reserved`` octets and one two-octet entry) is exactly the
        residue at which :rfc:`7401` Section 5.2.1 wants no padding at all,
        ``11 + 4 - (4 + 3) % 8 == 8``, and at which the old contents-aligning
        rule appended four octets that must not have been there. The two
        copies stay, because two consecutive parameters are what prove the
        reader's stride rather than merely its handling of one record.

        """
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.internet.hip import HIP

        proto = object.__new__(HIP)

        nat_schema = proto._make_param_nat_traversal_mode(
            Parameter.NAT_TRAVERSAL_MODE, version=2, modes=[1])
        nat_one = bytes(nat_schema)
        self.assertEqual(nat_one, bytes.fromhex('0260000400000001'))
        self.assertEqual(len(nat_one) % 8, 0)

        esp_schema = proto._make_param_esp_transform(
            Parameter.ESP_TRANSFORM, version=2, suites=[1])
        esp_one = bytes(esp_schema)
        self.assertEqual(esp_one, bytes.fromhex('0fff000400000001'))
        self.assertEqual(len(esp_one) % 8, 0)

        for one, code, attr in (
            (nat_one, Parameter.NAT_TRAVERSAL_MODE, 'mode_id'),
            (esp_one, Parameter.ESP_TRANSFORM, 'suite_id'),
        ):
            with self.subTest(code=code):
                param_area = one * 2
                self.assertEqual(len(param_area) % 8, 0)
                hdr_len_units = 4 + len(param_area) // 8

                # next(1) len(1) pkt(1) ver(1)=0x01 (the reserved bit that must
                # be 1) checksum(2) control(2) shit(16) rhit(16) -- the fixed
                # 40-octet header, declaring the parameter area to follow.
                fixed = (bytes([0x3b, hdr_len_units, 0x00, 0x01]) + bytes(2) +
                          bytes(2) + bytes(16) + bytes(16))
                self.assertEqual(len(fixed), 40)
                raw = fixed + param_area

                parsed = HIP(raw, len(raw), extension=True)
                copies = parsed.info.parameters.getlist(code)
                self.assertEqual(len(copies), 2)
                for copy in copies:
                    self.assertEqual(getattr(copy, attr), (1,))

    def test_hip_r1_counter_code_128_resolves_to_its_own_schema(self) -> None:
        """#690: HIPv1's ``R1_Counter`` (code 128) must not fall through to
        ``UnassignedParameter`` on the parse path.

        ``R1CounterParameter`` used to register itself with ``code=
        Enum_Parameter.R1_COUNTER`` alone -- 129, the HIPv2 spelling.
        :attr:`~pcapkit.protocols.internet.hip.HIP.__parameter__` already
        carries two hand-written entries -- not a name-normalisation rule --
        mapping both 128 and 129 to ``_read_param_r1_counter``, and
        ``_make_param_r1_counter`` already built a real ``R1CounterParameter``
        for 128 -- so construction worked and only parsing was broken. The
        *schema* used to unpack a parameter off the wire is chosen by a
        different mapping, :attr:`~pcapkit.protocols.schema.schema.EnumSchema.
        registry`, wired into :class:`HIP`'s ``param`` field as
        ``OptionField(..., registry=Parameter.registry)``, and that one is
        keyed solely by the ``code=`` a schema class declares. So code 128
        fell to ``Parameter.__default__`` -- ``UnassignedParameter``, whose
        schema has ``value: bytes`` and no ``counter`` -- and
        ``_read_param_r1_counter`` failed reading ``schema.counter`` off it
        with ``AttributeError: 'UnassignedParameter' object has no attribute
        'counter'``. Measured verbatim on the tree before this fix, with the
        exact bytes this test builds.

        The expected wire bytes below are derived from
        ``R1CounterParameter.__fields__`` rather than a hex literal, on
        purpose: a literal is exactly what made the first version of this
        test fail the moment #696 widened ``counter`` from four octets to
        eight (12-octet records became 16). Deriving from the field widths
        keeps this test about the registry dispatch it names, rather than
        about a wire width #696's own ``test_hip_r1_counter_width_unit.py``
        already pins.

        Two copies, matching
        ``test_hip_nat_traversal_mode_and_esp_transform_survive_the_full_parser``'s
        own reason: proving the reader's stride across repeated occurrences
        of the same code, not working around any alignment defect. With #696
        landed a lone ``R1_COUNTER`` record already packs to a self-aligned
        16 octets and parses cleanly on its own -- measured directly, one
        copy raises nothing and reads back the same counter -- so two copies
        here are a stride check, not a workaround.

        """
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.data.internet import hip as hip_data
        from pcapkit.protocols.internet.hip import HIP
        from pcapkit.protocols.schema.internet import hip as hip_schema

        # The schema registry itself: both codes now resolve to the same class.
        self.assertIs(hip_schema.Parameter.registry[Parameter.R1_Counter],
                      hip_schema.R1CounterParameter)
        self.assertIs(hip_schema.Parameter.registry[Parameter.R1_COUNTER],
                      hip_schema.R1CounterParameter)

        proto = object.__new__(HIP)

        r1_schema = proto._make_param_r1_counter(Parameter.R1_Counter, version=1,
                                                 counter=0xaabbccdd)
        r1_one = bytes(r1_schema)

        # Derived from the schema's own declared field widths -- see the
        # docstring above for why this is not a hex literal. This only agrees
        # with the actual packed record because _make_param_r1_counter hard-
        # codes len=12 (below) rather than deriving it the same way; the two
        # would diverge the moment reserved + counter stopped summing to 12.
        reserved_len = hip_schema.R1CounterParameter.__fields__['reserved'].length
        counter_len = hip_schema.R1CounterParameter.__fields__['counter'].length
        content_len = reserved_len + counter_len
        self.assertEqual(content_len, 12)  # matches _make_param_r1_counter's len=12
        total_len = hip_schema.parameter_total_len(content_len)
        padding_len = total_len - 4 - content_len
        expected = (
            int(Parameter.R1_Counter).to_bytes(2, 'big')
            + content_len.to_bytes(2, 'big')
            + bytes(reserved_len)
            + (0xaabbccdd).to_bytes(counter_len, 'big')
            + bytes(padding_len)
        )
        self.assertEqual(r1_one, expected)
        self.assertEqual(len(r1_one), total_len)
        self.assertEqual(len(r1_one) % 8, 0)

        param_area = r1_one * 2
        self.assertEqual(len(param_area) % 8, 0)
        hdr_len_units = 4 + len(param_area) // 8

        # next(1)=0x3b len(1) pkt(1)=0x00 ver(1)=0x11 (version nibble 1, plus
        # the reserved bit that must be 1) checksum(2) control(2) shit(16)
        # rhit(16) -- the fixed 40-octet header, declaring HIPv1 and the
        # parameter area to follow.
        fixed = (bytes([0x3b, hdr_len_units, 0x00, 0x11]) + bytes(2) +
                  bytes(2) + bytes(16) + bytes(16))
        self.assertEqual(len(fixed), 40)
        raw = fixed + param_area

        parsed = HIP(raw, len(raw), extension=True)
        self.assertEqual(parsed.info.version, 1)
        copies = parsed.info.parameters.getlist(Parameter.R1_Counter)
        self.assertEqual(len(copies), 2)
        for copy in copies:
            self.assertIsInstance(copy, hip_data.R1CounterParameter)
            self.assertEqual(copy.counter, 0xaabbccdd)

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

        # #438: ``reg_request``/``reg_response``/``reg_failed`` size their
        # registration-type list as ``Length - 1``, the ``- 1`` accounting for
        # the ``lifetime`` octet already read unconditionally.
        self.assertEqual(hip_schema.registration_type_list_len({'len': 1}), 0)
        self.assertEqual(hip_schema.registration_type_list_len({'len': 4}), 3)
        # a ``Length`` too small to hold that ``lifetime`` octet must raise
        # rather than drive the list length negative.
        with self.assertRaisesRegex(FieldValueError, 'invalid parameter length'):
            hip_schema.registration_type_list_len({'len': 0})

        # #463/#466: ``TRANSPORT_FORMAT_LIST`` has no prefix octet ahead of
        # its list, so its length is ``Length`` exactly -- including zero.
        self.assertEqual(hip_schema.transport_format_list_len({'len': 0}), 0)
        self.assertEqual(hip_schema.transport_format_list_len({'len': 4}), 4)
        # unreachable from real wire bytes (``len`` is unsigned on the wire),
        # but a direct, bypassing construction call could still pass a
        # negative ``len``; keep it to the same floor-and-raise discipline.
        with self.assertRaisesRegex(FieldValueError, 'invalid parameter length'):
            hip_schema.transport_format_list_len({'len': -1})

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

    def test_hip_solution_parameter_length_is_two_whole_octet_fields(self) -> None:
        """#608: a ``SOLUTION`` parameter must be built with an even contents
        width, because its own reader splits that width into two equal halves.

        :rfc:`7401#section-5.2.5` gives the ``SOLUTION`` parameter's ``Length``
        as ``4 + RHASH_len / 4``, over a ``Random #I`` and a ``Puzzle solution
        #J`` of ``RHASH_len / 8`` octets *each*. The ``/ 4`` is shorthand for
        twice ``/ 8`` and holds only because ``RHASH_len`` -- the natural output
        length of a hash function, in bits -- is a whole number of octets.
        :meth:`~pcapkit.protocols.internet.hip.HIP._make_param_solution` used to
        apply that shorthand to an arbitrary :meth:`int.bit_length`, where the
        identity fails, and so emitted an odd contents width that
        :meth:`~pcapkit.protocols.internet.hip.HIP._read_param_solution`'s
        ``(len - 4) % 2`` guard rejects -- the library refusing to parse what it
        had just built.

        Two independent symptoms, both asserted below. The odd ``len`` is
        rejected outright; and because
        :class:`~pcapkit.protocols.schema.internet.hip.SolutionParameter` sizes
        each field from that same ``len``, an undersized ``len`` also silently
        *truncates* the values on the way out -- ``solution=0xfff`` packed into
        the one octet ``len=7`` allowed for it came back as ``0xff``.

        On the widths chosen
        --------------------
        Only the widths that are **not** multiples of 8 can tell the right
        formula from the wrong ones, which is why five of the eight cases below
        are 1, 9, 12, 17 and 25 bits. At 12 bits, for instance, the four
        plausible field-pair widths disagree: ``2 * ceil(12 / 8) == 4``
        (correct), ``ceil(12 / 4) == 3`` (the defect), ``2 * floor(12 / 8) == 2``,
        and ``ceil(12 / 8) == 2`` (one field's worth rather than two). At 1 bit
        they are 2, 1, 0 and 1.

        The 8-, 16- and 24-bit cases are deliberate controls rather than
        discriminators: at a multiple of 8 the defect's ``ceil(bits / 4)`` and
        the floor variant both coincide with the correct width, which is exactly
        why every byte-aligned fixture this library ships passed through the
        defect unharmed. They are asserted to confirm the repair changes nothing
        on the path that already worked.

        """
        import math

        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.internet.hip import HIP
        from pcapkit.protocols.schema.internet import hip as hip_schema

        proto = object.__new__(HIP)
        options = OrderedMultiDict()

        # (random, solution) pairs, ordered by the width that governs the length.
        #        random,   solution,  bits, expected len
        cases = (
            (0x1, 0x1, 1, 6),            # discriminates: /4 -> 5, floor -> 4, half -> 5
            (0xff, 0xff, 8, 6),          # control: /4 and floor both agree here
            (0x1, 0x1ff, 9, 8),          # discriminates: /4 -> 7, floor -> 6, half -> 6
            (0x1, 0xfff, 12, 8),         # the issue's headline case; /4 -> 7
            (0xffff, 0x1, 16, 8),        # control: /4 and floor both agree here
            (0x1ffff, 0x3, 17, 10),      # discriminates: /4 -> 9, floor -> 8, half -> 7
            (0xffffff, 0xffffff, 24, 10),  # control -- the width #601's fixture uses
            (0x1ffffff, 0x0, 25, 12),    # discriminates: /4 -> 11, floor -> 10, half -> 8
        )
        for random, solution, bits, expected in cases:
            with self.subTest(random=random, solution=solution, bits=bits):
                self.assertEqual(max(random.bit_length(), solution.bit_length()), bits)
                self.assertEqual(expected, 4 + 2 * math.ceil(bits / 8))

                schema = proto._make_param_solution(
                    Parameter.SOLUTION, version=2, index=1, reserved=0,
                    opaque=b'op', random=random, solution=solution,
                )
                self.assertEqual(schema.len, expected)

                # The reader's own guard: an odd contents width cannot be split
                # into the two equal fields the schema declares.
                self.assertEqual((schema.len - 4) % 2, 0)
                parsed = proto._read_param_solution(schema, version=2, options=options)
                self.assertEqual(parsed.random, random)
                self.assertEqual(parsed.solution, solution)

                # ... and the values must survive the octets, not just the schema:
                # too small a `len` narrows both fields and drops the high octets.
                packed = bytes(schema)
                reparsed = hip_schema.SolutionParameter.unpack(packed)
                self.assertEqual(reparsed.len, expected)
                self.assertEqual(reparsed.random, random)
                self.assertEqual(reparsed.solution, solution)

    def test_hip_solution_parameter_at_57_bits_stays_legal_for_hipv1(self) -> None:
        """#608: a 57-bit puzzle value must still build the 20-octet
        ``SOLUTION`` parameter that HIPv1 requires.

        :rfc:`5201#section-5.2.5` fixes ``Random #I`` and ``Puzzle solution #J``
        at 8 octets each and the parameter's ``Length`` at 20, and
        :meth:`~pcapkit.protocols.internet.hip.HIP._read_param_solution`
        enforces exactly that for ``version=1``. A 57-bit value is a perfectly
        ordinary 8-octet field with seven leading zero bits, so it must produce
        ``Length = 20``; ``4 + ceil(57 / 4)`` produces 19, which fails both the
        HIPv1 equality check and the ``(len - 4) % 2`` parity check.

        57 bits is the discriminating width here precisely because 64 is not:
        ``4 + ceil(64 / 4)`` and ``4 + 2 * ceil(64 / 8)`` are both 20, so a test
        written with a full-width 64-bit value would pass either way.

        """
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.internet.hip import HIP

        proto = object.__new__(HIP)
        options = OrderedMultiDict()

        random = 1 << 56  # bit_length() == 57
        solution = 0x1
        self.assertEqual(random.bit_length(), 57)

        schema = proto._make_param_solution(
            Parameter.SOLUTION, version=1, index=1, reserved=0,
            opaque=b'op', random=random, solution=solution,
        )
        self.assertEqual(schema.len, 20)

        parsed = proto._read_param_solution(schema, version=1, options=options)
        self.assertEqual(parsed.random, random)
        self.assertEqual(parsed.solution, solution)

    def test_hip_puzzle_and_solution_keep_the_on_wire_field_width(self) -> None:
        """#653: re-serialising a parsed ``PUZZLE`` or ``SOLUTION`` must reproduce
        the field width it arrived with, leading zero octets included.

        The width of ``Random #I`` -- and, for ``SOLUTION``, of ``Puzzle solution
        #J`` -- is ``RHASH_len / 8`` octets (:rfc:`7401#section-5.2.4`,
        :rfc:`7401#section-5.2.5`), a property of the Responder's HIT Suite rather
        than of the number that happens to sit in the field. Both builders derived
        it from :meth:`int.bit_length` instead, and the data model carried nothing
        better to derive it from, so every leading zero octet was dropped on the way
        out: measured on ``origin/main`` at ``0c7f2b7c9``, a ``SOLUTION`` read with
        ``Length = 20`` re-serialised as ``Length = 6`` and a ``PUZZLE`` read with
        ``Length = 12`` as ``Length = 5``.

        What makes this worth a test of its own rather than an
        ``EXPECTED_FAILURES`` entry is that the cycle *closes*: nothing raises, the
        integers survive, and the round trip silently yields a parameter describing
        a different puzzle -- a conformant peer reads ``RHASH_len = 8`` bits where
        the sender said 64. It only became reachable end to end once #608 was fixed
        (#629); before that the undersized rebuild tripped
        :meth:`~pcapkit.protocols.internet.hip.HIP._read_param_solution`'s parity
        guard first and failed loudly.

        The octets below are written by hand, not by this library's own builder,
        which is the only way to present it with a value narrower than its field.
        Every HIP fixture is generated by the code under test, and the generator
        passes ``random`` and ``solution`` as ``0`` -- the one value that has no
        width to lose -- which is why no fixture could ever have caught this.

        """
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.internet.hip import HIP
        from pcapkit.protocols.schema.internet import hip as hip_schema

        proto = object.__new__(HIP)
        options = OrderedMultiDict()

        # SOLUTION: Type 321, Length 20, #K = 1, Reserved = 0x20, Opaque = b'op',
        # then Random #I and Puzzle solution #J as 8 octets each carrying 1.
        #
        # Reserved is 0x20 rather than the conformant 0x00 *only* so that this case
        # isolates #653 on the unfixed tree: a 0x00 there trips #654's
        # ``math.log2(0)`` first and the width loss is never reached. #654's own
        # test below uses the conformant 0x00.
        wire = bytes.fromhex('0141' '0014' '01' '20' '6f70'
                             '0000000000000001' '0000000000000001' '00000000')
        self.assertEqual(len(wire), 28)

        unpacked = hip_schema.SolutionParameter.unpack(wire)
        self.assertEqual(unpacked.len, 20)
        self.assertEqual(unpacked.random, 1)
        self.assertEqual(unpacked.solution, 1)

        parsed = proto._read_param_solution(unpacked, version=2, options=options)
        self.assertEqual(parsed.random, 1)
        self.assertEqual(parsed.solution, 1)
        # The width is declared on the data model, not inferred from the values.
        self.assertEqual(parsed.rhash_len, 64)

        rebuilt = proto._make_param_solution(Parameter.SOLUTION, parsed, version=2)
        self.assertEqual(rebuilt.len, 20)
        self.assertNotEqual(rebuilt.len, 6)  # what the unfixed builder produced
        # Compared without the trailing padding, and then against the re-packed
        # source schema rather than against the literal. Both are deliberate: the
        # padding rule is itself in flight (#651/#664), and this test is about the
        # `Length` field and the payload octets, not about how many alignment octets
        # follow them. Either assertion alone would be weaker -- the first pins the
        # octets that came off the wire, the second pins losslessness end to end.
        self.assertEqual(bytes(rebuilt)[:4 + rebuilt.len], wire[:4 + unpacked.len])
        self.assertEqual(bytes(rebuilt), bytes(unpacked))

        # PUZZLE: Type 257, Length 12, #K = 1, Lifetime = 0x20, Opaque = b'op',
        # then Random #I as 8 octets carrying 1.
        wire = bytes.fromhex('0101' '000c' '01' '20' '6f70'
                             '0000000000000001' '00000000')
        self.assertEqual(len(wire), 20)

        unpacked = hip_schema.PuzzleParameter.unpack(wire)
        self.assertEqual(unpacked.len, 12)
        self.assertEqual(unpacked.random, 1)

        parsed = proto._read_param_puzzle(unpacked, version=2, options=options)
        self.assertEqual(parsed.random, 1)
        self.assertEqual(parsed.rhash_len, 64)

        rebuilt = proto._make_param_puzzle(Parameter.PUZZLE, parsed, version=2)
        self.assertEqual(rebuilt.len, 12)
        self.assertNotEqual(rebuilt.len, 5)  # what the unfixed builder produced
        self.assertEqual(bytes(rebuilt)[:4 + rebuilt.len], wire[:4 + unpacked.len])
        self.assertEqual(bytes(rebuilt), bytes(unpacked))

    def test_hip_solution_second_octet_is_reserved_not_a_lifetime(self) -> None:
        """#654: ``SOLUTION``'s second contents octet is ``Reserved``, and must be
        zero when sent.

        :rfc:`7401#section-5.2.5` names it ``Reserved`` -- "zero when sent, ignored
        when received" -- and :rfc:`5201#section-5.2.5` says the same, so there is
        no HIP version under which it is a duration. Only ``PUZZLE``
        (:rfc:`7401#section-5.2.4`) has a ``Lifetime`` at that offset, and only
        §5.2.4 defines the ``2^(value - 32)`` seconds encoding that pcapkit was
        applying to both. Measured on ``origin/main`` at ``0c7f2b7c9``, the octet
        came out as ``0x20``, ``0x21``, ``0x25`` or ``0x2b`` depending on the
        lifetime asked for, and the one value the RFC actually permits -- zero --
        could not be written at all.

        Three things are asserted, in the order they matter. The octet is zero for a
        from-scratch build, whatever else is passed. A parameter that arrives with
        the conformant ``0x00`` survives the round trip, where it used to be
        unbuildable. And a parameter that arrives with a non-zero ``Reserved``
        re-emits that same octet rather than a re-derived one, because round-trip
        fidelity is what #653 is about and "ignored when received" is honoured by
        not interpreting the value, not by discarding it.

        """
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.data.internet import hip as hip_data
        from pcapkit.protocols.internet.hip import HIP
        from pcapkit.protocols.schema.internet import hip as hip_schema
        from pcapkit.utilities.exceptions import UnsupportedCall

        proto = object.__new__(HIP)
        options = OrderedMultiDict()

        # The data model no longer claims SOLUTION has a lifetime.
        self.assertIn('reserved', hip_data.SolutionParameter.__annotations__)
        self.assertNotIn('lifetime', hip_data.SolutionParameter.__annotations__)
        self.assertIn('reserved', hip_schema.SolutionParameter.__annotations__)
        self.assertNotIn('lifetime', hip_schema.SolutionParameter.__annotations__)
        # ... while PUZZLE, where the RFC does put one, still does.
        self.assertIn('lifetime', hip_data.PuzzleParameter.__annotations__)

        # Zero when sent, for a from-scratch build, at the default and explicitly.
        for reserved in (None, 0):
            with self.subTest(reserved=reserved):
                kwargs = {} if reserved is None else {'reserved': reserved}
                schema = proto._make_param_solution(
                    Parameter.SOLUTION, version=2, index=1, opaque=b'op',
                    random=1 << 63, solution=1 << 63, **kwargs,
                )
                self.assertEqual(schema.reserved, 0)
                self.assertEqual(schema.len, 20)
                # Octet 5 of the parameter is the Reserved position: two octets of
                # Type, two of Length, one of #K, then Reserved.
                self.assertEqual(bytes(schema)[5], 0x00)
                for stale in (0x20, 0x21, 0x25, 0x2b):
                    self.assertNotEqual(bytes(schema)[5], stale)

        # A conformant SOLUTION -- Reserved = 0x00 -- parsed and re-serialised. On
        # the unfixed tree this raised a bare ValueError from ``math.log2(0.0)``,
        # because 0x00 was read as ``2 ** (0 - 32)`` seconds, which is below
        # timedelta's microsecond resolution and rounds to timedelta(0).
        # Compared against the re-packed source schema rather than against the
        # literal, and with the trailing padding excluded, for the reason given in
        # `test_hip_puzzle_and_solution_keep_the_on_wire_field_width`: the padding
        # rule is in flight (#651/#664) and is not what this test is about.
        conformant = bytes.fromhex('0141' '0014' '01' '00' '6f70'
                                   '8000000000000000' '8000000000000000' '00000000')
        conformant_schema = hip_schema.SolutionParameter.unpack(conformant)
        parsed = proto._read_param_solution(conformant_schema, version=2, options=options)
        self.assertEqual(parsed.reserved, 0)
        rebuilt = proto._make_param_solution(Parameter.SOLUTION, parsed, version=2)
        self.assertEqual(rebuilt.reserved, 0)
        self.assertEqual(bytes(rebuilt)[:4 + rebuilt.len], conformant[:4 + rebuilt.len])
        self.assertEqual(bytes(rebuilt), bytes(conformant_schema))

        # A non-zero Reserved is carried verbatim rather than re-derived.
        received = bytes.fromhex('0141' '0014' '01' '2b' '6f70'
                                 '8000000000000000' '8000000000000000' '00000000')
        received_schema = hip_schema.SolutionParameter.unpack(received)
        parsed = proto._read_param_solution(received_schema, version=2, options=options)
        self.assertEqual(parsed.reserved, 0x2b)
        rebuilt = proto._make_param_solution(Parameter.SOLUTION, parsed, version=2)
        self.assertEqual(bytes(rebuilt)[5], 0x2b)
        self.assertEqual(bytes(rebuilt)[:4 + rebuilt.len], received[:4 + rebuilt.len])
        self.assertEqual(bytes(rebuilt), bytes(received_schema))

        # ... but an explicit `reserved` still overrides it, which is the only way to
        # write the conformant zero over a peer's non-conformant octet: the data
        # model is immutable, so the parsed object cannot be corrected in place.
        with self.assertRaises(UnsupportedCall):
            parsed.reserved = 0  # type: ignore[misc]
        sanitised = proto._make_param_solution(
            Parameter.SOLUTION, parsed, version=2, reserved=0,
        )
        self.assertEqual(sanitised.reserved, 0)
        self.assertEqual(bytes(sanitised)[5], 0x00)
        # `received` and `conformant` differ in that octet alone, so zeroing it
        # reproduces the conformant parameter exactly.
        self.assertEqual(bytes(sanitised), bytes(conformant_schema))

    def test_hip_puzzle_lifetime_guard_raises_an_in_library_error(self) -> None:
        """#654: a lifetime ``math.log2`` cannot encode must raise a pcapkit
        exception, not a bare :exc:`ValueError`.

        :mod:`pcapkit.utilities.exceptions` exists so that only user-facing stack
        information reaches the user: raising a
        :class:`~pcapkit.utilities.exceptions.BaseError` logs once at
        ``CRITICAL`` and, outside development mode, trims the traceback. A bare
        :exc:`ValueError` from ``math.log2`` gets none of that -- it is invisible to
        ``except BaseError``, it is not logged, and its message, ``expected a
        positive input``, names neither HIP nor the parameter nor the field.

        :class:`~pcapkit.utilities.exceptions.ProtocolError` is the right member of
        that family rather than the nearest-named one. It is already what both
        readers raise for a malformed ``PUZZLE`` or ``SOLUTION``, and it is declared
        ``ProtocolError(BaseError, ValueError)`` -- so it joins the family *and*
        stays catchable by any caller already written around the
        :exc:`ValueError` that escapes today. Both halves are asserted below,
        because the second is what makes this a non-breaking change.
        :class:`~pcapkit.utilities.exceptions.EnumError` would not do: it is
        ``EnumError(BaseError, TypeError)``, so it would silently stop being caught.

        Reachable from conformant input rather than only from a crafted one: a
        ``Lifetime`` octet of ``0x00`` is a legal encoding of ``2^-32`` seconds,
        which :class:`~datetime.timedelta` rounds to zero, so parsing an ordinary
        PUZZLE and re-emitting it lands here.

        """
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.internet.hip import HIP
        from pcapkit.protocols.schema.internet import hip as hip_schema
        from pcapkit.utilities.exceptions import BaseError, ProtocolError

        proto = object.__new__(HIP)
        options = OrderedMultiDict()

        self.assertTrue(issubclass(ProtocolError, BaseError))
        self.assertTrue(issubclass(ProtocolError, ValueError))

        # Non-positive lifetimes, as an int and as a timedelta. ``0`` is the
        # builder's own default, which is what the round-trip generator overrides
        # with ``{'lifetime': 1}`` to dodge -- an override that also left `random`
        # at 0 and so hid #608 for as long as it existed.
        for lifetime in (0, 0.0, datetime.timedelta(0), -1, datetime.timedelta(seconds=-1)):
            with self.subTest(lifetime=lifetime):
                with self.assertRaises(ProtocolError) as caught:
                    proto._make_param_puzzle(
                        Parameter.PUZZLE, version=2, index=1, lifetime=lifetime,
                        opaque=b'op', random=1 << 63,
                    )
                self.assertIsInstance(caught.exception, BaseError)
                self.assertIsInstance(caught.exception, ValueError)
                self.assertIn('invalid lifetime', str(caught.exception))
                self.assertIn('257', str(caught.exception))

        # A lifetime too large for the one-octet field. ``UInt8Field`` wraps rather
        # than raising -- measured, 300 packs as 0x2c -- so without this guard the
        # parameter would carry some other, valid-looking duration.
        with self.assertRaises(ProtocolError) as caught:
            proto._make_param_puzzle(
                Parameter.PUZZLE, version=2, index=1, lifetime=1 << 240,
                opaque=b'op', random=1 << 63,
            )
        self.assertIn('invalid lifetime', str(caught.exception))

        # A PUZZLE whose Lifetime octet is 0x00, parsed then re-serialised: the
        # conformant-input path. On the unfixed tree this was a bare ValueError.
        wire = bytes.fromhex('0101' '000c' '01' '00' '6f70'
                             '8000000000000000' '00000000')
        parsed = proto._read_param_puzzle(
            hip_schema.PuzzleParameter.unpack(wire), version=2, options=options,
        )
        self.assertEqual(parsed.lifetime, datetime.timedelta(0))
        with self.assertRaises(ProtocolError) as caught:
            proto._make_param_puzzle(Parameter.PUZZLE, parsed, version=2)
        self.assertIsInstance(caught.exception, BaseError)

        # A positive lifetime still encodes exactly as it did before.
        self.assertEqual(proto._make_param_puzzle(
            Parameter.PUZZLE, version=2, index=1, lifetime=1,
            opaque=b'op', random=1 << 63,
        ).lifetime, 32)

    def test_hip_puzzle_and_solution_size_from_version_under_hipv1(self) -> None:
        """#655: under HIPv1 both builders must size from ``version``, not from the
        value's bit length.

        :rfc:`5201#section-5.2.4` and :rfc:`5201#section-5.2.5` state the widths as
        literal constants -- ``Random #I`` and ``Puzzle solution #J`` are 8 bytes
        each, ``Length`` is 12 for ``PUZZLE`` and 20 for ``SOLUTION`` -- and
        "Random #I is represented as a 64-bit integer" leaves no narrower reading.
        Both builders took a ``version`` keyword and neither read it, so measured on
        ``origin/main`` at ``0c7f2b7c9`` the ``version=1`` and ``version=2`` lengths
        were **identical at every bit width**, and under HIPv1 each builder accepted
        only values whose ``bit_length()`` landed in 57..64. Everything narrower
        built a parameter this library's own reader rejects -- the same shape as
        #608 -- and everything wider overshot.

        On the widths chosen
        --------------------
        Multiples of 8 cannot discriminate: at 8, 16, 32, 56, 64 and 128 bits the
        correct ``2 * ceil(b / 8)`` agrees with #608's ``ceil(b / 4)`` and with the
        floor variant, which is exactly why every byte-aligned fixture passed
        through that defect unharmed. So 1, 9, 15, 17, 57 and 65 are the ones
        carrying the weight here, and the byte-aligned rows are kept as controls.
        57 and 65 bracket HIPv1's field: 57 is the narrowest value whose derived
        width reached the required 20, and 65 the narrowest that overshoots it.

        """
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.internet.hip import HIP
        from pcapkit.utilities.exceptions import ProtocolError

        proto = object.__new__(HIP)
        options = OrderedMultiDict()

        #  bits, SOLUTION len v2, PUZZLE len v2 -- HIPv1 is always 20 and 12.
        cases = (
            (1, 6, 5),
            (8, 6, 5),
            (9, 8, 6),
            (15, 8, 6),
            (16, 8, 6),
            (17, 10, 7),
            (32, 12, 8),
            (56, 18, 11),
            (57, 20, 12),
            (64, 20, 12),
        )
        for bits, solution_v2, puzzle_v2 in cases:
            value = 1 << (bits - 1)
            with self.subTest(bits=bits):
                self.assertEqual(value.bit_length(), bits)

                # HIPv1: the RFC's constants, at every width, narrow values
                # included. PUZZLE goes first deliberately -- its keyword arguments
                # are the same before and after this change, so on the unfixed tree
                # this assertion is reached and reports #655 directly (measured:
                # ``AssertionError: 12 != 5`` at 1 bit). SOLUTION's cannot be, since
                # there the unfixed builder crashes on its own ``lifetime`` default
                # before any length is computed -- which is #654.
                schema = proto._make_param_puzzle(
                    Parameter.PUZZLE, version=1, index=1, lifetime=1,
                    opaque=b'op', random=value,
                )
                self.assertEqual(schema.len, 12)
                # ... and the reader, which enforces `len == 12`, accepts it.
                self.assertEqual(proto._read_param_puzzle(
                    schema, version=1, options=options,
                ).random, value)

                schema = proto._make_param_solution(
                    Parameter.SOLUTION, version=1, index=1, reserved=0,
                    opaque=b'op', random=value, solution=value,
                )
                self.assertEqual(schema.len, 20)
                self.assertEqual(proto._read_param_solution(
                    schema, version=1, options=options,
                ).random, value)

                # HIPv2: unchanged, still derived from the value when nothing
                # declares the width. This is what makes the v1 column a fix rather
                # than a blanket constant.
                self.assertEqual(proto._make_param_puzzle(
                    Parameter.PUZZLE, version=2, index=1, lifetime=1,
                    opaque=b'op', random=value,
                ).len, puzzle_v2)
                self.assertEqual(proto._make_param_solution(
                    Parameter.SOLUTION, version=2, index=1, reserved=0,
                    opaque=b'op', random=value, solution=value,
                ).len, solution_v2)

                # The two versions agree only where the derived width happens to be
                # the RFC's constant, which is the whole of the defect: they used to
                # agree everywhere.
                self.assertEqual(solution_v2 == 20, bits in (57, 64))
                self.assertEqual(puzzle_v2 == 12, bits in (57, 64))

        # A value HIPv1 cannot represent is refused outright, with a pcapkit
        # exception, rather than built into a parameter the reader will reject.
        for bits in (65, 128):
            value = 1 << (bits - 1)
            with self.subTest(bits=bits):
                with self.assertRaises(ProtocolError):
                    proto._make_param_puzzle(
                        Parameter.PUZZLE, version=1, index=1, lifetime=1,
                        opaque=b'op', random=value,
                    )
                with self.assertRaises(ProtocolError):
                    proto._make_param_solution(
                        Parameter.SOLUTION, version=1, index=1, reserved=0,
                        opaque=b'op', random=value, solution=value,
                    )

    def test_hip_puzzle_and_solution_accept_an_explicit_field_width(self) -> None:
        """#653/#655: ``rhash_len`` declares the field width for a from-scratch
        build, which is the only way HIPv2 can express one.

        Under HIPv2 the width is ``RHASH_len / 8`` octets, where ``RHASH_len`` is
        the output length of the Responder's HIT hash algorithm
        (:rfc:`7401#section-2.3`). It genuinely varies -- ``RSA,DSA/SHA-256`` is the
        REQUIRED HIT Suite (:rfc:`7401#section-5.2.10`), giving a 256-bit
        ``RHASH_len`` and a 32-octet field -- so no constant and no version can
        supply it, and a caller building a full-width parameter around a small value
        has nowhere else to say so.

        """
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.internet.hip import HIP
        from pcapkit.utilities.exceptions import ProtocolError

        proto = object.__new__(HIP)
        options = OrderedMultiDict()

        # RHASH_len = 256 bits, the REQUIRED HIT Suite's hash: 32-octet fields, so
        # Length is 4 + 2 * 32 = 68 for SOLUTION and 4 + 32 = 36 for PUZZLE -- even
        # though the value would otherwise derive a 1-octet field.
        schema = proto._make_param_solution(
            Parameter.SOLUTION, version=2, index=1, reserved=0, opaque=b'op',
            random=1, solution=1, rhash_len=256,
        )
        self.assertEqual(schema.len, 68)
        self.assertEqual(proto._read_param_solution(
            schema, version=2, options=options,
        ).rhash_len, 256)

        schema = proto._make_param_puzzle(
            Parameter.PUZZLE, version=2, index=1, lifetime=1, opaque=b'op',
            random=1, rhash_len=256,
        )
        self.assertEqual(schema.len, 36)
        self.assertEqual(proto._read_param_puzzle(
            schema, version=2, options=options,
        ).rhash_len, 256)

        # A width that is not a whole number of octets, or is negative, is not an
        # RHASH_len -- the natural output length of a hash function, in bits.
        for rhash_len in (12, -8):
            with self.subTest(rhash_len=rhash_len):
                with self.assertRaises(ProtocolError):
                    proto._make_param_puzzle(
                        Parameter.PUZZLE, version=2, index=1, lifetime=1, opaque=b'op',
                        random=1, rhash_len=rhash_len,
                    )

        # Nor is one too narrow for the value it has to hold: silently truncating
        # is what an undersized `len` used to do.
        with self.assertRaises(ProtocolError):
            proto._make_param_solution(
                Parameter.SOLUTION, version=2, index=1, reserved=0, opaque=b'op',
                random=1 << 64, solution=1, rhash_len=64,
            )

        # Under HIPv1 the RFC's constant is not negotiable.
        with self.assertRaises(ProtocolError):
            proto._make_param_solution(
                Parameter.SOLUTION, version=1, index=1, reserved=0, opaque=b'op',
                random=1, solution=1, rhash_len=256,
            )

        # An explicit width overrides the one a parsed parameter carries, so a
        # parameter can be re-emitted for a different association.
        parsed = proto._read_param_solution(
            proto._make_param_solution(
                Parameter.SOLUTION, version=2, index=1, reserved=0, opaque=b'op',
                random=1, solution=1, rhash_len=64,
            ),
            version=2, options=options,
        )
        self.assertEqual(parsed.rhash_len, 64)
        self.assertEqual(proto._make_param_solution(
            Parameter.SOLUTION, parsed, version=2, rhash_len=128,
        ).len, 36)
        # ... and the same for PUZZLE, whose ``param``-plus-explicit-width branch is
        # otherwise never taken.
        parsed = proto._read_param_puzzle(
            proto._make_param_puzzle(
                Parameter.PUZZLE, version=2, index=1, lifetime=1, opaque=b'op',
                random=1, rhash_len=64,
            ),
            version=2, options=options,
        )
        self.assertEqual(parsed.rhash_len, 64)
        self.assertEqual(proto._make_param_puzzle(
            Parameter.PUZZLE, parsed, version=2, rhash_len=128,
        ).len, 20)
    def test_hip_parameter_total_length_matches_the_rfc_7401_formula(self) -> None:
        """#651: a HIP parameter's *total* length is what must be 8-aligned.

        :rfc:`7401` Section 5.2.1 states the arithmetic outright, so this test
        compares against the RFC rather than against pcapkit --

        ::

            All of the encoded TLV parameters have a length (that includes the
            Type and Length fields), which is a multiple of 8 bytes.

            Total Length = 11 + Length - (Length + 3) % 8;

        -- and that matters more here than usual, because **pcapkit round-trips
        its own output whatever this formula says**: the writer and the reader
        shared one wrong expression, so their disagreement with a real peer was
        invisible to every construct-parse-construct test in the suite. Only an
        independent statement of the RFC's arithmetic can see it, which is what
        ``rfc_total`` below is. It is written out longhand from the RFC text and
        deliberately does *not* call
        :func:`~pcapkit.protocols.schema.internet.hip.parameter_total_len`,
        since comparing an implementation with itself asserts nothing.

        Every ``Length`` from 0 to 63 is checked, which is what makes the widths
        discriminate. The defect was exactly ``4 (mod 8)``, so it is not enough
        to test a handful of convenient values:

        * ``Length = 4``, a whole ``SEQ``, and ``Length = 20``, a whole
          ``SOLUTION``: contents plus the four-octet header are *already*
          8-aligned, so the RFC wants **no padding at all**. The old rule
          appended four octets that must not be there, and a rule that dropped
          the outer ``% 8`` -- ``8 - (Length + 4) % 8`` rather than
          ``(8 - (Length + 4) % 8) % 8`` -- would append eight. Only the
          residue ``Length % 8 == 4`` separates the correct answer from both.
        * ``Length = 0``, ``8``, ``16``: contents are 8-aligned on their own, so
          the old rule appended nothing and left the record four octets short.
          This is the residue at which the defect *under*-pads, and it is the
          one a test of "is the result at least as long as the contents" cannot
          see.
        * ``Length`` not a multiple of four -- 1, 2, 3, 5, 6, 7 -- where the pad
          is 3, 2, 1, 7, 6, 5. A formula that only ever moved in steps of four,
          which both the old and the fixed one look like at a glance, is caught
          here and nowhere else.

        The old and the correct formula never agree, at any ``Length``: there is
        no residue at which this test would have passed before the fix.

        """
        from pcapkit.protocols.schema.internet import hip as hip_schema

        def rfc_total(length: int) -> int:
            """RFC 7401 5.2.1, transcribed rather than imported."""
            return 11 + length - (length + 3) % 8

        def pre_651_total(length: int) -> int:
            """What every one of the 95 padding sites computed before #651."""
            return 4 + length + (8 - (length % 8)) % 8

        for length in range(64):
            with self.subTest(length=length):
                total = hip_schema.parameter_total_len(length)
                self.assertEqual(total, rfc_total(length))
                # the property the RFC gives the formula *for*
                self.assertEqual(total % 8, 0)
                # padding is "0-7 bytes, added if needed", and the record is the
                # header, the contents and that padding, with nothing left over
                padding = hip_schema.parameter_padding_len({'len': length})
                self.assertEqual(4 + length + padding, total)
                self.assertGreaterEqual(padding, 0)
                self.assertLessEqual(padding, 7)
                # and the defect is gone at every single residue, not on average
                self.assertNotEqual(total, pre_651_total(length))

        # Which parameters this governs, stated rather than implied: every padding
        # site in ``schema/internet/hip.py`` and every reported record length in
        # ``internet/hip.py`` routes through these two helpers -- 45 of the 46
        # parameter schemas and 48 of the 49 reported lengths. The forty-sixth is
        # ``LOCATOR_SET``, which since #679 uses
        # :func:`~pcapkit.protocols.schema.internet.hip.locator_set_padding_len`
        # instead: the same arithmetic, read off a snapshot of the parameter's
        # own ``Length`` rather than off ``pkt['len']``, which its nested
        # locators shadow while they pack. The counts and the identity of that
        # one callback are asserted directly in
        # :meth:`test_hip_padding_sites_are_the_two_known_callbacks_and_nothing_else`,
        # so a third expression cannot appear unnoticed.
        #
        # The sweep above covers all eight residues, which is enough for any
        # formula periodic in ``Length % 8`` -- but not for one that is not.
        # A ``parameter_total_len`` that masked its argument (``length & 0xFF``,
        # say) agrees on 0..63 and diverges at 256, and nothing in the generator
        # builds a parameter that long, so the whole suite would pass. ``len`` is
        # an unsigned 16-bit field, so check the field's entire domain; it is one
        # cheap loop and it closes that gap outright.
        diverged = [length for length in range(65536)
                    if hip_schema.parameter_total_len(length) != rfc_total(length)]
        self.assertEqual(
            diverged[:16], [],
            f'parameter_total_len diverges from RFC 7401 5.2.1 at '
            f'{len(diverged)} of the 65536 representable Length values, first '
            f'at {diverged[:16]}'
        )

        # the three spot values worth naming, so a regression reads as a number
        # rather than as a loop index
        self.assertEqual(hip_schema.parameter_total_len(4), 8)    # SEQ: no padding
        self.assertEqual(hip_schema.parameter_total_len(8), 16)   # was 12, short by 4
        self.assertEqual(hip_schema.parameter_total_len(20), 24)  # SOLUTION: was 28
        self.assertEqual(hip_schema.parameter_padding_len({'len': 4}), 0)
        self.assertEqual(hip_schema.parameter_padding_len({'len': 8}), 4)

        # unreachable from real wire bytes (``len`` is unsigned on the wire), but
        # a direct construction call could pass a negative ``len``, for which the
        # RFC formula answers 8 -- a "total" shorter than the header alone. Keep
        # it to the same floor-and-raise discipline as the other length helpers.
        from pcapkit.utilities.exceptions import FieldValueError
        with self.assertRaisesRegex(FieldValueError, 'invalid parameter length'):
            hip_schema.parameter_total_len(-1)
        with self.assertRaisesRegex(FieldValueError, 'invalid parameter length'):
            hip_schema.parameter_padding_len({'len': -1})

    def test_hip_padding_sites_are_the_two_known_callbacks_and_nothing_else(self) -> None:
        """#651/#664/#679: two padding callbacks cover all 46, and no third exists.

        #651 routed every HIP padding site through
        :func:`~pcapkit.protocols.schema.internet.hip.parameter_padding_len`, with
        one deliberate exception. ``LOCATOR_SET`` carried two defects that
        cancelled at the shape its tests sampled -- a ``Length`` in 4-octet units
        where :rfc:`7401` Section 5.2.1 counts bytes, and a padding callback
        reading the nested ``Locator.len`` instead of the parameter's -- so
        correcting either alone made the wire output worse, and #664 documented
        the exclusion rather than leaving it to look accidental.

        **#679 fixed the pair, so the exclusion is no longer a hold-back.**
        ``LocatorSetParameter.padding`` now uses
        :func:`~pcapkit.protocols.schema.internet.hip.locator_set_padding_len`,
        which defers to ``parameter_padding_len`` for the arithmetic and differs
        from it only in *where it reads the length from*: the
        :data:`~pcapkit.protocols.schema.internet.hip.LOCATOR_SET_LEN` snapshot
        that :func:`~pcapkit.protocols.schema.internet.hip.locator_set_len_callback`
        takes before the nested locators overwrite ``pkt['len']``.

        So the shape this guards has changed, and the reason to keep guarding it
        has not. Three failure modes, none of which anything else catches:

        * **A third expression appearing.** A later change that gives some
          parameter an inline lambda -- to make a pinned literal pass, say --
          would be indistinguishable from the two legitimate callbacks by
          inspection. ``bespoke`` below must stay empty.
        * **The ``LOCATOR_SET`` callback regressing to a raw ``pkt['len']``
          read.** That is the pre-#664 state, and it silently re-introduces
          defect 1: the value read would be the last locator's 4, so the padding
          would be four octets at every locator count again.
        * **``LOCATOR_SET`` being "tidied" onto ``parameter_padding_len``
          directly.** That looks like a simplification and is not one: on the
          packing path the nested locators have already shadowed ``len`` by then,
          so it would read 4 for an IPv6 locator and 5 for an SPI-bearing one
          rather than the parameter's byte count.

        This reads the declared field objects rather than the module source, so it
        is about what the schemas *do*, not about how they are written.

        """
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.schema.internet import hip as hip_schema

        on_helper = []  # type: list[str]
        on_locator_set = []  # type: list[str]
        bespoke = []  # type: list[str]
        unpadded = []  # type: list[str]
        for name in dir(hip_schema):
            obj = getattr(hip_schema, name)
            if not (isinstance(obj, type)
                    and issubclass(obj, hip_schema.Parameter)
                    and obj is not hip_schema.Parameter):
                continue
            field = obj.__fields__.get('padding')
            if field is None:
                unpadded.append(name)
                continue
            callback = getattr(field, '_length_callback', None)
            if callback is hip_schema.parameter_padding_len:
                on_helper.append(name)
            elif callback is hip_schema.locator_set_padding_len:
                on_locator_set.append(name)
            else:
                bespoke.append(name)

        self.assertEqual(
            bespoke, [],
            'every HIP parameter schema must pad through parameter_padding_len '
            'or, for LOCATOR_SET alone, locator_set_padding_len. A name here is '
            'a third padding expression, which is what #651 existed to remove.'
        )
        self.assertEqual(
            on_locator_set, ['LocatorSetParameter'],
            'exactly one HIP parameter schema reads its padding length from the '
            'LOCATOR_SET_LEN snapshot, and it is LocatorSetParameter (see #679). '
            'If this emptied, LOCATOR_SET is reading a len its nested locators '
            'have already shadowed; if it grew, some other parameter has been '
            'given a snapshot it has no nested schemas to need.'
        )

        # Three schemas declare no padding field at all, which is correct rather
        # than an omission and is unchanged by #651: their contents are a fixed
        # 20 octets (a two-octet port, two reserved and a 16-octet address), and
        # 11 + 20 - (20 + 3) % 8 == 24 == 4 + 20, so the RFC asks for no padding.
        # Measured on this tree and on b34f132f6: all three pack to 24 octets.
        # Listed explicitly because a *fourth* name appearing here would mean a
        # parameter had quietly lost its padding field.
        self.assertEqual(
            sorted(unpadded),
            ['RegFromParameter', 'RelayFromParameter', 'RelayToParameter'])

        self.assertEqual(len(on_helper), 45)
        self.assertEqual(
            len(on_helper) + len(on_locator_set) + len(bespoke) + len(unpadded), 49)

        # and the one on the snapshot is the schema registered for LOCATOR_SET,
        # not some similarly-named class that merely sorts next to it
        self.assertIs(hip_schema.Parameter.registry[Parameter.LOCATOR_SET],
                      hip_schema.LocatorSetParameter)

        # the snapshot callback is installed where it has to be -- on the
        # ``locators`` ListField, which resolves before any nested Locator has
        # packed -- rather than merely existing in the module
        self.assertIs(
            getattr(hip_schema.LocatorSetParameter.__fields__['locators'],
                    '_callback', None),
            hip_schema.locator_set_len_callback)

    def test_hip_parameter_records_are_eight_octet_aligned_on_the_wire(self) -> None:
        """#651: the octets a real parameter packs, not just the arithmetic.

        :func:`~pcapkit.protocols.schema.internet.hip.parameter_total_len` being
        right is necessary but not sufficient -- all 46 padding sites in the
        schema module have to *use* it. So this packs real parameter schemas,
        chosen to cover the residues that discriminate, and measures the octets.

        ``SEQ`` is the one to read first. It carries a single four-octet Update
        ID, so it is complete in eight octets and needs no padding whatsoever;
        pre-#651 pcapkit emitted twelve, appending four octets a conformant
        receiver would read as the start of the next parameter. :rfc:`7401`
        Section 5.3.5 puts a ``SEQ`` or an ``ACK`` on every ``UPDATE``, so this
        is not a corner of the parameter space.

        The last assertion is the stride check: two consecutive parameters
        through the full parser. A wrong padding rule still reads a *lone*
        parameter correctly -- it only lands in the wrong place at the start of
        the next one -- so one record cannot distinguish any padding rule from
        any other.

        Nothing here imports
        :func:`~pcapkit.protocols.schema.internet.hip.parameter_total_len`: the
        RFC's formula is written out inline, so on a pre-#651 tree this fails
        with a real octet-count mismatch rather than with an
        :exc:`AttributeError` for a helper that does not exist there yet.

        """
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.internet.hip import HIP

        proto = object.__new__(HIP)

        # (maker, kwargs, declared Length, total octets, pre-#651 octets)
        cases = [
            ('_make_param_seq', {'update_id': 0x01020304}, 4, 8, 12),
            ('_make_param_esp_info', {}, 12, 16, 20),
            # #608 sizes SOLUTION's ``len`` from the operands' own widths, so
            # reaching the RFC's ``Length = 20`` needs eight octets of each:
            # 4 + 2 * ceil(57 / 8) == 20. No ``lifetime=`` here: an earlier
            # revision of this case passed one to dodge #654's ``math.log2(0)``,
            # and #665 removed that keyword, after which it survived only by
            # being swallowed by ``**kwargs``. Dead keywords in a table like this
            # read as requirements, so it is gone.
            ('_make_param_solution', {'index': 1, 'opaque': b'op',
                                      'random': 1 << 56, 'solution': 1 << 56},
             20, 24, 28),
            ('_make_param_unassigned', {'contents': b''}, 0, 8, 4),
            ('_make_param_unassigned', {'contents': b'x'}, 1, 8, 12),
            ('_make_param_unassigned', {'contents': b'x' * 5}, 5, 16, 12),
            ('_make_param_unassigned', {'contents': b'x' * 8}, 8, 16, 12),
        ]
        code_for = {
            '_make_param_seq': Parameter.SEQ,
            '_make_param_esp_info': Parameter.ESP_INFO,
            '_make_param_solution': Parameter.SOLUTION,
            '_make_param_unassigned': Parameter.Unassigned_512,
        }

        for meth_name, kwargs, declared, total, pre_651 in cases:
            with self.subTest(maker=meth_name, length=declared):
                schema = getattr(proto, meth_name)(
                    code_for[meth_name], version=2, **kwargs)
                packed = bytes(schema)
                self.assertEqual(schema.len, declared)
                self.assertEqual(len(packed), total)
                self.assertEqual(len(packed) % 8, 0)
                self.assertEqual(len(packed), 11 + declared - (declared + 3) % 8)
                # the octet count that would have been emitted before the fix,
                # so the case is stated as a difference rather than a value
                self.assertNotEqual(len(packed), pre_651)
                # any padding present is zeroed, as 5.2.1 requires of the sender
                self.assertEqual(packed[4 + declared:], bytes(total - 4 - declared))

        seq = bytes(proto._make_param_seq(Parameter.SEQ, version=2,
                                          update_id=0x01020304))
        self.assertEqual(seq, bytes.fromhex('0181000401020304'))

        # the stride: two SEQs back to back, read through the full parser. The
        # 40-octet fixed header declares (len - 4) * 8 == 16 octets to follow.
        fixed = bytes([0x3b, 0x06, 0x00, 0x01]) + bytes(2) + bytes(2) + bytes(16) + bytes(16)
        self.assertEqual(len(fixed), 40)
        parsed = HIP(fixed + seq * 2, 40 + 16, extension=True)
        copies = parsed.info.parameters.getlist(Parameter.SEQ)
        self.assertEqual(len(copies), 2)
        for copy in copies:
            self.assertEqual(copy.id, 0x01020304)
            # the record length the data model reports is the RFC total, not the
            # contents-aligned one -- this is the 49 sites in the protocol module
            self.assertEqual(copy.length, 8)

        # and the header's own ``len`` is now exact rather than exact-in-pairs:
        # 4 + 16 // 8 == 6, with nothing lost to the floor division.
        rebuilt = bytes(HIP(parameters=[(Parameter.SEQ, {'update_id': 0x01020304})] * 2,
                           extension=True, next=6, packet=1, version=2,
                           checksum=b'\x00\x00', controls_anonymous=False,
                           shit=0, rhit=0, payload=b''))
        self.assertEqual(rebuilt[1], 6)
        self.assertEqual(rebuilt[40:], seq * 2)

    def test_hip_encrypted_data_length_excludes_reserved_and_iv(self) -> None:
        """#651: ``ENCRYPTED``'s ``data`` field had to be fixed with the padding.

        :rfc:`7401` Section 5.2.18 puts ``Reserved``, ``IV`` and the encrypted
        data all inside ``Length``, and
        ``_make_param_encrypted`` writes ``len = 4 + len(iv) + len(data)`` to
        match -- but the ``data`` field's length callback subtracted only the
        ``iv``, so it claimed four octets more than the parameter holds.

        The two defects cancelled at some residues of ``Length`` and not others.
        Measured across all eight, the old total agreed with the RFC at
        ``Length % 8`` in ``{0, 5, 6, 7}`` and was eight octets over at
        ``{1, 2, 3, 4}`` -- so ``Length = 8`` is one of the four where the
        module emitted RFC-conformant ``ENCRYPTED`` octets while getting both
        halves wrong. Fixing the padding alone would have taken ``ENCRYPTED``
        from right at four of the eight residues to four octets too long at all
        eight, so the pair is asserted here together: ``Length = 8`` (where they
        used to cancel) and ``Length = 4`` (where they did not, and the record
        used to be eight octets over).

        """
        from pcapkit.const.hip.cipher import Cipher
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.internet.hip import HIP
        from pcapkit.protocols.schema.internet import hip as hip_schema
        from pcapkit.utilities.exceptions import FieldValueError

        proto = object.__new__(HIP)

        # Length = 8: four ``reserved`` octets and four of data. The record is
        # 16 octets, which is also what the pre-#651 tree emitted -- by the two
        # errors cancelling rather than by either being right.
        schema = proto._make_param_encrypted(
            Parameter.ENCRYPTED, version=2, cipher=Cipher.NULL_ENCRYPT,
            data=b'DATA')
        self.assertEqual(schema.len, 8)
        self.assertEqual(bytes(schema),
                         bytes.fromhex('028100080000000044415441') + bytes(4))
        self.assertEqual(len(bytes(schema)), 16)

        # Length = 4: no data at all, and the record is 8 octets. Pre-#651 this
        # packed 16 -- the ``data`` field zero-extending b'' out to four octets
        # and the padding rule adding four more.
        empty = proto._make_param_encrypted(
            Parameter.ENCRYPTED, version=2, cipher=Cipher.NULL_ENCRYPT, data=b'')
        self.assertEqual(empty.len, 4)
        self.assertEqual(bytes(empty), bytes.fromhex('0281000400000000'))

        # The residue claim in the docstring, asserted rather than asserted in
        # prose. The old record total was ``8 + Length + (-Length % 8)``: four
        # octets of ``reserved``, a ``data`` field four octets too wide, and
        # contents-aligned padding. It agreed with the RFC at exactly four of
        # the eight residues -- which is why a suite that only ever built
        # ``Length = 8`` could not see either defect.
        def old_total(length: int) -> int:
            return 8 + length + (-length % 8)

        def rfc_total(length: int) -> int:
            return 11 + length - (length + 3) % 8

        self.assertEqual(
            sorted({L % 8 for L in range(64) if old_total(L) == rfc_total(L)}),
            [0, 5, 6, 7])
        self.assertEqual(
            sorted({L % 8 for L in range(64) if old_total(L) != rfc_total(L)}),
            [1, 2, 3, 4])

        # the callback itself, at the three shapes that matter
        self.assertEqual(hip_schema.encrypted_data_len({'len': 4}), 0)
        self.assertEqual(hip_schema.encrypted_data_len({'len': 8}), 4)
        self.assertEqual(
            hip_schema.encrypted_data_len({'len': 24, 'iv': b'\x11' * 16}), 4)
        # a ``Length`` too short for the fields already read must raise rather
        # than drive the data length negative
        with self.assertRaisesRegex(FieldValueError, 'invalid parameter length'):
            hip_schema.encrypted_data_len({'len': 3})
        with self.assertRaisesRegex(FieldValueError, 'invalid parameter length'):
            hip_schema.encrypted_data_len({'len': 19, 'iv': b'\x11' * 16})


if __name__ == '__main__':
    unittest.main()
