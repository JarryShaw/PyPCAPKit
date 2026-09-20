from __future__ import annotations

import importlib.util
import inspect
import unittest
from unittest import mock

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: Public ``register_*`` helpers that take a schema class. Listed so the signature
#: contract test cannot pass vacuously should discovery ever stop finding them; the
#: test loops over whatever it discovers, so a newly added sibling is covered
#: without this tuple having to be updated.
SCHEMA_REGISTRARS = (
    'register_hip_parameter',
    'register_hopopt_option',
    'register_http_frame',
    'register_ipv4_option',
    'register_ipv6_opts_option',
    'register_ipv6_route_routing',
    'register_mh_extension',
    'register_mh_message',
    'register_mh_option',
    'register_pcapng_block',
    'register_pcapng_option',
    'register_pcapng_record',
    'register_pcapng_secrets',
    'register_tcp_mp_option',
    'register_tcp_option',
)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class ProtocolRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def _unit_protocol(self):
        from pcapkit.protocols.protocol import ProtocolBase

        class UnitProtocol(ProtocolBase):
            pass

        return UnitProtocol

    def test_register_protocol_validates_and_updates_registry(self) -> None:
        from pcapkit.foundation.registry import protocols as registry
        from pcapkit.utilities.exceptions import RegistryError

        UnitProtocol = self._unit_protocol()
        registry.register_protocol(UnitProtocol)
        self.assertIs(registry.protocol_registry['UNITPROTOCOL'], UnitProtocol)

        with self.assertRaises(RegistryError):
            registry.register_protocol(object)  # type: ignore[arg-type]

    def test_top_level_link_internet_and_transport_protocol_wrappers(self) -> None:
        from pcapkit.const.reg.apptype import AppType, TransportProtocol
        from pcapkit.const.reg.ethertype import EtherType
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.foundation.registry import protocols as registry
        from pcapkit.utilities.exceptions import RegistryError

        UnitProtocol = self._unit_protocol()
        raw_module = ('pcapkit.protocols.misc.raw', 'Raw')

        class_routes = [
            (registry.register_linktype, LinkType.ETHERNET,
             [(registry.Frame, 'register'), (registry.PCAPNG, 'register')]),
            (registry.register_pcap, LinkType.ETHERNET, [(registry.Frame, 'register')]),
            (registry.register_pcapng, LinkType.ETHERNET, [(registry.PCAPNG, 'register')]),
            (registry.register_ethertype, EtherType.Internet_Protocol_version_4,
             [(registry.Link, 'register')]),
            (registry.register_transtype, TransType.TCP, [(registry.Internet, 'register')]),
        ]
        for func, code, targets in class_routes:
            with self.subTest(func=f'{func.__name__}-class'):
                patches = [mock.patch.object(target, method) for target, method in targets]
                active = [patch.start() for patch in patches]
                self.addCleanup(lambda patches=patches: [patch.stop() for patch in patches])
                with mock.patch.object(registry, 'register_protocol') as register_protocol:
                    func(code, UnitProtocol)
                for register in active:
                    register.assert_called()
                    self.assertIs(register.call_args.args[1], UnitProtocol)
                register_protocol.assert_called_once_with(UnitProtocol)
                for patch in patches:
                    patch.stop()

            with self.subTest(func=f'{func.__name__}-string'):
                patches = [mock.patch.object(target, method) for target, method in targets]
                active = [patch.start() for patch in patches]
                self.addCleanup(lambda patches=patches: [patch.stop() for patch in patches])
                with mock.patch.object(registry, 'register_protocol') as register_protocol:
                    func(code, *raw_module)
                for register in active:
                    self.assertIsInstance(register.call_args.args[1], registry.ModuleDescriptor)
                self.assertEqual(register_protocol.call_args.args[0].__name__, 'Raw')
                for patch in patches:
                    patch.stop()

        with mock.patch.object(registry.TCP, 'register') as tcp_register:
            with mock.patch.object(registry.UDP, 'register') as udp_register:
                with mock.patch.object(registry, 'register_protocol') as register_protocol:
                    registry.register_apptype(AppType.AppType_3com_amp3, UnitProtocol)
        tcp_register.assert_called_once()
        udp_register.assert_called_once()
        register_protocol.assert_called_once_with(UnitProtocol)

        with mock.patch.object(registry.TCP, 'register') as tcp_register:
            with mock.patch.object(registry.UDP, 'register') as udp_register:
                with mock.patch.object(registry, 'register_protocol') as register_protocol:
                    registry.register_apptype(AppType.AppType_3com_amp3, UnitProtocol,
                                              proto=TransportProtocol.udp)
        tcp_register.assert_not_called()
        udp_register.assert_called_once()
        register_protocol.assert_called_once_with(UnitProtocol)

        with mock.patch.object(registry.TCP, 'register') as tcp_register:
            with mock.patch.object(registry.UDP, 'register') as udp_register:
                with mock.patch.object(registry, 'register_protocol') as register_protocol:
                    registry.register_apptype(65000, *raw_module, proto='tcp')
        tcp_register.assert_called_once()
        udp_register.assert_not_called()
        self.assertEqual(register_protocol.call_args.args[0].__name__, 'Raw')

        with self.assertRaises(RegistryError):
            registry.register_apptype(65001, UnitProtocol, proto=TransportProtocol.dccp)

        with mock.patch.object(registry.TCP, 'register') as tcp_register:
            with mock.patch.object(registry, 'register_protocol') as register_protocol:
                registry.register_tcp(AppType.AppType_3exmp, UnitProtocol)
        tcp_register.assert_called_once_with(AppType.AppType_3exmp.port, UnitProtocol)
        register_protocol.assert_called_once_with(UnitProtocol)

        with mock.patch.object(registry.TCP, 'register') as tcp_register:
            with mock.patch.object(registry, 'register_protocol') as register_protocol:
                registry.register_tcp(65002, *raw_module)
        self.assertIsInstance(tcp_register.call_args.args[1], registry.ModuleDescriptor)
        self.assertEqual(register_protocol.call_args.args[0].__name__, 'Raw')

        with mock.patch.object(registry.UDP, 'register') as udp_register:
            with mock.patch.object(registry, 'register_protocol') as register_protocol:
                registry.register_udp(AppType.AppType_2ping, UnitProtocol)
        udp_register.assert_called_once_with(AppType.AppType_2ping.port, UnitProtocol)
        register_protocol.assert_called_once_with(UnitProtocol)

        with mock.patch.object(registry.UDP, 'register') as udp_register:
            with mock.patch.object(registry, 'register_protocol') as register_protocol:
                registry.register_udp(65003, *raw_module)
        self.assertIsInstance(udp_register.call_args.args[1], registry.ModuleDescriptor)
        self.assertEqual(register_protocol.call_args.args[0].__name__, 'Raw')

    def test_option_like_registry_wrappers_validate_methods_and_register_schema(self) -> None:
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.const.http.frame import Frame as HTTPFrame
        from pcapkit.const.ipv4.option_number import OptionNumber
        from pcapkit.const.ipv6.option import Option as IPv6Option
        from pcapkit.const.ipv6.routing import Routing
        from pcapkit.const.mh.cga_extension import CGAExtension
        from pcapkit.const.mh.option import Option as MHOption
        from pcapkit.const.mh.packet import Packet as MHPacket
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.const.pcapng.record_type import RecordType
        from pcapkit.const.pcapng.secrets_type import SecretsType
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption
        from pcapkit.const.tcp.option import Option as TCPOption
        from pcapkit.foundation.registry import protocols as registry
        from pcapkit.utilities.exceptions import RegistryError

        cases = [
            (registry.register_ipv4_option, registry.IPv4, '_read_opt_unit',
             registry.Schema_IPv4_Option, 'register_option', OptionNumber.NOP),
            (registry.register_hip_parameter, registry.HIP, '_read_param_unit',
             registry.Schema_HIP_Parameter, 'register_parameter', Parameter.HIP_TRANSFORM),
            (registry.register_hopopt_option, registry.HOPOPT, '_read_opt_unit',
             registry.Schema_HOPOPT_Option, 'register_option', IPv6Option.Pad1),
            (registry.register_ipv6_opts_option, registry.IPv6_Opts, '_read_opt_unit',
             registry.Schema_IPv6_Opts_Option, 'register_option', IPv6Option.Pad1),
            (registry.register_ipv6_route_routing, registry.IPv6_Route, '_read_data_type_unit',
             registry.Schema_IPv6_Route_RoutingType, 'register_routing', Routing.Source_Route),
            (registry.register_mh_message, registry.MH, '_read_msg_unit',
             registry.Schema_MH_Packet, 'register_message', MHPacket.Binding_Refresh_Request),
            (registry.register_mh_option, registry.MH, '_read_opt_unit',
             registry.Schema_MH_Option, 'register_option', MHOption.Pad1),
            (registry.register_mh_extension, registry.MH, '_read_ext_unit',
             registry.Schema_MH_CGAExtension, 'register_extension', CGAExtension.Multi_Prefix),
            (registry.register_tcp_option, registry.TCP, '_read_mode_unit',
             registry.Schema_TCP_Option, 'register_option', TCPOption.No_Operation),
            (registry.register_tcp_mp_option, registry.TCP, '_read_mptcp_unit',
             registry.Schema_TCP_MPTCP, 'register_mp_option', MPTCPOption.MP_CAPABLE),
            (registry.register_http_frame, registry.HTTPv2, '_read_http_unit',
             registry.Schema_HTTP_FrameType, 'register_frame', HTTPFrame.DATA),
            (registry.register_pcapng_block, registry.PCAPNG, '_read_block_unit',
             registry.Schema_PCAPNG_BlockType, 'register_block', BlockType.Section_Header_Block),
            (registry.register_pcapng_option, registry.PCAPNG, '_read_option_unit',
             registry.Schema_PCAPNG_Option, 'register_option', OptionType.opt_endofopt),
            (registry.register_pcapng_record, registry.PCAPNG, '_read_record_unit',
             registry.Schema_PCAPNG_NameResolutionRecord, 'register_record',
             RecordType.nrb_record_ipv4),
            (registry.register_pcapng_secrets, registry.PCAPNG, '_read_secrets_unit',
             registry.Schema_PCAPNG_DSBSecrets, 'register_secrets', SecretsType.TLS_Key_Log),
        ]

        schema = object
        for func, owner, attr, schema_owner, register_name, code in cases:
            with self.subTest(func=f'{func.__name__}-invalid'):
                with self.assertRaises(RegistryError):
                    func(code, 'missing')  # type: ignore[arg-type]

            setattr(owner, attr, lambda *args, **kwargs: None)
            try:
                with self.subTest(func=f'{func.__name__}-valid'):
                    with mock.patch.object(owner, register_name) as register:
                        with mock.patch.object(schema_owner, 'register') as schema_register:
                            func(code, 'unit', schema=schema)  # type: ignore[arg-type]
                    register.assert_called_once_with(code, 'unit')
                    schema_register.assert_called_once_with(code, schema)

                with self.subTest(func=f'{func.__name__}-callable'):
                    parser = (lambda *args, **kwargs: None, lambda *args, **kwargs: None)
                    with mock.patch.object(owner, register_name) as register:
                        func(code, parser)  # type: ignore[arg-type]
                    register.assert_called_once_with(code, parser)
            finally:
                delattr(owner, attr)

    def test_schema_registrars_share_one_signature_contract(self) -> None:
        """Every schema-taking ``register_*`` helper exposes the same call shape.

        ``code`` and ``meth`` are positional, ``schema`` is keyword-only. See #516,
        where :func:`~pcapkit.foundation.registry.protocols.register_mh_extension`
        was missing the ``*`` that its fourteen siblings carry and so accepted
        ``schema`` positionally.

        """
        from pcapkit.foundation.registry import protocols as registry
        from pcapkit.utilities.exceptions import BaseError

        siblings = {}
        for name in registry.__all__:
            if not name.startswith('register_'):
                continue
            signature = inspect.signature(getattr(registry, name))
            if 'schema' in signature.parameters:
                siblings[name] = signature

        for name in SCHEMA_REGISTRARS:
            self.assertIn(name, siblings)

        sentinel = object()
        for name, signature in sorted(siblings.items()):
            with self.subTest(func=name):
                parameters = signature.parameters

                schema = parameters['schema']
                self.assertIs(schema.kind, inspect.Parameter.KEYWORD_ONLY)
                self.assertIsNone(schema.default)

                for positional in ('code', 'meth'):
                    parameter = parameters[positional]
                    self.assertIn(parameter.kind, (inspect.Parameter.POSITIONAL_ONLY,
                                                   inspect.Parameter.POSITIONAL_OR_KEYWORD))
                    self.assertIs(parameter.default, inspect.Parameter.empty)

                # Binding is the contract stated behaviourally: ``code`` and ``meth``
                # take positionally, ``schema`` only by keyword. Nothing is called,
                # so this stays free of registry side effects.
                signature.bind(sentinel, sentinel)
                signature.bind(sentinel, sentinel, schema=sentinel)
                with self.assertRaises(TypeError):
                    signature.bind(sentinel, sentinel, sentinel)

                # The assertions above describe :mod:`inspect`'s model of the
                # signature; this one is the function itself refusing the
                # positional form. A keyword-only parameter is rejected while
                # the interpreter binds arguments, before the body runs, so no
                # registry state is touched even though this is a real call.
                with self.assertRaises(TypeError) as caught:
                    getattr(registry, name)(sentinel, sentinel, sentinel)

                # ``RegistryError`` derives from ``TypeError``, so a bare
                # ``assertRaises(TypeError)`` would also be satisfied by a body
                # that accepted a third positional and then rejected its value
                # -- exactly the #516 behaviour this test exists to forbid.
                # Pin the interpreter's arity error, not a library one.
                self.assertNotIsInstance(caught.exception, BaseError)
                self.assertRegex(str(caught.exception), 'positional argument')


if __name__ == '__main__':
    unittest.main()
