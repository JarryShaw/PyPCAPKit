from __future__ import annotations

import importlib.util
import inspect
import unittest
import warnings
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

    def _guard_registry(self, registry, key) -> None:
        """Restore ``key`` in ``registry`` on teardown, absence included.

        Every registry in this package is process-global and order-dependent, so
        a test that writes into one has to put back exactly what it found. A
        plain read-and-restore is not enough: a key that was *absent* has no
        value to restore, and writing one back leaves a stray entry that the
        next test in the process inherits -- the class of defect #674 is open
        for. Hence the sentinel and the ``pop``.

        """
        missing = object()
        previous = registry.get(key, missing)

        def restore() -> None:
            if previous is missing:
                registry.pop(key, None)
            else:
                registry[key] = previous

        self.addCleanup(restore)

    @staticmethod
    def _registry_warnings(caught, category) -> 'list[str]':
        """The messages of the captured warnings that are of ``category``.

        Filtering by category matters: the parse and import paths raise other
        warning types, and a bare count of everything captured would make an
        assertion about "no warning" pass or fail for unrelated reasons.

        """
        return [str(item.message) for item in caught
                if issubclass(item.category, category)]

    def test_register_protocol_warns_when_a_colliding_name_overwrites(self) -> None:
        """Three dispatchable classes are all named ``HTTP``, so they share a key.

        The registry is keyed on ``protocol.__name__.upper()``, so
        :class:`pcapkit.protocols.application.http.HTTP`,
        :class:`pcapkit.protocols.application.httpv1.HTTP` and
        :class:`pcapkit.protocols.application.httpv2.HTTP` all land on ``'HTTP'``
        and registering one replaces whichever was there. Before #675 the
        replacement was silent -- no exception, no warning -- so a later bare-name
        lookup simply returned a different class than it had before, with nothing
        connecting the symptom to the registration that caused it.

        """
        from pcapkit.foundation.registry import protocols as registry
        from pcapkit.protocols.application import http, httpv1, httpv2
        from pcapkit.utilities.warnings import RegistryWarning

        self._guard_registry(registry.protocol_registry, 'HTTP')

        # The premise the defect rests on: three *different* classes, one key.
        colliding = (http.HTTP, httpv1.HTTP, httpv2.HTTP)
        self.assertEqual(len(set(colliding)), 3)
        self.assertEqual({cls.__name__.upper() for cls in colliding}, {'HTTP'})

        registry.protocol_registry['HTTP'] = http.HTTP

        # Both directions, so the test is not pinned to one registration order.
        for incumbent, replacement in ((http.HTTP, httpv2.HTTP),
                                       (httpv2.HTTP, httpv1.HTTP)):
            with self.subTest(replacing=incumbent.__module__):
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter('always')
                    registry.register_protocol(replacement)

                # The overwrite still happens. This fix reports the collision,
                # it does not resolve it -- resolving it is #514's business.
                self.assertIs(registry.protocol_registry['HTTP'], replacement)

                messages = self._registry_warnings(caught, RegistryWarning)
                self.assertEqual(len(messages), 1)

                # Naming both classes is the point of the message: 'HTTP already
                # registered' on its own does not say *which* HTTP was lost, and
                # the module is the only thing that distinguishes these three.
                # ``repr`` rather than ``__module__`` because
                # 'pcapkit.protocols.application.http' is a prefix of
                # '...application.httpv1', so a substring test on the module name
                # alone would pass on the wrong class.
                self.assertIn(repr(incumbent), messages[0])
                self.assertIn(repr(replacement), messages[0])
                self.assertLess(messages[0].index(repr(incumbent)),
                                messages[0].index(repr(replacement)))

    def test_a_protocol_subclass_shadowing_a_builtin_name_warns(self) -> None:
        """The collision is reachable without calling the registrar at all.

        :meth:`Protocol.__init_subclass__
        <pcapkit.protocols.protocol.Protocol.__init_subclass__>` calls
        :func:`~pcapkit.foundation.registry.protocols.register_protocol`
        unconditionally, so merely *defining* a subclass of the public
        :class:`~pcapkit.protocols.protocol.Protocol` under a name a built-in
        already holds displaces the built-in's entry. That is the sharpest form
        of #675: there is no call to any registry function anywhere in the
        user's code, so before the fix nothing at all marked the moment the
        dispatch table changed meaning.

        """
        from pcapkit.foundation.registry import protocols as registry
        from pcapkit.protocols.protocol import Protocol
        from pcapkit.utilities.warnings import RegistryWarning

        incumbent = registry.protocol_registry['HTTP']
        self._guard_registry(registry.protocol_registry, 'HTTP')

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')

            class HTTP(Protocol):
                """A user protocol that happens to be named like the built-in."""

        self.assertIs(registry.protocol_registry['HTTP'], HTTP)
        self.assertIsNot(registry.protocol_registry['HTTP'], incumbent)

        messages = self._registry_warnings(caught, RegistryWarning)
        self.assertEqual(len(messages), 1)
        self.assertIn(repr(incumbent), messages[0])
        self.assertIn(repr(HTTP), messages[0])

    def test_register_protocol_stays_quiet_when_nothing_is_displaced(self) -> None:
        """A fresh key and an identical re-registration are both silent.

        This pins the one place this registrar deliberately departs from its
        siblings, which warn on mere key presence. A sibling is keyed on a
        ``code`` the caller passes, so a repeat call there is a caller mistake
        worth reporting even when the value is identical. This registry's key is
        *derived* from the class, and this function is the funnel every wrapper
        registrar ends in, so registering one class under two codes -- supported,
        and exactly what :func:`~pcapkit.foundation.registry.protocols.register_tcp`
        followed by :func:`~pcapkit.foundation.registry.protocols.register_udp`
        does -- reaches it twice with the same class and nothing displaced. A
        presence-only guard would warn there, and a caller who filters
        :exc:`~pcapkit.utilities.warnings.RegistryWarning` to silence that noise
        stops seeing the ``HTTP`` collision the warning exists for.

        """
        from pcapkit.foundation.registry import protocols as registry
        from pcapkit.protocols.transport.tcp import TCP
        from pcapkit.protocols.transport.udp import UDP
        from pcapkit.utilities.warnings import RegistryWarning

        UnitProtocol = self._unit_protocol()
        self._guard_registry(registry.protocol_registry, 'UNITPROTOCOL')

        for label in ('fresh-key', 'identical-repeat'):
            with self.subTest(case=label):
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter('always')
                    registry.register_protocol(UnitProtocol)

                self.assertIs(registry.protocol_registry['UNITPROTOCOL'], UnitProtocol)
                self.assertEqual(self._registry_warnings(caught, RegistryWarning), [])

        # ... and the real call shape, through two wrapper registrars. Each ends
        # in ``register_protocol(module)``, so this reaches the guard twice with
        # the same class.
        tcp_registry = TCP.__dict__['__proto__']
        udp_registry = UDP.__dict__['__proto__']
        tcp_port, udp_port = 65500, 65501

        # Asserted rather than assumed: an already-occupied port would make the
        # *sibling* registry warn, and the count below could not tell the two
        # sources of warning apart.
        self.assertNotIn(tcp_port, tcp_registry)
        self.assertNotIn(udp_port, udp_registry)
        self._guard_registry(tcp_registry, tcp_port)
        self._guard_registry(udp_registry, udp_port)

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            registry.register_tcp(tcp_port, UnitProtocol)
            registry.register_udp(udp_port, UnitProtocol)

        self.assertIs(tcp_registry[tcp_port], UnitProtocol)
        self.assertIs(udp_registry[udp_port], UnitProtocol)
        self.assertEqual(self._registry_warnings(caught, RegistryWarning), [])

    def test_sibling_registries_still_warn_on_an_identical_re_registration(self) -> None:
        """The presence-only guard elsewhere is left exactly as it was.

        :func:`~pcapkit.foundation.registry.protocols.register_protocol` now
        warns only when a *different* class is displaced. That relaxation must
        not leak into the code-keyed registries, which report a repeat
        registration even when the incumbent and the replacement are the same
        object. Asserted with the same class twice, which is precisely the case
        the two guards disagree about -- so this fails if anyone ever
        "harmonises" the siblings onto the guard used above.

        """
        from pcapkit.const.reg.ethertype import EtherType
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.protocols.link.link import Link
        from pcapkit.protocols.misc.pcap.frame import Frame
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.protocols.transport.tcp import TCP
        from pcapkit.utilities.warnings import RegistryWarning

        cases = (
            ('link-ethertype', Link, EtherType.Internet_Protocol_version_4),
            ('pcap-frame-linktype', Frame, LinkType.ETHERNET),
            ('tcp-port', TCP, 80),
        )
        for label, owner, code in cases:
            with self.subTest(registry=label):
                sibling = owner.__dict__['__proto__']
                self._guard_registry(sibling, code)

                # Seed the incumbent, then register the very same class again.
                # Nothing changes value, so only a presence-only guard warns.
                sibling[code] = Raw
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter('always')
                    owner.register(code, Raw)

                self.assertIs(sibling[code], Raw)
                self.assertEqual(
                    len(self._registry_warnings(caught, RegistryWarning)), 1)

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
