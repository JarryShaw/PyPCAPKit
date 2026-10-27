# -*- coding: utf-8 -*-
"""A registrar handed a ``code`` outside its enum changes nothing. C.f. #2186 and #2224.

The registrars keyed on an enum code log ``code.name`` once the registration is
done, so without a check an ``int`` or :obj:`None` fails there with
:exc:`AttributeError` after the protocol's table has been written. Each
registrar rejects such a ``code``
with :exc:`~pcapkit.utilities.exceptions.RegistryError` before it touches
anything.

Every case snapshots each registry the registrars here write -- the dispatch and
method tables, the schema tables, :data:`pcapkit.protocols.__proto__` and the
name leases -- calls the registrar with an otherwise valid argument list, and
compares every registry with the snapshot. The registrars that take a plain
``int`` port or PPID (``register_tcp``, ``register_udp``, ``register_sctp`` and
``register_apptype``) are out of scope for those codes: an ``int`` is a valid
code there.

Every registrar, those four included, also rejects a member of an enum other
than the one it is typed on (#2224). The registry enums compare equal to their
values, so such a member keys the entry of the registrar's own member of that
value: without the check, ``register_linktype(TransType.ICMP, ...)`` replaces
``Frame.__proto__[LinkType.ETHERNET]``. Each wrong-enum case picks a member
equal to one of the registrar's own where the value types allow, so the check
has to be on the type.

"""

from __future__ import annotations

import importlib
import importlib.util
import unittest
import warnings

from tests._support import reimport_once_per_class

#: Test tier (#1958): a pure-Python guard sweep over the registrars.
__tier__ = 'LATEST'

HAS_RUNTIME = all(importlib.util.find_spec(name) is not None
                  for name in ('tbtrim', 'aenum', 'chardet', 'dictdumper'))

#: Registrars keyed on an enum code and given a parser method, with the protocol
#: and schema classes holding the tables they write.
METHOD_REGISTRARS = (
    ('register_ipv4_option', 'pcapkit.protocols.internet.ipv4:IPv4',
     'pcapkit.protocols.schema.internet.ipv4:Option'),
    ('register_hip_parameter', 'pcapkit.protocols.internet.hip:HIP',
     'pcapkit.protocols.schema.internet.hip:Parameter'),
    ('register_hopopt_option', 'pcapkit.protocols.internet.hopopt:HOPOPT',
     'pcapkit.protocols.schema.internet.hopopt:Option'),
    ('register_ipv6_opts_option', 'pcapkit.protocols.internet.ipv6_opts:IPv6_Opts',
     'pcapkit.protocols.schema.internet.ipv6_opts:Option'),
    ('register_ipv6_route_routing', 'pcapkit.protocols.internet.ipv6_route:IPv6_Route',
     'pcapkit.protocols.schema.internet.ipv6_route:RoutingType'),
    ('register_mh_message', 'pcapkit.protocols.internet.mh:MH',
     'pcapkit.protocols.schema.internet.mh:Packet'),
    ('register_mh_option', 'pcapkit.protocols.internet.mh:MH',
     'pcapkit.protocols.schema.internet.mh:Option'),
    ('register_mh_extension', 'pcapkit.protocols.internet.mh:MH',
     'pcapkit.protocols.schema.internet.mh:CGAExtension'),
    ('register_tcp_option', 'pcapkit.protocols.transport.tcp:TCP',
     'pcapkit.protocols.schema.transport.tcp:Option'),
    ('register_tcp_mp_option', 'pcapkit.protocols.transport.tcp:TCP',
     'pcapkit.protocols.schema.transport.tcp:MPTCP'),
    ('register_http_frame', 'pcapkit.protocols.application.httpv2:HTTP',
     'pcapkit.protocols.schema.application.httpv2:FrameType'),
    ('register_pcapng_block', 'pcapkit.protocols.misc.pcapng:PCAPNG',
     'pcapkit.protocols.schema.misc.pcapng:BlockType'),
    ('register_pcapng_option', 'pcapkit.protocols.misc.pcapng:PCAPNG',
     'pcapkit.protocols.schema.misc.pcapng:Option'),
    ('register_pcapng_record', 'pcapkit.protocols.misc.pcapng:PCAPNG',
     'pcapkit.protocols.schema.misc.pcapng:NameResolutionRecord'),
    ('register_pcapng_secrets', 'pcapkit.protocols.misc.pcapng:PCAPNG',
     'pcapkit.protocols.schema.misc.pcapng:DSBSecrets'),
)

#: Registrars keyed on an enum code and given a protocol class, with the classes
#: whose ``__proto__`` they write.
MODULE_REGISTRARS = (
    ('register_linktype', ('pcapkit.protocols.misc.pcap.frame:Frame',
                           'pcapkit.protocols.misc.pcapng:PCAPNG')),
    ('register_pcap', ('pcapkit.protocols.misc.pcap.frame:Frame',)),
    ('register_pcapng', ('pcapkit.protocols.misc.pcapng:PCAPNG',)),
    ('register_ethertype', ('pcapkit.protocols.link.link:Link',)),
    ('register_transtype', ('pcapkit.protocols.internet.internet:Internet',)),
)

#: Codes that are not enum members: the issue's ``int``, :obj:`None`, and a
#: :class:`str` (the PCAP-NG option codes are a string enum).
BAD_CODES = (250, None, '250')

#: The enum each registrar above is typed on, for the wrong-enum cases (#2224).
REGISTRAR_ENUMS = {
    'register_ipv4_option': 'pcapkit.const.ipv4.option_number:OptionNumber',
    'register_hip_parameter': 'pcapkit.const.hip.parameter:Parameter',
    'register_hopopt_option': 'pcapkit.const.ipv6.option:Option',
    'register_ipv6_opts_option': 'pcapkit.const.ipv6.option:Option',
    'register_ipv6_route_routing': 'pcapkit.const.ipv6.routing:Routing',
    'register_mh_message': 'pcapkit.const.mh.packet:Packet',
    'register_mh_option': 'pcapkit.const.mh.option:Option',
    'register_mh_extension': 'pcapkit.const.mh.cga_extension:CGAExtension',
    'register_tcp_option': 'pcapkit.const.tcp.option:Option',
    'register_tcp_mp_option': 'pcapkit.const.tcp.mp_tcp_option:MPTCPOption',
    'register_http_frame': 'pcapkit.const.http.frame:Frame',
    'register_pcapng_block': 'pcapkit.const.pcapng.block_type:BlockType',
    'register_pcapng_option': 'pcapkit.const.pcapng.option_type:OptionType',
    'register_pcapng_record': 'pcapkit.const.pcapng.record_type:RecordType',
    'register_pcapng_secrets': 'pcapkit.const.pcapng.secrets_type:SecretsType',
    'register_linktype': 'pcapkit.const.reg.linktype:LinkType',
    'register_pcap': 'pcapkit.const.reg.linktype:LinkType',
    'register_pcapng': 'pcapkit.const.reg.linktype:LinkType',
    'register_ethertype': 'pcapkit.const.reg.ethertype:EtherType',
    'register_transtype': 'pcapkit.const.reg.transtype:TransType',
}

#: Registrars that also take a plain ``int``: the port or PPID used, the classes
#: whose ``__proto__`` they write, and any trailing arguments.
NUMBER_REGISTRARS = (
    ('register_tcp', 80, ('pcapkit.protocols.transport.tcp:TCP',), ()),
    ('register_udp', 53, ('pcapkit.protocols.transport.udp:UDP',), ()),
    ('register_sctp', 60, ('pcapkit.protocols.transport.sctp:SCTP',), ()),
    ('register_apptype', 80, ('pcapkit.protocols.transport.tcp:TCP',
                              'pcapkit.protocols.transport.udp:UDP'), ('tcp',)),
)


def resolve(path: 'str') -> 'type':
    module, _, name = path.partition(':')
    return getattr(importlib.import_module(module), name)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class RegistrarCodeCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _registries(self, classes: 'tuple[type, ...]') -> 'dict[tuple[str, str], dict]':
        """Every dict-valued class attribute of ``classes``, plus the module-wide registries."""
        from pcapkit.foundation.registry import protocols as registrars
        from pcapkit.protocols import __proto__ as protocol_registry

        found = {('pcapkit.protocols', '__proto__'): protocol_registry,
                 ('registrars', '_CODE_LEASES'): registrars._CODE_LEASES}
        for cls in classes:
            for attr, value in vars(cls).items():
                if isinstance(value, dict):
                    found[(cls.__qualname__, attr)] = value
        return found

    def _wrong_code(self, name: 'str') -> 'object':
        """A member of another enum, equal to one of ``name``'s own where the value types allow."""
        from pcapkit.const.pcapng.tls_key_label import TLSKeyLabel
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.const.reg.transtype import TransType

        kind = resolve(REGISTRAR_ENUMS[name])
        own = next(iter(kind))
        if kind is LinkType:
            # the issue's example: ICMP == 1 == LinkType.ETHERNET
            wrong, own = TransType.ICMP, LinkType.ETHERNET
        elif isinstance(own.value, int):
            wrong = LinkType(own.value)
        else:
            # the PCAP-NG option codes are a string enum, which no other enum equals
            return TLSKeyLabel.RSA
        self.assertNotIsInstance(wrong, kind)
        self.assertEqual(wrong, own)
        return wrong

    def _assert_rejected_unchanged(self, name: 'str', classes: 'tuple[type, ...]', *args: 'object',
                                   codes: 'tuple[object, ...]' = BAD_CODES, **kwargs: 'object') -> None:
        from pcapkit.foundation.registry import protocols as registrars
        from pcapkit.utilities.exceptions import RegistryError

        registries = self._registries(classes)
        for code in codes:
            with self.subTest(registrar=name, code=code):
                before = {key: dict(table) for key, table in registries.items()}
                try:
                    with warnings.catch_warnings():
                        warnings.simplefilter('ignore')
                        with self.assertRaises(RegistryError):
                            getattr(registrars, name)(code, *args, **kwargs)
                    after = {key: dict(table) for key, table in registries.items()}
                    for key, table in before.items():
                        self.assertEqual(after[key], table, f'{name}({code!r}) changed {key}')
                finally:
                    for key, table in before.items():
                        registries[key].clear()
                        registries[key].update(table)

    def test_method_registrars_reject_a_non_enum_code_before_registering(self) -> None:
        def parser(*args: 'object', **kwargs: 'object') -> None: ...

        for name, proto, schema in METHOD_REGISTRARS:
            proto_cls, schema_cls = resolve(proto), resolve(schema)
            self._assert_rejected_unchanged(name, (proto_cls, schema_cls),
                                            (parser, parser), schema=schema_cls)

    def test_module_registrars_reject_a_non_enum_code_before_registering(self) -> None:
        from pcapkit.protocols.misc.raw import Raw

        for name, targets in MODULE_REGISTRARS:
            self._assert_rejected_unchanged(name, tuple(map(resolve, targets)), Raw)

    def test_method_registrars_reject_a_member_of_another_enum(self) -> None:
        def parser(*args: 'object', **kwargs: 'object') -> None: ...

        for name, proto, schema in METHOD_REGISTRARS:
            proto_cls, schema_cls = resolve(proto), resolve(schema)
            self._assert_rejected_unchanged(name, (proto_cls, schema_cls), (parser, parser),
                                            codes=(self._wrong_code(name),), schema=schema_cls)

    def test_module_registrars_reject_a_member_of_another_enum(self) -> None:
        from pcapkit.protocols.misc.raw import Raw

        for name, targets in MODULE_REGISTRARS:
            self._assert_rejected_unchanged(name, tuple(map(resolve, targets)), Raw,
                                            codes=(self._wrong_code(name),))

    def test_number_registrars_reject_a_member_of_another_enum(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.protocols.misc.raw import Raw

        for name, number, targets, extra in NUMBER_REGISTRARS:
            # an IntEnum member is an int, so accepting an int must not let it in
            wrong = LinkType(number)
            self.assertIsInstance(wrong, int)
            self.assertEqual(wrong, number)
            self._assert_rejected_unchanged(name, tuple(map(resolve, targets)), Raw, *extra,
                                            codes=(wrong,))

    def test_number_registrars_reject_a_bool(self) -> None:
        """A :class:`bool` is an :class:`int` subclass, but never a port or PPID (#2269)."""
        from pcapkit.foundation.registry import protocols as registrars
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.protocols.transport.tcp import TCP
        from pcapkit.utilities.exceptions import RegistryError

        for name, _, targets, extra in NUMBER_REGISTRARS:
            self._assert_rejected_unchanged(name, tuple(map(resolve, targets)), Raw, *extra,
                                            codes=(True, False))
        with self.assertRaisesRegex(RegistryError, r'^TCP: code must be an int or a member of AppType, not True$'):
            registrars._check_code(True, registrars.Enum_AppType, TCP, number=True)

    def test_every_rejection_names_the_destination_registry(self) -> None:
        """The message says *whose* registry rejected the key (#2268).

        Each registrar hands
        :func:`~pcapkit.foundation.registry.protocols._check_code` the protocol
        class whose registry the key is destined for, and the shared message
        leads with its name -- several registrars are typed on the same enum, so
        the enum alone does not say which one refused. The class expected here is
        the first one listed above for that registrar, which for the two
        registrars writing into a pair of registries keyed alike
        (``register_linktype``, ``register_apptype``) is the one the check names.
        """
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.foundation.registry import protocols as registrars
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.utilities.exceptions import RegistryError

        def parser(*args: 'object', **kwargs: 'object') -> None: ...

        cases = []  # type: list[tuple[str, str, object, tuple[object, ...], dict[str, object]]]
        for name, proto, schema in METHOD_REGISTRARS:
            cases.append((name, resolve(proto).__name__, self._wrong_code(name),
                          ((parser, parser),), {'schema': resolve(schema)}))
        for name, targets in MODULE_REGISTRARS:
            cases.append((name, resolve(targets[0]).__name__, self._wrong_code(name), (Raw,), {}))
        for name, number, targets, extra in NUMBER_REGISTRARS:
            # these four take a plain int, so only a member of another enum is wrong
            cases.append((name, resolve(targets[0]).__name__, LinkType(number),
                          (Raw, *extra), {}))

        for name, expected, code, args, kwargs in cases:
            with self.subTest(registrar=name):
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    with self.assertRaisesRegex(RegistryError, rf'^{expected}: code must be '):
                        getattr(registrars, name)(code, *args, **kwargs)


if __name__ == '__main__':
    unittest.main()
