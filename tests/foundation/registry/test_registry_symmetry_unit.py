# -*- coding: utf-8 -*-
"""A registrar handed back what it shipped with leaves every registry as it was. C.f. #1202.

:mod:`pcapkit.foundation.registry` has no ``unregister``: the way to undo a
registration is to register the entry it displaced, which the owner ruled a
registrar must accept for the entry a code shipped with (#1363). So the round
trip here is *override, then restore*: snapshot every registry any public
registrar writes, register a custom entry over a shipped code, register the
shipped entry back, and compare every registry with the snapshot -- the same
keys, and under each key the very object that was there.

Each registrar runs in these variants, where they apply:

``noop``
    hand back the shipped entry without overriding it first;
``override``
    override with a custom class (or method pair and schema) whose name is new
    to the package, then restore the shipped entry object;
``override-same-name``
    the same, with a custom class named like the one it displaces;
``restore-by-name``
    override, then restore by ``(module, class)`` strings, which build a
    descriptor equal to the shipped one.

and the comparison is split in two, so that two root causes cannot hide behind
one another: ``dispatch`` covers the tables the registrar names -- the
``__proto__`` it targets, the option and schema registries, the extractor and
flow-tracing tables -- and ``names`` covers :data:`pcapkit.protocols.__proto__`,
the by-name registry the protocol registrars all funnel into.

The scope is the 36 public registrars in
:data:`pcapkit.foundation.registry.__all__`. Of those, the callback registrars
(``register_reassembly_*_callback`` and ``register_traceflow_tcp_callback``)
only append, and offer nothing to undo an append with, so they have no case
here; nor does ``register_protocol_code``, which funnels into the same
:meth:`ProtocolBase.register <pcapkit.protocols.protocol.ProtocolBase.register>`
the ``register_tcp`` cases reach. Class-level registrars with no foundation wrapper are out of scope:
``SCTP.register_chunk``, ``register_parameter`` and ``register_cause``
(covered by :file:`tests/protocols/transport/test_sctp_unit.py`),
``Schema.register``, the PCAP-NG ``Option.register`` and ``ESP.register``.

Every case restores the registries it touched, whatever its outcome. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

from __future__ import annotations

import importlib
import importlib.util
import unittest
import warnings
from typing import TYPE_CHECKING, NamedTuple

from tests._support import reimport_once_per_class
from tests.foundation import _roundtrip as harness
from tests.foundation._roundtrip import Gap, Outcome

if TYPE_CHECKING:
    from typing import Any, Callable

HAS_RUNTIME = all(importlib.util.find_spec(name) is not None
                  for name in ('tbtrim', 'aenum', 'chardet', 'dictdumper'))


def resolve(path: 'str') -> 'Any':
    module, _, name = path.partition(':')
    return getattr(importlib.import_module(module), name)


#: Protocol classes whose ``__proto__`` a module registrar writes.
DISPATCH = {
    'Frame': 'pcapkit.protocols.misc.pcap.frame:Frame',
    'PCAPNG': 'pcapkit.protocols.misc.pcapng:PCAPNG',
    'Link': 'pcapkit.protocols.link.link:Link',
    'Internet': 'pcapkit.protocols.internet.internet:Internet',
    'TCP': 'pcapkit.protocols.transport.tcp:TCP',
    'UDP': 'pcapkit.protocols.transport.udp:UDP',
    'SCTP': 'pcapkit.protocols.transport.sctp:SCTP',
}


class MethodRegistrar(NamedTuple):
    """A registrar keyed by an option-like code, with its two tables."""

    name: 'str'
    #: Protocol class and the attribute holding its method table.
    proto: 'str'
    table: 'str'
    #: Schema class whose ``__enum__`` (or ``registry``) holds the schemas.
    schema: 'str'
    #: Codes to override, as ``module:Enum.member`` paths.
    codes: 'tuple[str, ...]'


METHOD_REGISTRARS = (
    MethodRegistrar('register_ipv4_option', 'pcapkit.protocols.internet.ipv4:IPv4', '__option__',
                    'pcapkit.protocols.schema.internet.ipv4:Option',
                    ('pcapkit.const.ipv4.option_number:OptionNumber.NOP',)),
    MethodRegistrar('register_hip_parameter', 'pcapkit.protocols.internet.hip:HIP', '__parameter__',
                    'pcapkit.protocols.schema.internet.hip:Parameter',
                    ('pcapkit.const.hip.parameter:Parameter.R1_Counter',)),
    MethodRegistrar('register_hopopt_option', 'pcapkit.protocols.internet.hopopt:HOPOPT', '__option__',
                    'pcapkit.protocols.schema.internet.hopopt:Option',
                    ('pcapkit.const.ipv6.option:Option.PadN',)),
    MethodRegistrar('register_ipv6_opts_option', 'pcapkit.protocols.internet.ipv6_opts:IPv6_Opts',
                    '__option__', 'pcapkit.protocols.schema.internet.ipv6_opts:Option',
                    ('pcapkit.const.ipv6.option:Option.PadN',)),
    MethodRegistrar('register_ipv6_route_routing', 'pcapkit.protocols.internet.ipv6_route:IPv6_Route',
                    '__routing__', 'pcapkit.protocols.schema.internet.ipv6_route:RoutingType',
                    ('pcapkit.const.ipv6.routing:Routing.Type_2_Routing_Header',)),
    MethodRegistrar('register_mh_message', 'pcapkit.protocols.internet.mh:MH', '__message__',
                    'pcapkit.protocols.schema.internet.mh:Packet',
                    ('pcapkit.const.mh.packet:Packet.Home_Test_Init',)),
    MethodRegistrar('register_mh_option', 'pcapkit.protocols.internet.mh:MH', '__option__',
                    'pcapkit.protocols.schema.internet.mh:Option',
                    ('pcapkit.const.mh.option:Option.PadN',)),
    MethodRegistrar('register_mh_extension', 'pcapkit.protocols.internet.mh:MH', '__extension__',
                    'pcapkit.protocols.schema.internet.mh:CGAExtension',
                    ('pcapkit.const.mh.cga_extension:CGAExtension.Exp_FFFD',)),
    MethodRegistrar('register_tcp_option', 'pcapkit.protocols.transport.tcp:TCP', '__option__',
                    'pcapkit.protocols.schema.transport.tcp:Option',
                    ('pcapkit.const.tcp.option:Option.No_Operation',)),
    MethodRegistrar('register_tcp_mp_option', 'pcapkit.protocols.transport.tcp:TCP', '__mp_option__',
                    'pcapkit.protocols.schema.transport.tcp:MPTCP',
                    ('pcapkit.const.tcp.mp_tcp_option:MPTCPOption.MP_JOIN',)),
    MethodRegistrar('register_http_frame', 'pcapkit.protocols.application.httpv2:HTTP', '__frame__',
                    'pcapkit.protocols.schema.application.httpv2:FrameType',
                    ('pcapkit.const.http.frame:Frame.HEADERS',)),
    MethodRegistrar('register_pcapng_block', 'pcapkit.protocols.misc.pcapng:PCAPNG', '__block__',
                    'pcapkit.protocols.schema.misc.pcapng:BlockType',
                    ('pcapkit.const.pcapng.block_type:BlockType.Interface_Description_Block',)),
    MethodRegistrar('register_pcapng_option', 'pcapkit.protocols.misc.pcapng:PCAPNG', '__option__',
                    'pcapkit.protocols.schema.misc.pcapng:Option',
                    ('pcapkit.const.pcapng.option_type:OptionType.opt_comment',
                     'pcapkit.const.pcapng.option_type:OptionType.if_name',
                     'pcapkit.const.pcapng.option_type:OptionType.epb_flags')),
    MethodRegistrar('register_pcapng_record', 'pcapkit.protocols.misc.pcapng:PCAPNG', '__record__',
                    'pcapkit.protocols.schema.misc.pcapng:NameResolutionRecord',
                    ('pcapkit.const.pcapng.record_type:RecordType.nrb_record_ipv4',)),
    MethodRegistrar('register_pcapng_secrets', 'pcapkit.protocols.misc.pcapng:PCAPNG', '__secrets__',
                    'pcapkit.protocols.schema.misc.pcapng:DSBSecrets',
                    ('pcapkit.const.pcapng.secrets_type:SecretsType.WireGuard_Key_Log',)),
)


class ModuleRegistrar(NamedTuple):
    """A registrar keyed by a dispatch code or a name, taking a class or descriptor."""

    name: 'str'
    #: The code, as a ``module:Enum.member`` path, or a literal ``int`` or ``str``.
    code: 'str | int'
    #: Where the shipped entry is read from: a ``DISPATCH`` name, or
    #: ``'engine'``/``'reassembly'``/``'traceflow'``/``'output'``/``'trace-output'``.
    source: 'str'
    #: The base a custom class must subclass, as a ``module:Class`` path.
    base: 'str'
    #: Extra positional arguments after the module, e.g. ``'tcp'`` for apptype.
    extra: 'tuple[str, ...]' = ()


MODULE_REGISTRARS = (
    ModuleRegistrar('register_linktype', 'pcapkit.const.reg.linktype:LinkType.ETHERNET', 'Frame',
                    'pcapkit.protocols.link.link:Link'),
    ModuleRegistrar('register_pcap', 'pcapkit.const.reg.linktype:LinkType.ETHERNET', 'Frame',
                    'pcapkit.protocols.link.link:Link'),
    ModuleRegistrar('register_pcapng', 'pcapkit.const.reg.linktype:LinkType.ETHERNET', 'PCAPNG',
                    'pcapkit.protocols.link.link:Link'),
    ModuleRegistrar('register_ethertype',
                    'pcapkit.const.reg.ethertype:EtherType.Address_Resolution_Protocol', 'Link',
                    'pcapkit.protocols.link.link:Link'),
    ModuleRegistrar('register_transtype', 'pcapkit.const.reg.transtype:TransType.TCP', 'Internet',
                    'pcapkit.protocols.transport.transport:Transport'),
    ModuleRegistrar('register_tcp', 80, 'TCP', 'pcapkit.protocols.application.application:Application'),
    ModuleRegistrar('register_udp', 1701, 'UDP', 'pcapkit.protocols.link.link:Link'),
    ModuleRegistrar('register_apptype', 80, 'TCP',
                    'pcapkit.protocols.application.application:Application', ('tcp',)),
    ModuleRegistrar('register_sctp',
                    'pcapkit.const.sctp.payload_protocol_identifier:PayloadProtocolIdentifier.'
                    'PayloadProtocolIdentifier_3GPP_NG_Application_Protocol', 'SCTP',
                    'pcapkit.protocols.application.application:Application'),
    ModuleRegistrar('register_extractor_engine', 'dpkt', 'engine',
                    'pcapkit.foundation.engines.engine:Engine'),
    ModuleRegistrar('register_extractor_reassembly', 'ipv4', 'reassembly',
                    'pcapkit.foundation.reassembly.reassembly:Reassembly'),
    ModuleRegistrar('register_extractor_traceflow', 'tcp', 'traceflow',
                    'pcapkit.foundation.traceflow.traceflow:TraceFlow'),
    ModuleRegistrar('register_dumper', 'json', 'output', 'dictdumper:JSON'),
    ModuleRegistrar('register_extractor_dumper', 'json', 'output', 'dictdumper:JSON'),
    ModuleRegistrar('register_traceflow_dumper', 'json', 'trace-output', 'dictdumper:JSON'),
)

MODULE_VARIANTS = ('noop', 'override', 'override-same-name', 'restore-by-name')
METHOD_VARIANTS = ('noop', 'override')
ASPECTS = ('dispatch', 'names')


def _code(spec: 'str | int') -> 'Any':
    if isinstance(spec, str) and ':' in spec:
        module, _, rest = spec.partition(':')
        enum, _, member = rest.partition('.')
        return getattr(getattr(importlib.import_module(module), enum), member)
    return spec


###############################################################################
# Snapshots.
###############################################################################

def _tables() -> 'dict[str, dict[Any, Any]]':
    """Every registry a public registrar writes, by name, as live objects."""
    from pcapkit.foundation.extraction import Extractor
    from pcapkit.foundation.traceflow import TraceFlow
    from pcapkit.protocols import __proto__ as names

    tables = {'names': names}  # type: dict[str, dict[Any, Any]]
    for label, path in DISPATCH.items():
        tables[f'{label}.__proto__'] = resolve(path).__proto__
    for registrar in METHOD_REGISTRARS:
        proto = resolve(registrar.proto)
        tables[f'{proto.__name__}.{registrar.table}'] = getattr(proto, registrar.table)
        schema = resolve(registrar.schema)
        registry = getattr(schema, 'registry', None)
        if registry is not None and all(isinstance(value, dict) for value in registry.values()):
            tables[f'{schema.__name__}.registry'] = registry
            for namespace, table in registry.items():
                tables[f'{schema.__name__}.registry[{namespace}]'] = table
        else:
            tables[f'{schema.__module__}.{schema.__name__}.__enum__'] = schema.__enum__
    tables['Extractor.__engine__'] = Extractor.__engine__
    tables['Extractor.__reassembly__'] = Extractor.__reassembly__
    tables['Extractor.__traceflow__'] = Extractor.__traceflow__
    tables['Extractor.__output__'] = Extractor.__output__
    tables['TraceFlow.__output__'] = TraceFlow.__output__
    return tables


def _snapshot() -> 'dict[str, dict[Any, Any]]':
    return {name: dict(table) for name, table in _tables().items()}


def _restore(snapshot: 'dict[str, dict[Any, Any]]') -> None:
    tables = _tables()
    for name, copy in snapshot.items():
        tables[name].clear()
        tables[name].update(copy)


def _same(one: 'Any', two: 'Any') -> 'bool':
    if one is two:
        return True
    if isinstance(one, tuple) and isinstance(two, tuple):
        return len(one) == len(two) and all(_same(a, b) for a, b in zip(one, two))
    return isinstance(one, (str, int)) and type(one) is type(two) and one == two


def _diff(before: 'dict[str, dict[Any, Any]]', aspect: 'str') -> 'list[str]':
    out = []
    for name, table in _tables().items():
        if (name == 'names') != (aspect == 'names'):
            continue
        old = before[name]
        for key in sorted(set(old) | set(table), key=repr):
            if key not in table:
                out.append(f'{name}[{key!r}] removed')
            elif key not in old:
                out.append(f'{name}[{key!r}] added {table[key]!r}')
            elif not _same(table[key], old[key]):
                out.append(f'{name}[{key!r}] {old[key]!r} -> {table[key]!r}')
    return out


###############################################################################
# Cases.
###############################################################################

def _shipped(registrar: 'ModuleRegistrar', code: 'Any') -> 'Any':
    from pcapkit.foundation.extraction import Extractor
    from pcapkit.foundation.traceflow import TraceFlow

    if registrar.source in DISPATCH:
        return resolve(DISPATCH[registrar.source]).__proto__[code]
    return {
        'engine': Extractor.__engine__, 'reassembly': Extractor.__reassembly__,
        'traceflow': Extractor.__traceflow__, 'output': Extractor.__output__,
        'trace-output': TraceFlow.__output__,
    }[registrar.source][code]


def _module_steps(registrar: 'ModuleRegistrar', variant: 'str') -> 'list[Callable[[], None]]':
    """The calls one module-registrar case makes, in order."""
    from pcapkit.corekit.module import ModuleDescriptor
    from pcapkit.foundation import registry

    register = getattr(registry, registrar.name)
    code = _code(registrar.code)
    shipped = _shipped(registrar, code)
    ext = ()  # type: tuple[Any, ...]
    kwargs = {}  # type: dict[str, Any]
    if registrar.source in ('output', 'trace-output'):
        shipped, extension = shipped
        kwargs = {'ext': extension}
    descriptor = shipped if isinstance(shipped, ModuleDescriptor) else None
    target = descriptor.klass if descriptor is not None else shipped
    base = resolve(registrar.base)
    name = target.__name__ if variant == 'override-same-name' else 'RoundTripCustom'
    custom = type(name, (base,), {'__module__': __name__})
    ext = registrar.extra

    def call(*args: 'Any') -> 'Callable[[], None]':
        return lambda: register(code, *args, *ext, **kwargs)

    if variant == 'noop':
        return [call(shipped)]
    if variant == 'restore-by-name':
        module, klass = ((descriptor.module, descriptor.name) if descriptor is not None
                         else (target.__module__, target.__name__))
        return [call(custom), call(module, klass)]
    return [call(custom), call(shipped)]


def _method_steps(registrar: 'MethodRegistrar', code_path: 'str', variant: 'str') -> 'list[Callable[[], None]]':
    from pcapkit.foundation import registry

    register = getattr(registry, registrar.name)
    proto, schema = resolve(registrar.proto), resolve(registrar.schema)
    code = _code(code_path)
    key = code
    if registrar.name == 'register_pcapng_option':
        from pcapkit.protocols.misc.pcapng import _option_key
        key = _option_key(code)
        namespace = code.name.split('_')[0]
        shipped_schema = schema.registry[namespace][code]
    else:
        shipped_schema = schema.__enum__[code]
    shipped = getattr(proto, registrar.table)[key]
    if variant == 'noop':
        return [lambda: register(code, shipped, schema=shipped_schema)]

    def parser(*args: 'Any', **kwargs: 'Any') -> 'Any':
        raise NotImplementedError

    custom_schema = type('RoundTripCustom', (schema,), {'__module__': __name__})
    return [lambda: register(code, (parser, parser), schema=custom_schema),
            lambda: register(code, shipped, schema=shipped_schema)]


def _labels() -> 'list[str]':
    labels = []
    for module in MODULE_REGISTRARS:
        labels.extend(f'{module.name}/{variant}/{aspect}' for variant in MODULE_VARIANTS
                      for aspect in ASPECTS)
    for method in METHOD_REGISTRARS:
        for code in method.codes:
            member = code.rpartition('.')[2]
            labels.extend(f'{method.name}:{member}/{variant}/{aspect}' for variant in METHOD_VARIANTS
                          for aspect in ASPECTS)
    labels.extend(f'register_protocol/HTTP/{aspect}' for aspect in ASPECTS)
    return labels


def _steps(label: 'str') -> 'list[Callable[[], None]]':
    head, variant, _ = label.split('/')
    if head == 'register_protocol':
        from pcapkit.foundation.registry import register_protocol
        from pcapkit.protocols import __proto__ as names
        from pcapkit.protocols.application import httpv2

        shipped = names['HTTP']
        return [lambda: register_protocol(httpv2.HTTP), lambda: register_protocol(shipped)]
    name, _, member = head.partition(':')
    for module in MODULE_REGISTRARS:
        if module.name == name:
            return _module_steps(module, variant)
    for method in METHOD_REGISTRARS:
        if method.name == name:
            code, = (code for code in method.codes if code.rpartition('.')[2] == member)
            return _method_steps(method, code, variant)
    raise AssertionError(label)


def run_case(label: 'str') -> 'Outcome':
    """Snapshot, run the case's calls, compare one aspect, and put everything back."""
    aspect = label.rpartition('/')[2]
    before = _snapshot()
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            try:
                for step in _steps(label):
                    step()
            except Exception as exc:  # pylint: disable=broad-except
                return Outcome('RAISED', f'{type(exc).__name__}: {exc}')
        diff = _diff(before, aspect)
    finally:
        _restore(before)
    if diff:
        return Outcome('CHANGED', '; '.join(diff))
    return Outcome('OK')


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TestRegistrySymmetry(harness.RoundTripBase):
    """Override then restore leaves every registry exactly as shipped."""

    STATUSES = ('RAISED', 'CHANGED')
    KNOWN_FAILURES = (
        Gap(1504, 'restoring a shipped dispatch entry over an override stores the class it names, '
               'not the shipped ModuleDescriptor: each register resolves a descriptor unequal '
               'to the incumbent (pcapkit/protocols/protocol.py:924, link/link.py:148, '
               'internet/internet.py:168, transport/transport.py:122, misc/pcap/frame.py:155, '
               'misc/pcapng.py:1027, transport/sctp.py:748), where the foundation registrars '
               'keep the shipped object (#1363, #1364)',
            'CHANGED', ("ModuleDescriptor(module='pcapkit.protocols.",),
            tuple(f'{name}/{variant}/dispatch'
                  for name in ('register_linktype', 'register_pcap', 'register_pcapng',
                               'register_ethertype', 'register_transtype', 'register_tcp',
                               'register_udp', 'register_apptype', 'register_sctp')
                  for variant in ('override', 'override-same-name', 'restore-by-name'))),
        Gap(1505, 'a protocol registrar adds the class it registers to pcapkit.protocols.__proto__ '
               'by name (pcapkit/foundation/registry/protocols.py:235, reached from e.g. :416), '
               'and restoring the code leaves that name behind: nothing removes it',
            'CHANGED', "names['ROUNDTRIPCUSTOM'] added",
            tuple(f'{name}/{variant}/names'
                  for name in ('register_linktype', 'register_pcap', 'register_pcapng',
                               'register_ethertype', 'register_transtype', 'register_tcp',
                               'register_udp', 'register_apptype', 'register_sctp')
                  for variant in ('override', 'restore-by-name'))),
    )

    def setUp(self) -> None:
        super().setUp()
        reimport_once_per_class(self)

    def labels(self) -> 'list[str]':
        return _labels()

    def outcome(self, label: 'str') -> 'Outcome':
        return run_case(label)

    def test_every_public_registrar_is_covered_or_excused(self) -> None:
        """A registrar added tomorrow needs a case, or a reason it has none."""
        from pcapkit.foundation import registry

        covered = {r.name for r in MODULE_REGISTRARS} | {r.name for r in METHOD_REGISTRARS}
        excused = {
            'register_protocol': 'covered by the register_protocol/HTTP case',
            'register_protocol_code': 'funnels into ProtocolBase.register, as register_tcp does',
            'register_reassembly_ipv4_callback': 'append-only, nothing to undo with',
            'register_reassembly_ipv6_callback': 'append-only, nothing to undo with',
            'register_reassembly_tcp_callback': 'append-only, nothing to undo with',
            'register_traceflow_tcp_callback': 'append-only, nothing to undo with',
        }
        self.assertEqual(sorted(set(registry.__all__) - covered - set(excused)), [])
        self.assertEqual(sorted((covered | set(excused)) - set(registry.__all__)), [])

    def test_case_leaves_registries_as_found(self) -> None:
        """The harness's own restore puts back what each case changed."""
        before = _snapshot()
        for label in self.labels()[:8]:
            run_case(label)
        self.assertEqual(_diff(before, 'dispatch') + _diff(before, 'names'), [])


if __name__ == '__main__':
    unittest.main()
