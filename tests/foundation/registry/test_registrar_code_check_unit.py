# -*- coding: utf-8 -*-
"""A registrar handed a ``code`` that is not an enum member changes nothing. C.f. #2186.

The registrars keyed on an enum code log ``code.name`` once the registration is
done, so an ``int`` or :obj:`None` failed there with :exc:`AttributeError` after
the protocol's table had been written. Each registrar rejects such a ``code``
with :exc:`~pcapkit.utilities.exceptions.RegistryError` before it touches
anything.

Every case snapshots each registry the registrars here write -- the dispatch and
method tables, the schema tables, :data:`pcapkit.protocols.__proto__` and the
name leases -- calls the registrar with an otherwise valid argument list, and
compares every registry with the snapshot. The registrars that take a plain
``int`` port or PPID (``register_tcp``, ``register_udp``, ``register_sctp`` and
``register_apptype``) are out of scope: an ``int`` is a valid code there.

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

    def _assert_rejected_unchanged(self, name: 'str', classes: 'tuple[type, ...]', *args: 'object',
                                   **kwargs: 'object') -> None:
        from pcapkit.foundation.registry import protocols as registrars
        from pcapkit.utilities.exceptions import RegistryError

        registries = self._registries(classes)
        for code in BAD_CODES:
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


if __name__ == '__main__':
    unittest.main()
