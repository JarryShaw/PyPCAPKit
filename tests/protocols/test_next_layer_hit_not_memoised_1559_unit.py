# -*- coding: utf-8 -*-
"""GitHub issue #1559: a next-layer hit is resolved, not memoised.

:meth:`ProtocolBase._lookup_next_layer
<pcapkit.protocols.protocol.ProtocolBase._lookup_next_layer>` used to write the
class a registered :class:`~pcapkit.corekit.module.ModuleDescriptor` resolved to
back over that descriptor. Three consequences, one test each:

* after :func:`importlib.reload` of the protocol's module, dispatch kept reaching
  the pre-reload class, so a parsed layer failed :func:`isinstance` against the
  live one -- what the method's own docstring said a memo would do;
* parsing mutated registries shared by the whole process, so what a registry
  held depended on what had been parsed before;
* so whether re-registering a shipped code warned depended on it too.

Every lookup now resolves through :attr:`ModuleDescriptor.klass
<pcapkit.corekit.module.ModuleDescriptor.klass>`, which reads
:data:`sys.modules`. Each test reloads or parses on a private import, under
:func:`~tests._support.isolate_modules`, so neither a reloaded module nor a
mutated registry outlives it.

"""

import importlib
import struct
import sys
import unittest
import warnings
from unittest import mock

from tests._support import isolate_modules

#: Module of the class the reload tests dispatch to.
UDP_MODULE = 'pcapkit.protocols.transport.udp'

#: An HTTP request, so that a TCP segment to port 80 dispatches once more.
HTTP_REQUEST = b'GET / HTTP/1.1\r\nHost: x\r\n\r\n'


def _ipv4(proto: 'int', body: 'bytes') -> 'bytes':
    """An IPv4 packet carrying ``body`` as next layer ``proto``."""
    return struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(body), 0, 0x4000, 64, proto, 0,
                       bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2])) + body


def _udp(body: 'bytes') -> 'bytes':
    """A UDP datagram between two ports no registry dispatches on."""
    return struct.pack('!HHHH', 12345, 9999, 8 + len(body), 0) + body


def _tcp(dstport: 'int', body: 'bytes') -> 'bytes':
    """A TCP segment, PSH/ACK, to ``dstport``."""
    return struct.pack('!HHIIBBHHH', 12345, dstport, 1, 0, 5 << 4, 0x18, 65535, 0, 0) + body


class NextLayerHitNotMemoisedTests(unittest.TestCase):
    def setUp(self) -> None:
        isolate_modules(self)

    def _parse_ipv4_udp(self) -> 'object':
        """Parse an IPv4/UDP packet and return its UDP layer."""
        from pcapkit.protocols.internet.ipv4 import IPv4

        packet = _ipv4(17, _udp(b'hello'))
        return IPv4(packet, len(packet)).payload

    def test_a_reload_after_a_hit_dispatches_to_the_reloaded_class(self) -> None:
        """The issue's reproduction, and the same through a real parse."""
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.internet import Internet
        from pcapkit.protocols.protocol import ProtocolBase

        registry = Internet.__proto__
        module = importlib.import_module(UDP_MODULE)
        before = ProtocolBase._lookup_next_layer(registry, TransType.UDP)
        self.assertIs(before, module.UDP)
        self.assertIs(type(self._parse_ipv4_udp()), module.UDP)

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            importlib.reload(module)
        self.assertIsNot(module.UDP, before)  # the reload really minted a class

        self.assertIs(ProtocolBase._lookup_next_layer(registry, TransType.UDP), module.UDP)
        self.assertIsInstance(self._parse_ipv4_udp(), module.UDP)

        # and popping the module, which replaces the module object outright
        reloaded = module.UDP
        sys.modules.pop(UDP_MODULE)
        fresh = importlib.import_module(UDP_MODULE)
        self.assertIsNot(fresh.UDP, reloaded)
        self.assertIs(ProtocolBase._lookup_next_layer(registry, TransType.UDP), fresh.UDP)

    def test_a_parse_leaves_the_shared_registries_as_declared(self) -> None:
        """Ethernet/IPv4/TCP/HTTP hits each registry once; none of them changes."""
        from pcapkit.const.reg.ethertype import EtherType
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.protocols.application.http import HTTP
        from pcapkit.protocols.internet.internet import Internet
        from pcapkit.protocols.link.ethernet import Ethernet
        from pcapkit.protocols.link.link import Link
        from pcapkit.protocols.transport.tcp import TCP

        hits = (
            ('Link', Link.__proto__, EtherType.Internet_Protocol_version_4),
            ('Internet', Internet.__proto__, TransType.TCP),
            ('TCP', TCP.__proto__, 80),
        )
        before = {name: dict(registry) for name, registry, _ in hits}
        for name, registry, code in hits:
            with self.subTest(registry=name, when='before'):
                self.assertIsInstance(registry[code], ModuleDescriptor)

        frame = bytes(6) + bytes([2, 0, 0, 0, 0, 1]) + b'\x08\x00' + _ipv4(6, _tcp(80, HTTP_REQUEST))
        parsed = Ethernet(frame, len(frame))
        self.assertIsInstance(parsed.payload.payload.payload, HTTP)  # every hit really dispatched

        for name, registry, code in hits:
            with self.subTest(registry=name, when='after'):
                self.assertIsInstance(registry[code], ModuleDescriptor)
                self.assertEqual(dict(registry), before[name])

    def test_registering_a_dispatched_code_warns_alike_before_and_after_a_parse(self) -> None:
        """Whether ``register`` warns no longer depends on what was parsed.

        ``register`` warns when it displaces an incumbent other than the class
        it is handed, and a shipped descriptor counts as different from the
        class it names. While a hit wrote the class back, re-registering UDP
        warned before any parse and was silent after one had reached UDP.

        """
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.internet import Internet
        from pcapkit.protocols.transport.udp import UDP

        def overwrites() -> 'list[str]':
            with mock.patch.dict(Internet.__proto__), warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter('always')
                Internet.register(TransType.UDP, UDP)
            return [str(record.message) for record in caught
                    if 'already registered' in str(record.message)]

        before = overwrites()
        self.assertEqual(len(before), 1)
        self.assertIs(type(self._parse_ipv4_udp()), UDP)
        self.assertEqual(overwrites(), before)


if __name__ == '__main__':
    unittest.main()
