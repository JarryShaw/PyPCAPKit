# -*- coding: utf-8 -*-
"""GitHub issue #2860: ESP refused a protocol object as its payload.

:meth:`ESP.read <pcapkit.protocols.internet.esp.protocol.ESP.read>` took the
payload field's value, which :meth:`ESP.make
<pcapkit.protocols.internet.esp.protocol.ESP.make>` leaves a protocol or schema
as, so ``ESP(payload=TCP(...))`` concatenated a ``TCP`` with the ICV and raised
:exc:`TypeError`. It reads the packed octets now, through :meth:`Schema.get_payload
<pcapkit.protocols.schema.Schema.get_payload>`.

Each mode of ``make`` is checked against :rfc:`4303`: the SPI and Sequence Number
as 32-bit words, the payload, then the ICV, or with ``encrypt`` the
:rfc:`4303#section-2.4` padding, Pad Length and Next Header. ``ENCR_NULL`` needs no
``cryptography``. Classes are imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

from __future__ import annotations

import importlib.util
import struct
import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): hand-picked make -> parse round trips.
__tier__ = 'ALL'

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

SPI = 0x4321
SEQ = 7
#: The SPI and Sequence Number, each a 32-bit word in network order (RFC 4303 s2).
HEADER = struct.pack('!II', SPI, SEQ)
ICV = bytes(range(0xA0, 0xAC))


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class ProtocolPayloadTests(unittest.TestCase):
    """A protocol or schema payload packs to its octets, in every mode of ``make``."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def payloads(self) -> 'tuple[bytes, dict[str, Any]]':
        """A TCP header's octets, and the protocol and schema that pack to them."""
        from pcapkit.protocols.transport.tcp import TCP

        tcp = TCP(srcport=1, dstport=2)
        return bytes(tcp), {'protocol': tcp, 'schema': tcp.schema}

    def test_each_make_mode_packs_a_protocol_payload(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.corekit.context import ContextRegistry
        from pcapkit.protocols.internet.esp.protocol import (ESP, ESPContext, ESPStatus,
                                                             SecurityAssociation)

        inner, payloads = self.payloads()
        null = ContextRegistry.make(ESPContext(SecurityAssociation(spi=SPI)))
        # ENCR_NULL aligns to 4 octets: 20 of TCP and the 2 of the trailer leave 2 of padding.
        modes = {
            'opaque': ({}, None, inner, ESPStatus.NO_SA, 'ESP:Raw'),
            'icv': ({'icv': ICV}, None, inner + ICV, ESPStatus.NO_SA, 'ESP:Raw'),
            'encrypt': ({'encrypt': True, 'next': TransType.TCP}, null,
                        inner + bytes([1, 2]) + bytes([2, TransType.TCP]),
                        ESPStatus.DECRYPTED, 'ESP:TCP'),
        }
        for mode, (kwargs, context, body, status, chain) in modes.items():
            for kind, payload in payloads.items():
                with self.subTest(mode=mode, payload=kind):
                    extra = {} if context is None else {'__context__': context}
                    built = ESP(spi=SPI, seq=SEQ, payload=payload, **kwargs, **extra)
                    wire = bytes(built)
                    self.assertEqual(wire, HEADER + body)
                    self.assertEqual(built.info.length, len(wire))
                    self.assertIs(built.info.status, status)
                    self.assertEqual(str(built.protochain), chain)

                    parsed = ESP(wire, len(wire), **extra)
                    self.assertEqual(parsed.info, built.info)
                    if mode == 'encrypt':
                        self.assertEqual(parsed.info.plaintext, inner)
                        self.assertEqual(parsed.info.next, TransType.TCP)
                        self.assertEqual(parsed.info.padding, bytes([1, 2]))
                    else:
                        self.assertEqual(parsed.info.payload_data, body)
                        self.assertEqual(parsed.payload.data, body)

                    rebuilt = ESP.from_data(parsed.info, **extra)
                    self.assertEqual(bytes(rebuilt), wire)
                    self.assertEqual(rebuilt.info, parsed.info)

    def test_from_schema_takes_a_protocol_payload(self) -> None:
        from pcapkit.protocols.internet.esp.protocol import ESP, ESPStatus
        from pcapkit.protocols.internet.esp.schema import ESP as Schema_ESP

        inner, payloads = self.payloads()
        for kind, payload in payloads.items():
            with self.subTest(payload=kind):
                esp = ESP.from_schema(Schema_ESP(spi=SPI, seq=SEQ, payload=payload))
                self.assertEqual(bytes(esp), HEADER + inner)
                self.assertIs(esp.info.status, ESPStatus.NO_SA)
                self.assertEqual(esp.info.payload_data, inner)


if __name__ == '__main__':
    unittest.main()
