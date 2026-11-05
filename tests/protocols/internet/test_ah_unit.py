from __future__ import annotations

import importlib.util
import io
import unittest
import warnings
from unittest import mock

from tests._support import reimport_once_per_class

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


class DummyDict(dict):
    __getattr__ = dict.__getitem__


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class AHUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_ah_index_length_and_make_data(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ah.protocol import AH

        data = DummyDict(
            next=TransType.TCP,
            reserved=0xdead,
            spi=0x12345678,
            seq=7,
            icv=b'auth',
            __next_type__=None,
        )
        proto = object.__new__(AH)

        self.assertEqual(AH.__index__(), TransType.AH)
        self.assertEqual(proto.__length_hint__(), 20)
        values = AH._make_data(data)
        self.assertEqual(values['next'], TransType.TCP)
        self.assertEqual(values['reserved'], 0xdead)
        self.assertEqual(values['spi'], 0x12345678)
        self.assertEqual(values['seq'], 7)
        self.assertEqual(values['icv'], b'auth')
        self.assertIn('payload', values)

    def test_ah_make_builds_schema_with_payload_length(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ah.protocol import AH

        proto = object.__new__(AH)
        schema = proto.make(
            next=TransType.UDP,
            spi=1,
            seq=2,
            icv=b'12345678',
            payload=b'data',
        )

        self.assertEqual(schema.next, TransType.UDP)
        self.assertEqual(schema.spi, 1)
        self.assertEqual(schema.seq, 2)
        self.assertEqual(schema.icv, b'12345678')
        self.assertEqual(schema.len, 3)

    def test_ah_read_properties_and_ipsec_id(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ah.protocol import AH
        from pcapkit.protocols.internet.ipsec.protocol import IPsec
        from pcapkit.protocols.internet.ah.schema import AH as Schema_AH
        from pcapkit.utilities.exceptions import UnsupportedCall

        proto = object.__new__(AH)
        proto.__header__ = Schema_AH(
            next=TransType.TCP,
            len=3,
            spi=0x12345678,
            seq=9,
            icv=b'12345678',
            payload=b'data',
        )
        proto._data = b'\x00' * 24
        proto.__cached__ = {}
        proto._extf = False
        proto._info = DummyDict(length=20)

        self.assertEqual(IPsec.id(), ('AH', 'ESP'))
        self.assertEqual(AH.id(), ('AH',))
        self.assertEqual(proto.name, 'Authentication Header')
        self.assertEqual(proto.length, 20)
        proto._next = 'payload'
        proto._protos = ['TCP']
        self.assertEqual(proto.payload, 'payload')
        self.assertEqual(proto.protocol, 'TCP')
        self.assertEqual(proto.protochain, ['TCP'])

        ext_data = proto.read(extension=True)
        self.assertEqual(ext_data.next, TransType.TCP)
        self.assertEqual(ext_data.length, 20)
        self.assertEqual(ext_data.spi, 0x12345678)

        with mock.patch.object(AH, '_decode_next_layer', return_value='decoded') as decode:
            self.assertEqual(proto.read(length=24), 'decoded')
        decode.assert_called_once()

        proto._extf = True
        with self.assertRaises(UnsupportedCall):
            _ = proto.payload
        with self.assertRaises(UnsupportedCall):
            _ = proto.protocol
        with self.assertRaises(UnsupportedCall):
            _ = proto.protochain

        with mock.patch.object(IPsec, '__post_init__', return_value=None) as post_init:
            post_proto = object.__new__(AH)
            post_proto.__post_init__(extension=True, version=6, custom=True)
        self.assertTrue(post_proto._extf)
        post_init.assert_called_once()

    def test_docstring_cites_the_extension_header_registry(self) -> None:
        """GitHub issue #931: the class docstring cites the right authorities.

        Membership rests on IANA's *IPv6 Extension Header Types* registry, which
        :rfc:`8200#section-4` names as authoritative, not on the
        ``protocol-numbers-1.csv`` column #926 moved the const generator off
        (it disagreed on 147, ``BIT_EMU``). :rfc:`4302#section-3.1.1` is cited
        only for what it says: IPv6 placement after hop-by-hop, routing and
        fragmentation, and IPv4 placement after the IP header. Per
        :ref:`extension-header-subclassing`'s *The IPv4-Payload Test*, the IPv4
        sentence *qualifies* AH for a second base; it neither makes AH
        standalone nor names the base. So the test bans the wrong phrasings, not
        the word "IPv4".
        """
        import re

        from pcapkit.protocols.internet.ah.protocol import AH

        # Normalise the docstring's line-wrapping before matching, since the
        # citation may be split across lines by hand-wrapping.
        doc = ' '.join((AH.__doc__ or '').split())
        self.assertNotIn('protocol-numbers-1.csv', doc)
        self.assertNotIn('among the IPv6 extension headers', doc)
        self.assertNotIn('second base', doc)
        self.assertNotIn('directly after an IPv4 header', doc)

        # Pin the claim, not just the phrase: the parenthetical on the
        # membership sentence carries no IPv4 evidence, however it is worded.
        membership_clause = re.search(r'registry lists it at 51 \((.*?)\)', doc)
        self.assertIsNotNone(membership_clause, 'could not locate the membership clause')
        self.assertNotIn('IPv4', membership_clause.group(1))

        self.assertIn('IPv6 Extension Header Types', doc)
        self.assertIn(':rfc:`4302#section-3.1.1`', doc)
        self.assertIn('hop-by-hop, routing and fragmentation', doc)
        self.assertIn('IPv6 header chain', doc)
        self.assertIn('travels directly as an IPv4 payload', doc)
        self.assertIn('qualifies it for a base besides', doc)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class AHMembershipTests(unittest.TestCase):
    """``in`` on a terminal AH layer parsed from an IPv6 extension chain (#2484).

    The AH layer is taken from ``IPv6.extension_headers`` in extension mode.
    ``in`` on it does not raise, and is False for a selector that does not match AH.
    Frames are built in memory; no capture is read.
    """

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @staticmethod
    def _ipv6(first: int, body: bytes) -> bytes:
        import struct  # pylint: disable=import-outside-toplevel

        return struct.pack('!IHBB', 6 << 28, len(body), first, 64) + bytes(32) + body

    @staticmethod
    def _ah(next_: int) -> bytes:
        import struct  # pylint: disable=import-outside-toplevel

        # 12-octet ICV: AH is 24 octets, so the Payload Len field is 4
        return struct.pack('!BBHII', next_, 4, 0, 0x1234, 1) + bytes(12)

    @staticmethod
    def _esp() -> bytes:
        import struct  # pylint: disable=import-outside-toplevel

        return struct.pack('!II', 0x1234, 1) + bytes(16)

    def _parse_ipv6(self, data: bytes):  # type: ignore[no-untyped-def]
        from pcapkit.protocols.internet.ipv6.protocol import IPv6

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            return IPv6(io.BytesIO(data), len(data))

    def test_terminal_ah_membership_is_false_for_other_selectors(self) -> None:
        from pcapkit.protocols.internet.ah.protocol import AH

        ipv6 = self._parse_ipv6(self._ipv6(51, self._ah(59)))
        (ah,) = [ext for ext in ipv6.extension_headers.values() if isinstance(ext, AH)]

        self.assertIn('AH', ah)
        self.assertNotIn('ESP', ah)
        self.assertNotIn('TCP', ah)

    def test_ah_followed_by_esp_membership_does_not_raise(self) -> None:
        from pcapkit.protocols.internet.ah.protocol import AH

        ipv6 = self._parse_ipv6(self._ipv6(51, self._ah(50) + self._esp()))
        ah = next(ext for ext in ipv6.extension_headers.values() if isinstance(ext, AH))

        self.assertNotIn('ESP', ah)

    def test_esp_extension_layer_membership_is_unchanged(self) -> None:
        from pcapkit.protocols.internet.esp.protocol import ESP

        ipv6 = self._parse_ipv6(self._ipv6(50, self._esp()))
        esp = next(ext for ext in ipv6.extension_headers.values() if isinstance(ext, ESP))

        self.assertIn('ESP', esp)
        self.assertNotIn('AH', esp)

    def test_ipv4_ah_membership_is_unchanged(self) -> None:
        import struct  # pylint: disable=import-outside-toplevel

        from pcapkit.protocols.internet.ipv4.protocol import IPv4

        body = self._ah(59)
        data = struct.pack('!BBHHHBBH', 0x45, 0, 20 + len(body), 0, 0, 64, 51, 0) + bytes(8) + body
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            ipv4 = IPv4(io.BytesIO(data), len(data))

        self.assertNotIn('ESP', ipv4.payload)
        self.assertIn('AH', ipv4.payload)


if __name__ == '__main__':
    unittest.main()
