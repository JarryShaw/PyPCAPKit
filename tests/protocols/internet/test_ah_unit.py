from __future__ import annotations

import importlib.util
import unittest
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
        from pcapkit.protocols.internet.ah import AH

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
        from pcapkit.protocols.internet.ah import AH

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
        from pcapkit.protocols.internet.ah import AH
        from pcapkit.protocols.internet.ipsec import IPsec
        from pcapkit.protocols.schema.internet.ah import AH as Schema_AH
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
        """GitHub issue #931.

        The class docstring's extension-header *membership* claim must
        rest on IANA's authoritative *IPv6 Extension Header Types*
        registry (and this package's own registry, generated from it),
        not the ``protocol-numbers-1.csv`` *IPv6 Extension Header* column
        that #926 repointed the const generator away from -- that column
        is a derived signal, not the registry :rfc:`8200#section-4` names
        as authoritative, and disagreed with it on header 147
        (``BIT_EMU``).

        :rfc:`4302#section-3.1.1` is cited too, but only for what it
        actually says: an IPv6-context placement recommendation ("should
        appear after hop-by-hop, routing, and fragmentation extension
        headers"), not a membership assertion -- membership is the
        registry's claim, per
        ``docs/source/contributing/conventions/extension-header-subclassing.rst``'s
        "being *in* that registry is what makes something an extension
        header" ruling.
        Rephrasing the placement sentence as "places it among the IPv6
        extension headers" overstated the RFC; that was caught in review
        on the second version of this fix.

        The section's separate IPv4-context sentence ("placed after the
        IP header ... before the next layer protocol") is legitimate
        prose here too -- it is the primary-source evidence that AH
        also travels directly as an IPv4 payload, exactly as
        :mod:`~pcapkit.protocols.internet.hip` cites its own IPv4
        appendix for the same reason. Per
        ``docs/source/contributing/conventions/extension-header-subclassing.rst``'s
        "own-protocolhood on its own is not sufficient" ruling (MH is the
        settling case),
        that fact *qualifies* an already-standalone header for a base
        besides :class:`~pcapkit.protocols.internet.ipv6_ext.IPv6_Ext`;
        it does not *make* the header standalone, and the RFC has no
        say in which base is named. An earlier revision of this
        docstring's ``ESP`` counterpart claimed the RFC "makes it a
        standalone protocol" and "names ``IPsec`` as the second base",
        the latter positionally false and unsupported by the cited
        section; both were caught in review on the third version of
        this fix. So this test targets the exact wrong phrasing from
        the earlier rounds rather than banning "IPv4" outright, which
        would forbid the legitimate use kept above.
        """
        import re

        from pcapkit.protocols.internet.ah import AH

        # Normalise the docstring's line-wrapping before matching, since the
        # citation may be split across lines by hand-wrapping.
        doc = ' '.join((AH.__doc__ or '').split())
        self.assertNotIn('protocol-numbers-1.csv', doc)
        self.assertNotIn('among the IPv6 extension headers', doc)
        self.assertNotIn('second base', doc)
        self.assertNotIn('directly after an IPv4 header', doc)

        # Pin the claim, not just the phrase: whatever the RFC-placement
        # parenthetical attached directly to the registry-membership
        # sentence says, it must not smuggle in IPv4 evidence for that
        # claim, regardless of how a future revision words it.
        membership_clause = re.search(r'registry lists it at 51 \((.*?)\)', doc)
        self.assertIsNotNone(membership_clause, 'could not locate the membership clause')
        self.assertNotIn('IPv4', membership_clause.group(1))

        self.assertIn('IPv6 Extension Header Types', doc)
        self.assertIn(':rfc:`4302#section-3.1.1`', doc)
        self.assertIn('hop-by-hop, routing and fragmentation', doc)
        self.assertIn('IPv6 header chain', doc)
        self.assertIn('travels directly as an IPv4 payload', doc)
        self.assertIn('qualifies it for a base besides', doc)


if __name__ == '__main__':
    unittest.main()
