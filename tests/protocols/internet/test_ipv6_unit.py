from __future__ import annotations

import importlib.util
from types import SimpleNamespace
import unittest
from unittest import mock

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


class DummyDict(dict):
    __getattr__ = dict.__getitem__


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class IPv6UnitTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_ipv6_index_length_and_id_are_stable(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ipv6 import IPv6

        proto = object.__new__(IPv6)

        self.assertEqual(IPv6.id(), ('IPv6',))
        self.assertEqual(IPv6.__index__(), TransType.IPv6)
        self.assertEqual(proto.__length_hint__(), 40)

    def test_ipv6_make_data_preserves_selected_fields(self) -> None:
        from ipaddress import ip_address

        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ipv6 import IPv6

        data = DummyDict({
            'class': 0x2a,
            'label': 0x12345,
            'next': TransType.TCP,
            'limit': 32,
            'src': ip_address('2001:db8::1'),
            'dst': ip_address('2001:db8::2'),
            '__next_type__': None,
        })

        values = IPv6._make_data(data)
        self.assertEqual(values['traffic_class'], 0x2a)
        self.assertEqual(values['flow_label'], 0x12345)
        self.assertEqual(values['next'], TransType.TCP)
        self.assertEqual(values['hop_limit'], 32)
        self.assertEqual(values['src'], ip_address('2001:db8::1'))
        self.assertEqual(values['dst'], ip_address('2001:db8::2'))
        self.assertIn('payload', values)

    def test_ipv6_make_builds_schema_with_normalised_fields(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ipv6 import IPv6

        proto = object.__new__(IPv6)
        schema = proto.make(
            traffic_class=0x2a,
            flow_label=0x12345,
            next=TransType.UDP,
            hop_limit=16,
            src='2001:db8::1',
            dst='2001:db8::2',
            payload=b'data',
        )

        self.assertEqual(schema.hextet['version'], 6)
        self.assertEqual(schema.hextet['class'], 0x2a)
        self.assertEqual(schema.hextet['label'], 0x12345)
        self.assertEqual(schema.length, 4)
        self.assertEqual(schema.next, TransType.UDP)
        self.assertEqual(schema.limit, 16)

    def test_ipv6_properties_read_and_low_level_field_readers(self) -> None:
        from ipaddress import ip_address

        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.protocols.schema.internet.ipv6 import IPv6 as Schema_IPv6

        proto = object.__new__(IPv6)
        proto._info = DummyDict(
            protocol=TransType.UDP,
            src=ip_address('2001:db8::1'),
            dst=ip_address('2001:db8::2'),
        )
        proto._exthdr = 'extensions'

        self.assertEqual(proto.name, 'Internet Protocol version 6')
        self.assertEqual(proto.length, 40)
        self.assertEqual(proto.protocol, TransType.UDP)
        self.assertEqual(proto.src, ip_address('2001:db8::1'))
        self.assertEqual(proto.dst, ip_address('2001:db8::2'))
        self.assertEqual(proto.extension_headers, 'extensions')

        proto.__header__ = Schema_IPv6(
            hextet={'version': 6, 'class': 0x2a, 'label': 0x12345},
            length=4,
            next=TransType.TCP,
            limit=31,
            src='2001:db8::3',
            dst='2001:db8::4',
            payload=b'data',
        )
        proto._data = bytes(proto.__header__)
        proto.__cached__ = {}
        packet = {}
        with mock.patch.object(proto, '_decode_next_layer', return_value='decoded') as decode:
            self.assertEqual(proto.read(__packet__=packet), 'decoded')
        decode.assert_called_once()
        decoded_ipv6 = decode.call_args.args[0]
        self.assertEqual(decoded_ipv6.version, 6)
        self.assertEqual(decoded_ipv6['class'], 0x2a)
        self.assertEqual(decoded_ipv6.label, 0x12345)
        self.assertEqual(decoded_ipv6.payload, 4)
        self.assertEqual(decoded_ipv6.next, TransType.TCP)
        self.assertEqual(decoded_ipv6.limit, 31)
        self.assertEqual(str(packet['src']), '2001:db8::3')
        self.assertEqual(str(packet['dst']), '2001:db8::4')

        proto._read_fileng = mock.Mock(side_effect=[
            bytes.fromhex('6abcdef0'),
            ip_address('2001:db8::5').packed,
        ])
        self.assertEqual(proto._read_ip_hextet(), (6, 0x6a, 0xbcdef0))
        self.assertEqual(proto._read_ip_addr(), ip_address('2001:db8::5'))

    def test_ipv6_decode_next_layer_handles_extension_headers_and_fragments(self) -> None:
        from ipaddress import ip_address

        from pcapkit.const.ipv6.extension_header import ExtensionHeader
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.data.internet.ipv6 import IPv6 as Data_IPv6
        from pcapkit.protocols.internet.internet import Internet
        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.protocols.internet.ipv6_frag import IPv6_Frag

        proto = object.__new__(IPv6)
        proto.__header__ = SimpleNamespace(get_payload=lambda: b'fragment-payload')
        proto._read_packet = mock.Mock(return_value='fragment-data')

        ipv6 = Data_IPv6.from_dict({
            'version': 6,
            'class': 0,
            'label': 0,
            'payload': len(b'fragment-payload'),
            'next': TransType.IPv6_Frag,
            'limit': 64,
            'src': ip_address('2001:db8::1'),
            'dst': ip_address('2001:db8::2'),
        })
        fragment = object.__new__(IPv6_Frag)
        fragment._info = DummyDict(next=TransType.UDP)

        with mock.patch.object(proto, '_import_next_layer', return_value=fragment) as import_next:
            with mock.patch.object(Internet, '_decode_next_layer', return_value='decoded') as decode:
                self.assertEqual(proto._decode_next_layer(
                    ipv6,
                    TransType.IPv6_Frag,
                    ipv6.payload,
                    packet={'seen': True},
                ), 'decoded')

        import_next.assert_called_once()
        self.assertEqual(import_next.call_args.kwargs['version'], 6)
        self.assertTrue(import_next.call_args.kwargs['extension'])
        self.assertEqual(import_next.call_args.kwargs['payload'], b'fragment-payload')
        proto._read_packet.assert_called_once_with(header=48, payload=len(b'fragment-payload') - 8)
        self.assertEqual(ipv6.frag.next, TransType.UDP)
        self.assertEqual(ipv6.fragment, 'fragment-data')
        self.assertEqual(ipv6.hdr_len, 48)
        self.assertEqual(ipv6.raw_len, len(b'fragment-payload') - 8)
        self.assertEqual(ipv6.protocol, TransType.UDP)
        self.assertEqual(list(proto._exthdr.keys()), [ExtensionHeader.IPv6_Frag])
        self.assertEqual(decode.call_args.args[1], TransType.UDP)
        self.assertEqual(decode.call_args.args[2], len(b'fragment-payload') - 8)

    def test_ipv6_decode_next_layer_without_extensions_and_import_branches(self) -> None:
        from collections import defaultdict
        from ipaddress import ip_address

        from pcapkit.const.reg.transtype import TransType
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.protocols.data.internet.ipv6 import IPv6 as Data_IPv6
        from pcapkit.protocols.internet.internet import Internet
        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.protocols.misc.null import NoPayload
        from pcapkit.protocols.misc.raw import Raw

        proto = object.__new__(IPv6)
        proto.__header__ = SimpleNamespace(get_payload=lambda: b'udp-data')

        ipv6 = Data_IPv6.from_dict({
            'version': 6,
            'class': 0,
            'label': 0,
            'payload': len(b'udp-data'),
            'next': TransType.UDP,
            'limit': 64,
            'src': ip_address('2001:db8::1'),
            'dst': ip_address('2001:db8::2'),
        })

        with mock.patch.object(Internet, '_decode_next_layer', return_value='decoded') as decode:
            self.assertEqual(proto._decode_next_layer(ipv6, TransType.UDP, ipv6.payload), 'decoded')
        self.assertEqual(ipv6.hdr_len, 40)
        self.assertEqual(ipv6.raw_len, len(b'udp-data'))
        self.assertEqual(ipv6.protocol, TransType.UDP)
        self.assertEqual(list(proto._exthdr.keys()), [])
        self.assertEqual(decode.call_args.args[1], TransType.UDP)
        self.assertEqual(decode.call_args.kwargs['payload'], b'udp-data')

        proto._sigterm = False
        proto._exlayer = None
        proto._exproto = None
        self.assertIsInstance(proto._import_next_layer(TransType.UDP, payload=b'', packet={}), NoPayload)

        proto._sigterm = True
        self.assertIsInstance(proto._import_next_layer(TransType.UDP, payload=b'raw'), Raw)

        proto._sigterm = False
        custom_proto = TransType.get(250)
        proto.__proto__ = defaultdict(lambda: Raw, {
            custom_proto: ModuleDescriptor('pcapkit.protocols.misc.raw', 'Raw'),
        })
        imported = proto._import_next_layer(custom_proto, payload=b'module')
        self.assertIsInstance(imported, Raw)
        self.assertIs(proto.__proto__[custom_proto], Raw)

    def test_ipv6_remaining_decode_and_import_edges(self) -> None:
        from collections import defaultdict
        from ipaddress import ip_address

        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.data.internet.ipv6 import IPv6 as Data_IPv6
        from pcapkit.protocols.internet.hopopt import HOPOPT
        from pcapkit.protocols.internet.internet import Internet
        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.protocols.schema.internet.ipv6 import IPv6 as Schema_IPv6

        proto = object.__new__(IPv6)
        proto.__header__ = Schema_IPv6(
            hextet={'version': 6, 'class': 1, 'label': 2},
            length=0,
            next=TransType.UDP,
            limit=3,
            src='2001:db8::6',
            dst='2001:db8::7',
            payload=b'',
        )
        with mock.patch.object(proto, '_decode_next_layer', return_value='decoded') as decode:
            self.assertEqual(proto.read(length=40), 'decoded')
        self.assertEqual(str(decode.call_args.kwargs['packet']['src']), '2001:db8::6')
        self.assertEqual(str(decode.call_args.kwargs['packet']['dst']), '2001:db8::7')

        proto = object.__new__(IPv6)
        proto.__header__ = SimpleNamespace(get_payload=lambda: b'hopopt-rest')
        hopopt = object.__new__(HOPOPT)
        hopopt._info = DummyDict(next=TransType.UDP, length=2)
        ipv6 = Data_IPv6.from_dict({
            'version': 6,
            'class': 0,
            'label': 0,
            'payload': len(b'hopopt-rest'),
            'next': TransType.HOPOPT,
            'limit': 64,
            'src': ip_address('2001:db8::1'),
            'dst': ip_address('2001:db8::2'),
        })
        with mock.patch.object(proto, '_import_next_layer', return_value=hopopt):
            with mock.patch.object(Internet, '_decode_next_layer', return_value='decoded') as decode:
                self.assertEqual(proto._decode_next_layer(ipv6, TransType.HOPOPT, ipv6.payload), 'decoded')
        self.assertEqual(ipv6.hdr_len, 42)
        self.assertEqual(ipv6.raw_len, len(b'hopopt-rest') - 2)
        self.assertEqual(decode.call_args.kwargs['payload'], b'popt-rest')

        proto._sigterm = False
        proto._exlayer = None
        proto._exproto = None
        proto.__header__ = SimpleNamespace(get_payload=lambda: b'direct')
        custom_proto = TransType.get(249)
        proto.__proto__ = defaultdict(lambda: Raw, {custom_proto: Raw})
        self.assertIsInstance(proto._import_next_layer(custom_proto, length=6), Raw)

    def test_flow_label_is_read_from_bits_12_to_31(self) -> None:
        """The flow label occupies bits 12-31 of the first hextet.

        Per :rfc:`8200#section-3` the IPv6 header opens with Version (4 bits),
        Traffic Class (8 bits) and Flow Label (20 bits), so the label starts at
        bit 12. The :class:`~pcapkit.corekit.fields.strings.BitField` namespace
        spells each subfield as ``(start_bit, length_in_bits)``, so declaring the
        label as ``(8, 20)`` reads bits 8-27 instead: the parsed value picks up
        the low nibble of the Traffic Class and drops the low nibble of the real
        label.

        A zero flow label behind a non-zero Traffic Class is the clearest case,
        and also the most common one -- :rfc:`6437` makes a zero label lawful.

        """
        import io
        import struct

        from pcapkit.protocols.internet.ipv6 import IPv6

        src = bytes.fromhex('fe80000000000000a423b61d7c9270c6')
        dst = bytes.fromhex('fe80000000000000821f12fffec9d13d')

        cases = (
            (0x00, 0x12345),
            (0xff, 0x00000),   # a zero label behind a saturated traffic class
            (0xff, 0x12345),
            (0x00, 0xfffff),
            (0xab, 0xcdef0),
        )
        for tclass, label in cases:
            with self.subTest(tclass=tclass, label=label):
                hextet = (6 << 28) | (tclass << 20) | label
                raw = struct.pack('>IHBB', hextet, 0, 59, 64) + src + dst
                info = IPv6(io.BytesIO(raw), len(raw)).info

                self.assertEqual(info.version, 6)
                self.assertEqual(info['class'], tclass)
                self.assertEqual(info.label, label)

                # the value the (8, 20) declaration produced: bits 8-27 rather
                # than bits 12-31 of the same four octets
                bits = f'{hextet:032b}'
                self.assertEqual(int(bits[12:32], 2), label)
                if int(bits[8:28], 2) != label:
                    self.assertNotEqual(info.label, int(bits[8:28], 2))

    def test_flow_label_subfields_tile_the_hextet_without_overlap(self) -> None:
        """No two subfields of the first hextet may claim the same bit.

        The ``(start, length)`` namespace is written to in declaration order, so
        an overlapping declaration silently corrupts whichever subfield is
        written first -- which is how the flow label came to overwrite the low
        nibble of the traffic class on the way out as well as misreading it on
        the way in. Asserting an exact tiling catches both directions at once.

        """
        from pcapkit.protocols.schema.internet.ipv6 import IPv6 as Schema_IPv6

        namespace = Schema_IPv6.__fields__['hextet']._namespace
        self.assertEqual(namespace, {'version': (0, 4), 'class': (4, 8), 'label': (12, 20)})

        coverage = [0] * 32
        for start, size in namespace.values():
            for bit in range(start, start + size):
                coverage[bit] += 1
        self.assertEqual(coverage, [1] * 32)

    def test_flow_label_survives_a_wire_round_trip(self) -> None:
        """Building then parsing a header must preserve traffic class and label.

        ``BitField`` writes and reads through the same namespace, so a wrong bit
        range round-trips cleanly whenever the subfields do not overlap and is
        therefore invisible to a build-then-parse test on its own. This test
        pins the *wire* bytes as well, which is what makes it a real check.

        """
        import io

        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.protocols.schema.internet.ipv6 import IPv6 as Schema_IPv6

        schema = Schema_IPv6(
            hextet={'version': 6, 'class': 0x2a, 'label': 0x12345},
            length=0,
            next=59,
            limit=64,
            src='2001:db8::1',
            dst='2001:db8::2',
            payload=b'',
        )
        raw = bytes(schema)

        # version 6, traffic class 0x2a, flow label 0x12345 packs as 0x62a12345
        self.assertEqual(raw[:4], bytes.fromhex('62a12345'))

        info = IPv6(io.BytesIO(raw), len(raw)).info
        self.assertEqual(info.version, 6)
        self.assertEqual(info['class'], 0x2a)
        self.assertEqual(info.label, 0x12345)


if __name__ == '__main__':
    unittest.main()
