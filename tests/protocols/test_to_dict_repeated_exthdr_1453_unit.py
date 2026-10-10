# -*- coding: utf-8 -*-
"""``from_data(info.to_dict())`` keeps a repeated IPv6 extension header.

GitHub issue #1453: :meth:`Info.to_dict <pcapkit.corekit.infoclass.Info.to_dict>`
keyed the extension headers by name, so a second header of the same type
overwrote the first and the dict rebuild silently came back shorter --
Destination Options, Destination Options, UDP rebuilt 56 of 64 octets.

``to_dict`` returns an :class:`~pcapkit.corekit.multidict.OrderedMultiDict`
(#1484): indexing sees the first value of each key, and ``items(multi=True)``
yields every header in wire order for the rebuild. The dumpers write every
header too.

Every case builds its own octets and reads no capture. Classes are imported
inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import copy
import io
import json
import os
import pickle  # nosec: B403 -- round-trips objects built here
import struct
import tempfile
import unittest
import warnings

from tests._support import reimport_once_per_class

HOP, DST, ROUTE, UDP = 0, 60, 43, 17
MAC = bytes.fromhex('0123456789ab' 'fedcba987654')
SRC6 = bytes.fromhex('20010db8' + '00' * 11 + '01')
DST6 = bytes.fromhex('20010db8' + '00' * 11 + '02')

#: Little-endian global header: v2.4, Ethernet.
GLOBAL = bytes.fromhex('d4c3b2a1' '0200' '0400' '00000000' '00000000' 'ffff0000' '01000000')


def exthdr(code: int, nxt: int, mark: int) -> bytes:
    """An 8-octet extension header of type ``code``; ``mark`` tells repeats apart."""
    if code == ROUTE:
        # An unassigned routing type, with ``mark`` in its type-specific data.
        return bytes([nxt, 0, 253, 0, 0, 0, 0, mark])
    # Options: a PadN carrying ``mark``.
    return bytes([nxt, 0, 1, 4, 0, 0, 0, mark])


def ipv6(codes: 'list[int]') -> bytes:
    """An IPv6 packet carrying the extension headers ``codes``, then UDP."""
    body = b''
    for index, code in enumerate(codes):
        body += exthdr(code, codes[index + 1] if index + 1 < len(codes) else UDP, index)
    body += struct.pack('!HHHH', 40000, 40000, 12, 0) + b'ping'
    return struct.pack('!IHBB16s16s', 6 << 28, len(body), codes[0], 64, SRC6, DST6) + body


#: Chains repeating a header type, back to back or not.
CHAINS = {
    'dst-dst': [DST, DST],
    'hop-dst-dst': [HOP, DST, DST],
    'dst-dst-dst': [DST, DST, DST],
    'route-route': [ROUTE, ROUTE],
    'dst-route-dst': [DST, ROUTE, DST],
    'hop-dst-route-dst': [HOP, DST, ROUTE, DST],
}


def canonical(value):  # type: ignore[no-untyped-def]
    """``value`` with every multi-mapping in it turned into its class and pairs, recursively.

    Exports are compared through this: an
    :class:`~pcapkit.corekit.multidict.OrderedMultiDict` compares its values
    with ``!=``, which for a nested one compares its internal buckets.

    """
    from pcapkit.corekit.multidict import MultiDict

    if isinstance(value, MultiDict):
        return (type(value).__qualname__, [(key, canonical(val)) for key, val in value.items(multi=True)])
    return value


class TestToDictRepeatedExtensionHeader(unittest.TestCase):
    """Pin the dict rebuild of a repeated extension header chain."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        quiet = warnings.catch_warnings()
        quiet.__enter__()  # pylint: disable=unnecessary-dunder-call
        self.addCleanup(quiet.__exit__, None, None, None)
        warnings.simplefilter('ignore')

    def frame(self, name: str):  # type: ignore[no-untyped-def]
        """Parse ``CHAINS[name]`` over Ethernet as the first record of a PCAP file."""
        from pcapkit.protocols.misc.pcap.frame import Frame
        from pcapkit.protocols.misc.pcap.header import Header

        packet = MAC + b'\x86\xdd' + ipv6(CHAINS[name])
        record = struct.pack('<IIII', 1, 2, len(packet), len(packet)) + packet
        self.header = Header(GLOBAL).info
        return Frame(io.BytesIO(record), num=1, header=self.header)

    def test_every_layer_rebuilds_from_its_dict(self) -> None:
        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.protocols.link.ethernet import Ethernet
        from pcapkit.protocols.misc.pcap.frame import Frame

        for name in CHAINS:
            frame = self.frame(name)
            with self.subTest(chain=name, layer='IPv6'):
                ip6 = frame[IPv6]
                self.assertEqual(len(ip6.data), 40 + 8 * len(CHAINS[name]) + 12)
                self.assertEqual(IPv6.from_data(ip6.info.to_dict()).data, ip6.data)
            with self.subTest(chain=name, layer='Ethernet'):
                eth = frame[Ethernet]
                self.assertEqual(Ethernet.from_data(eth.info.to_dict()).data, eth.data)
            with self.subTest(chain=name, layer='Frame'):
                rebuilt = Frame.from_data(frame.info.to_dict(), num=1, header=self.header)
                self.assertEqual(rebuilt.data, frame.data)

    def test_rebuilt_chain_has_the_parsed_headers(self) -> None:
        from pcapkit.protocols.internet.ipv6 import IPv6

        for name in CHAINS:
            with self.subTest(chain=name):
                ip6 = self.frame(name)[IPv6]
                rebuilt = IPv6.from_data(ip6.info.to_dict())
                self.assertEqual([ext.data for ext in rebuilt.extension_headers.values()],
                                 [ext.data for ext in ip6.extension_headers.values()])

    def test_to_dict_keeps_every_header_in_wire_order(self) -> None:
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.internet.ipv6 import IPv6

        for name in CHAINS:
            with self.subTest(chain=name):
                ip6 = self.frame(name)[IPv6]
                dict_ = ip6.info.to_dict()
                self.assertIsInstance(dict_, OrderedMultiDict)

                parsed = [canonical(ext.info.to_dict()) for ext in ip6.extension_headers.values()]
                held = [canonical(val) for _, val in dict_.items(multi=True) if canonical(val) in parsed]
                self.assertEqual(held, parsed)

                # Indexing sees the first of each.
                first = {}  # type: dict[str, object]
                for key, val in dict_.items(multi=True):
                    first.setdefault(key, val)
                self.assertEqual({key: dict_[key] for key in dict_}, first)

    def test_info_from_dict_keeps_the_repeats(self) -> None:
        from pcapkit.protocols.data.internet.ipv6 import IPv6 as Data_IPv6
        from pcapkit.protocols.internet.ipv6 import IPv6

        for name in CHAINS:
            with self.subTest(chain=name):
                info = self.frame(name)[IPv6].info
                dict_ = info.to_dict()
                rebuilt = Data_IPv6.from_dict(dict_)
                self.assertEqual([key for key, _ in rebuilt.items(multi=True)],
                                 [key for key, _ in dict_.items(multi=True)])
                self.assertEqual(canonical(rebuilt.to_dict()), canonical(dict_))
                self.assertEqual(rebuilt, info)

    def test_to_dict_is_a_plain_ordered_multi_dict(self) -> None:
        from pcapkit.corekit.infoclass import Info
        from pcapkit.corekit.multidict import OrderedMultiDict

        dict_ = Info(a=1, b=Info(c=2)).to_dict()
        self.assertIsInstance(dict_, OrderedMultiDict)
        self.assertIsInstance(dict_['b'], OrderedMultiDict)
        self.assertEqual(dict_.to_dict(flat=True)['a'], 1)
        self.assertEqual(list(dict_), ['a', 'b'])

        repeated = Info.from_dict(OrderedMultiDict([('a', 1), ('b', 2), ('a', 3)])).to_dict()
        self.assertEqual(list(repeated.items(multi=True)), [('a', 1), ('b', 2), ('a', 3)])
        self.assertEqual(repeated['a'], 1)
        self.assertEqual(repeated.getlist('a'), [1, 3])
        for clone in (copy.copy(repeated), copy.deepcopy(repeated), pickle.loads(pickle.dumps(repeated))):  # nosec: B301
            with self.subTest(clone=clone):
                self.assertIs(type(clone), type(repeated))
                self.assertEqual(list(clone.items(multi=True)), [('a', 1), ('b', 2), ('a', 3)])

    def test_info_copy_keeps_its_own_repeats(self) -> None:
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.internet.ipv6 import IPv6

        info = self.frame('dst-dst')[IPv6].info
        before = list(info.items(multi=True))
        extra = info['opts']
        for clone in (copy.copy(info), copy.deepcopy(info)):
            with self.subTest(clone=type(clone).__name__):
                self.assertIsNot(clone.__multi__, info.__multi__)
                self.assertIsNot(clone.__map__, info.__map__)
                clone.__update__(OrderedMultiDict([('opts', extra)]))
                self.assertEqual(len(list(clone.items(multi=True))), len(before) + 1)
                self.assertEqual(list(info.items(multi=True)), before)

    def test_dumper_writes_every_header(self) -> None:
        import dictdumper.json

        from pcapkit.dumpkit.common import make_dumper

        frame = self.frame('dst-route-dst')
        outputs = []
        with tempfile.TemporaryDirectory() as tmp:
            for index, value in enumerate((frame.info, frame.info.to_dict())):
                path = os.path.join(tmp, f'{index}.json')
                make_dumper(dictdumper.json.JSON)(path)(value, name='Frame 1')
                with open(path, encoding='utf-8') as file:
                    outputs.append(json.load(file))
        ipv6 = outputs[0]['Frame 1']['ethernet']['ipv6']
        self.assertEqual(len(ipv6['opts']), 2)
        self.assertIsInstance(ipv6['route'], dict)
        # Handed the export, the dumper writes the top level the same way.
        self.assertEqual(list(outputs[1]['Frame 1']), list(outputs[0]['Frame 1']))

if __name__ == '__main__':
    unittest.main()
