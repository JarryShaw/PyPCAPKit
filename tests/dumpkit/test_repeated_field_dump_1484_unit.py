# -*- coding: utf-8 -*-
"""Every value of a repeated field reaches the ``json``, ``plist`` and ``tree`` dumps.

GitHub issue #1484. An IPv6 packet carrying two Destination Options headers
holds both under the one ``opts`` key, and every dump held only the first.
Each dump now writes the field as the list of both headers, in wire order,
while a field held once is written as its value.

Every case builds its input in a temporary directory, and reads no capture.
:mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import importlib.util
import json
import os
import plistlib
import struct
import tempfile
import unittest
import warnings

from tests._support import reimport_once_per_class

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

DST, UDP = 60, 17
MAC = bytes.fromhex('0123456789ab' 'fedcba987654')
SRC6 = bytes.fromhex('20010db8' + '00' * 11 + '01')
DST6 = bytes.fromhex('20010db8' + '00' * 11 + '02')

#: Little-endian global header: v2.4, Ethernet.
GLOBAL = bytes.fromhex('d4c3b2a1' '0200' '0400' '00000000' '00000000' 'ffff0000' '01000000')

#: Last octet of each header's PadN, telling the two apart.
MARKS = (0xa1, 0xb2)


def capture() -> bytes:
    """A PCAP file of one Ethernet/IPv6 frame: Destination Options twice, then UDP."""
    body = bytes([DST, 0, 1, 4, 0, 0, 0, MARKS[0]]) + bytes([UDP, 0, 1, 4, 0, 0, 0, MARKS[1]])
    body += struct.pack('!HHHH', 40000, 40000, 12, 0) + b'ping'
    packet = MAC + b'\x86\xdd' + struct.pack('!IHBB16s16s', 6 << 28, len(body), DST, 64, SRC6, DST6) + body
    return GLOBAL + struct.pack('<IIII', 1, 2, len(packet), len(packet)) + packet


def pads(headers: 'list[dict]') -> 'list[str]':
    """The PadN octets of each Destination Options header, as the JSON dump spells them."""
    return [next(iter(header['options'][0].values()))['pad']['hex'] for header in headers]


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class RepeatedFieldDumpTests(unittest.TestCase):
    """Read each dump back and find both headers in it."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        self.tmpdir = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.addCleanup(self.tmpdir.cleanup)
        quiet = warnings.catch_warnings()
        quiet.__enter__()  # pylint: disable=unnecessary-dunder-call
        self.addCleanup(quiet.__exit__, None, None, None)
        warnings.simplefilter('ignore')

    def dump(self, fmt: 'str') -> 'bytes':
        """Extract :func:`capture` as ``fmt``; return the output file."""
        from pcapkit import extract

        src = os.path.join(self.tmpdir.name, 'in.pcap')
        with open(src, 'wb') as file:
            file.write(capture())
        extractor = extract(fin=src, fout=os.path.join(self.tmpdir.name, f'out-{fmt}'), format=fmt, store=False)
        with open(extractor.output, 'rb') as file:
            return file.read()

    def test_json_holds_both_headers_in_order(self) -> None:
        ipv6 = json.loads(self.dump('json'))['Frame 1']['ethernet']['ipv6']
        self.assertIsInstance(ipv6['opts'], list)
        self.assertEqual(pads(ipv6['opts']), [f'000000{mark:02x}' for mark in MARKS])
        # A field held once is still written as its value.
        self.assertEqual(ipv6['limit'], 64)

    def test_plist_holds_both_headers_in_order(self) -> None:
        ipv6 = plistlib.loads(self.dump('plist'))['Frame 1']['ethernet']['ipv6']
        self.assertIsInstance(ipv6['opts'], list)
        self.assertEqual([next(iter(header['options'][0].values()))['pad'] for header in ipv6['opts']],
                         [b'\x00\x00\x00' + bytes([mark]) for mark in MARKS])

    def test_tree_holds_both_headers(self) -> None:
        text = self.dump('tree').decode('utf-8')
        for mark in MARKS:
            with self.subTest(mark=mark):
                self.assertIn(f'pad -> 00 00 00 {mark:02x}', text)

    def test_the_writer_takes_the_info_or_its_export(self) -> None:
        """Handed the info, the writer holds both headers; handed ``to_dict()``, the same top level.

        Below the top level an export cannot tell a nested :class:`Info` from an
        option list, both being an ``OrderedMultiDict``, so only the info itself
        is written with nested fields as mappings.

        """
        import io

        import dictdumper

        from pcapkit.dumpkit.common import make_dumper
        from pcapkit.protocols.misc.pcap.frame import Frame
        from pcapkit.protocols.misc.pcap.header import Header

        raw = capture()
        frame = Frame(io.BytesIO(raw[24:]), num=1, header=Header(raw[:24]).info)
        tops = []
        for index, value in enumerate((frame.info, frame.info.to_dict())):
            path = os.path.join(self.tmpdir.name, f'{index}.json')
            make_dumper(dictdumper.JSON)(path)(value, name='Frame 1')
            with open(path, encoding='utf-8') as file:
                tops.append(json.load(file)['Frame 1'])
        self.assertEqual(pads(tops[0]['ethernet']['ipv6']['opts']), [f'000000{mark:02x}' for mark in MARKS])
        self.assertEqual(list(tops[1]), list(tops[0]))
        self.assertEqual(list(tops[0]), list(frame.info.to_dict()))


if __name__ == '__main__':
    unittest.main()
