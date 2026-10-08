# -*- coding: utf-8 -*-
"""GitHub issue #1422: a PCAP-NG SHB or IDB shorter than its fixed fields.

A Section Header Block below 28 octets, or an Interface Description Block
below 20, read its fixed fields past the Block Total Length and rebuilt at the
full fixed size (SHB 16 or 20 to 28, IDB 12 or 16 to 20). The block body is
now kept as ``block_raw`` and written back at the declared length, as #1414
does for EPB/PB. A 12-octet SHB has no Byte-Order Magic and takes the byte
order in which its Block Total Length reads as 12.

:mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import struct
import unittest
import warnings
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

#: Section and interface blocks below their fixed size, by issue length.
SHORT = ('shb-12', 'shb-16', 'shb-20', 'shb-24', 'idb-12', 'idb-16')
#: The same blocks at their full fixed size, already byte-exact before #1422.
FULL = ('shb-28', 'idb-20')


def _block(endian: 'str', type_: 'int', body: 'bytes') -> 'bytes':
    """A block of ``type_`` around ``body`` in ``endian`` byte order."""
    length = len(body) + 12
    return struct.pack(f'{endian}II', type_, length) + body + struct.pack(f'{endian}I', length)


def _octets(name: 'str', endian: 'str') -> 'bytes':
    """The block ``name`` (``shb-16``, ``idb-20``, ...) in ``endian`` byte order."""
    kind, size = name.split('-')
    if kind == 'shb':
        fixed = struct.pack(f'{endian}IHHq', 0x1A2B3C4D, 1, 0, -1)
        return _block(endian, 0x0A0D0D0A, fixed[:int(size) - 12])
    fixed = struct.pack(f'{endian}HHI', 1, 0, 0x40000)
    return _block(endian, 1, fixed[:int(size) - 12])


class TestPCAPNGShortSHBIDB(unittest.TestCase):
    """Pin that short SHBs and IDBs rebuild at the length they declare."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _kwargs(self, octets: 'bytes', endian: 'str') -> 'dict[str, Any]':
        """Constructor arguments for ``octets``, an SHB or a block in a section."""
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.foundation.engines.pcapng import Context
        from pcapkit.protocols.misc.pcapng import PCAPNG

        if octets[:4] == b'\x0a\x0d\x0d\x0a':
            return {'num': 0, 'sct': 1, 'ctx': None}
        section = PCAPNG(num=0, sct=1, ctx=None, type=BlockType.Section_Header_Block,
                         block={'byteorder': 'little' if endian == '<' else 'big'})
        return {'num': 1, 'sct': 1, 'ctx': Context(section.info)}

    def _parse(self, octets: 'bytes', kwargs: 'dict[str, Any]') -> 'tuple[Any, list[str]]':
        from pcapkit.protocols.misc.pcapng import PCAPNG

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            parsed = PCAPNG(octets, len(octets), **kwargs)
        return parsed, [str(item.message) for item in caught]

    def _rebuild(self, info: 'Any', kwargs: 'dict[str, Any]') -> 'Any':
        from pcapkit.protocols.misc.pcapng import PCAPNG

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            return PCAPNG.from_data(info, **kwargs)

    def test_parse_rebuild_is_byte_exact(self) -> None:
        """parse -> rebuild: every short and full block rebuilds at its own length."""
        for endian in '<>':
            for name in SHORT + FULL:
                with self.subTest(endian=endian, block=name):
                    octets = _octets(name, endian)
                    self.assertEqual(len(octets), int(name.split('-')[1]))
                    kwargs = self._kwargs(octets, endian)
                    parsed, messages = self._parse(octets, kwargs)
                    self.assertFalse(any('block length mismatch' in text for text in messages), messages)
                    self.assertEqual(self._rebuild(parsed.info, kwargs).data.hex(), octets.hex())

    def test_short_block_is_kept_as_captured(self) -> None:
        """A short block warns, keeps its body and reads no octet past its end."""
        for endian in '<>':
            for name in SHORT:
                with self.subTest(endian=endian, block=name):
                    octets = _octets(name, endian)
                    minimum = 28 if name.startswith('shb') else 20
                    parsed, messages = self._parse(octets + b'\xff' * 16, self._kwargs(octets, endian))
                    self.assertTrue(any(f'block length {len(octets)} is below the {minimum}-octet minimum'
                                        in text for text in messages), messages)
                    info = parsed.info
                    self.assertEqual(info.length, len(octets))
                    self.assertEqual(info.block_raw, octets[8:-4])
                    self.assertEqual(len(info.options), 0)

    def test_full_block_has_no_block_raw(self) -> None:
        """A full-size SHB or IDB parses its fields and keeps no raw body."""
        for endian in '<>':
            for name in FULL:
                with self.subTest(endian=endian, block=name):
                    octets = _octets(name, endian)
                    parsed, _ = self._parse(octets, self._kwargs(octets, endian))
                    self.assertFalse(hasattr(parsed.info, 'block_raw'))

    def test_short_shb_keeps_byte_order_and_fields(self) -> None:
        """The magic sets the byte order; fields past the block read as zero."""
        for endian, order in (('<', 'little'), ('>', 'big')):
            for name, version, section_length in (('shb-12', (0, 0), 0), ('shb-16', (0, 0), 0),
                                                  ('shb-20', (1, 0), 0),
                                                  ('shb-24', (1, 0), 0xFFFF_FFFF if endian == '<'
                                                   else -0x1_0000_0000)):
                with self.subTest(endian=endian, block=name):
                    octets = _octets(name, endian)
                    info = self._parse(octets, self._kwargs(octets, endian))[0].info
                    self.assertEqual(info.byteorder, order)
                    self.assertEqual((info.version.major, info.version.minor), version)
                    self.assertEqual(info.section_length, section_length)

    def test_short_idb_keeps_fields(self) -> None:
        """A 16-octet IDB keeps its link type; the snaplen it lacks reads as zero."""
        from pcapkit.const.reg.linktype import LinkType

        for endian in '<>':
            for name, linktype in (('idb-12', LinkType.NULL), ('idb-16', LinkType.ETHERNET)):
                with self.subTest(endian=endian, block=name):
                    octets = _octets(name, endian)
                    info = self._parse(octets, self._kwargs(octets, endian))[0].info
                    self.assertEqual(info.linktype, linktype)
                    self.assertEqual(info.snaplen, 0)

    def test_make_parse_is_exact(self) -> None:
        """make -> parse: the rebuilt block parses back to the same data model."""
        for endian in '<>':
            for name in SHORT + FULL:
                with self.subTest(endian=endian, block=name):
                    octets = _octets(name, endian)
                    kwargs = self._kwargs(octets, endian)
                    info = self._parse(octets, kwargs)[0].info
                    made = self._rebuild(info, kwargs)
                    reparsed = self._parse(made.data, kwargs)[0].info
                    for parsed in (made.info, reparsed):
                        self.assertEqual(parsed.length, info.length)
                        self.assertEqual(getattr(parsed, 'block_raw', None), getattr(info, 'block_raw', None))
                        for field in ('byteorder', 'version', 'section_length', 'linktype', 'snaplen'):
                            self.assertEqual(getattr(parsed, field, None), getattr(info, field, None), field)

    def test_shb_without_magic_needs_a_length_of_12(self) -> None:
        """A magic slot reading as length 12 is only a byte order when the block is 12 octets."""
        from pcapkit.utilities.exceptions import ProtocolError

        octets = struct.pack('<II', 0x0A0D0D0A, 16) + struct.pack('<I', 12) + struct.pack('<I', 16)
        with self.assertRaisesRegex(ProtocolError, r'^unknown byteorder magic: 0xc000000$'):
            self._parse(octets, self._kwargs(octets, '<'))

    def test_extraction_continues_past_short_shb_and_idb(self) -> None:
        """A stream opening with a 16-octet SHB and IDB still reads the EPB behind them."""
        from pcapkit.foundation.extraction import Extractor
        from tests.protocols.misc.test_pcapng_unit import NamedBuffer

        good = _block('<', 6, struct.pack('<IIIII', 0, 0, 0, 4, 4) + b'abcd')
        stream = _octets('shb-16', '<') + _octets('idb-16', '<') + good
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            extractor = Extractor(NamedBuffer(stream), nofile=True, store=True)
            frames = extractor.frame
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].info.captured_len, 4)
        section = extractor.engine._ctx_list[0].section
        self.assertEqual(section.byteorder, 'little')
        rebuilt = self._rebuild(section, {'num': 0, 'sct': 1, 'ctx': None}).data
        self.assertEqual(rebuilt.hex(), _octets('shb-16', '<').hex())


if __name__ == '__main__':
    unittest.main()
