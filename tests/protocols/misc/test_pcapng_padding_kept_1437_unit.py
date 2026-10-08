# -*- coding: utf-8 -*-
"""GitHub issue #1437 (part B): PCAP-NG padding rebuilds as captured.

#1436 made :class:`~pcapkit.corekit.fields.strings.PaddingField` pack the octets
it is given, but the PCAP-NG reader never handed them on, so non-zero padding
parsed silently and came back zeroed: the packet data padding of an SPB, EPB and
Packet Block, the secrets padding of a DSB, the IDB reserved octets, and the
padding of every option and NRB record. Octets after ``opt_endofopt`` were
dropped outright, shrinking the block. Each is now kept on the data model --
padding only when it is not all zeros, the octets after ``opt_endofopt``
whenever there are any -- and written back by ``make``.

Every case builds its own octets in memory and reads no capture.

"""

import struct
import warnings

from tests.protocols.misc.test_pcapng_roundtrip2_unit import PCAPNGTestCase


def _block(type_: 'int', body: 'bytes') -> 'bytes':
    """A little-endian block of ``type_`` around ``body``."""
    length = len(body) + 12
    return struct.pack('<II', type_, length) + body + struct.pack('<I', length)


def _option(code: 'int', value: 'bytes', padding: 'bytes') -> 'bytes':
    """A little-endian option of ``code`` holding ``value``, then ``padding``."""
    return struct.pack('<HH', code, len(value)) + value + padding


#: ``opt_endofopt``.
END = bytes(4)
#: Fixed fields of a Section Header Block, version 1.0, unknown section length.
SHB = struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1)
#: Fixed fields of an Enhanced Packet Block on interface 0 holding ``n`` octets.
EPB = lambda n: struct.pack('<IIIII', 0, 0, 0, n, n)  # noqa: E731
#: Fixed fields of an obsolete Packet Block holding one octet.
PB = struct.pack('<HHIIII', 0, 0, 0, 0, 1, 1)
#: Fixed fields of an Interface Description Block, Ethernet, ``reserved`` given.
IDB = lambda reserved: struct.pack('<HHI', 1, reserved, 0)  # noqa: E731
#: Fixed fields of an Interface Statistics Block.
ISB = struct.pack('<III', 0, 0, 0)
#: Fixed fields of a Decryption Secrets Block of an unknown type, ``n`` octets.
DSB = lambda n: struct.pack('<II', 0x12345678, n)  # noqa: E731

#: Blocks whose padding rebuilt as zeros, or whose trailing octets were dropped.
BLOCKS = {
    'SPB packet data padding': _block(3, struct.pack('<I', 1) + b'a' + b'\xee' * 3),
    'EPB packet data padding': _block(6, EPB(1) + b'a' + b'\xee' * 3),
    'PB packet data padding': _block(2, PB + b'a' + b'\xee' * 3),
    'DSB secrets padding': _block(10, DSB(3) + b'abc\xee'),
    'IDB reserved octets': _block(1, IDB(0xAABB)),
    'SHB opt_comment padding': _block(0x0A0D0D0A, SHB + _option(1, b'x', b'\xee' * 3) + END),
    'SHB shb_hardware padding': _block(0x0A0D0D0A, SHB + _option(2, b'xy', b'\xee' * 2) + END),
    'SHB unknown option padding': _block(0x0A0D0D0A, SHB + _option(0x7777, b'x', b'\xee' * 3) + END),
    'SHB opt_custom padding': _block(0x0A0D0D0A, SHB + _option(2988, b'\x00\x00\x00\x01x', b'\xee' * 3) + END),
    'IDB if_name padding': _block(1, IDB(0) + _option(2, b'x', b'\xee' * 3) + END),
    'EPB opt_comment padding': _block(6, EPB(4) + b'abcd' + _option(1, b'x', b'\xee' * 3) + END),
    'ISB opt_comment padding': _block(5, ISB + _option(1, b'x', b'\xee' * 3) + END),
    'NRB opt_comment padding': _block(4, END + _option(1, b'x', b'\xee' * 3) + END),
    'NRB IPv4 record padding': _block(4, _option(1, b'\x0a\x00\x00\x01a\x00', b'\xee' * 2) + END),
    'SHB octets after opt_endofopt': _block(0x0A0D0D0A, SHB + END + b'\xdd' * 4),
    'IDB octets after opt_endofopt': _block(1, IDB(0) + END + bytes(4)),
    'EPB octets after opt_endofopt': _block(6, EPB(4) + b'abcd' + _option(1, b'xyzw', b'') + END + b'\xdd' * 4),
    'PB octets after opt_endofopt': _block(2, PB + b'a' + bytes(3) + END + b'\xdd' * 4),
    'ISB octets after opt_endofopt': _block(5, ISB + END + b'\xdd' * 4),
    'NRB octets after opt_endofopt': _block(4, END + _option(1, b'x', bytes(3)) + END + b'\xdd' * 4),
    'DSB octets after opt_endofopt': _block(10, DSB(4) + b'abcd' + END + b'\xdd' * 4),
}


class TestPCAPNGPaddingKept(PCAPNGTestCase):
    """Pin that PCAP-NG padding octets survive a parse and rebuild."""

    def test_blocks_rebuild_byte_for_byte(self) -> None:
        for name, octets in BLOCKS.items():
            with self.subTest(name), warnings.catch_warnings():
                warnings.simplefilter('ignore')
                self.assertRebuilds(octets)

    def test_padding_is_kept_on_the_data_model(self) -> None:
        """Each site's octets land under its key, exactly as captured."""
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            spb = self._parse(BLOCKS['SPB packet data padding']).info
            epb = self._parse(BLOCKS['EPB octets after opt_endofopt']).info
            idb = self._parse(BLOCKS['IDB reserved octets']).info
            shb = self._parse(BLOCKS['SHB opt_comment padding']).info
            nrb = self._parse(BLOCKS['NRB IPv4 record padding']).info
        self.assertEqual(spb.padding_data, b'\xee' * 3)
        self.assertEqual(epb.padding_opts, b'\xdd' * 4)
        self.assertEqual(idb.reserved, b'\xbb\xaa')
        self.assertEqual(shb.options[1].padding, b'\xee' * 3)
        self.assertEqual(next(iter(nrb.records.values())).padding, b'\xee' * 2)

    def test_zero_padding_is_not_recorded(self) -> None:
        """All-zero padding, and an area ending at ``opt_endofopt``, add no key."""
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')  # one octet of Ethernet is too short
            spb = self._parse(_block(3, struct.pack('<I', 1) + b'a' + bytes(3))).info
        self.assertNotIn('padding_data', spb)
        idb = self._parse(_block(1, IDB(0) + _option(2, b'x', bytes(3)) + END)).info
        self.assertNotIn('reserved', idb)
        self.assertNotIn('padding_opts', idb)
        self.assertNotIn('padding', idb.options[2])

    def test_fresh_builds_write_zeros(self) -> None:
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.protocols.misc.pcapng import PCAPNG

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')  # one octet of Ethernet is too short
            spb = PCAPNG(num=2, sct=1, ctx=self._context(), type=BlockType.Simple_Packet_Block,
                         block={'packet_data': b'a'})
        self.assertEqual(spb.data.hex(), '03000000140000000100000061000000' '14000000')

        def shb(comment: 'dict[str, object]') -> 'str':
            block = {'byteorder': 'little', 'options': [(OptionType.opt_comment, comment)]}
            return PCAPNG(num=0, sct=1, ctx=None, type=BlockType.Section_Header_Block,
                          block=block).data[24:32].hex()

        self.assertEqual(shb({'comment': 'x'}), '0100010078000000')
        # an option given as keyword arguments takes its padding as one
        self.assertEqual(shb({'comment': 'x', 'padding': b'\xee' * 3}), '0100010078eeeeee')


if __name__ == '__main__':
    import unittest
    unittest.main()
