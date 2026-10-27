# -*- coding: utf-8 -*-
"""A PCAP-NG block handed over as raw bytes parses and rebuilds.

This guards against GitHub issue #2354. ``block`` is typed to accept
:obj:`bytes`, and the header schema writes such a block back verbatim past the
Block Type -- but the schema the maker returned then held octets where the
reader expected fields, so a Decryption Secrets Block built that way raised
``AttributeError: 'bytes' object has no attribute 'length'``, and so did every
other block type that got as far as the reader.

The octets are parsed off the buffer the construction path has just packed, the
way the short-block path parses the body it kept: the block that comes back is
the one the octets describe, and it rebuilds byte for byte. Octets that are no
block at all are refused with the library's own errors rather than an
:exc:`AttributeError`.

A Section Header Block handed raw octets with no section context is the one
case left out, and it is not pinned here: it never reaches the reader, raising
``AttributeError: 'PCAPNG' object has no attribute '_byte'`` out of the packer
instead, since the byte order a section header carries is the one its own maker
chose and no maker runs for raw octets. That is tracked separately.

Every case builds its own octets in memory and reads no capture. :mod:`pcapkit`
is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import unittest
import warnings
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): a hand-picked round trip, one case per block type.
__tier__ = 'ALL'

#: A TLS key log, four-octet aligned so the Decryption Secrets Block needs no
#: padding.
TLS_LOG = b'CLIENT_RANDOM 00 11\n'
#: ``TLSK``, the Secrets Type of a TLS key log, as the field carries it.
TLS_KEY_LOG = 0x544C534B

#: Keywords that build one block for each of the types below, for the round trip
#: that follows. A Section Header Block is not among them, for the reason the
#: module docstring gives. A Packet Block and an Enhanced Packet Block both need
#: a timestamp, their makers reading the parsed data model for a resolution
#: without one.
CASES = {
    'IDB': ('Interface_Description_Block', {'linktype': 1, 'snaplen': 0xFFFF}),
    'EPB': ('Enhanced_Packet_Block', {'packet_data': b'abcd', 'timestamp': 0}),
    'PB': ('Packet_Block', {'packet_data': b'abcd', 'timestamp': 0}),
    'SPB': ('Simple_Packet_Block', {'packet_data': b'abcde'}),
    'ISB': ('Interface_Statistics_Block', {'interface_id': 0, 'timestamp': 0}),
    'systemd': ('systemd_Journal_Export_Block', {'entries': b'MESSAGE=hi\n'}),
    'CB': ('Custom_Block_that_rewriters_can_copy_into_new_files',
           {'pen': 1, 'data': b'abcd'}),
    'unknown': ('Reserved_0x00000000', {'data': b'abcd'}),
}


def _dsb_body(secrets: 'bytes') -> 'bytes':
    """A little-endian Decryption Secrets Block past its Block Type."""
    assert len(secrets) % 4 == 0, len(secrets)
    length = 20 + len(secrets)
    return b''.join((
        length.to_bytes(4, 'little'),
        TLS_KEY_LOG.to_bytes(4, 'little'),
        len(secrets).to_bytes(4, 'little'),
        secrets,
        length.to_bytes(4, 'little'),
    ))


class TestPCAPNGRawBlockBytes(unittest.TestCase):
    """Pin that ``make(block=<bytes>)`` builds a block rather than raising."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _context(self) -> 'Any':
        """A one-section context with one Ethernet interface, as the engine builds it."""
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.foundation.engines.pcapng import Context
        from pcapkit.protocols.misc.pcapng import PCAPNG

        section = PCAPNG(num=0, sct=1, ctx=None, type=BlockType.Section_Header_Block, block={})
        context = Context(section.info)  # type: Any
        interface = PCAPNG(num=1, sct=1, ctx=context, type=BlockType.Interface_Description_Block,
                           block={'linktype': LinkType.ETHERNET, 'snaplen': 0x40000})
        context.interfaces.append(interface.info)
        return context

    def test_a_dsb_handed_its_octets_parses_them(self) -> None:
        """#2354: the issue's own case, a DSB built from raw bytes."""
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.pcapng.secrets_type import SecretsType
        from pcapkit.const.pcapng.tls_key_label import TLSKeyLabel
        from pcapkit.protocols.misc.pcapng import PCAPNG

        body = _dsb_body(TLS_LOG)
        block = PCAPNG(num=2, sct=1, ctx=self._context(),
                       type=BlockType.Decryption_Secrets_Block, block=body)

        self.assertEqual(block.info.secrets_type, SecretsType.TLS_Key_Log)
        self.assertEqual(block.info.secrets_length, len(TLS_LOG))
        self.assertEqual(block.info.secrets_data.data, TLS_LOG.decode())
        self.assertIn(TLSKeyLabel.CLIENT_RANDOM, block.info.secrets_data.entries)
        # The octets are written back exactly as handed over, after the type.
        self.assertEqual(block.data,
                         int(BlockType.Decryption_Secrets_Block).to_bytes(4, 'little') + body)

    def test_every_block_type_handed_its_octets_round_trips(self) -> None:
        """#2354: raw octets parse as the block they describe, and rebuild byte for byte."""
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.protocols.misc.pcapng import PCAPNG

        for label, (name, keywords) in CASES.items():
            with self.subTest(block=label):
                type_ = getattr(BlockType, name)
                context = self._context()
                with warnings.catch_warnings():
                    # a Packet Block warns that the block is obsolete
                    warnings.simplefilter('ignore')
                    built = PCAPNG(num=2, sct=1, ctx=context, type=type_, block=keywords)
                    again = PCAPNG(num=2, sct=1, ctx=context, type=type_, block=built.data[4:])

                self.assertEqual(again.data, built.data)
                self.assertEqual(str(again.info), str(built.info))

    def test_octets_that_are_no_block_are_refused(self) -> None:
        """#2354: a short or impossible block raises the library's own error."""
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.protocols.misc.pcapng import PCAPNG
        from pcapkit.utilities.exceptions import ProtocolError, StreamEOFError

        context = self._context()
        # Shorter than the twelve octets a block takes, the Block Type counted.
        for body in (b'', b'raw', b'\x00' * 7):
            with self.subTest(body=body):
                with self.assertRaisesRegex(StreamEOFError, r'fewer than the 12 a block needs'):
                    PCAPNG(num=2, sct=1, ctx=context,
                           type=BlockType.Decryption_Secrets_Block, block=body)

        # Long enough, but declaring a Block Total Length of zero.
        for body in (b'\x00' * 8, b'\x00' * 12):
            with self.subTest(body=body):
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    with self.assertRaisesRegex(ProtocolError, r'invalid length: 0'):
                        PCAPNG(num=2, sct=1, ctx=context,
                               type=BlockType.Decryption_Secrets_Block, block=body)


if __name__ == '__main__':
    unittest.main()
