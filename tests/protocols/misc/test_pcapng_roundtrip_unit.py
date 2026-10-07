# -*- coding: utf-8 -*-
"""PCAP-NG blocks build from keywords, and rebuild from their data model.

Five defects, each of which stopped a block from surviving
:meth:`~pcapkit.protocols.protocol.ProtocolBase.from_data`:

* #1267 -- :meth:`PCAPNG.__post_init__ <pcapkit.protocols.misc.pcapng.PCAPNG.__post_init__>`
  packs a constructed block and then parses it on the same instance, and the
  make pass's option count carried into the parse pass, so every option with
  an "only one" guard tripped it on itself.
* #1268 -- ``if_IPv6addr`` declared a length of 8 for its 17-octet value.
* #1269 -- ``isb_starttime`` / ``isb_endtime`` read an interface ID only the
  parse path set.
* #1270 -- an EPB, SPB or PB rebuilt from its data model lost its packet data.
* #1271 -- the TLS and WireGuard key-log writers ended lines with
  :data:`os.sep` and stamped the current time, and the data model kept neither
  the comments nor the order of the lines.

Every case builds its own octets in memory and reads no capture.

:mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, not at module load, so that a
module that purged it earlier does not leave these tests holding stale classes.

"""

import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

#: A little-endian Enhanced Packet Block on interface 0, timestamp 0, carrying
#: the four octets ``abcd`` -- the repro of #1270.
EPB = bytes.fromhex('06000000 24000000 00000000 00000000 00000000'
                    '04000000 04000000 61626364 24000000')
#: A Simple Packet Block carrying ``abcde``, so that it needs three pad octets.
SPB = bytes.fromhex('03000000 18000000 05000000 6162636465000000 18000000')
#: A Packet Block (obsolete) on interface 0 carrying ``abcd``.
PB = bytes.fromhex('02000000 24000000 0000 0000 00000000 00000000'
                   '04000000 04000000 61626364 24000000')
#: An Interface Statistics Block carrying ``isb_starttime`` -- the repro of
#: #1269.
ISB = bytes.fromhex('05000000 28000000 00000000 00000000 00000000'
                    '0200 0800 00000000 00000000 0000 0000 28000000')

#: A TLS key log whose labels interleave and which carries comments -- the
#: order and the comments are what #1271's data model used to drop. Padded to a
#: multiple of four octets, so that the Decryption Secrets Block needs no pad.
TLS_LOG = ('# a comment\n'
           'CLIENT_RANDOM 00 11\n'
           'SERVER_HANDSHAKE_TRAFFIC_SECRET 22 33\n'
           '# another\n'
           'CLIENT_RANDOM 44 55\n')
#: A WireGuard key log with a comment, likewise four-octet aligned.
WG_LOG = ('# wg ok\n'
          'LOCAL_STATIC_PRIVATE_KEY = AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\n')


def _dsb(code: 'int', text: 'str') -> 'bytes':
    """A little-endian Decryption Secrets Block carrying ``text``."""
    body = text.encode('ascii')
    assert len(body) % 4 == 0, len(body)
    length = 20 + len(body)
    return b''.join((
        (10).to_bytes(4, 'little'), length.to_bytes(4, 'little'),
        code.to_bytes(4, 'little'), len(body).to_bytes(4, 'little'),
        body, length.to_bytes(4, 'little'),
    ))


class TestPCAPNGRoundTrip(unittest.TestCase):
    """Pin that a PCAP-NG block survives being built and rebuilt."""

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

    def _rebuild(self, octets: 'bytes') -> 'bytes':
        """Parse ``octets`` as one block and rebuild it from its data model."""
        import warnings

        from pcapkit.protocols.misc.pcapng import PCAPNG

        context = self._context()
        with warnings.catch_warnings():
            # the Packet Block's maker warns that the block is obsolete
            warnings.simplefilter('ignore')
            parsed = PCAPNG(octets, len(octets), num=2, sct=1, ctx=context)
            return PCAPNG.from_data(parsed.info, num=2, sct=1, ctx=context).data

    def test_an_option_with_an_only_one_guard_builds(self) -> None:
        """#1267: the make pass's option count does not reach the parse pass."""
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.protocols.misc.pcapng import PCAPNG

        block = PCAPNG(num=2, sct=1, ctx=self._context(), type=BlockType.Interface_Description_Block,
                       block={'linktype': 1, 'snaplen': 65535,
                              'options': [(OptionType.if_name, {'name': 'eth0'})]})
        self.assertEqual(block.info.options[OptionType.if_name].name, 'eth0')
        self.assertEqual(self._rebuild(block.data), block.data)

    def test_a_repeated_only_one_option_is_still_rejected(self) -> None:
        """#1267: the guard itself still holds within one pass."""
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.protocols.misc.pcapng import PCAPNG
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaisesRegex(ProtocolError, r'\[if_name\] option must be only one, but 2 found'):
            PCAPNG(num=2, sct=1, ctx=self._context(), type=BlockType.Interface_Description_Block,
                   block={'linktype': 1, 'snaplen': 65535,
                          'options': [(OptionType.if_name, {'name': 'eth0'}),
                                      (OptionType.if_name, {'name': 'eth1'})]})

    def test_if_ipv6addr_is_seventeen_octets(self) -> None:
        """#1268: ``if_IPv6addr`` declares the 17 octets it carries."""
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.protocols.misc.pcapng import PCAPNG

        block = PCAPNG(num=2, sct=1, ctx=self._context(), type=BlockType.Interface_Description_Block,
                       block={'linktype': 1, 'snaplen': 65535,
                              'options': [(OptionType.if_IPv6addr, {'interface': '2001:db8::1/64'})]})
        # 20 octets of block (16 before the options), a 4-octet option header, 17 octets of value and
        # 3 of padding
        self.assertEqual(len(block.data), 44)
        self.assertEqual(block.data[16:20], bytes.fromhex('0500 1100'))
        self.assertEqual(str(block.info.options[OptionType.if_IPv6addr].interface), '2001:db8::1/64')

    def test_isb_starttime_rebuilds(self) -> None:
        """#1269: the ISB time options build from the block's own interface ID."""
        self.assertEqual(self._rebuild(ISB), ISB)

    def test_packet_blocks_keep_their_packet_data(self) -> None:
        """#1270: the packet octets survive ``from_data``."""
        for name, octets in (('EPB', EPB), ('SPB', SPB), ('PB', PB)):
            with self.subTest(block=name):
                self.assertEqual(self._rebuild(octets), octets)

    def test_an_empty_epb_rebuilds_without_growing(self) -> None:
        """#1270: a ``captured_len`` of zero rebuilds as zero packet octets.

        The parsed ``packet`` of such a block can hold the trailing Block Total
        Length (#1275), and writing that back would make the block 36 octets.

        """
        import struct

        for original_len in (0, 60):
            with self.subTest(original_len=original_len):
                body = struct.pack('<IIIII', 0, 0, 0, 0, original_len)
                octets = struct.pack('<II', 6, 32) + body + struct.pack('<I', 32)
                self.assertEqual(self._rebuild(octets), octets)

    def test_key_logs_rebuild_with_comments_and_order(self) -> None:
        """#1271: a parsed key log is written back as it was read."""
        from pcapkit.const.pcapng.secrets_type import SecretsType

        for name, code, text in (('TLS', SecretsType.TLS_Key_Log, TLS_LOG),
                                 ('WireGuard', SecretsType.WireGuard_Key_Log, WG_LOG)):
            with self.subTest(secrets=name):
                octets = _dsb(code, text)
                self.assertEqual(self._rebuild(octets), octets)

    def test_key_log_writers_end_lines_with_newlines(self) -> None:
        """#1271: entries built from keywords parse back, with no wall-clock time."""
        from pcapkit.const.pcapng.secrets_type import SecretsType
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.misc.pcapng import PCAPNG, TLSKeyLabel, WireGuardKeyLabel
        from pcapkit.protocols.schema.misc.pcapng import TLSKeyLog, WireGuardKeyLog

        proto = PCAPNG.__new__(PCAPNG)
        tls = proto._make_secrets_tls(SecretsType.TLS_Key_Log, entries={
            TLSKeyLabel.CLIENT_RANDOM: OrderedMultiDict([(b'\x00\x11', b'\x22\x33')])})
        self.assertTrue(tls.data.endswith('\nCLIENT_RANDOM 0011 2233\n'), tls.data)
        self.assertNotRegex(tls.data, r'\d{4}-\d\d-\d\dT')
        parsed_tls = TLSKeyLog.unpack(tls.pack(), packet={'__length__': len(tls.pack())})
        self.assertEqual(list(parsed_tls.entries[TLSKeyLabel.CLIENT_RANDOM].items(multi=True)),
                         [(b'\x00\x11', b'\x22\x33')])

        key = bytes(range(32))
        wg = proto._make_secrets_wireguard(SecretsType.WireGuard_Key_Log, entries=OrderedMultiDict(
            [(WireGuardKeyLabel.LOCAL_STATIC_PRIVATE_KEY, key)]))
        self.assertTrue(wg.data.endswith('\n'), wg.data)
        self.assertNotRegex(wg.data, r'\d{4}-\d\d-\d\dT')
        parsed_wg = WireGuardKeyLog.unpack(wg.pack(), packet={'__length__': len(wg.pack())})
        self.assertEqual(list(parsed_wg.entries.items(multi=True)),
                         [(WireGuardKeyLabel.LOCAL_STATIC_PRIVATE_KEY, key)])


if __name__ == '__main__':
    unittest.main()
