# -*- coding: utf-8 -*-
"""A raw option or record in a PCAP-NG block builds in the right byte order.

This guards against GitHub issue #2353. An option handed to a block maker as raw
:obj:`bytes` has its Option Code read back out of those octets, and a name
resolution record handed over the same way has its Record Type read the same
way. Both read it in the block's byte order. Without the fix, only the section
header block's maker and the :manpage:`systemd(1)` journal block's maker settle
that order, so every other block -- an Interface Description Block and a Name
Resolution Block among them -- raises ``AttributeError: 'PCAPNG' object has no
attribute '_byte'`` instead of building.

The byte order resolved has to be the one the block is written in, not merely
some byte order: read in the wrong one, a code is misread, which silently loses
the "only one of this option" guard and attributes the option to a type that is
not there. So the cases below pin the code actually resolved, in a big-endian
section as well as a little-endian one, and parse each built block back from its
octets rather than trusting the schema the maker returned.

The order is resolved through a chain: a bound section's own byte order wins,
then the one the packet data declares -- at either nesting level -- and the host
byte order is the fallback. The cases below pin each link of it, and pin that
packet data handed over as :data:`None` resolves to the fallback rather than
raising.

Every case builds its own octets in memory and reads no capture. :mod:`pcapkit`
is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any, Literal

#: Test tier (#1958): a hand-picked round trip, over the host byte order and
#: both section byte orders.
__tier__ = 'ALL'


def _raw(code: 'int', value: 'bytes', order: 'Literal["little", "big"]') -> 'bytes':
    """A whole option or record of ``code`` carrying ``value``, padded to 32 bits."""
    return (int(code).to_bytes(2, order) + len(value).to_bytes(2, order)
            + value + bytes(-len(value) % 4))


#: An ``if_name`` option value, and the name it decodes to.
IF_NAME = b'eth0'
#: A ``nrb_record_ipv4`` record value: the loopback address, then a
#: zero-terminated name.
NRB_RECORD = bytes([127, 0, 0, 1]) + b'host\x00'


class TestPCAPNGRawOptionByteOrder(unittest.TestCase):
    """Pin that a raw option or record area resolves the block's byte order."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _context(self, order: 'Literal["little", "big"]') -> 'Any':
        """A one-section context of ``order``, with one Ethernet interface."""
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.foundation.engines.pcapng import Context
        from pcapkit.protocols.misc.pcapng import PCAPNG

        section = PCAPNG(num=0, sct=1, ctx=None, type=BlockType.Section_Header_Block,
                         block={'byteorder': order})
        self.assertEqual(section.info.byteorder, order)

        context = Context(section.info)  # type: Any
        interface = PCAPNG(num=1, sct=1, ctx=context, type=BlockType.Interface_Description_Block,
                           block={'linktype': LinkType.ETHERNET, 'snaplen': 0x40000})
        context.interfaces.append(interface.info)
        return context

    def _reparse(self, octets: 'bytes', context: 'Any') -> 'Any':
        """Parse ``octets`` as one block, as a reader of the file would."""
        from pcapkit.protocols.misc.pcapng import PCAPNG

        return PCAPNG(octets, len(octets), num=2, sct=1, ctx=context)

    def test_a_raw_option_builds_with_no_byte_order_set(self) -> None:
        """#2353: an IDB takes a raw option without an earlier call setting one."""
        import sys

        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.protocols.misc.pcapng import PCAPNG

        option = _raw(OptionType.if_name, IF_NAME, sys.byteorder)
        block = PCAPNG(num=2, sct=1, ctx=None, type=BlockType.Interface_Description_Block,
                       block={'linktype': 1, 'snaplen': 0xFFFF, 'options': [option]})
        self.assertEqual(block.info.options_raw, option)

        parsed = self._reparse(block.data, None)
        self.assertEqual(parsed.info.options[OptionType.if_name].name, IF_NAME.decode())
        self.assertEqual(PCAPNG.from_data(parsed.info, num=2, sct=1, ctx=None).data, block.data)

    def test_a_raw_record_builds_with_no_byte_order_set(self) -> None:
        """#2353: an NRB takes a raw record without an earlier call setting one."""
        import ipaddress
        import sys

        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.pcapng.record_type import RecordType
        from pcapkit.protocols.misc.pcapng import PCAPNG

        record = _raw(RecordType.nrb_record_ipv4, NRB_RECORD, sys.byteorder)
        block = PCAPNG(num=2, sct=1, ctx=None, type=BlockType.Name_Resolution_Block,
                       block={'records': [record]})
        self.assertEqual(block.info.records_raw, record)

        parsed = self._reparse(block.data, None)
        self.assertEqual(parsed.info.mapping[ipaddress.ip_address('127.0.0.1')], 'host')
        self.assertEqual(PCAPNG.from_data(parsed.info, num=2, sct=1, ctx=None).data, block.data)

    def test_a_raw_option_round_trips_in_either_section_byte_order(self) -> None:
        """#2353: the option area is written, and reads back, in the section's order."""
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.protocols.misc.pcapng import PCAPNG

        for order in ('little', 'big'):  # type: Literal['little', 'big']
            with self.subTest(order=order):
                context = self._context(order)
                option = _raw(OptionType.if_name, IF_NAME, order)
                block = PCAPNG(num=2, sct=1, ctx=context,
                               type=BlockType.Interface_Description_Block,
                               block={'linktype': 1, 'snaplen': 0xFFFF, 'options': [option]})
                self.assertEqual(block.byteorder, order)
                # The Block Type is the block's first field, so the section's
                # byte order is visible in the octets emitted.
                self.assertEqual(block.data[:4],
                                 int(BlockType.Interface_Description_Block).to_bytes(4, order))
                self.assertIn(option, block.data)

                parsed = self._reparse(block.data, context)
                self.assertEqual(parsed.info.options[OptionType.if_name].name, IF_NAME.decode())
                self.assertEqual(
                    PCAPNG.from_data(parsed.info, num=2, sct=1, ctx=context).data, block.data)

    def test_a_raw_record_round_trips_in_either_section_byte_order(self) -> None:
        """#2353: the record area is written, and reads back, in the section's order."""
        import ipaddress

        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.pcapng.record_type import RecordType
        from pcapkit.protocols.misc.pcapng import PCAPNG

        for order in ('little', 'big'):  # type: Literal['little', 'big']
            with self.subTest(order=order):
                context = self._context(order)
                record = _raw(RecordType.nrb_record_ipv4, NRB_RECORD, order)
                block = PCAPNG(num=2, sct=1, ctx=context,
                               type=BlockType.Name_Resolution_Block,
                               block={'records': [record]})
                self.assertEqual(block.byteorder, order)
                self.assertIn(record, block.data)

                parsed = self._reparse(block.data, context)
                self.assertEqual(parsed.info.mapping[ipaddress.ip_address('127.0.0.1')], 'host')
                self.assertEqual(
                    PCAPNG.from_data(parsed.info, num=2, sct=1, ctx=context).data, block.data)

    def test_a_raw_option_code_is_read_in_the_section_byte_order(self) -> None:
        """#2353: the code read is the section's, so the "only one" guard still holds.

        A raw ``if_name`` followed by one built from keywords is two of an option
        there may only be one of. The guard counts the raw one by the code read
        out of its octets, so it only fires when that code was read in the byte
        order the section is written in -- the host's would read ``if_name`` as
        some other type on one of the two sections below.

        """
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.protocols.misc.pcapng import PCAPNG
        from pcapkit.utilities.exceptions import ProtocolError

        for order in ('little', 'big'):  # type: Literal['little', 'big']
            with self.subTest(order=order):
                context = self._context(order)
                with self.assertRaisesRegex(ProtocolError,
                                            r'\[if_name\] option must be only one, not 2'):
                    PCAPNG(num=2, sct=1, ctx=context,
                           type=BlockType.Interface_Description_Block,
                           block={'linktype': 1, 'snaplen': 0xFFFF,
                                  'options': [_raw(OptionType.if_name, IF_NAME, order),
                                              (OptionType.if_name, {'name': 'eth1'})]})

    def test_a_raw_option_code_is_read_in_the_packet_byte_order(self) -> None:
        """#2353: with no section, the byte order the packet data declares is used.

        :meth:`PCAPNG.pack <pcapkit.protocols.misc.pcapng.PCAPNG.pack>` writes
        the block in the order ``__packet__`` declares when there is no section
        to take one from, so that is the order the code has to be read in too.

        """
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.protocols.misc.pcapng import PCAPNG
        from pcapkit.utilities.exceptions import ProtocolError

        for order in ('little', 'big'):  # type: Literal['little', 'big']
            with self.subTest(order=order):
                with self.assertRaisesRegex(ProtocolError,
                                            r'\[if_name\] option must be only one, not 2'):
                    PCAPNG(num=2, sct=1, ctx=None,
                           type=BlockType.Interface_Description_Block,
                           block={'linktype': 1, 'snaplen': 0xFFFF,
                                  'options': [_raw(OptionType.if_name, IF_NAME, order),
                                              (OptionType.if_name, {'name': 'eth1'})]},
                           __packet__={'byteorder': order})

    def test_a_raw_option_code_is_read_in_the_host_byte_order(self) -> None:
        """#2353: with neither a section nor packet data, the host's order is used.

        :data:`sys.byteorder` is the last link of the chain, and it is the order
        the block is written in too, so a raw option written in it is the one
        whose code reads back as ``if_name`` and trips the "only one" guard. The
        other order is read as some other option type, so the guard stays quiet
        -- which is what pins *which* of the two the fallback is, on a
        little-endian host as well as a big-endian one.

        """
        import sys

        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.protocols.misc.pcapng import PCAPNG
        from pcapkit.utilities.exceptions import ProtocolError

        other = 'big' if sys.byteorder == 'little' else 'little'  # type: Literal['little', 'big']

        def build(order: 'Literal["little", "big"]') -> 'Any':
            return PCAPNG(num=2, sct=1, ctx=None,
                          type=BlockType.Interface_Description_Block,
                          block={'linktype': 1, 'snaplen': 0xFFFF,
                                 'options': [_raw(OptionType.if_name, IF_NAME, order),
                                             (OptionType.if_name, {'name': 'eth1'})]})

        with self.assertRaisesRegex(ProtocolError,
                                    r'\[if_name\] option must be only one, not 2'):
            build(sys.byteorder)

        block = build(other)
        self.assertEqual(block.byteorder, sys.byteorder)

    def test_a_bound_section_outranks_the_byte_order_the_packet_data_declares(self) -> None:
        """#2353: the section's own order wins over ``__packet__``'s.

        A block of a section is written in that section's byte order whatever
        ``__packet__`` says -- :meth:`PCAPNG.pack
        <pcapkit.protocols.misc.pcapng.PCAPNG.pack>` overwrites the key from it
        -- so the section's is the order a raw option's code has to be read in.

        """
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.protocols.misc.pcapng import PCAPNG
        from pcapkit.utilities.exceptions import ProtocolError

        for order in ('little', 'big'):  # type: Literal['little', 'big']
            other = 'big' if order == 'little' else 'little'  # type: Literal['little', 'big']
            with self.subTest(order=order, declared=other):
                block = PCAPNG(num=2, sct=1, ctx=self._context(order),
                               type=BlockType.Interface_Description_Block,
                               block={'linktype': 1, 'snaplen': 0xFFFF},
                               __packet__={'byteorder': other})
                self.assertEqual(block.byteorder, order)
                self.assertEqual(block.data[:4],
                                 int(BlockType.Interface_Description_Block).to_bytes(4, order))

                with self.assertRaisesRegex(ProtocolError,
                                            r'\[if_name\] option must be only one, not 2'):
                    PCAPNG(num=2, sct=1, ctx=self._context(order),
                           type=BlockType.Interface_Description_Block,
                           block={'linktype': 1, 'snaplen': 0xFFFF,
                                  'options': [_raw(OptionType.if_name, IF_NAME, order),
                                              (OptionType.if_name, {'name': 'eth1'})]},
                           __packet__={'byteorder': other})

    def test_a_nested_packet_byte_order_is_read_one_level_up(self) -> None:
        """#2353: a byte order nested under ``__packet__`` is the one resolved.

        :meth:`SchemaField.pack
        <pcapkit.corekit.fields.misc.SchemaField.pack>` hands a nested schema
        its parent's packet data under a ``__packet__`` key of its own, so
        :func:`~pcapkit.corekit.fields.byteorder.packet_byteorder` looks one
        level up when the outer level declares no order. A block made from such
        packet data is written in the nested order, so that is the order its raw
        options are read in.

        """
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.protocols.misc.pcapng import PCAPNG
        from pcapkit.utilities.exceptions import ProtocolError

        for order in ('little', 'big'):  # type: Literal['little', 'big']
            with self.subTest(order=order):
                block = PCAPNG(num=2, sct=1, ctx=None,
                               type=BlockType.Interface_Description_Block,
                               block={'linktype': 1, 'snaplen': 0xFFFF},
                               __packet__={'__packet__': {'byteorder': order}})
                self.assertEqual(block.byteorder, order)
                self.assertEqual(block.data[:4],
                                 int(BlockType.Interface_Description_Block).to_bytes(4, order))

                with self.assertRaisesRegex(ProtocolError,
                                            r'\[if_name\] option must be only one, not 2'):
                    PCAPNG(num=2, sct=1, ctx=None,
                           type=BlockType.Interface_Description_Block,
                           block={'linktype': 1, 'snaplen': 0xFFFF,
                                  'options': [_raw(OptionType.if_name, IF_NAME, order),
                                              (OptionType.if_name, {'name': 'eth1'})]},
                           __packet__={'__packet__': {'byteorder': order}})

    def test_packet_data_handed_over_as_none_resolves_the_host_byte_order(self) -> None:
        """A ``__packet__`` of :data:`None` means no packet data, not a type error.

        :meth:`Schema.pack <pcapkit.protocols.schema.schema.Schema.pack>` takes
        :data:`None` for "no packet data", so a caller passing the key through
        with that value reaches :meth:`PCAPNG.make
        <pcapkit.protocols.misc.pcapng.PCAPNG.make>` with it. Resolving the byte
        order out of it has to degrade to the host fallback; reading it as a
        mapping raises ``TypeError: argument of type 'NoneType' is not a
        container or iterable`` instead of building the block.

        """
        import sys

        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.protocols.misc.pcapng import PCAPNG

        option = _raw(OptionType.if_name, IF_NAME, sys.byteorder)
        block = PCAPNG(num=2, sct=1, ctx=None, type=BlockType.Interface_Description_Block,
                       block={'linktype': 1, 'snaplen': 0xFFFF, 'options': [option]},
                       __packet__=None)
        self.assertEqual(block.byteorder, sys.byteorder)
        self.assertEqual(block.info.options_raw, option)
        self.assertEqual(block.data[:4],
                         int(BlockType.Interface_Description_Block).to_bytes(4, sys.byteorder))

        # The same block, with the key omitted rather than handed over empty.
        omitted = PCAPNG(num=2, sct=1, ctx=None, type=BlockType.Interface_Description_Block,
                         block={'linktype': 1, 'snaplen': 0xFFFF, 'options': [option]})
        self.assertEqual(block.data, omitted.data)


if __name__ == '__main__':
    unittest.main()
