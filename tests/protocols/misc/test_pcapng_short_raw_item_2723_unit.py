# -*- coding: utf-8 -*-
"""A PCAP-NG option or record given as raw octets shorter than its code is refused.

GitHub issue #2723: ``_make_pcapng_options`` and ``_make_nrb_records`` read the
16-bit Option Code or Record Type of a raw item before they check that the
octets hold one. An empty item read as code 0, so ``[b'']`` was taken for an
``opt_endofopt`` or an ``nrb_record_end`` and written as one, rather than
refused; a single octet read as a code of its own. Octets shorter than the
field raise ``ProtocolError``, as the other malformed items in those
branches do, in a little-endian section and a big-endian one.

A raw item that holds its code builds as given: a whole ``if_name``
option sits at the start of an Interface Description Block's option area,
after the 8 octets of the block's Type and Total Length and the 8 of its
LinkType, Reserved and SnapLen fields, and a whole ``nrb_record_ipv4`` record
at the start of a Name Resolution Block's record area, after the 8 octets of
the block's Type and Total Length.

Every case builds its own octets in memory and reads no capture. :mod:`pcapkit`
is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""
# Deferring these is the design: each build runs after the per-class re-import.
# pylint: disable=import-outside-toplevel
from __future__ import annotations

import re
import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any, Literal

#: The section byte orders covered.
ORDERS = ('little', 'big')  # type: tuple[Literal['little', 'big'], ...]
#: Raw octets too short to hold a 16-bit code.
SHORT = (b'', b'\x00', b'\x01')


def _raw(code: 'int', value: 'bytes', order: 'Literal["little", "big"]') -> 'bytes':
    """A whole option or record of ``code`` carrying ``value``, padded to 32 bits."""
    return (int(code).to_bytes(2, order) + len(value).to_bytes(2, order)
            + value + bytes(-len(value) % 4))


class TestPCAPNGShortRawItem(unittest.TestCase):
    """Raw octets short of the code raise ``ProtocolError``; a whole item builds."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _block(self, order: 'Literal["little", "big"]', name: 'str', block: 'dict[str, Any]') -> 'bytes':
        """The octets of the block named ``name``, built from ``block`` in a section of ``order``."""
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.foundation.engines.pcapng import Context
        from pcapkit.protocols.misc.pcapng import PCAPNG

        section = PCAPNG(num=0, sct=1, ctx=None, type=BlockType.Section_Header_Block,
                         block={'byteorder': order})
        context = Context(section.info)  # type: Any
        interface = PCAPNG(num=1, sct=1, ctx=context, type=BlockType.Interface_Description_Block,
                           block={'linktype': LinkType.ETHERNET, 'snaplen': 0x40000})
        context.interfaces.append(interface.info)
        return PCAPNG(num=2, sct=1, ctx=context, type=BlockType[name], block=block).data

    def test_short_option_is_refused(self) -> None:
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.utilities.exceptions import ProtocolError

        for order in ORDERS:
            whole = _raw(OptionType.if_name, b'eth0', order)
            for short in SHORT:
                message = re.escape(f'invalid option: {short!r} holds no whole option code')
                for options in ([short], [whole, short]):
                    with self.subTest(order=order, options=options):
                        with self.assertRaisesRegex(ProtocolError, message):
                            self._block(order, 'Interface_Description_Block',
                                        {'linktype': 1, 'snaplen': 0xFFFF, 'options': options})

    def test_short_record_is_refused(self) -> None:
        from pcapkit.const.pcapng.record_type import RecordType
        from pcapkit.utilities.exceptions import ProtocolError

        for order in ORDERS:
            whole = _raw(RecordType.nrb_record_ipv4, bytes([192, 0, 2, 1]) + b'host\x00', order)
            for short in SHORT:
                message = re.escape(f'invalid record: {short!r} holds no whole record type')
                for records in ([short], [whole, short]):
                    with self.subTest(order=order, records=records):
                        with self.assertRaisesRegex(ProtocolError, message):
                            self._block(order, 'Name_Resolution_Block', {'records': records})

    def test_whole_items_build_as_given(self) -> None:
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.const.pcapng.record_type import RecordType

        for order in ORDERS:
            with self.subTest(order=order):
                option = _raw(OptionType.if_name, b'eth0', order)
                built = self._block(order, 'Interface_Description_Block',
                                    {'linktype': 1, 'snaplen': 0xFFFF, 'options': [option]})
                self.assertEqual(int.from_bytes(built[4:8], order), len(built))
                self.assertEqual(built[16:16 + len(option)], option)

                record = _raw(RecordType.nrb_record_ipv4, bytes([192, 0, 2, 1]) + b'host\x00', order)
                built = self._block(order, 'Name_Resolution_Block', {'records': [record]})
                self.assertEqual(int.from_bytes(built[4:8], order), len(built))
                self.assertEqual(built[8:8 + len(record)], record)


if __name__ == '__main__':
    unittest.main()
