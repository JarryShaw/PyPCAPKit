# -*- coding: utf-8 -*-
"""The capture-header and PCAP-NG option-guard messages take the house form. C.f. #2300, #2301.

Every other message in these modules reads ``PCAP: …`` or ``PCAP-NG: …``, the
house ``<prefix>: <lowercase description>: … {value!r}`` form with no closing
full stop (#2232, #2257). These guards did not.

#2300 -- the guards that reject a file's magic number or byte order carried no
prefix at all: :func:`~pcapkit.protocols.schema.misc.pcap.header.magic_number_callback`
raised ``invalid magic number``, naming neither the module nor the four octets
it had just read; :meth:`Header._make_magic
<pcapkit.protocols.misc.pcap.header.Header._make_magic>` raised ``unresolved
byte order`` and ``unknown byte order: 'middle'``; and PCAP-NG's
:func:`~pcapkit.protocols.schema.misc.pcapng.shb_byteorder_callback` and
:meth:`SectionHeaderBlock.post_process
<pcapkit.protocols.schema.misc.pcapng.SectionHeaderBlock.post_process>` raised
``unknown byteorder magic: 0x11223344``, spelling the specification's
"Byte-Order Magic" as one word.

#2301 -- the PCAP-NG option guards closed with a full stop, and the placement
guard formatted :attr:`PCAPNG._type <pcapkit.protocols.misc.pcapng.PCAPNG._type>`
with a bare ``{}``. That attribute is an :class:`~enum.IntEnum`, which a bare
``{}`` renders as its value, so the message named the block type as a number:
``must be in Interface Description Block, but found in 6 block.`` rather than
``not Enhanced_Packet_Block``.

The placement guard is reached on both passes, and ``_type`` is not the same
kind of object on each: the parse pass assigns the
:class:`~pcapkit.const.pcapng.block_type.BlockType` off the schema, while the
make pass assigns what :meth:`~pcapkit.protocols.protocol.Protocol._make_index`
returns, a plain :obj:`int` that is only :func:`~typing.cast` to the
enumeration. Reading ``.name`` off it directly therefore raises
:exc:`AttributeError` on the make pass, which is what
:func:`~pcapkit.protocols.misc.pcapng._block_type_name` exists to avoid; the
make-pass cases below are what pin that.

Every case builds its own octets in memory and reads no capture. Classes are
imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, so they match the live
:mod:`pcapkit` import.

"""

import io
import struct
import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any


class TestPCAPHeaderMessages(unittest.TestCase):
    """#2300: PCAP's magic-number and byte-order guards."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_magic_number_is_prefixed_and_names_the_octets(self) -> None:
        """The magic-number guard says which module rejected what."""
        from pcapkit.protocols.misc.pcap.header import Header
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaises(ProtocolError) as ctx:
            Header(io.BytesIO(b'\x00' * 24))
        self.assertEqual(str(ctx.exception),
                         "PCAP: invalid magic number: b'\\x00\\x00\\x00\\x00'")

    def test_magic_number_names_the_octets_it_read(self) -> None:
        """The rejected octets are the ones read, not a fixed string."""
        from pcapkit.protocols.misc.pcap.header import Header
        from pcapkit.utilities.exceptions import ProtocolError

        octets = b'\xde\xad\xbe\xef' + b'\x00' * 20
        with self.assertRaises(ProtocolError) as ctx:
            Header(io.BytesIO(octets))
        self.assertEqual(str(ctx.exception),
                         "PCAP: invalid magic number: b'\\xde\\xad\\xbe\\xef'")

    def test_unresolved_byte_order_is_prefixed(self) -> None:
        """Contradictory ``lilendian`` and ``bigendian`` flags name the module."""
        from pcapkit.protocols.misc.pcap.header import Header
        from pcapkit.utilities.exceptions import EndianError

        with self.assertRaises(EndianError) as ctx:
            Header.__new__(Header)._make_magic(lilendian=True, bigendian=True)
        self.assertEqual(str(ctx.exception), 'PCAP: unresolved byte order')

    def test_unknown_byte_order_is_prefixed(self) -> None:
        """An unrecognised ``byteorder`` names the module and the value."""
        from pcapkit.protocols.misc.pcap.header import Header
        from pcapkit.utilities.exceptions import EndianError

        with self.assertRaises(EndianError) as ctx:
            Header.__new__(Header)._make_magic(byteorder='middle')  # type: ignore[arg-type]
        self.assertEqual(str(ctx.exception), "PCAP: unknown byte order: 'middle'")


class TestPCAPNGByteOrderMessages(unittest.TestCase):
    """#2300: PCAP-NG's Byte-Order Magic guards."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_callback_is_prefixed_and_hyphenates_byte_order(self) -> None:
        """``shb_byteorder_callback`` takes the house prefix."""
        from pcapkit.protocols.schema.misc.pcapng import shb_byteorder_callback
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaises(ProtocolError) as ctx:
            shb_byteorder_callback(None, {'match': {'byteorder': 0x11223344}})
        self.assertEqual(str(ctx.exception),
                         'PCAP-NG: unknown byte-order magic: 0x11223344')

    def test_post_process_is_prefixed_and_hyphenates_byte_order(self) -> None:
        """The same guard on :meth:`SectionHeaderBlock.post_process` matches it.

        A Section Header Block of 16 octets has no room for the Byte-Order
        Magic, so its slot holds the trailing Block Total Length -- 16 here,
        which is a byte order in neither direction (#1422).

        """
        from pcapkit.protocols.misc.pcapng import PCAPNG
        from pcapkit.utilities.exceptions import ProtocolError

        octets = struct.pack('<II', 0x0A0D0D0A, 16) + struct.pack('<I', 12) + struct.pack('<I', 16)
        with self.assertRaises(ProtocolError) as ctx:
            PCAPNG(octets, len(octets), num=0, sct=1, ctx=None)
        self.assertEqual(str(ctx.exception),
                         'PCAP-NG: unknown byte-order magic: 0xc000000')


class TestPCAPNGOptionGuardMessages(unittest.TestCase):
    """#2301: the option placement and "only one" guards."""

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
        interface = PCAPNG(num=1, sct=1, ctx=context,
                           type=BlockType.Interface_Description_Block,
                           block={'linktype': LinkType.ETHERNET, 'snaplen': 0x40000})
        context.interfaces.append(interface.info)
        return context

    def test_placement_guard_names_the_block_type(self) -> None:
        """The block type is named, not numbered, and the message has no full stop.

        This runs through :meth:`PCAPNG.make`, where ``_type`` is a plain
        :obj:`int`, so it is also what pins the guard against the
        :exc:`AttributeError` a direct ``.name`` would raise there.

        """
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.protocols.misc.pcapng import PCAPNG
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaises(ProtocolError) as ctx:
            PCAPNG(num=2, sct=1, ctx=self._context(),
                   type=BlockType.Interface_Statistics_Block,
                   block={'interface_id': 0, 'timestamp': 0,
                          'options': [(OptionType.if_name, {'name': 'eth0'})]})
        self.assertEqual(str(ctx.exception),
                         'PCAP-NG: [if_name] option must be in Interface Description '
                         'Block, not Interface_Statistics_Block')

    def test_placement_guard_does_not_raise_attribute_error(self) -> None:
        """The make pass's plain-``int`` ``_type`` reaches the guard, not an AttributeError."""
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.protocols.misc.pcapng import PCAPNG
        from pcapkit.utilities.exceptions import ProtocolError

        seen = {}  # type: dict[str, Any]
        original = PCAPNG._make_option_if_name

        def spy(inner_self: 'Any', *args: 'Any', **kwargs: 'Any') -> 'Any':
            seen['class'] = inner_self._type.__class__.__name__
            return original(inner_self, *args, **kwargs)

        PCAPNG._make_option_if_name = spy  # type: ignore[method-assign]
        try:
            with self.assertRaises(ProtocolError):
                PCAPNG(num=2, sct=1, ctx=self._context(),
                       type=BlockType.Interface_Statistics_Block,
                       block={'interface_id': 0, 'timestamp': 0,
                              'options': [(OptionType.if_name, {'name': 'eth0'})]})
        finally:
            PCAPNG._make_option_if_name = original  # type: ignore[method-assign]

        # The guard ran with a plain ``int``, which has no ``.name``.
        self.assertEqual(seen['class'], 'int')

    def test_block_type_name_takes_both_an_enum_and_a_plain_int(self) -> None:
        """The helper covers both passes' idea of ``_type``.

        The parse pass assigns the enumeration member off the schema and the
        make pass a plain :obj:`int`, and the guard is shared, so the helper
        has to name either. Reaching a placement guard through a *parse* is
        not possible -- an option code is resolved in the namespace of the
        block being parsed, so code 2 in an Interface Statistics Block is
        ``isb_starttime`` and never ``if_name`` -- which is why this is
        checked on the helper rather than through a capture.

        """
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.protocols.misc.pcapng import _block_type_name

        self.assertEqual(_block_type_name(BlockType.Enhanced_Packet_Block),
                         'Enhanced_Packet_Block')
        self.assertEqual(_block_type_name(6), 'Enhanced_Packet_Block')  # type: ignore[arg-type]
        self.assertEqual(_block_type_name(BlockType.Interface_Description_Block),
                         'Interface_Description_Block')
        self.assertEqual(_block_type_name(1), 'Interface_Description_Block')  # type: ignore[arg-type]

    def test_only_one_guard_has_no_full_stop(self) -> None:
        """A repeated "only one" option reports the count in the house form."""
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.protocols.misc.pcapng import PCAPNG
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaises(ProtocolError) as ctx:
            PCAPNG(num=2, sct=1, ctx=self._context(),
                   type=BlockType.Interface_Description_Block,
                   block={'linktype': 1, 'snaplen': 65535,
                          'options': [(OptionType.if_name, {'name': 'eth0'}),
                                      (OptionType.if_name, {'name': 'eth1'})]})
        self.assertEqual(str(ctx.exception),
                         'PCAP-NG: [if_name] option must be only one, not 2')

    def test_if_tsresol_guard_has_no_full_stop(self) -> None:
        """The ``if_tsresol`` resolution guard takes the same ``not …`` form."""
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.protocols.misc.pcapng import PCAPNG
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaises(ProtocolError) as ctx:
            PCAPNG(num=2, sct=1, ctx=self._context(),
                   type=BlockType.Interface_Description_Block,
                   block={'linktype': 1, 'snaplen': 65535,
                          'options': [(OptionType.if_tsresol, {'resolution': 3})]})
        self.assertEqual(str(ctx.exception),
                         'PCAP-NG: [if_tsresol] option resolution must be power '
                         'of 10 or 2, not 3')

    def test_if_tzone_guard_has_no_full_stop(self) -> None:
        """The ``if_tzone`` timezone guard takes the same ``not …`` form."""
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.protocols.misc.pcapng import PCAPNG
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaises(ProtocolError) as ctx:
            PCAPNG(num=2, sct=1, ctx=self._context(),
                   type=BlockType.Interface_Description_Block,
                   block={'linktype': 1, 'snaplen': 65535,
                          'options': [(OptionType.if_tzone, {'tzone': 'UTC'})]})
        self.assertEqual(str(ctx.exception),
                         'PCAP-NG: [if_tzone] option timezone must be int, '
                         'timedelta or timezone, not str')

    def test_no_option_guard_message_ends_in_a_full_stop(self) -> None:
        """#2301: the whole module is free of the full-stop form, not just the guards hit above."""
        import re

        from pcapkit.protocols.misc import pcapng

        with open(pcapng.__file__, encoding='utf-8') as file:
            source = file.read()

        # A message fragment on its own line, closing the call and ending in a
        # full stop -- the shape every guard in #2301 had.
        offenders = re.findall(r"^\s+f?'[^']*\.'\)", source, re.MULTILINE)
        self.assertEqual(offenders, [])

    def test_no_guard_formats_the_block_type_with_a_bare_brace(self) -> None:
        """#2301: ``{self._type}`` in a message would render the block type as a number."""
        from pcapkit.protocols.misc import pcapng

        with open(pcapng.__file__, encoding='utf-8') as file:
            source = file.read()

        self.assertNotIn('but found in {self._type} block', source)


if __name__ == '__main__':
    unittest.main()
