# -*- coding: utf-8 -*-
"""PCAP-NG Dumper
====================

.. module:: pcapkit.dumpkit.pcapng

:mod:`pcapkit.dumpkit.pcapng` holds the PCAP-NG file dumper, :class:`PCAPNGIO`.

"""
import sys
from typing import TYPE_CHECKING, cast

from pcapkit.const.pcapng.block_type import BlockType as Enum_BlockType
from pcapkit.const.pcapng.option_type import OptionType as Enum_OptionType
from pcapkit.const.reg.linktype import LinkType as Enum_LinkType
from pcapkit.corekit.const.capture import RESOLUTION
from pcapkit.corekit.multidict import OrderedMultiDict
from pcapkit.dumpkit.common import DumperBase
from pcapkit.protocols.misc.pcap.header.data import Header as Data_Header
from pcapkit.protocols.misc.pcapng.protocol import PCAPNG as P_PCAPNG
from pcapkit.utilities.exceptions import FormatError

if TYPE_CHECKING:
    from decimal import Decimal
    from enum import IntEnum as StdlibIntEnum
    from typing import IO, Any, Optional

    from aenum import IntEnum as AenumIntEnum
    from typing_extensions import Literal

    from pcapkit.foundation.engines.pcapng import Context
    from pcapkit.protocols.misc.pcap.frame.data import Frame as Data_Frame
    from pcapkit.protocols.misc.pcapng.data import \
        InterfaceDescriptionBlock as Data_InterfaceDescriptionBlock
    from pcapkit.protocols.misc.pcapng.data import SectionHeaderBlock as Data_SectionHeaderBlock
    from pcapkit.protocols.misc.pcapng.protocol import Packet as Data_Packet

__all__ = [
    'PCAPNGIO',
]


class PCAPNGIO(DumperBase):
    """PCAP-NG file dumper.

    It writes one Section Header Block, an Interface Description Block for
    each distinct interface, and an Enhanced Packet Block per frame.

    Args:
        fname: output file name
        protocol: data link type of a frame that names no interface
        byteorder: section byte order
        nanosecond: nanosecond-resolution flag of that frame's interface
        snaplen: snapshot length of that frame's interface, ``0`` for no limit
        **kwargs: arbitrary keyword arguments

    .. versionadded:: 1.7.0

    """
    if TYPE_CHECKING:
        #: Section context of the output, holding the interfaces written so far.
        _ctx: 'Context'

    #: Output file :meth:`open` keeps open, or :data:`None` while each call
    #: opens it.
    _handle = None  # type: Optional[IO[bytes]]

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def kind(self) -> 'Literal["pcapng"]':
        """File format of current dumper."""
        return 'pcapng'

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, fname: 'str', *,
                 protocol: 'Optional[Enum_LinkType | StdlibIntEnum | AenumIntEnum | str | int]' = None,
                 byteorder: 'Literal["big", "little"]' = sys.byteorder, nanosecond: 'bool' = False,
                 snaplen: 'int' = 0, **kwargs: 'Any') -> 'None':  # pylint: disable=arguments-differ
        """Initialise dumper.

        Args:
            fname: output file name
            protocol: data link type of a frame that names no interface
            byteorder: section byte order
            nanosecond: nanosecond-resolution flag of that frame's interface
            snaplen: snapshot length of that frame's interface, ``0`` for no
                limit
            **kwargs: arbitrary keyword arguments

        """
        #: Optional[Enum_LinkType | StdlibIntEnum | AenumIntEnum | str | int]: Data link type.
        self._link = protocol
        #: bool: Nanosecond-resolution flag.
        self._nsec = nanosecond
        #: int: Snapshot length.
        self._snap = snaplen
        #: dict[bytes, int]: Interface ID of each IDB written, by its octets.
        self._index = {}  # type: dict[bytes, int]
        #: dict[int, tuple[Optional[Data_InterfaceDescriptionBlock], int]]: Interface ID
        #: of each interface met, by :func:`id`, beside the interface it was taken of.
        self._seen = {}  # type: dict[int, tuple[Optional[Data_InterfaceDescriptionBlock], int]]
        #: Optional[P_PCAPNG]: First IDB written, whose :meth:`PCAPNG.pack
        #: <pcapkit.protocols.misc.pcapng.protocol.PCAPNG.pack>` makes each EPB.
        self._writer = None  # type: Optional[P_PCAPNG]

        super().__init__(fname, protocol=protocol, byteorder=byteorder, **kwargs)

    def __call__(self, value: 'P_PCAPNG | Data_Frame', name: 'Optional[str]' = None) -> 'PCAPNGIO':
        """Dump a new frame.

        Args:
            value: content to be dumped
            name: name of current content block

        Returns:
            The dumper itself (to support chain calling).

        Notes:
            While :meth:`open` keeps the file open, the frame is written there,
            then flushed, so the file on disk holds every frame written, as when
            each call closed it.

        """
        file = self._handle
        if file is None:
            with open(self._file, 'ab') as file:
                self._append_value(value, file, name or '')
            return self
        self._append_value(value, file, name or '')
        file.flush()
        return self

    ##########################################################################
    # Methods.
    ##########################################################################

    def open(self) -> 'None':
        """Keep the output file open for the calls that follow, until :meth:`close`."""
        if self._handle is None:
            self._handle = open(self._file, 'ab')  # pylint: disable=consider-using-with

    def close(self) -> 'None':
        """Close the file :meth:`open` kept open; later calls open it themselves."""
        file, self._handle = self._handle, None
        if file is not None:
            file.close()

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _dump_header(self, *, byteorder: 'Literal["big", "little"]' = sys.byteorder,  # pylint: disable=arguments-differ
                     **kwargs: 'Any') -> 'None':  # pylint: disable=unused-argument
        """Initially dump file heads and tails.

        Args:
            byteorder: section byte order
            **kwargs: arbitrary keyword arguments

        """
        # NOTE: imported here, as :mod:`pcapkit.foundation` imports this package.
        from pcapkit.foundation.engines.pcapng import \
            Context  # pylint: disable=import-outside-toplevel

        header = P_PCAPNG.build(num=0, sct=1, ctx=None, type=Enum_BlockType.Section_Header_Block,
                                block={'byteorder': byteorder})
        with open(self._file, 'wb') as file:
            file.write(header.data)
        self._ctx = Context(cast('Data_SectionHeaderBlock', header.info))

    def _append_value(self, value: 'P_PCAPNG | Data_Frame', file: 'IO[bytes]', name: 'str') -> 'None':  # pylint: disable=unused-argument
        """Call this function to write contents.

        Args:
            value: content to be dumped
            file: output file
            name: name of current content block

        Notes:
            ``value`` is one of:

            * a PCAP-NG block, as the
              :class:`~pcapkit.foundation.engines.pcapng.PCAPNG` engine hands
              it: a packet block -- EPB, SPB or obsolete Packet Block -- is
              written as an EPB with its own options, an Interface Description
              Block as itself, and any other block not at all;
            * a frame, written as an EPB on the interface
              :func:`~pcapkit.toolkit.pcapng.block2frame` kept, with the
              block's options, or else on one of ``protocol``, ``snaplen`` and
              ``nanosecond``;
            * a PCAP global header, not written.

            An interface is written before the first block on it, and those
            whose IDBs would be the same octets share one. Each keeps its
            options, ``if_tsresol`` and ``if_tsoffset`` among them, so
            timestamps are written exactly. Captured Packet Length is the
            octets written, as for :meth:`PCAPIO._append_value
            <pcapkit.dumpkit.pcap.PCAPIO._append_value>`.

            Every block is made by :meth:`PCAPNG.make
            <pcapkit.protocols.misc.pcapng.protocol.PCAPNG.make>`; an EPB is
            packed by :meth:`PCAPNG.pack
            <pcapkit.protocols.misc.pcapng.protocol.PCAPNG.pack>` alone,
            without dissecting the frame again.

        """
        if isinstance(value, P_PCAPNG):
            info = cast('Data_Packet', value.info)
            if info.type == Enum_BlockType.Interface_Description_Block:
                self._interface_id(file, cast('Data_InterfaceDescriptionBlock', info))
                return
            if info.type not in P_PCAPNG.PACKET_TYPES:
                return

            interfaces = value.section_context.interfaces
            interface = interfaces[info.interface_id]  # type: Optional[Data_InterfaceDescriptionBlock]
            options = getattr(info, 'options_raw', getattr(info, 'options', None))
            packet = info.packet[:info.captured_len]
            original_len = info.original_len
            timestamp = info.timestamp_epoch  # type: Decimal
        elif isinstance(value, Data_Header):
            return
        else:
            # NOTE: payload first, so a mapping passed for a frame fails naming ``packet``,
            # as for :class:`~pcapkit.dumpkit.pcap.PCAPIO`.
            packet = value.packet
            original_len = value.frame_info.orig_len
            timestamp = value.time_epoch
            interface = getattr(value, '__interface__', None)
            options = getattr(value, '__options__', None)

        interface_id = self._interface_id(file, interface)
        writer = cast('P_PCAPNG', self._writer)
        file.write(writer.pack(type=Enum_BlockType.Enhanced_Packet_Block, block={
            'interface_id': interface_id,
            'timestamp': timestamp,
            'captured_len': len(packet),
            'original_len': original_len,
            'packet_data': packet,
            'options': self._epb_options(options),
        }))

    @staticmethod
    def _epb_options(options: 'Any') -> 'Any':
        """Options of a packet block, as an EPB holds them.

        Args:
            options: the block's options, or its option area as captured

        Returns:
            ``options``, with each obsolete Packet Block option under the EPB
            option of its code -- ``pack_flags`` as ``epb_flags`` and
            ``pack_hash`` as ``epb_hash``, which share their layouts.

        """
        if options is None or isinstance(options, (bytes, bytearray)):
            return options
        if not any(getattr(code, 'opt_name', '').startswith('pack_') for code in options):
            return options
        return OrderedMultiDict(
            (Enum_OptionType.get(code.opt_value, namespace='epb')
             if getattr(code, 'opt_name', '').startswith('pack_') else code, option)
            for code, option in options.items(multi=True)
        )

    def _interface_id(self, file: 'IO[bytes]', interface: 'Optional[Data_InterfaceDescriptionBlock]') -> 'int':
        """Interface ID of an interface in the output, writing its IDB if new.

        Args:
            file: output file
            interface: the interface, or :data:`None` for the one of
                ``protocol``, ``snaplen`` and ``nanosecond``

        Returns:
            Index of the interface's IDB in the output section.

        Raises:
            FormatError: If ``interface`` is :data:`None` and the dumper was
                given no ``protocol``.

        """
        seen = self._seen.get(id(interface))
        if seen is not None and seen[0] is interface:
            return seen[1]

        if interface is not None:
            block = interface  # type: Data_InterfaceDescriptionBlock | dict[str, Any]
        elif self._link is None:
            raise FormatError('PCAP-NG: a frame of no interface needs the dumper\'s protocol')
        else:
            options = None
            if self._nsec:
                options = [(Enum_OptionType.if_tsresol, {'resolution': RESOLUTION[True]}),
                           (Enum_OptionType.opt_endofopt, {})]
            block = {
                # NOTE: :meth:`PCAPNG.make` takes a member or a code (#2594); this dumper's
                # protocol also takes a name, so it is resolved here.
                'linktype': P_PCAPNG.resolve_index(self._link, namespace=Enum_LinkType),
                'snaplen': self._snap,
                'options': options,
            }

        idb = P_PCAPNG.build(num=0, sct=1, ctx=self._ctx,
                             type=Enum_BlockType.Interface_Description_Block, block=block)
        index = self._index.get(idb.data)
        if index is None:
            index = self._index[idb.data] = len(self._ctx.interfaces)
            self._ctx.interfaces.append(cast('Data_InterfaceDescriptionBlock', idb.info))
            if self._writer is None:
                self._writer = idb
            file.write(idb.data)

        self._seen[id(interface)] = (interface, index)
        return index
