# -*- coding: utf-8 -*-
"""PCAP Dumper
=================

.. module:: pcapkit.dumpkit.pcap

:mod:`pcapkit.dumpkit.pcap` is the dumper for :mod:`pcapkit` implementation,
specifically for PCAP format, which is alike those described in
:mod:`dictdumper`.

"""
import struct
import sys
from typing import TYPE_CHECKING

from pcapkit.dumpkit.common import DumperBase
from pcapkit.protocols.data.misc.pcap.header import Header as Data_Header
from pcapkit.protocols.misc.pcap.header import Header

if TYPE_CHECKING:
    from enum import IntEnum as StdlibIntEnum
    from typing import IO, Any, Optional

    from aenum import IntEnum as AenumIntEnum
    from typing_extensions import Literal

    from pcapkit.const.reg.linktype import LinkType as Enum_LinkType
    from pcapkit.protocols.data.misc.pcap.frame import Frame as Data_Frame

__all__ = [
    'PCAPIO',
]

#: Per-byte-order record header packers for the four ``uint32`` fields of a PCAP
#: record header -- ``ts_sec``, ``ts_usec``, ``incl_len``, ``orig_len``. Keyed by
#: the byte order of the global header this dumper wrote, so that the records
#: agree with the magic number a reader will find in front of them.
_RECORD_HEADER = {
    'little': struct.Struct('<IIII'),
    'big': struct.Struct('>IIII'),
}

#: Truncation mask for those four fields. :class:`~pcapkit.corekit.fields.numbers.UInt32Field`,
#: which used to pack them, masks to the field width in
#: :meth:`~pcapkit.corekit.fields.numbers.NumberField.pre_process` rather than
#: rejecting an out-of-range value -- a ``ts_sec`` of ``2**32 + 5`` was written as
#: ``5``. :func:`struct.pack` raises instead, so the mask is applied here to keep
#: the two spellings writing the same octets for every input.
_UINT32_MASK = 0xFFFF_FFFF


class PCAPIO(DumperBase):
    """PCAP file dumper.

    Args:
        fname: output file name
        protocol: data link type
        byteorder: header byte order
        nanosecond: nanosecond-resolution file flag
        **kwargs: arbitrary keyword arguments

    """
    if TYPE_CHECKING:
        #: PCAP file global header.
        _ghdr: 'Data_Header'
        #: Record header packer, in the global header's byte order.
        _rechdr: 'struct.Struct'

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def kind(self) -> 'Literal["pcap"]':
        """File format of current dumper."""
        return 'pcap'

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, fname: 'str', *, protocol: 'Enum_LinkType | StdlibIntEnum | AenumIntEnum | str | int',
                 byteorder: 'Literal["big", "little"]' = sys.byteorder,
                 nanosecond: 'bool' = False, **kwargs: 'Any') -> 'None':  # pylint: disable=arguments-differ
        """Initialise dumper.

        Args:
            fname: output file name
            protocol: data link type
            byteorder: header byte order
            nanosecond: nanosecond-resolution file flag
            **kwargs: arbitrary keyword arguments

        """
        #: int: Frame counter.
        self._fnum = 1
        # NOTE: Both of these now only record how the dumper was configured -- the
        # values that shape the output reach it through :meth:`self._dump_header
        # <_dump_header>`'s own arguments, and are readable afterwards from
        # :attr:`self._ghdr <_ghdr>`. They are kept because they are part of the
        # instance surface a subclass may already read.
        #: bool: Nanosecond-resolution file flag.
        self._nsec = nanosecond
        #: Enum_LinkType | StdlibIntEnum | AenumIntEnum | str | int: Data link type.
        self._link = protocol

        super().__init__(fname, protocol=protocol, byteorder=byteorder, nanosecond=nanosecond, **kwargs)

    def __call__(self, value: 'Data_Frame', name: 'Optional[str]' = None) -> 'PCAPIO':
        """Dump a new frame.

        Args:
            value: content to be dumped
            name: name of current content block

        Returns:
            The dumper class itself (to support chain calling).

        """
        with open(self._file, 'ab') as file:
            self._append_value(value, file, name or '')
        return self

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _dump_header(self, *, protocol: 'Enum_LinkType | StdlibIntEnum | AenumIntEnum | str | int',  # pylint: disable=arguments-differ
                     byteorder: 'Literal["big", "little"]' = sys.byteorder, nanosecond: 'bool' = False,
                     **kwargs: 'Any') -> 'None':  # pylint: disable=unused-argument
        """Initially dump file heads and tails.

        Args:
            protocol: data link type
            byteorder: header byte order
            nanosecond: nanosecond-resolution file flag
            **kwargs: arbitrary keyword arguments

        """
        header = Header(
            network=protocol,
            byteorder=byteorder,
            nanosecond=nanosecond,
        )
        packet = header.data
        with open(self._file, 'wb') as file:
            file.write(packet)
        self._ghdr = header.info

        #: struct.Struct: Packer for the record header preceding each frame, in the
        #: byte order of the global header just written. Taken from
        #: :attr:`self._ghdr <_ghdr>` rather than from the ``byteorder`` argument
        #: because :class:`~pcapkit.protocols.misc.pcap.header.Header` is what
        #: validates and normalises it.
        self._rechdr = _RECORD_HEADER[self._ghdr.magic_number.byteorder]

    def _append_value(self, value: 'Data_Frame', file: 'IO[bytes]', name: 'str') -> 'None':  # pylint: disable=unused-argument
        """Call this function to write contents.

        Args:
            value: content to be dumped
            file: output file
            name: name of current content block

        Notes:
            A PCAP record is a 16-octet header followed by the packet octets, and
            both are already in hand: the header fields are exactly
            ``value.frame_info`` and the octets are exactly ``value.packet``. So
            this writes them directly, rather than handing them to
            :class:`~pcapkit.protocols.misc.pcap.frame.Frame`, whose constructor
            packs the record and then **dissects it again** through the whole
            protocol stack to arrive at bytes it was given. That round trip was
            about 82% of the cost of a flow-traced extraction -- ``http.pcap``,
            1117 frames, best of 7: 2319 ms with the rebuild against 1263 ms
            without, over a 1030 ms untraced baseline.

            Dropping it is not only cheaper. The re-dissection re-emitted every
            parse warning the frame had already produced once, and warned about
            payloads it had no business parsing at all -- writing a 3-octet
            payload raised ``SchemaWarning: packet length < 0: -3`` from a dumper
            that only had to copy it.

        """
        # NOTE: The payload is read before the metadata so that a caller passing a
        # mapping rather than a dissected frame -- which the flow-tracing adapters
        # of several engines do -- still fails naming ``packet``, as the ``Frame``
        # construction did. :mod:`pcapkit.foundation.extraction` substitutes a
        # dict-capable trace format on the strength of that error.
        packet = value.packet
        frame_info = value.frame_info

        file.write(self._rechdr.pack(frame_info.ts_sec & _UINT32_MASK,
                                     frame_info.ts_usec & _UINT32_MASK,
                                     frame_info.incl_len & _UINT32_MASK,
                                     frame_info.orig_len & _UINT32_MASK) + packet)
        self._fnum += 1
