# -*- coding: utf-8 -*-
"""DPKT Support
==================

.. module:: pcapkit.foundation.engines.dpkt

This module contains the implementation for `DPKT`_ engine
support, as is used by :class:`pcapkit.foundation.extraction.Extractor`.

.. _DPKT: https://dpkt.readthedocs.io

"""
import decimal
from typing import TYPE_CHECKING, cast

from pcapkit.const.pcapng.block_type import BlockType as Enum_BlockType
from pcapkit.const.pcapng.option_type import OptionType as Enum_OptionType
from pcapkit.const.reg.linktype import LinkType as Enum_LinkType
from pcapkit.foundation.engines.engine import EngineBase
from pcapkit.utilities.compat import localcontext
from pcapkit.utilities.exceptions import FormatError, stacklevel
from pcapkit.utilities.logging import get_logger
from pcapkit.utilities.warnings import AttributeWarning, DPKTWarning, warn

__all__ = ['DPKT', 'PCAPNGReader']

if TYPE_CHECKING:
    from typing import IO, Iterator, Literal, Optional, Type, Union

    from dpkt.dpkt import Packet as DPKTPacket
    from dpkt.pcap import Reader as PCAPReader

    from pcapkit.foundation.engines.pcapng import Context
    from pcapkit.foundation.extraction import Extractor
    from pcapkit.protocols.data.misc.pcapng import \
        InterfaceDescriptionBlock as Data_InterfaceDescriptionBlock
    from pcapkit.protocols.data.misc.pcapng import SectionHeaderBlock as Data_SectionHeaderBlock

    Reader = Union[PCAPReader, 'PCAPNGReader']

#: logging.Logger: Module-level logger, a child of the package-wide
#: :data:`pcapkit.utilities.logging.logger`.
logger = get_logger(__name__)


class PCAPNGReader:
    """PCAP-NG reader for the DPKT engine, aware of every interface.

    :class:`dpkt.pcapng.Reader` reads only the first Interface Description
    Block (IDB) of a file, and applies its link type and timestamp resolution
    to every packet (:issue:`1379`). This reader walks the blocks itself
    instead: it parses each Section Header Block and IDB with :mod:`pcapkit`'s
    own :class:`~pcapkit.protocols.misc.pcapng.PCAPNG`, keeps the interfaces
    of the current section, and resolves every packet's link type,
    ``if_tsresol`` and ``if_tsoffset`` from the interface it names. Packet
    blocks are still decoded by `DPKT`_.

    As :class:`dpkt.pcapng.Reader` does, it yields Enhanced Packet Blocks and
    (obsolete) Packet Blocks only, and skips every other block.

    .. _DPKT: https://dpkt.readthedocs.io

    Args:
        file: Source PCAP-NG stream, positioned at its first Section Header Block.

    """

    def __init__(self, file: 'IO[bytes]') -> 'None':
        #: Source PCAP-NG stream.
        self._file = file
        #: Context of the current section.
        self._ctx = cast('Context', None)
        #: Section index number.
        self._sect = 0
        #: Link type of the packet last yielded.
        self._linktype = cast('Enum_LinkType', Enum_LinkType.NULL)
        #: Underlying block iterator.
        self._iter = self._read()

    def datalink(self) -> 'Enum_LinkType':
        """Link type of the interface the packet last yielded was captured on."""
        return self._linktype

    def __iter__(self) -> 'PCAPNGReader':
        return self

    def __next__(self) -> 'tuple[float, bytes]':
        return next(self._iter)

    def _read(self) -> 'Iterator[tuple[float, bytes]]':
        """Read blocks until the next packet block, and yield its timestamp and data."""
        from pcapkit.foundation.engines.pcapng import Context
        from pcapkit.protocols.misc.pcapng import PCAPNG as P_PCAPNG

        while True:
            head = self._file.read(8)
            if len(head) < 8:
                return

            # the SHB block type is a palindrome, so it reads the same in
            # either byte order; any other block uses the section's order
            byteorder: 'Literal["big", "little"]'
            if head[:4] == b'\x0a\x0d\x0d\x0a':
                head += self._file.read(4)
                byteorder = 'little' if head[8:] == b'\x4d\x3c\x2b\x1a' else 'big'
            else:
                byteorder = self._ctx.section.byteorder
            block_type = int.from_bytes(head[:4], byteorder)
            length = int.from_bytes(head[4:8], byteorder)
            if length < 12:
                raise FormatError(f'PCAP-NG: [Block {block_type}] invalid block length: {length}')

            buf = head + self._file.read(length - len(head))
            if len(buf) < length:
                return

            if block_type == Enum_BlockType.Section_Header_Block:
                self._sect += 1
                shb = P_PCAPNG(buf, num=0, sct=self._sect, ctx=None)
                self._ctx = Context(cast('Data_SectionHeaderBlock', shb.info))
            elif block_type == Enum_BlockType.Interface_Description_Block:
                idb = P_PCAPNG(buf, num=0, sct=self._sect, ctx=self._ctx)
                self._ctx.interfaces.append(cast('Data_InterfaceDescriptionBlock', idb.info))
            elif block_type in (Enum_BlockType.Enhanced_Packet_Block, Enum_BlockType.Packet_Block):
                yield self._read_packet(buf, block_type, byteorder == 'little')

    def _read_packet(self, buf: 'bytes', block_type: 'int',
                     little: 'bool') -> 'tuple[float, bytes]':
        """Decode a packet block with `DPKT`_, against the interface it names.

        Args:
            buf: Whole block, as read from the file.
            block_type: Block type, an EPB or an (obsolete) Packet Block.
            little: Whether the enclosing section is little-endian.

        Returns:
            Timestamp in seconds since the UNIX epoch, and the packet data.

        Raises:
            FormatError: If the section describes no interface of the ID the
                block names.

        """
        import dpkt  # isort:skip

        if block_type == Enum_BlockType.Enhanced_Packet_Block:
            tag = 'EPB'
            pkt = (dpkt.pcapng.EnhancedPacketBlockLE(buf) if little
                   else dpkt.pcapng.EnhancedPacketBlock(buf))
        else:
            tag = 'Packet'
            pkt = dpkt.pcapng.PacketBlockLE(buf) if little else dpkt.pcapng.PacketBlock(buf)

        iface_id = pkt.iface_id  # pylint: disable=no-member
        if iface_id >= len(self._ctx.interfaces):
            raise FormatError(f'PCAP-NG: [{tag}] invalid interface ID: {iface_id}')
        interface = self._ctx.interfaces[iface_id]

        tsresol = interface.options.get(Enum_OptionType.if_tsresol)
        tsoffset = interface.options.get(Enum_OptionType.if_tsoffset)
        resolution = 1_000_000 if tsresol is None else tsresol.resolution
        offset = 0 if tsoffset is None else tsoffset.offset

        # same arithmetic as :meth:`PCAPNG._read_timestamp
        # <pcapkit.protocols.misc.pcapng.PCAPNG._read_timestamp>`
        ticks = (pkt.ts_high << 32) | pkt.ts_low
        with localcontext(prec=64):
            timestamp = decimal.Decimal(ticks) / resolution + offset

        self._linktype = interface.linktype
        return float(timestamp), pkt.pkt_data


class DPKT(EngineBase['DPKTPacket']):
    """DPKT engine support.

    A PCAP-NG file is read by :class:`PCAPNGReader` rather than by
    :class:`dpkt.pcapng.Reader`, so each packet takes the link type and the
    timestamp resolution and offset of the interface it was captured on.

    Like `DPKT`_'s reader, it yields Enhanced Packet Blocks and (obsolete)
    Packet Blocks only, and skips every other block without a warning -- the
    Simple Packet Block included. A packet carried in a Simple Packet Block is
    therefore missing from this engine's output; the default engine reads it.

    .. _DPKT: https://dpkt.readthedocs.io

    Args:
        extractor: :class:`~pcapkit.foundation.extraction.Extractor` instance.

    """
    if TYPE_CHECKING:
        import dpkt

        #: Engine extraction package.
        _expkg: 'dpkt'
        #: Engine extraction temporary storage.
        _extmp: 'Reader'

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Engine name.
    __engine_name__ = 'DPKT'

    #: Engine module name.
    __engine_module__ = 'dpkt'

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, extractor: 'Extractor') -> 'None':
        import dpkt  # isort:skip

        self._expkg = dpkt
        self._extmp = cast('Reader', None)

        super().__init__(extractor)

    ##########################################################################
    # Methods.
    ##########################################################################

    def run(self) -> 'None':
        """Call :class:`dpkt.pcap.Reader` to extract PCAP files.

        This method assigns :attr:`self._expkg <DPKT._expkg>`
        as :mod:`dpkt` and :attr:`self._extmp <DPKT._extmp>`
        as an iterator from :class:`dpkt.pcap.Reader`, or from
        :class:`PCAPNGReader` for a PCAP-NG file.

        The global header is parsed and dumped first, by
        :meth:`self.extractor.record_header <pcapkit.foundation.extraction.Extractor.record_header>`.

        Warns:
            AttributeWarning: If :attr:`self.extractor._exlyr <pcapkit.foundation.extraction.Extractor._exlyr>`
                and/or :attr:`self.extractor._exptl <pcapkit.foundation.extraction.Extractor._exptl>`
                is provided as the DPKT engine does not support such operations;
                or if :attr:`self.extractor._exctx <pcapkit.foundation.extraction.Extractor._exctx>`
                is provided, as the DPKT engine does not parse with :mod:`pcapkit`'s own
                protocol implementations.

        Raises:
            FormatError: If the file format is not supported, i.e., not a PCAP
                and/or PCAP-NG file.

        """
        from pcapkit.foundation.engines.pcap import PCAP
        from pcapkit.foundation.engines.pcapng import PCAPNG

        ext = self._extractor
        dpkt = self._expkg

        if ext._exlyr != 'none' or ext._exptl != 'null':
            warn("'Extractor(engine=dpkt)' does not support protocol and layer threshold; "
                 f"'layer={ext._exlyr}' and 'protocol={ext._exptl}' ignored",
                 AttributeWarning, stacklevel=stacklevel())

        if ext._exctx:
            warn("'Extractor(engine=dpkt)' does not parse with pcapkit's own protocol "
                 "implementations, so the parsing context supplied through "
                 "'context=' is ignored",
                 AttributeWarning, stacklevel=stacklevel())

        # setup verbose handler
        if ext._flag_v:
            from pcapkit.toolkit.dpkt import packet2chain  # isort:skip
            ext._vfunc = lambda e, f: print(
                f'Frame {e._frnum:>3d}: {packet2chain(f)}'  # pylint: disable=protected-access
            )

        # extract global header
        ext.record_header()

        if ext.magic_number in PCAP.MAGIC_NUMBER:
            logger.debug('dpkt: reading %s as PCAP', ext._ifnm)
            reader = dpkt.pcap.Reader(ext._ifile)
        elif ext.magic_number in PCAPNG.MAGIC_NUMBER:
            logger.debug('dpkt: reading %s as PCAP-NG', ext._ifnm)
            reader = PCAPNGReader(ext._ifile)
        else:
            raise FormatError(f'unsupported file format: {ext.magic_number!r}')

        # extract & analyse file
        self._extmp = reader

    def read_frame(self) -> 'DPKTPacket':
        """Read frames with DPKT engine.

        Returns:
            Parsed frame instance.

        See Also:
            Please refer to :meth:`PCAP.read_frame <pcapkit.foundation.engines.pcap.PCAP.read_frame>`
            for more operational information.

        """
        from pcapkit.toolkit.dpkt import (attach_buffer, attach_timestamp, ipv4_reassembly,
                                          ipv6_reassembly, packet2dict, tcp_reassembly,
                                          tcp_traceflow)
        ext = self._extractor

        reader = self._extmp

        # fetch DPKT packet; a PCAP-NG reader reports the link type of the
        # interface this packet was captured on, so ask only after reading it
        timestamp, pkt = cast('tuple[float, bytes]', next(reader))
        linktype = Enum_LinkType.get(reader.datalink())
        protocol = self._get_protocol(linktype)
        try:
            packet = protocol(pkt)  # type: DPKTPacket
        except Exception as exc:  # pylint: disable=broad-except
            # NOTE: Caught broadly, as :meth:`ProtocolBase.analyze
            # <pcapkit.protocols.protocol.ProtocolBase.analyze>` does: dpkt raises
            # more than its own ``UnpackError`` while parsing -- dpkt 1.9.8 reads
            # ``frag_off`` from whatever header follows an IPv6 Fragment header,
            # so a Fragment header followed by ESP or Destination Options raises
            # :exc:`AttributeError` (:issue:`1351`). The frame is kept as a raw
            # packet, so one undecodable frame does not end the extraction and
            # the frame numbering still matches the other engines, which fall
            # back to a raw payload in the same way.
            warn(f'Frame {ext._frnum + 1}: dpkt cannot parse the frame '
                 f'({type(exc).__name__}: {exc}); kept as raw data',
                 DPKTWarning, stacklevel=stacklevel())
            packet = self._get_raw_protocol()(pkt)

        # DPKT hands the record's timestamp back beside its octets and only the
        # octets become a packet, so the frame would otherwise not know when it was
        # captured -- and anything reading a *stored* frame after this loop has
        # moved on could not find out. Keep the two together from the start.
        attach_timestamp(packet, timestamp)
        # Nor does the packet keep the octets it was parsed from, and serialising
        # it again recomputes zeroed checksums and lengths into it, so keep those
        # too for the adapters to slice the wire octets out of.
        attach_buffer(packet, pkt)

        # verbose output
        ext._frnum += 1
        ext._vfunc(ext, packet)

        # write plist
        frnum = f'Frame {ext._frnum}'
        if not ext._flag_q:
            info = packet2dict(packet, timestamp, data_link=linktype)
            if ext._flag_f:
                ofile = ext._ofile(f'{ext._ofnm}/{frnum}.{ext._fext}')
                ofile(info, name=frnum)
            else:
                ext._ofile(info, name=frnum)

        # record fragments
        if ext._flag_r:
            if ext._ipv4:
                data_ipv4 = ipv4_reassembly(packet, timestamp, count=ext._frnum)
                if data_ipv4 is not None:
                    ext._reasm.ipv4(data_ipv4)
            if ext._ipv6:
                data_ipv6 = ipv6_reassembly(packet, timestamp, count=ext._frnum)
                if data_ipv6 is not None:
                    ext._reasm.ipv6(data_ipv6)
            if ext._tcp:
                data_tcp = tcp_reassembly(packet, timestamp, count=ext._frnum)
                if data_tcp is not None:
                    ext._reasm.tcp(data_tcp)

        # trace flows
        if ext._flag_t:
            if ext._tcp:
                data_tf_tcp = tcp_traceflow(packet, timestamp, data_link=linktype, count=ext._frnum)
                if data_tf_tcp is not None:
                    ext._trace.tcp(data_tf_tcp)

        # record frames
        if ext._flag_d:
            # setattr(packet, 'packet2dict', packet2dict)
            # setattr(packet, 'packet2chain', packet2chain)
            ext._frame.append(packet)

        # return frame record
        return packet

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _get_protocol(self, linktype: 'Optional[Enum_LinkType]' = None) -> 'Type[DPKTPacket]':
        """Returns the protocol for parsing the current packet.

        Args:
            linktype: Link type code.

        """
        dpkt = self._expkg
        reader = self._extmp

        if linktype is None:
            linktype = Enum_LinkType.get(reader.datalink())

        if linktype == Enum_LinkType.ETHERNET:
            pkg = dpkt.ethernet.Ethernet
        elif linktype.value == Enum_LinkType.IPV4:
            pkg = dpkt.ip.IP
        elif linktype.value == Enum_LinkType.IPV6:
            pkg = dpkt.ip6.IP6
        else:
            warn('unrecognised link layer protocol; all analysis functions ignored',
                 DPKTWarning, stacklevel=stacklevel())
            pkg = self._get_raw_protocol()
        return pkg

    def _get_raw_protocol(self) -> 'Type[DPKTPacket]':
        """Returns a protocol that keeps the packet as raw data."""
        dpkt = self._expkg

        class RawPacket(dpkt.dpkt.Packet):  # type: ignore[name-defined]
            """Raw packet."""

            def __len__(ext) -> 'int':
                return len(ext.data)

            def __bytes__(ext) -> 'bytes':
                return ext.data

            def unpack(ext, buf: 'bytes') -> 'None':
                ext.data = buf

        return RawPacket
