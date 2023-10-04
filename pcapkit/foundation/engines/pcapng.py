# -*- coding: utf-8 -*-
"""PCAP-NG Support
=====================

.. module:: pcapkit.foundation.engines.pcapng

This module contains the implementation for PCAP-NG file extraction
support, as is used by :class:`pcapkit.foundation.extraction.Extractor`.

"""
from logging import warn
from typing import TYPE_CHECKING, cast

from pcapkit.const.pcapng.block_type import BlockType as Enum_BlockType
from pcapkit.corekit.infoclass import Info, info_final
from pcapkit.foundation.engines.engine import EngineBase as Engine
from pcapkit.protocols.misc.pcapng import PCAPNG as P_PCAPNG
from pcapkit.utilities.exceptions import FormatError, stacklevel
from pcapkit.utilities.warnings import DeprecatedFormatWarning

__all__ = ['PCAPNG']

if TYPE_CHECKING:
    from pcapkit.foundation.extraction import Extractor
    from pcapkit.protocols.data.misc.pcapng import PCAPNG as Data_PCAPNG
    from pcapkit.protocols.data.misc.pcapng import CustomBlock as Data_CustomBlock
    from pcapkit.protocols.data.misc.pcapng import \
        DecryptionSecretsBlock as Data_DecryptionSecretsBlock
    from pcapkit.protocols.data.misc.pcapng import EnhancedPacketBlock as Data_EnhancedPacketBlock
    from pcapkit.protocols.data.misc.pcapng import \
        InterfaceDescriptionBlock as Data_InterfaceDescriptionBlock
    from pcapkit.protocols.data.misc.pcapng import \
        InterfaceStatisticsBlock as Data_InterfaceStatisticsBlock
    from pcapkit.protocols.data.misc.pcapng import NameResolutionBlock as Data_NameResolutionBlock
    from pcapkit.protocols.data.misc.pcapng import PacketBlock as Data_PacketBlock
    from pcapkit.protocols.data.misc.pcapng import SectionHeaderBlock as Data_SectionHeaderBlock
    from pcapkit.protocols.data.misc.pcapng import \
        SystemdJournalExportBlock as Data_SystemdJournalExportBlock
    from pcapkit.protocols.data.misc.pcapng import UnknownBlock as Data_UnknownBlock


@info_final
class Context(Info):
    """Context manager for PCAP-NG file format."""

    #: Section header.
    section: 'Data_SectionHeaderBlock'

    def __post_init__(self) -> None:
        """Post initialisation hook."""
        self.__update__(
            interfaces=[],
            #packets=[],
            names=[],
            journals=[],
            secrets=[],
            custom=[],
            statistics=[],
            unknown=[],
        )

    if TYPE_CHECKING:
        #: Interface descriptions.
        interfaces: 'list[Data_InterfaceDescriptionBlock]'
        #: Packets.
        #packets: 'list[Data_PacketBlock | Data_SimplePacketBlock | Data_EnhancedPacketBlock]'
        #: Name resolution records.
        names: 'list[Data_NameResolutionBlock]'
        #: :manpage:`systemd(1)` journal export records.
        journals: 'list[Data_SystemdJournalExportBlock]'
        #: Decryption secrets.
        secrets: 'list[Data_DecryptionSecretsBlock]'
        #: Custom blocks.
        custom: 'list[Data_CustomBlock]'
        #: Interface statistics.
        statistics: 'list[Data_InterfaceStatisticsBlock]'
        #: Unknown blocks.
        unknown: 'list[Data_UnknownBlock]'

        def __init__(self, section: 'Data_SectionHeaderBlock') -> 'None': ...


class PCAPNG(Engine[P_PCAPNG]):
    """PCAP-NG file extraction support.

    Args:
        extractor: :class:`~pcapkit.foundation.extraction.Extractor` instance.

    """
    if TYPE_CHECKING:
        #: Current context.
        _ctx: 'Context'
        #: File context storage.
        _ctx_list: 'list[Context]'

    MAGIC_NUMBER = (
        b'\x0a\x0d\x0d\x0a',
    )

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Engine name.
    __engine_name__ = 'PCAP-NG'

    #: Engine module name.
    __engine_module__ = 'pcapkit.protocols.misc.pcapng'

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, extractor: 'Extractor') -> 'None':
        self._ctx = None  # type: ignore[assignment]
        self._ctx_list = []

        super().__init__(extractor)

    ##########################################################################
    # Methods.
    ##########################################################################

    def run(self) -> 'None':
        """Start extraction.

        This method is the entry point for PCAP-NG file extraction. It will
        directly extract the first block, which should be a section header
        block, and then save the related information into the internal
        context storage.

        """
        ext = self._extractor

        shb = P_PCAPNG(ext._ifile, num=0, sct=1, ctx=None)
        if shb.info.type != Enum_BlockType.Section_Header_Block:
            raise FormatError(f'PCAP-NG: [SHB] invalid block type: {shb.info.type!r}')

        self._ctx = Context(cast('Data_SectionHeaderBlock', shb.info))
        self._ctx_list.append(self._ctx)
        shb._ctx = self._ctx

        self._write_file(shb.info, name=f'Section Header {len(self._ctx_list)}')

    def read_frame(self) -> 'P_PCAPNG':
        """Read frames.

        This method performs following tasks:

        - read the next block from input file;
        - check if the block is a packet block;
        - if not, save the block into the internal context storage and repeat;
        - if yes, save the related information into the internal context storage;
        - write the parsed block into output file.
        - reassemble IP and/or TCP fragments;
        - trace TCP flows if any;
        - record frame information if any.

        Returns:
            Parsed PCAP-NG block.

        """
        from pcapkit.toolkit.pcapng import (ipv4_reassembly, ipv6_reassembly, tcp_reassembly,
                                            tcp_traceflow)
        ext = self._extractor

        while True:
            # read next block
            block = P_PCAPNG(ext._ifile, num=ext._frnum+1, sct=len(self._ctx_list),
                             ctx=self._ctx, layer=ext._exlyr, protocol=ext._exptl,
                             __packet__={
                                 'snaplen': self._get_snaplen(),
                             })

            # check block type
            if block.info.type == Enum_BlockType.Section_Header_Block:
                self._ctx = Context(cast('Data_SectionHeaderBlock', block.info))
                self._ctx_list.append(self._ctx)
                block._ctx = self._ctx

                self._write_file(block.info, name=f'Section Header {len(self._ctx_list)}')

            elif block.info.type == Enum_BlockType.Interface_Description_Block:
                self._ctx.interfaces.append(cast('Data_InterfaceDescriptionBlock', block.info))
                self._write_file(block.info, name=f'Interface Description {len(self._ctx.interfaces)}')

            elif block.info.type == Enum_BlockType.Name_Resolution_Block:
                self._ctx.names.append(cast('Data_NameResolutionBlock', block.info))
                self._write_file(block.info, name=f'Name Resolution {len(self._ctx.names)}')

            elif block.info.type == Enum_BlockType.systemd_Journal_Export_Block:
                self._ctx.journals.append(cast('Data_SystemdJournalExportBlock', block.info))
                self._write_file(block.info, name=f'systemd Journal Export {len(self._ctx.journals)}')

            elif block.info.type == Enum_BlockType.Decryption_Secrets_Block:
                self._ctx.secrets.append(cast('Data_DecryptionSecretsBlock', block.info))
                self._write_file(block.info, name=f'Decryption Secrets {len(self._ctx.secrets)}')

            elif block.info.type == Enum_BlockType.Interface_Statistics_Block:
                isb_info = cast('Data_InterfaceStatisticsBlock', block.info)
                if isb_info.interface_id >= len(self._ctx.interfaces):
                    raise FormatError(f'PCAP-NG: [ISB] invalid interface ID: {isb_info.interface_id}')
                self._ctx.statistics.append(isb_info)

                self._write_file(isb_info, name=f'Interface Statistics {len(self._ctx.statistics)}')

            elif block.info.type in (Enum_BlockType.Custom_Block_that_rewriters_can_copy_into_new_files,
                                    Enum_BlockType.Custom_Block_that_rewriters_should_not_copy_into_new_files):
                self._ctx.custom.append(cast('Data_CustomBlock', block.info))
                self._write_file(block.info, name=f'Custom {len(self._ctx.custom)}')

            elif block.info.type == Enum_BlockType.Enhanced_Packet_Block:
                epb_info = cast('Data_EnhancedPacketBlock', block.info)
                if epb_info.interface_id >= len(self._ctx.interfaces):
                    raise FormatError(f'PCAP-NG: [EPB] invalid interface ID: {epb_info.interface_id}')
                break

            elif block.info.type == Enum_BlockType.Simple_Packet_Block:
                if len(self._ctx.interfaces) != 1:
                    raise FormatError(f'PCAP-NG: [SPB] invalid section with {len(self._ctx.interfaces)} interfaces')
                break

            elif block.info.type == Enum_BlockType.Packet_Block:
                pack_info = cast('Data_PacketBlock', block.info)
                if pack_info.interface_id >= len(self._ctx.interfaces):
                    raise FormatError(f'PCAP-NG: [Packet] invalid interface ID: {pack_info.interface_id}')

                warn('PCAP-NG: [Packet] deprecated block type', DeprecatedFormatWarning,
                     stacklevel=stacklevel())
                break

            else:
                self._ctx.unknown.append(cast('Data_UnknownBlock', block.info))
                self._write_file(block.info, name=f'Unknown {len(self._ctx.unknown)}')

        # increment frame number
        ext._frnum += 1

        # verbose output
        ext._vfunc(ext, block)

        # write plist
        self._write_file(block.info, name=f'Frame {ext._frnum}')

        # record fragments
        if ext._flag_r:
            if ext._ipv4:
                data_ipv4 = ipv4_reassembly(block)
                if data_ipv4 is not None:
                    ext._reasm.ipv4(data_ipv4)
            if ext._ipv6:
                data_ipv6 = ipv6_reassembly(block)
                if data_ipv6 is not None:
                    ext._reasm.ipv6(data_ipv6)
            if ext._tcp:
                data_tcp = tcp_reassembly(block)
                if data_tcp is not None:
                    ext._reasm.tcp(data_tcp)

        # trace flows
        if ext._flag_t:
            if ext._tcp:
                data_tf_tcp = tcp_traceflow(block, nanosecond=block.nanosecond)
                if data_tf_tcp is not None:
                    ext._trace.tcp(data_tf_tcp)

        # record blocks
        if ext._flag_d:
            ext._frame.append(block)

        # return block record
        return block

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _write_file(self, block: 'Data_PCAPNG', *, name: 'str') -> 'None':
        """Write the parsed block into output file.

        Args:
            block: The parsed block.
            name: The name of the block.

        """
        ext = self._extractor
        if ext._flag_q:
            return

        if ext._flag_f:
            ofile = ext._ofile(f'{ext._ofnm}/{name}.{ext._fext}')
            ofile(block.to_dict(), name=name)
        else:
            ext._ofile(block.to_dict(), name=name)
            ofile = ext._ofile
        ext._offmt = ofile.kind

    def _get_snaplen(self) -> 'int':
        """Get snapshot length from the current context.

        This method is used for providing the snapshot length to the ``__packet__``
        argument when parsing a Simple Packet Block (SPB).

        Notes:
            If there is no interface, return ``0xFFFF_FFFF_FFFF_FFFF``.

        """
        if self._ctx.interfaces:
            return self._ctx.interfaces[0].snaplen
        return 0xFFFF_FFFF_FFFF_FFFF
