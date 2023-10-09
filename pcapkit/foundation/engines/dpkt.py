# -*- coding: utf-8 -*-
"""DPKT Support
==================

.. module:: pcapkit.foundation.engines.dpkt

This module contains the implementation for `DPKT`_ engine
support, as is used by :class:`pcapkit.foundation.extraction.Extractor`.

.. _DPKT: https://dpkt.readthedocs.io

"""
from typing import TYPE_CHECKING, cast

from pcapkit.const.reg.linktype import LinkType as Enum_LinkType
from pcapkit.foundation.engines.engine import EngineBase as Engine
from pcapkit.utilities.exceptions import FormatError, stacklevel
from pcapkit.utilities.warnings import AttributeWarning, DPKTWarning, warn

__all__ = ['DPKT']

if TYPE_CHECKING:
    from typing import Optional, Type, Union

    from dpkt.dpkt import Packet as DPKTPacket
    from dpkt.pcap import Reader as PCAPReader
    from dpkt.pcapng import Reader as PCAPNGReader

    from pcapkit.foundation.extraction import Extractor

    Reader = Union[PCAPReader, PCAPNGReader]


class DPKT(Engine['DPKTPacket']):
    """DPKT engine support.

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
        as an iterator from :class:`dpkt.pcap.Reader`.

        Warns:
            AttributeWarning: If :attr:`self.extractor._exlyr <pcapkit.foundation.extraction.Extractor._exlyr>`
                and/or :attr:`self.extractor._exptl <pcapkit.foundation.extraction.Extractor._exptl>`
                is provided as the DPKT engine currently does not support such operations.

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

        # setup verbose handler
        if ext._flag_v:
            from pcapkit.toolkit.dpkt import packet2chain  # isort:skip
            ext._vfunc = lambda e, f: print(
                f'Frame {e._frnum:>3d}: {packet2chain(f)}'  # pylint: disable=protected-access
            )  # pylint: disable=logging-fstring-interpolation

        if ext.magic_number in PCAP.MAGIC_NUMBER:
            reader = dpkt.pcap.Reader(ext._ifile)
        elif ext.magic_number in PCAPNG.MAGIC_NUMBER:
            reader = dpkt.pcapng.Reader(ext._ifile)
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
        from pcapkit.toolkit.dpkt import (ipv4_reassembly, ipv6_reassembly, packet2dict,
                                          tcp_reassembly, tcp_traceflow)
        ext = self._extractor

        reader = self._extmp
        linktype = Enum_LinkType.get(reader.datalink())

        # fetch DPKT packet
        timestamp, pkt = cast('tuple[float, bytes]', next(reader))
        protocol = self._get_protocol(linktype)
        packet = protocol(pkt)  # type: DPKTPacket

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
                ofile = ext._ofile
            ext._offmt = ofile.kind

        # record fragments
        if ext._flag_r:
            if ext._ipv4:
                data_ipv4 = ipv4_reassembly(packet, count=ext._frnum)
                if data_ipv4 is not None:
                    ext._reasm.ipv4(data_ipv4)
            if ext._ipv6:
                data_ipv6 = ipv6_reassembly(packet, count=ext._frnum)
                if data_ipv6 is not None:
                    ext._reasm.ipv6(data_ipv6)
            if ext._tcp:
                data_tcp = tcp_reassembly(packet, count=ext._frnum)
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

            class RawPacket(dpkt.dpkt.Packet):  # type: ignore[name-defined]
                """Raw packet."""

                def __len__(ext) -> 'int':
                    return len(ext.data)

                def __bytes__(ext) -> 'bytes':
                    return ext.data

                def unpack(ext, buf: 'bytes') -> 'None':
                    ext.data = buf

            pkg = RawPacket
        return pkg
