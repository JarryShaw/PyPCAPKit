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
from pcapkit.foundation.engines.engine import Engine
from pcapkit.utilities.exceptions import stacklevel
from pcapkit.utilities.warnings import AttributeWarning, DPKTWarning, warn

__all__ = ['DPKT']

if TYPE_CHECKING:
    from typing import Iterator

    from dpkt.dpkt import Packet as DPKTPacket

    from pcapkit.foundation.extraction import Extractor


class DPKT(Engine['DPKTPacket']):
    """DPKT engine support.

    Args:
        extractor: :class:`~pcapkit.foundation.extraction.Extractor` instance.

    """

    ##########################################################################
    # Properties.
    ##########################################################################

    @classmethod
    def name(cls) -> 'str':
        """Engine name."""
        return 'DPKT'

    @classmethod
    def module(cls) -> 'str':
        """Engine module name."""
        return 'dpkt'

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, extractor: 'Extractor') -> 'None':
        import dpkt  # isort:skip

        self._expkg = dpkt
        self._extmp = cast('Iterator[tuple[float, DPKTPacket]]', None)

        super().__init__(extractor)

    ##########################################################################
    # Methods.
    ##########################################################################

    def run(self) -> 'None':
        """Call :class:`dpkt.pcap.Reader` to extract PCAP files.

        This method assigns :attr:`self._expkg <Extractor._expkg>` as :mod:`dpkt` and
        :attr:`self._extmp <Extractor._extmp>` as an iterator from :class:`dpkt.pcap.Reader`.

        Warns:
            AttributeWarning: If :attr:`self._exlyr <Extractor._exlyr>` and/or
                :attr:`self._exptl <Extractor._exptl>` is provided as the DPKT
                engine currently does not support such operations.

        """
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

        # extract global header
        ext.record_header()

        if ext._dlink == Enum_LinkType.ETHERNET:
            pkg = dpkt.ethernet.Ethernet
        elif ext._dlink.value == Enum_LinkType.IPV4:
            pkg = dpkt.ip.IP
        elif ext._dlink.value == Enum_LinkType.IPV6:
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

        # extract & analyse file
        self._expkg = pkg
        self._extmp = iter(dpkt.pcap.Reader(ext._ifile))

    def read_frame(self) -> 'DPKTPacket':
        """Read frames with DPKT engine.

        Returns:
            dpkt.dpkt.Packet: Parsed frame instance.

        See Also:
            Please refer to :meth:`_default_read_frame` for more operational information.

        """
        from pcapkit.toolkit.dpkt import (ipv4_reassembly, ipv6_reassembly, packet2dict,
                                          tcp_reassembly, tcp_traceflow)
        ext = self._extractor

        # fetch DPKT packet
        timestamp, pkt = cast('tuple[float, bytes]', next(self._extmp))
        packet = self._expkg(pkt)  # type: DPKTPacket

        # verbose output
        ext._frnum += 1
        ext._vfunc(ext, packet)

        # write plist
        frnum = f'Frame {ext._frnum}'
        if not ext._flag_q:
            info = packet2dict(packet, timestamp, data_link=ext._dlink)
            if ext._flag_f:
                ofile = ext._ofile(f'{ext._ofnm}/{frnum}.{ext._fext}')
                ofile(info, name=frnum)
            else:
                ext._ofile(info, name=frnum)

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
                data_tf_tcp = tcp_traceflow(packet, timestamp, data_link=ext._dlink, count=ext._frnum)
                if data_tf_tcp is not None:
                    ext._trace.tcp(data_tf_tcp)

        # record frames
        if ext._flag_d:
            # setattr(packet, 'packet2dict', packet2dict)
            # setattr(packet, 'packet2chain', packet2chain)
            ext._frame.append(packet)

        # return frame record
        return packet
