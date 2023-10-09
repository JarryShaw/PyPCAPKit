# -*- coding: utf-8 -*-
"""Scapy Support
===================

.. module:: pcapkit.foundation.engines.scapy

This module contains the implementation for `Scapy`_ engine
support, as is used by :class:`pcapkit.foundation.extraction.Extractor`.

.. _Scapy: https://scapy.net

"""
from typing import TYPE_CHECKING, cast

from pcapkit.foundation.engines.engine import EngineBase as Engine
from pcapkit.utilities.exceptions import stacklevel
from pcapkit.utilities.warnings import AttributeWarning, warn

__all__ = ['Scapy']

if TYPE_CHECKING:
    from typing import Iterator

    from scapy.packet import Packet as ScapyPacket

    from pcapkit.foundation.extraction import Extractor


class Scapy(Engine['ScapyPacket']):
    """Scapy engine support.

    Args:
        extractor: :class:`~pcapkit.foundation.extraction.Extractor` instance.

    """
    if TYPE_CHECKING:
        import scapy.sendrecv

        #: Engine extraction package.
        _expkg: 'scapy.sendrecv'
        #: Engine extraction temporary storage.
        _extmp: 'Iterator[ScapyPacket]'

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Engine name.
    __engine_name__ = 'Scapy'

    #: Engine module name.
    __engine_module__ = 'scapy'

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, extractor: 'Extractor') -> 'None':
        from scapy import sendrecv as scapy  # isort:skip

        self._expkg = scapy
        self._extmp = cast('Iterator[ScapyPacket]', None)

        super().__init__(extractor)

    ##########################################################################
    # Methods.
    ##########################################################################

    def run(self) -> 'None':
        """Call :func:`scapy.sendrecv.sniff` to extract PCAP files.

        This method assigns :attr:`self._expkg <Scapy._expkg>`
        as :mod:`scapy.sendrecv` and :attr:`self._extmp <Scapy._extmp>`
        as an iterator from :func:`scapy.sendrecv.sniff`.

        Warns:
            AttributeWarning: If :attr:`self.extractor._exlyr <pcapkit.foundation.extraction.Extractor._exlyr>`
                and/or :attr:`self.extractor._exptl <pcapkit.foundation.extraction.Extractor._exptl>`
                is provided as the Scapy engine currently does not support such operations.

        """
        ext = self._extractor

        if ext._exlyr != 'none' or ext._exptl != 'null':
            warn("'Extractor(engine=scapy)' does not support protocol and layer threshold; "
                 f"'layer={ext._exlyr}' and 'protocol={ext._exptl}' ignored",
                 AttributeWarning, stacklevel=stacklevel())

        # setup verbose handler
        if ext._flag_v:
            from pcapkit.toolkit.scapy import packet2chain  # isort:skip
            ext._vfunc = lambda e, f: print(
                f'Frame {e._frnum:>3d}: {packet2chain(f)}'  # pylint: disable=protected-access
            )  # pylint: disable=logging-fstring-interpolation

        # extract & analyse file
        self._extmp = iter(self._expkg.sniff(offline=ext._ifnm))

    def read_frame(self) -> 'ScapyPacket':
        """Read frames with Scapy engine.

        Returns:
            Parsed frame instance.

        See Also:
            Please refer to :meth:`PCAP.read_frame <pcapkit.foundation.engines.pcap.PCAP.read_frame>`
            for more operational information.

        """
        from pcapkit.toolkit.scapy import (ipv4_reassembly, ipv6_reassembly, packet2dict,
                                           tcp_reassembly, tcp_traceflow)
        ext = self._extractor

        # fetch Scapy packet
        packet = next(self._extmp)

        # verbose output
        ext._frnum += 1
        ext._vfunc(ext, packet)

        # write plist
        frnum = f'Frame {ext._frnum}'
        if not ext._flag_q:
            info = packet2dict(packet)
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
                data_tf_tcp = tcp_traceflow(packet, count=ext._frnum)
                if data_tf_tcp is not None:
                    ext._trace.tcp(data_tf_tcp)

        # record frames
        if ext._flag_d:
            # setattr(packet, 'packet2dict', packet2dict)
            # setattr(packet, 'packet2chain', packet2chain)
            ext._frame.append(packet)

        # return frame record
        return packet
