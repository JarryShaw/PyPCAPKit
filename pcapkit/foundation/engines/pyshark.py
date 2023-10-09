# -*- coding: utf-8 -*-
"""PyShark Support
=====================

.. module:: pcapkit.foundation.engines.pyshark

This module contains the implementation for `PyShark`_ engine
support, as is used by :class:`pcapkit.foundation.extraction.Extractor`.

.. _PyShark: https://kiminewt.github.io/pyshark

"""
from typing import TYPE_CHECKING, cast

from pcapkit.foundation.engines.engine import EngineBase as Engine
from pcapkit.foundation.reassembly import ReassemblyManager
from pcapkit.utilities.exceptions import stacklevel
from pcapkit.utilities.warnings import AttributeWarning, warn

__all__ = ['PyShark']

if TYPE_CHECKING:
    from pyshark.capture.file_capture import FileCapture
    from pyshark.packet.packet import Packet as PySharkPacket

    from pcapkit.foundation.extraction import Extractor


class PyShark(Engine['PySharkPacket']):
    """PyShark engine support.

    Args:
        extractor: :class:`~pcapkit.foundation.extraction.Extractor` instance.

    """
    if TYPE_CHECKING:
        import pyshark

        #: Engine extraction package.
        _expkg: 'pyshark'
        #: Engine extraction temporary storage.
        _extmp: 'FileCapture'

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Engine name.
    __engine_name__ = 'PyShark'

    #: Engine module name.
    __engine_module__ = 'pyshark'

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, extractor: 'Extractor') -> 'None':
        import pyshark  # isort:skip

        self._expkg = pyshark
        self._extmp = cast('FileCapture', None)

        super().__init__(extractor)

    ##########################################################################
    # Methods.
    ##########################################################################

    def run(self) -> 'None':
        """Call :class:`pyshark.FileCapture` to extract PCAP files.

        This method assigns :attr:`self._expkg <PyShark._expkg>`
        as :mod:`pyshark` and :attr:`self._extmp <PyShark._extmp>`
        as an iterator from :class:`pyshark.FileCapture`.

        Warns:
            AttributeWarning: Warns under following circumstances:

                * if :attr:`self.extractor._exlyr <pcapkit.foundation.extraction.Extractor._exlyr>`
                  and/or :attr:`self.extractor._exptl <pcapkit.foundation.extraction.Extractor._exptl>`
                  is provided as the PyShark engine currently does not
                  support such operations.
                * if reassembly is enabled, as the PyShark engine currently
                  does not support such operation.

        """
        ext = self._extractor

        if ext._exlyr != 'none' or ext._exptl != 'null':
            warn("'Extractor(engine='pyshark')' does not support protocol and layer threshold; "
                 f"'layer={ext._exlyr}' and 'protocol={ext._exptl}' ignored",
                 AttributeWarning, stacklevel=stacklevel())

        if ext._flag_r and (ext._ipv4 or ext._ipv6 or ext._tcp):
            ext._flag_r = False
            ext._reasm = ReassemblyManager(ipv4=None, ipv6=None, tcp=None)
            warn("'Extractor(engine='pyshark')' object dose not support reassembly; "
                 f"so 'ipv4={ext._ipv4}', 'ipv6={ext._ipv6}' and 'tcp={ext._tcp}' will be ignored",
                 AttributeWarning, stacklevel=stacklevel())

        # setup verbose handler
        if ext._flag_v:
            ext._vfunc = lambda e, f: print(
                f'Frame {e._frnum:>3d}: {f.frame_info.protocols}'  # pylint: disable=protected-access
            )  # pylint: disable=logging-fstring-interpolation

        # extract & analyse file
        self._extmp = self._expkg.FileCapture(ext._ifnm, keep_packets=False)

    def read_frame(self) -> 'PySharkPacket':
        """Read frames with PyShark engine.

        Returns:
            Parsed frame instance.

        See Also:
            Please refer to :meth:`PCAP.read_frame <pcapkit.foundation.engines.pcap.PCAP.read_frame>`
            for more operational information.

        """
        from pcapkit.toolkit.pyshark import packet2dict, tcp_traceflow
        ext = self._extractor

        # fetch PyShark packet
        packet = cast('PySharkPacket', self._extmp.next())

        # verbose output
        ext._frnum = int(packet.number)
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
                ofile = ext._ofile
            ext._offmt = ofile.kind

        # trace flows
        if ext._flag_t:
            if ext._tcp:
                data_tf_tcp = tcp_traceflow(packet)
                if data_tf_tcp is not None:
                    ext._trace.tcp(data_tf_tcp)

        # record frames
        if ext._flag_d:
            # setattr(packet, 'packet2dict', packet2dict)
            ext._frame.append(packet)

        # return frame record
        return packet

    def close(self) -> 'None':
        """Close engine.

        This method is to be used for closing the engine instance. It is to
        close the engine instance after the extraction process is finished.

        """
        self._extmp.close()
