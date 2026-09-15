# -*- coding: utf-8 -*-
"""PyPCAP Support
===================

.. module:: pcapkit.foundation.engines.pypcap

This module contains the implementation for `PyPCAP`_ engine
support, as is used by :class:`pcapkit.foundation.extraction.Extractor`.

.. _PyPCAP: https://github.com/pynetwork/pypcap

"""
import os
from typing import TYPE_CHECKING, cast

from pcapkit.const.reg.linktype import LinkType as Enum_LinkType
from pcapkit.foundation.engines.engine import EngineBase as Engine
from pcapkit.foundation.reassembly import ReassemblyManager
from pcapkit.foundation.traceflow import TraceFlowManager
from pcapkit.utilities.exceptions import FormatError, UnsupportedCall, stacklevel
from pcapkit.utilities.warnings import AttributeWarning, warn

__all__ = ['PyPCAP']

if TYPE_CHECKING:
    from typing import Iterator

    from pcap import pcap as Handle

    from pcapkit.foundation.extraction import Extractor

    #: A PyPCAP "frame": the ``(timestamp, bytes)`` pair that :class:`pcap.pcap`
    #: iteration yields. Deliberately *not* named ``Frame``, so that it is not
    #: mistaken for :class:`pcapkit.protocols.misc.pcap.frame.Frame`, which is
    #: what the built-in engines return.
    RawFrame = tuple[float, bytes]


class PyPCAP(Engine['RawFrame']):
    """PyPCAP engine support.

    `PyPCAP`_ is a binding over :manpage:`libpcap(3)`, primarily aimed at live
    capture. Offline it is a savefile reader and nothing more: iteration yields
    the ``(timestamp, bytes)`` pair from :c:func:`pcap_next_ex` and no protocol
    dissection is performed. Consequently this engine

    * returns each frame as a ``(timestamp, bytes)`` :obj:`tuple` rather than as
      a parsed packet object, and
    * disables both reassembly and flow tracing, warning as it does so, since
      neither can be derived without an IP or TCP layer to read.

    It also requires the input to be a real file on disk, because
    :c:func:`pcap_open_offline` opens by *name* -- there is no way to hand
    :manpage:`libpcap(3)` an already-open Python stream.

    .. _PyPCAP: https://github.com/pynetwork/pypcap

    Args:
        extractor: :class:`~pcapkit.foundation.extraction.Extractor` instance.

    """
    if TYPE_CHECKING:
        import pcap

        #: Engine extraction package.
        _expkg: 'pcap'
        #: Engine extraction temporary storage.
        _extmp: 'Iterator[RawFrame]'
        #: Data link layer protocol, from the capture handle.
        _dlink: 'Enum_LinkType'
        #: Closed flag, so that the handle is not closed twice.
        _closed: 'bool'

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Engine name.
    __engine_name__ = 'PyPCAP'

    #: Engine module name.
    __engine_module__ = 'pcap'

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def dlink(self) -> 'Enum_LinkType':
        """Data link layer protocol, as reported by the capture handle."""
        return self._dlink

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, extractor: 'Extractor') -> 'None':
        import pcap  # isort:skip

        self._expkg = pcap
        self._extmp = cast('Iterator[RawFrame]', None)
        self._dlink = cast('Enum_LinkType', None)
        self._closed = False

        super().__init__(extractor)

    ##########################################################################
    # Methods.
    ##########################################################################

    def run(self) -> 'None':
        """Call :class:`pcap.pcap` to extract PCAP files.

        This method assigns :attr:`self._expkg <PyPCAP._expkg>`
        as :mod:`pcap` and :attr:`self._extmp <PyPCAP._extmp>`
        as an iterator from :class:`pcap.pcap`.

        Warns:
            AttributeWarning: Warns under following circumstances:

                * if :attr:`self.extractor._exlyr <pcapkit.foundation.extraction.Extractor._exlyr>`
                  and/or :attr:`self.extractor._exptl <pcapkit.foundation.extraction.Extractor._exptl>`
                  is provided as the PyPCAP engine currently does not
                  support such operations.
                * if reassembly and/or flow tracing is enabled, as the PyPCAP
                  engine performs no protocol dissection and so cannot support
                  either operation.

        Raises:
            FormatError: If the file format is not supported, i.e., not a PCAP
                file. PCAP-NG is rejected explicitly rather than left to
                :manpage:`libpcap(3)`, which opens such a file without complaint
                and then yields no frames at all.
            UnsupportedCall: If the input is not a file on disk, as
                :c:func:`pcap_open_offline` can only open a savefile by name.

        """
        from pcapkit.foundation.engines.pcap import PCAP  # isort:skip

        ext = self._extractor

        if ext._exlyr != 'none' or ext._exptl != 'null':
            warn("'Extractor(engine=pypcap)' does not support protocol and layer threshold; "
                 f"'layer={ext._exlyr}' and 'protocol={ext._exptl}' ignored",
                 AttributeWarning, stacklevel=stacklevel())

        if ext.magic_number not in PCAP.MAGIC_NUMBER:
            raise FormatError(f'unsupported file format: {ext.magic_number!r}; '
                              'the PyPCAP engine reads PCAP savefiles only')

        if not os.path.isfile(ext._ifnm):
            raise UnsupportedCall(f"'Extractor(engine=pypcap)' requires a file on disk, "
                                  f'but {ext._ifnm!r} is not one; libpcap opens savefiles '
                                  'by name and cannot read an in-memory stream')

        if ext._flag_r and (ext._ipv4 or ext._ipv6 or ext._tcp):
            ext._flag_r = False
            ext._reasm = ReassemblyManager(ipv4=None, ipv6=None, tcp=None)
            warn("'Extractor(engine=pypcap)' object dose not support reassembly; "
                 f"so 'ipv4={ext._ipv4}', 'ipv6={ext._ipv6}' and 'tcp={ext._tcp}' will be ignored",
                 AttributeWarning, stacklevel=stacklevel())

        if ext._flag_t and ext._tcp:
            ext._flag_t = False
            ext._trace = TraceFlowManager(tcp=None)
            warn("'Extractor(engine=pypcap)' object dose not support flow tracing; "
                 f"so 'tcp={ext._tcp}' will be ignored", AttributeWarning, stacklevel=stacklevel())

        # NOTE: ``promisc=False`` is defensive only -- the offline branch of
        # ``pcap.pcap`` ignores it, but should ``pcap_open_offline`` ever fail the
        # constructor falls through to opening the name as a live device, and we
        # do not want that attempt to request promiscuous mode.
        handle = cast('Handle', self._expkg.pcap(name=ext._ifnm, promisc=False))
        self._dlink = Enum_LinkType.get(handle.datalink())

        # setup verbose handler
        if ext._flag_v:
            from pcapkit.toolkit.pypcap import packet2chain  # isort:skip
            ext._vfunc = lambda e, f: print(
                f'Frame {e._frnum:>3d}: {packet2chain(f[1], data_link=self._dlink)}'  # pylint: disable=protected-access
            )  # pylint: disable=logging-fstring-interpolation

        # extract & analyse file
        self._extmp = iter(handle)

    def read_frame(self) -> 'RawFrame':
        """Read frames with PyPCAP engine.

        Returns:
            The ``(timestamp, bytes)`` pair as yielded by :class:`pcap.pcap`.

        See Also:
            Please refer to :meth:`PCAP.read_frame <pcapkit.foundation.engines.pcap.PCAP.read_frame>`
            for more operational information.

        """
        from pcapkit.toolkit.pypcap import packet2dict  # isort:skip
        ext = self._extractor

        # fetch PyPCAP packet
        frame = cast('RawFrame', next(self._extmp))
        timestamp, packet = frame

        # verbose output
        ext._frnum += 1
        ext._vfunc(ext, frame)

        # write plist
        frnum = f'Frame {ext._frnum}'
        if not ext._flag_q:
            info = packet2dict(packet, timestamp, data_link=self._dlink)
            if ext._flag_f:
                ofile = ext._ofile(f'{ext._ofnm}/{frnum}.{ext._fext}')
                ofile(info, name=frnum)
            else:
                ext._ofile(info, name=frnum)
                ofile = ext._ofile
            ext._offmt = ofile.kind

        # NOTE: reassembly and flow tracing are disabled in ``run``, so there is
        # deliberately no bookkeeping for either here.

        # record frames
        if ext._flag_d:
            ext._frame.append(frame)

        # return frame record
        return frame

    def close(self) -> 'None':
        """Close engine.

        This method closes the underlying :class:`pcap.pcap` handle. It is
        idempotent, as :meth:`Extractor._cleanup
        <pcapkit.foundation.extraction.Extractor._cleanup>` and
        :meth:`Extractor.__exit__ <pcapkit.foundation.extraction.Extractor.__exit__>`
        may both reach it, and :meth:`pcap.pcap.close` is not safe to call twice.

        """
        if self._closed or self._extmp is None:
            return
        self._closed = True
        cast('Handle', self._extmp).close()
