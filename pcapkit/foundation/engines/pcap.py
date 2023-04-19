# -*- coding: utf-8 -*-
"""PCAP Support
==================

.. module:: pcapkit.foundation.engines.pcap

This module contains the implementation for PCAP file extraction
support, as is used by :class:`pcapkit.foundation.extraction.Extractor`.

"""
from pcapkit.foundation.engines.engine import Engine
from pcapkit.protocols.misc.pcap.frame import Frame
from pcapkit.protocols.misc.pcap.header import Header

__all__ = ['PCAP']


class PCAP(Engine[Frame]):
    """PCAP file extraction support.

    Args:
        extractor: :class:`~pcapkit.foundation.extraction.Extractor` instance.

    """

    MAGIC_NUMBER = (
        b'\xa1\xb2\x3c\x4d',
        b'\xa1\xb2\xc3\xd4',
        b'\x4d\x3c\xb2\xa1',
        b'\xd4\xc3\xb2\xa1',
    )

    ##########################################################################
    # Properties.
    ##########################################################################

    @classmethod
    def name(cls) -> 'str':
        """Engine name."""
        return 'PCAP'

    @classmethod
    def module(cls) -> 'str':
        """Engine module name."""
        return 'pcapkit.foundation.engine.pcap'

    ##########################################################################
    # Methods.
    ##########################################################################

    def run(self) -> 'None':
        """Start extraction.

        This method is the entry point for PCAP file extraction. It will start
        the extraction process by parsing the PCAP global header and then halt
        the extraction process until the :meth:`self.extractor._read_frame <Extractor._read_frame>` method
        is called.

        The method will parse the PCAP global header and save the parsed result
        as :attr:`self.extractor._gbhdr <Extractor._gbhdr>`. Information such as
        PCAP version, data link layer protocol type, nanosecond flag and byteorder
        will also be save the current :class:`Extractor` instance.

        If TCP flow tracing is enabled, the nanosecond flag and byteorder will
        be used for the output PCAP file of the traced TCP flows.

        For output, the method will dump the parsed PCAP global header under
        the name of ``Global Header``.

        """
        # pylint: disable=attribute-defined-outside-init,protected-access
        ext = self._extractor

        ext._gbhdr = Header(ext._ifile)
        ext._vinfo = ext._gbhdr.version
        ext._dlink = ext._gbhdr.protocol
        ext._nnsec = ext._gbhdr.nanosecond

        if ext._flag_t:
            ext._trace._endian = ext._gbhdr.byteorder
            ext._trace._nnsecd = ext._gbhdr.nanosecond

        if ext._flag_q:
            return

        if ext._flag_f:
            ofile = ext._ofile(f'{ext._ofnm}/Global Header.{ext._fext}')
            ofile(ext._gbhdr.info.to_dict(), name='Global Header')
        else:
            ext._ofile(ext._gbhdr.info.to_dict(), name='Global Header')
            ofile = ext._ofile
        ext._type = ofile.kind

    def read_frame(self) -> 'Frame':
        """Read frames.

        This method performs following operations:

        - extract frames and each layer of packets;
        - make :class:`~pcapkit.corekit.infoclass.Info` object out of frame properties;
        - write to output file with corresponding dumper;
        - reassemble IP and/or TCP datagram;
        - trace TCP flows if any;
        - record frame :class:`~pcapkit.corekit.infoclass.Info` object to frame storage.

        Returns:
            Parsed frame instance.

        """
        from pcapkit.toolkit.default import (ipv4_reassembly, ipv6_reassembly, tcp_reassembly,
                                             tcp_traceflow)
        ext = self._extractor

        # read frame header
        frame = Frame(ext._ifile, num=ext._frnum+1, header=ext._gbhdr.info,
                      layer=ext._exlyr, protocol=ext._exptl, nanosecond=ext._nnsec)
        ext._frnum += 1

        # verbose output
        ext._vfunc(ext, frame)

        # write plist
        frnum = f'Frame {ext._frnum}'
        if not ext._flag_q:
            if ext._flag_f:
                ofile = ext._ofile(f'{ext._ofnm}/{frnum}.{ext._fext}')
                ofile(frame.info.to_dict(), name=frnum)
            else:
                ext._ofile(frame.info.to_dict(), name=frnum)

        # record fragments
        if ext._flag_r:
            if ext._ipv4:
                data_ipv4 = ipv4_reassembly(frame)
                if data_ipv4 is not None:
                    ext._reasm.ipv4(data_ipv4)
            if ext._ipv6:
                data_ipv6 = ipv6_reassembly(frame)
                if data_ipv6 is not None:
                    ext._reasm.ipv6(data_ipv6)
            if ext._tcp:
                data_tcp = tcp_reassembly(frame)
                if data_tcp is not None:
                    ext._reasm.tcp(data_tcp)

        # trace flows
        if ext._flag_t:
            if ext._tcp:
                data_tf_tcp = tcp_traceflow(frame, data_link=ext._dlink)
                if data_tf_tcp is not None:
                    ext._trace.tcp(data_tf_tcp)

        # record frames
        if ext._flag_d:
            ext._frame.append(frame)

        # return frame record
        return frame
