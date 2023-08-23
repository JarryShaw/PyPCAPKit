# -*- coding: utf-8 -*-
"""Auxiliary Interface
=========================

.. module:: pcapkit.interface.misc

:mod:`pcapkit.interface.misc` contains miscellaneous
user interface functions, classes, etc., which are
generally provided per user's requests.

"""
import sys
from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import Info, info_final
from pcapkit.foundation.extraction import Extractor
from pcapkit.foundation.reassembly.tcp import TCP as TCP_Reassembly
from pcapkit.utilities.exceptions import stacklevel
from pcapkit.utilities.warnings import EngineWarning, warn

if TYPE_CHECKING:
    from typing import Optional

    from typing_extensions import Literal

    from pcapkit.foundation.extraction import Packet

    ByteOrder = Literal['little', 'big']
    Formats = Literal['pcap', 'json', 'tree', 'plist']
    Engines = Literal['default', 'pcapkit', 'dpkt', 'scapy', 'pyshark']

__all__ = ['follow_tcp_stream']

###############################################################################
# Follow TCP Stream
###############################################################################


@info_final
class Stream(Info):
    """Data model for TCP streams."""

    #: Output filename.
    filename: 'Optional[str]'
    #: Packet list.
    packets: 'tuple[Packet, ...]'
    #: TCP conversation.
    conversations: 'tuple[bytes | tuple[bytes, ...], ...]'

    if TYPE_CHECKING:
        def __init__(self, filename: 'Optional[str]', packets: 'tuple[Packet, ...]', conversations: 'tuple[bytes | tuple[bytes, ...], ...]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long


def follow_tcp_stream(fin: 'Optional[str]' = None, verbose: 'bool' = False,              # Extrator options
                      extension: 'bool' = True, engine: 'Optional[Engines]' = None,
                      fout: 'Optional[str]' = None, format: 'Optional[Formats]' = None,  # TraceFlow options # pylint: disable=redefined-builtin
                      byteorder: 'ByteOrder' = sys.byteorder, nanosecond: 'bool' = False) -> 'tuple[Stream, ...]':
    """Follow TCP streams.

    Arguments:
        fin: file name to be read; if file not exist, raise :exc:`FileNotFound`
        extension: if check and append extensions to output file
        verbose: if print verbose output information
        engine: extraction engine to be used

        fout: path name for flow tracer if necessary
        format: output file format of flow tracer
        byteorder: output file byte order
        nanosecond: output nanosecond-resolution file flag

    Returns:
        List of extracted TCP streams.

    """
    if engine is not None and engine.lower() == 'pyshark':
        warn(f'unsupported extraction engine: {engine}; fallback to default engine',
             EngineWarning, stacklevel=stacklevel())
        engine = None

    extraction = Extractor(fin=fin, fout=None, format=None, auto=True, extension=extension,
                           store=True, files=False, nofile=True, verbose=verbose, engine=engine,
                           layer=None, protocol=None, ip=False, ipv4=False, ipv6=False, tcp=True,
                           reassembly=False, trace=True, trace_fout=fout, trace_format=format,
                           trace_byteorder=byteorder, trace_nanosecond=nanosecond)  # type: ignore[var-annotated]

    fallback = False
    if extraction.engine == 'dpkt':  # type: ignore[comparison-overlap]
        from pcapkit.toolkit.dpkt import tcp_reassembly  # pylint: disable=import-outside-toplevel
    elif extraction.engine == 'scapy':  # type: ignore[comparison-overlap]
        from pcapkit.toolkit.scapy import tcp_reassembly  # isort: skip # pylint: disable=import-outside-toplevel
    else:
        from pcapkit.toolkit.pcap import tcp_reassembly  # type: ignore[assignment] # isort: skip # pylint: disable=import-outside-toplevel
        fallback = True

    streams = []  # type: list[Stream]
    frames = extraction.frame
    for stream in extraction.trace.tcp:
        reassembly = TCP_Reassembly(strict=False)

        packets = []  # type: list[Packet]
        for index in stream.index:
            frame = frames[index-1]
            packets.append(frame)

            if fallback:
                data = tcp_reassembly(frame)
            else:
                data = tcp_reassembly(frame, count=index)

            if data is not None:
                reassembly(data)

        streams.append(Stream(
            filename=stream.fpout,
            packets=tuple(packets),
            conversations=tuple(datagram.payload for datagram in sorted(
                reassembly.datagram, key=lambda datagram: datagram.index  # make sure the converstations are in order
            )),
        ))
    return tuple(streams)
