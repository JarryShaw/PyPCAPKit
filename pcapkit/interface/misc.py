# -*- coding: utf-8 -*-
"""Auxiliary Interface
=========================

.. module:: pcapkit.interface.misc

:mod:`pcapkit.interface.misc` contains auxiliary user interface
functions and their data models.

"""
import sys
from typing import TYPE_CHECKING, cast

from pcapkit.corekit.infoclass import Info, info_final
from pcapkit.foundation.engines.dpkt import DPKT as DPKT_Engine
from pcapkit.foundation.engines.pcap import PCAP as PCAP_Engine
from pcapkit.foundation.engines.pcapng import PCAPNG as PCAPNG_Engine
from pcapkit.foundation.engines.pypcapfile import PyPCAPFile as PyPCAPFile_Engine
from pcapkit.foundation.engines.scapy import Scapy as Scapy_Engine
from pcapkit.foundation.extraction import Extractor
from pcapkit.foundation.reassembly.tcp import TCP as TCP_Reassembly
from pcapkit.utilities.exceptions import stacklevel
from pcapkit.utilities.warnings import EngineWarning, warn

if TYPE_CHECKING:
    from typing import Any, Callable, Optional

    from typing_extensions import Literal

    from pcapkit.foundation.extraction import Packet
    from pcapkit.foundation.reassembly.data.tcp import Packet as TCP_Data

    #: A toolkit's ``tcp_reassembly`` adapter. The pcapkit-native adapters take only
    #: the frame; the third-party ones also accept a ``count`` keyword -- hence the
    #: open ``...`` parameter list, which lets both call shapes type-check.
    ReassemblyAdapter = Callable[..., 'Optional[TCP_Data]']

    ByteOrder = Literal['little', 'big']
    #: Every output format key shipped in
    #: :attr:`Extractor.__output__ <pcapkit.foundation.extraction.Extractor.__output__>`
    #: and :attr:`TraceFlow.__output__
    #: <pcapkit.foundation.traceflow.traceflow.TraceFlow.__output__>`, aliases
    #: included (``'cap'``, ``'xml'``, ``'text'``, ``'txt'``).
    Formats = Literal['pcap', 'cap', 'json', 'tree', 'text', 'txt', 'plist', 'xml']
    # NOTE: this alias duplicates the one in ``pcapkit.foundation.extraction``;
    # each copy needs updating when a new engine lands.
    Engines = Literal['default', 'pcapkit', 'dpkt', 'scapy', 'pyshark', 'pypcap', 'pcap_ct',
                      'pypcapfile']

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


def follow_tcp_stream(fin: 'Optional[str]' = None, verbose: 'bool' = False,              # Extractor options
                      extension: 'bool' = True, engine: 'Optional[Engines]' = None,
                      fout: 'Optional[str]' = None, format: 'Optional[Formats]' = None,  # TraceFlow options # pylint: disable=redefined-builtin
                      byteorder: 'ByteOrder' = sys.byteorder, nanosecond: 'bool' = False,
                      trace_bidirectional: 'bool' = True,
                      trace_analyse: 'bool' = False) -> 'tuple[Stream, ...]':
    """Follow TCP streams.

    Arguments:
        fin: file name to be read; if the file does not exist, raise
            :exc:`~pcapkit.utilities.exceptions.FileNotFound`
        extension: if check and append extensions to output file
        verbose: if print verbose output information
        engine: extraction engine to be used

        fout: path name for flow tracer if necessary
        format: output file format of flow tracer
        byteorder: output file byte order
        nanosecond: output nanosecond-resolution file flag
        trace_bidirectional: whether both directions of a conversation are
            followed as one stream, which is the default; :data:`False` gives
            one stream per direction
        trace_analyse: whether each traced flow reassembles its application
            layer, so that :attr:`Index.packet <pcapkit.foundation.traceflow.data.tcp.Index.packet>` can be read off
            :attr:`Extractor.trace <pcapkit.foundation.extraction.Extractor.trace>`.
            Off by default; the returned ``conversations`` come from the TCP
            reassembly this function always runs.

    Returns:
        Tuple of extracted TCP streams.

    .. versionchanged:: 1.5.0

       ``trace_bidirectional`` and ``trace_analyse`` are added. By default a
       stream holds both directions of a conversation; 1.4.x returned one
       stream per direction.

    """
    # NOTE: PyShark has no TCP reassembly adapter, and PyPCAP and PCAP_CT disable
    # TCP flow tracing, so none of them can follow a stream.
    if engine is not None and engine.lower() in ('pyshark', 'pypcap', 'pcap_ct'):
        warn(f'unsupported extraction engine: {engine!r}; using default engine instead',
             EngineWarning, stacklevel=stacklevel())
        engine = None

    extraction = Extractor(fin=fin, fout=None, format=None, auto=True, extension=extension,
                           store=True, files=False, nofile=True, verbose=verbose, engine=engine,
                           layer=None, protocol=None, ip=False, ipv4=False, ipv6=False, tcp=True,
                           reassembly=False, trace=True, trace_fout=fout, trace_format=format,
                           trace_byteorder=byteorder, trace_nanosecond=nanosecond,
                           trace_bidirectional=trace_bidirectional,
                           trace_analyse=trace_analyse)  # type: ignore[var-annotated]

    # NOTE: dispatch on the engine instance with ``isinstance`` (#399), so a subclass
    # of a built-in engine reaches its adapter; only third-party adapters take ``count``.
    exeng = extraction.engine
    tcp_reassembly = None  # type: Optional[ReassemblyAdapter]
    pass_count = True
    #: Reads a frame's capture timestamp back off the frame, for an adapter
    #: whose signature takes it. :data:`None` for the adapters that find it
    #: themselves.
    timestamp_of = None  # type: Optional[Callable[[Any], float]]
    if isinstance(exeng, PCAP_Engine):
        from pcapkit.toolkit import pcap as tk_pcap  # isort: skip # pylint: disable=import-outside-toplevel
        tcp_reassembly, pass_count = cast('ReassemblyAdapter', tk_pcap.tcp_reassembly), False
    elif isinstance(exeng, PCAPNG_Engine):
        from pcapkit.toolkit import pcapng as tk_pcapng  # isort: skip # pylint: disable=import-outside-toplevel
        tcp_reassembly, pass_count = cast('ReassemblyAdapter', tk_pcapng.tcp_reassembly), False
    elif isinstance(exeng, DPKT_Engine):
        from pcapkit.toolkit import dpkt as tk_dpkt  # isort: skip # pylint: disable=import-outside-toplevel
        # NOTE: DPKT's adapters take the capture timestamp as an argument; the
        # DPKT engine attaches it to every frame it reads, for readers like this.
        tcp_reassembly = cast('ReassemblyAdapter', tk_dpkt.tcp_reassembly)
        timestamp_of = tk_dpkt.packet2timestamp
    elif isinstance(exeng, Scapy_Engine):
        from pcapkit.toolkit import scapy as tk_scapy  # isort: skip # pylint: disable=import-outside-toplevel
        tcp_reassembly = cast('ReassemblyAdapter', tk_scapy.tcp_reassembly)
    elif isinstance(exeng, PyPCAPFile_Engine):
        from pcapkit.toolkit import pypcapfile as tk_pypcapfile  # isort: skip # pylint: disable=import-outside-toplevel
        tcp_reassembly = cast('ReassemblyAdapter', tk_pypcapfile.tcp_reassembly)
    else:
        # No adapter for this engine: falling back to the pcapkit one would give a
        # wrong or empty result indistinguishable from a real one (#399).
        warn(f'unsupported extraction engine for TCP stream following: {exeng.name!r}; '
             'returning no streams', EngineWarning, stacklevel=stacklevel())
        return ()

    streams = []  # type: list[Stream]
    frames = extraction.frame
    for stream in extraction.trace.tcp:
        reassembly = TCP_Reassembly(strict=False)

        packets = []  # type: list[Packet]
        for index in stream.index:
            frame = frames[index-1]
            packets.append(frame)

            if timestamp_of is not None:
                data = tcp_reassembly(frame, timestamp_of(frame), count=index)
            elif pass_count:
                data = tcp_reassembly(frame, count=index)
            else:
                data = tcp_reassembly(frame)

            if data is not None:
                reassembly(data)

        streams.append(Stream(
            filename=stream.fpout,
            packets=tuple(packets),
            conversations=tuple(datagram.payload for datagram in sorted(
                reassembly.datagram, key=lambda datagram: datagram.index  # make sure the conversations are in order
            )),
        ))
    return tuple(streams)
