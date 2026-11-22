# -*- coding: utf-8 -*-
"""Auxiliary Interface
=========================

.. module:: pcapkit.interface.misc

:mod:`pcapkit.interface.misc` contains auxiliary user interface
functions and their data models.

"""
from typing import TYPE_CHECKING, cast

from pcapkit.corekit.infoclass import Info, info_final
from pcapkit.foundation.engines.dpkt import DPKT as DPKT_Engine
from pcapkit.foundation.engines.pcap import PCAP as PCAP_Engine
from pcapkit.foundation.engines.pcapng import PCAPNG as PCAPNG_Engine
from pcapkit.foundation.engines.pypcapfile import PyPCAPFile as PyPCAPFile_Engine
from pcapkit.foundation.engines.scapy import Scapy as Scapy_Engine
from pcapkit.foundation.extraction import Extractor
from pcapkit.foundation.options import TraceFlowOptions
from pcapkit.foundation.reassembly.tcp import TCP as TCP_Reassembly
from pcapkit.utilities.exceptions import FormatError, stacklevel
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


def follow_tcp_stream(fin: 'str', *, verbose: 'bool' = False,           # Extractor options
                      engine: 'Optional[Engines]' = None,
                      traceflow: 'Optional[TraceFlowOptions]' = None) -> 'tuple[Stream, ...]':  # TraceFlow options
    """Follow TCP streams.

    Arguments:
        fin: file name to be read, as named; if the file does not exist, raise
            :exc:`~pcapkit.utilities.exceptions.FileNotFound`
        verbose: if print verbose output information
        engine: extraction engine to be used
        traceflow: flow tracing settings, whose
            :attr:`~pcapkit.foundation.options.TraceFlowOptions.protocols` name
            ``'tcp'``; :data:`None` takes their defaults. With
            :attr:`~pcapkit.foundation.options.TraceFlowOptions.analyze`,
            :attr:`Index.packet <pcapkit.foundation.traceflow.data.tcp.Index.packet>` can be read off
            :attr:`Extractor.traceflow <pcapkit.foundation.extraction.Extractor.traceflow>`;
            the returned ``conversations`` come from the TCP reassembly this
            function always runs. With
            :attr:`~pcapkit.foundation.options.TraceFlowOptions.bidirectional`,
            the default, a stream holds both directions of a conversation.

    Returns:
        Tuple of extracted TCP streams.

    Raises:
        FormatError: If ``traceflow`` does not name ``'tcp'``.

    .. versionchanged:: 1.5.0

       ``trace_bidirectional`` and ``trace_analyse`` are added. By default a
       stream holds both directions of a conversation; 1.4.x returned one
       stream per direction.

    .. versionchanged:: 1.7.0

       ``traceflow`` replaces ``fout``, ``format``, ``byteorder``, ``nanosecond``,
       ``trace_bidirectional`` and ``trace_analyse``, with no alias, and every
       parameter after ``fin`` is keyword-only. ``fin`` is required and opened
       as named, so ``extension`` is removed (:issue:`2836`).

    """
    if traceflow is None:
        traceflow = TraceFlowOptions(protocols=['tcp'])
    elif 'tcp' not in traceflow.protocols:
        raise FormatError(f'follow_tcp_stream traces TCP, but traceflow names {list(traceflow.protocols)!r}')

    # NOTE: PyShark has no TCP reassembly adapter, and PyPCAP and PCAP_CT disable
    # TCP flow tracing, so none of them can follow a stream.
    if engine is not None and engine.lower() in ('pyshark', 'pypcap', 'pcap_ct'):
        warn(f'unsupported extraction engine: {engine!r}; using default engine instead',
             EngineWarning, stacklevel=stacklevel())
        engine = None

    extraction = Extractor(fin, verbose=verbose, engine=engine or 'default',
                           traceflow=traceflow)  # type: ignore[var-annotated]

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
    for stream in extraction.traceflow.tcp:
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
