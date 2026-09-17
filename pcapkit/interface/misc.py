# -*- coding: utf-8 -*-
"""Auxiliary Interface
=========================

.. module:: pcapkit.interface.misc

:mod:`pcapkit.interface.misc` contains miscellaneous
user interface functions, classes, etc., which are
generally provided per user's requests.

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
from pcapkit.utilities.warnings import EngineWarning, FormatWarning, warn

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
    #: Every key registered in :attr:`Extractor.__output__
    #: <pcapkit.foundation.extraction.Extractor.__output__>` and in
    #: :attr:`TraceFlowBase.__output__
    #: <pcapkit.foundation.traceflow.traceflow.TraceFlowBase.__output__>` -- the two
    #: registries expose the same eight keys. This used to name only four of them,
    #: which made ``'cap'`` and the ``'txt'``/``'xml'`` aliases unspellable for a
    #: type checker even though every one of them is accepted at runtime.
    Formats = Literal['pcap', 'cap', 'json', 'tree', 'text', 'txt', 'plist', 'xml']
    # NOTE: this alias duplicates the one in ``pcapkit.foundation.extraction``;
    # both copies need updating when a new engine lands.
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


def follow_tcp_stream(fin: 'Optional[str]' = None, verbose: 'bool' = False,              # Extrator options
                      extension: 'bool' = True, engine: 'Optional[Engines]' = None,
                      fout: 'Optional[str]' = None, format: 'Optional[Formats]' = None,  # TraceFlow options # pylint: disable=redefined-builtin
                      byteorder: 'ByteOrder' = sys.byteorder, nanosecond: 'bool' = False,
                      trace_bidirectional: 'bool' = True,
                      trace_analyse: 'bool' = False) -> 'tuple[Stream, ...]':
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
        trace_bidirectional: whether both halves of a conversation are followed
            as one stream, which is the default -- a stream then holds the
            frames and the reassembled payload of *both* directions, which is
            what "following a TCP stream" means elsewhere. :data:`False`
            restores one stream per direction.
        trace_analyse: whether each traced flow reassembles its application
            layer, so that ``Index.packet`` can be read off
            :attr:`Extractor.trace <pcapkit.foundation.extraction.Extractor.trace>`.
            Off by default, and independent of the ``conversations`` this
            function returns -- those come from the reassembly below, which runs
            either way.

    Returns:
        List of extracted TCP streams.

    """
    # NOTE: all of these engines disable TCP flow tracing outright -- PyShark
    # because ``pcapkit`` has no reassembly adapter for it, PyPCAP and PCAP_CT
    # because they perform no protocol dissection at all -- so
    # ``extraction.trace`` below would raise instead of yielding streams.
    if engine is not None and engine.lower() in ('pyshark', 'pypcap', 'pcap_ct'):
        warn(f'unsupported extraction engine: {engine}; fallback to default engine',
             EngineWarning, stacklevel=stacklevel())
        engine = None

    # NOTE: the DPKT and Scapy engines hand their frames to the flow tracer as plain
    # :obj:`dict`\\ s, which the PCAP trace dumper cannot re-serialise -- it reaches
    # for ``frame.packet`` and dies with ``AttributeError: 'dict' object has no
    # attribute 'packet'`` (#399). The tracer defaults an unset ``format`` to
    # ``'pcap'``, so following a stream through either engine would crash *during
    # extraction*, before the reassembly below ever runs.
    #
    # :class:`Extractor <pcapkit.foundation.extraction.Extractor>` now guards both
    # engines itself, so this is no longer what keeps the extraction alive -- it is
    # what keeps it *quiet*. The two guards choose the same replacement format and so
    # produce byte-identical traces; they differ only in when they complain. The
    # Extractor warns for every substitution it makes, including the one nobody asked
    # for, whereas here an unset ``format`` is not a request and is upgraded silently,
    # and only an explicit but unusable one draws a warning -- with a message naming
    # the engine's limitation rather than the ``trace_format=`` argument this function
    # does not expose. Removing this therefore would not change any trace file, but it
    # would make ``follow_tcp_stream(engine='dpkt')`` warn about a default the caller
    # never chose.
    if engine is not None and engine.lower() in ('dpkt', 'scapy') and format in ('pcap', 'cap', None):
        if format is not None:
            warn(f"extraction engine {engine} cannot write '{format}' trace files; "
                 "using 'json' instead", FormatWarning, stacklevel=stacklevel())
        format = 'json'

    extraction = Extractor(fin=fin, fout=None, format=None, auto=True, extension=extension,
                           store=True, files=False, nofile=True, verbose=verbose, engine=engine,
                           layer=None, protocol=None, ip=False, ipv4=False, ipv6=False, tcp=True,
                           reassembly=False, trace=True, trace_fout=fout, trace_format=format,
                           trace_byteorder=byteorder, trace_nanosecond=nanosecond,
                           trace_bidirectional=trace_bidirectional,
                           trace_analyse=trace_analyse)  # type: ignore[var-annotated]

    # NOTE: ``Extractor.engine`` returns the running engine *instance* (see
    # :meth:`Extractor.engine <pcapkit.foundation.extraction.Extractor.engine>`),
    # never its name -- so the historical ``extraction.engine == 'dpkt'`` compared an
    # object against a string and was *always* :data:`False`. Every capture then fell
    # through to the pcapkit adapter, which crashed on DPKT frames and silently
    # returned no streams on Scapy frames (#399). Dispatch on the engine *type*
    # instead, and via :func:`isinstance` so that a third-party engine subclassing a
    # built-in still reaches the adapter that matches its frames.
    #
    # The adapter and its call convention are chosen together: the pcapkit-native
    # adapters (:mod:`~pcapkit.toolkit.pcap` and :mod:`~pcapkit.toolkit.pcapng`) read
    # the frame number straight off the dissected frame and accept no ``count``,
    # whereas the third-party adapters have no such number and must be handed the
    # frame index as ``count`` -- so the two forms are not interchangeable.
    exeng = extraction.engine
    tcp_reassembly = None  # type: Optional[ReassemblyAdapter]
    pass_count = True
    #: Reads a frame's capture timestamp back off the frame, for the one adapter
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
        # NOTE: DPKT's reader hands ``(timestamp, bytes)`` back and only the octets
        # become a packet, so its adapters take the capture timestamp as an
        # argument rather than finding it on the frame. That timestamp is real and
        # available -- :class:`~pcapkit.foundation.engines.dpkt.DPKT` attaches it to
        # every frame it reads, precisely so that a reader arriving after the
        # extraction loop (like this one) can get it back.
        tcp_reassembly = cast('ReassemblyAdapter', tk_dpkt.tcp_reassembly)
        timestamp_of = tk_dpkt.packet2timestamp
    elif isinstance(exeng, Scapy_Engine):
        from pcapkit.toolkit import scapy as tk_scapy  # isort: skip # pylint: disable=import-outside-toplevel
        tcp_reassembly = cast('ReassemblyAdapter', tk_scapy.tcp_reassembly)
    elif isinstance(exeng, PyPCAPFile_Engine):
        from pcapkit.toolkit import pypcapfile as tk_pypcapfile  # isort: skip # pylint: disable=import-outside-toplevel
        tcp_reassembly = cast('ReassemblyAdapter', tk_pypcapfile.tcp_reassembly)
    else:
        # A third-party engine pcapkit ships no reassembly adapter for. Falling back
        # to the pcapkit adapter is exactly the #399 failure mode -- a wrong or empty
        # result indistinguishable from a real one -- so warn and return no streams
        # rather than reassemble frames whose shape we cannot parse.
        warn(f'unsupported extraction engine for TCP stream following: {exeng.name}; '
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
                reassembly.datagram, key=lambda datagram: datagram.index  # make sure the converstations are in order
            )),
        ))
    return tuple(streams)
