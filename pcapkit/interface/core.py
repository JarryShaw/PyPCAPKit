# -*- coding: utf-8 -*-
"""Core Interface
====================

.. module:: pcapkit.interface.core

:mod:`pcapkit.interface.core` defines the user-facing functions and
macros, which wrap the classes of :mod:`pcapkit.foundation`.

"""
import sys
from typing import TYPE_CHECKING

from pcapkit.foundation.extraction import Extractor
from pcapkit.foundation.traceflow.tcp import TCP as TCP_TraceFlow
from pcapkit.protocols.protocol import ProtocolBase
from pcapkit.utilities.exceptions import FormatError

if TYPE_CHECKING:
    from typing import IO, Iterable, Mapping, Optional, Type

    from typing_extensions import Literal

    from pcapkit.corekit.context import ContextRegistry, ProtocolContext
    from pcapkit.foundation.extraction import Engines, Layers, Protocols, VerboseHandler
    from pcapkit.foundation.options import (DumpOptions, ReassemblyOptions, StreamOptions,
                                            TraceFlowOptions)
    from pcapkit.foundation.reassembly.reassembly import ReassemblyBase
    from pcapkit.foundation.traceflow.traceflow import TraceFlowBase

__all__ = [
    'extract', 'reassemble', 'trace',                       # interface functions
    'TREE', 'JSON', 'PLIST', 'PCAP',                        # format macros
    'LINK', 'INET', 'TRANS', 'APP', 'RAW',                  # layer macros
    'DPKT', 'Scapy', 'PyShark', 'PCAPKit',                  # engine macros
    'PyPCAP', 'PCAP_CT', 'PyPCAPFile',                      # engine macros
]

# output file formats
TREE = 'tree'
JSON = 'json'
PLIST = 'plist'
PCAP = 'pcap'

# layer thresholds
RAW = 'none'
LINK = 'link'
INET = 'internet'
TRANS = 'transport'
APP = 'application'

# extraction engines
#
# NOTE: a third-party value is the engine's key in ``Extractor.__engine__``, not
# its display name; an unknown key only warns and falls back to ``'default'``.
DPKT = 'dpkt'
Scapy = 'scapy'
PCAPKit = 'default'
PyShark = 'pyshark'
PyPCAP = 'pypcap'
PCAP_CT = 'pcap_ct'
PyPCAPFile = 'pypcapfile'


def extract(fin: 'str | IO[bytes]', *,
            dump: 'Optional[DumpOptions]' = None,
            engine: 'Engines' = 'default',
            layer: 'Optional[Layers | Type[ProtocolBase]]' = None,
            protocol: 'Optional[Protocols]' = None,
            context: 'Optional[ContextRegistry | ProtocolContext | Mapping[str, ProtocolContext] | Iterable[ProtocolContext]]' = None,  # pylint: disable=line-too-long
            reassembly: 'Optional[ReassemblyOptions | Iterable[str]]' = None,
            traceflow: 'Optional[TraceFlowOptions | Iterable[str]]' = None,
            stream: 'Optional[StreamOptions]' = None,
            auto: 'bool' = True, store: 'bool' = True,
            verbose: 'bool | VerboseHandler' = False) -> 'Extractor':
    """Extract a PCAP file.

    Arguments:
        fin: file name to be read, as named, or a binary IO object;
            if the file does not exist, raise :exc:`~pcapkit.utilities.exceptions.FileNotFound`
        dump: output settings, a
            :class:`~pcapkit.foundation.options.DumpOptions`; :data:`None`
            writes no output
        engine: extraction engine to be used
        layer: extract til which layer, by name or as a protocol class
        protocol: extract til which protocol
        context: caller supplied parsing context for protocols that need
            information not carried on the wire, keyed by protocol index ID --
            cf. :mod:`pcapkit.corekit.context`. The motivating case is
            :class:`~pcapkit.protocols.internet.esp.protocol.ESP`, which needs the
            Security Association to find the trailer and decrypt the payload::

                >>> from pcapkit.protocols.internet.esp.protocol import (Cipher, ESPContext,
                ...                                            SecurityAssociation)
                >>> sa = SecurityAssociation(spi=0x4321, encryption=Cipher.AES_CBC,
                ...                          encryption_key=key)
                >>> extraction = pcapkit.extract('esp.pcap', context=ESPContext(sa))

        reassembly: reassembly settings, a
            :class:`~pcapkit.foundation.options.ReassemblyOptions`, or the
            names of the reassemblers to enable, each as registered in
            :attr:`Extractor.__reassembly__
            <pcapkit.foundation.extraction.Extractor.__reassembly__>`;
            :data:`None`, or no names, reassembles nothing
        traceflow: flow tracing settings, a
            :class:`~pcapkit.foundation.options.TraceFlowOptions`, or the names
            of the flow tracers to enable, each as registered in
            :attr:`Extractor.__traceflow__
            <pcapkit.foundation.extraction.Extractor.__traceflow__>`;
            :data:`None`, or no names, traces nothing
        stream: input stream settings, a
            :class:`~pcapkit.foundation.options.StreamOptions`; :data:`None`
            takes their defaults
        auto: if automatically run till EOF
        store: if store extracted packet info
        verbose: a :obj:`bool` value or a function that takes the
            :class:`~pcapkit.foundation.extraction.Extractor`
            instance and current parsed frame (depends on engine selected) as
            parameters to print verbose output information

    Returns:
        An :class:`~pcapkit.foundation.extraction.Extractor` object.

    .. versionchanged:: 1.1.1.post2

       ``strict`` is renamed ``reasm_strict``, with no alias, and
       ``reasm_store`` is inserted after it, so a positional argument from
       ``trace`` onwards moves one place along.

    .. versionchanged:: 1.5.0

       ``reasm_timeout``, ``trace_bidirectional`` and ``trace_analyse`` are
       inserted among the positional parameters and ``context`` is appended,
       so a positional argument after ``reasm_store`` has to move to a
       keyword. Flows are traced bidirectionally by default, and IPv4 and IPv6
       reassembly buffers expire after 60 seconds of capture time.

    .. versionchanged:: 1.6.0

       ``dtls`` is inserted after ``tcp``, so a positional argument from
       ``buffer_size`` onwards moves one place along.

    .. versionchanged:: 1.7.0

       Takes exactly the parameters of
       :class:`~pcapkit.foundation.extraction.Extractor`, whose 1.7.0 note
       lists what is grouped and what is removed (:issue:`2836`).

    """
    return Extractor(fin, dump=dump, engine=engine, layer=layer, protocol=protocol, context=context,
                     reassembly=reassembly, traceflow=traceflow, stream=stream, auto=auto, store=store,
                     verbose=verbose)


def reassemble(protocol: 'str | Type[ProtocolBase]', strict: 'bool' = False,
               timeout: 'Optional[float]' = None) -> 'ReassemblyBase':
    """Reassemble fragmented datagrams.

    Arguments:
        protocol: protocol to be reassembled, a name registered in
            :attr:`Extractor.__reassembly__
            <pcapkit.foundation.extraction.Extractor.__reassembly__>`, matched
            lower-cased, or a protocol class, by the first of its
            :meth:`~pcapkit.protocols.protocol.ProtocolBase.id`
        strict: if :data:`True`, report a datagram that is not completely
            reassembled as the tuple of its received runs; otherwise as one
            contiguous payload
        timeout: reassembly timeout in seconds, on the capture's own clock;
            :data:`None` selects the protocol's own default; a reassembly that
            takes none, as DTLS's, is made without it

    Returns:
        A :class:`~pcapkit.foundation.reassembly.reassembly.ReassemblyBase` object of corresponding protocol.

    Raises:
        FormatError: If no reassembly is registered under ``protocol``.

    .. versionchanged:: 1.5.0

       ``timeout`` is added. IPv4 and IPv6 buffers expire after 60 seconds of
       capture time by default, where 1.4.x held them for the life of the
       object.

    .. versionchanged:: 1.7.0

       Makes any registered reassembly, through
       :meth:`Extractor.make_reassembly
       <pcapkit.foundation.extraction.Extractor.make_reassembly>`, where it
       made IPv4, IPv6 and TCP only (:issue:`2814`).

    """
    if isinstance(protocol, type) and issubclass(protocol, ProtocolBase):
        protocol = protocol.id()[0]
    return Extractor.make_reassembly(protocol, strict=strict, timeout=timeout)


def trace(protocol: 'str | Type[ProtocolBase]', fout: 'Optional[str]',
          format: 'Optional[str]',  # pylint: disable=redefined-builtin
          byteorder: 'Literal["little", "big"]' = sys.byteorder,
          nanosecond: bool = False, bidirectional: 'bool' = True) -> 'TraceFlowBase':
    """Trace flows.

    Arguments:
        protocol: protocol whose flows are to be traced
        fout: output path
        format: output format
        byteorder: output file byte order
        nanosecond: output nanosecond-resolution file flag
        bidirectional: whether both halves of a conversation are traced as one
            flow, which is the default

    Returns:
        A :class:`~pcapkit.foundation.traceflow.traceflow.TraceFlowBase` object.

    Raises:
        FormatError: If ``protocol`` is **NOT** TCP.

    .. versionchanged:: 1.5.0

       ``bidirectional`` is added, and by default both directions of a
       conversation are traced as one flow; 1.4.x traced each direction as a
       flow of its own.

    """
    if isinstance(protocol, type) and issubclass(protocol, ProtocolBase):
        protocol = protocol.id()[0]

    if protocol == 'TCP':
        return TCP_TraceFlow(fout=fout, format=format, byteorder=byteorder,
                             nanosecond=nanosecond, bidirectional=bidirectional)
    raise FormatError(f'unsupported flow tracing protocol: {protocol!r}')
