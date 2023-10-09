# -*- coding: utf-8 -*-
"""Core Interface
====================

.. module:: pcapkit.interface.core

:mod:`pcapkit.interface.core` defines core user-oriented
interfaces, variables, and etc., which wraps around the
foundation classes from :mod:`pcapkit.foundation`.

"""
import io
import sys
from typing import TYPE_CHECKING

from pcapkit.foundation.extraction import Extractor
from pcapkit.foundation.reassembly.ipv4 import IPv4 as IPv4_Reassembly
from pcapkit.foundation.reassembly.ipv6 import IPv6 as IPv6_Reassembly
from pcapkit.foundation.reassembly.tcp import TCP as TCP_Reassembly
from pcapkit.foundation.traceflow.tcp import TCP as TCP_TraceFlow
from pcapkit.protocols.protocol import ProtocolBase as Protocol
from pcapkit.utilities.exceptions import FormatError

if TYPE_CHECKING:
    from typing import IO, Optional, Type

    from typing_extensions import Literal

    from pcapkit.foundation.extraction import Engines, Formats, Layers, Protocols, VerboseHandler
    from pcapkit.foundation.reassembly.reassembly import ReassemblyBase as Reassembly
    from pcapkit.foundation.traceflow.traceflow import TraceFlowBase as TraceFlow

__all__ = [
    'extract', 'reassemble', 'trace',                       # interface functions
    'TREE', 'JSON', 'PLIST', 'PCAP',                        # format macros
    'LINK', 'INET', 'TRANS', 'APP', 'RAW',                  # layer macros
    'DPKT', 'Scapy', 'PyShark', 'PCAPKit',                  # engine macros
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
DPKT = 'dpkt'
Scapy = 'scapy'
PCAPKit = 'default'
PyShark = 'pyshark'


def extract(fin: 'Optional[str | IO[bytes]]' = None, fout: 'Optional[str]' = None, format: 'Optional[Formats]' = None,     # basic settings # pylint: disable=redefined-builtin
            auto: 'bool' = True, extension: 'bool' = True, store: 'bool' = True,                                           # internal settings # pylint: disable=line-too-long
            files: 'bool' = False, nofile: 'bool' = False, verbose: 'bool | VerboseHandler' = False,                       # output settings # pylint: disable=line-too-long
            engine: 'Optional[Engines]' = None, layer: 'Optional[Layers] | Type[Protocol]' = None,                         # extraction settings # pylint: disable=line-too-long
            protocol: 'Optional[Protocols]' = None,                                                                        # extraction settings # pylint: disable=line-too-long
            reassembly: 'bool' = False, reasm_strict: 'bool' = True, reasm_store: 'bool' = True,                           # reassembly settings # pylint: disable=line-too-long
            trace: 'bool' = False, trace_fout: 'Optional[str]' = None, trace_format: 'Optional[Formats]' = None,           # trace settings # pylint: disable=line-too-long
            trace_byteorder: 'Literal["big", "little"]' = sys.byteorder, trace_nanosecond: 'bool' = False,                 # trace settings # pylint: disable=line-too-long
            ip: 'bool' = False, ipv4: 'bool' = False, ipv6: 'bool' = False, tcp: 'bool' = False,                           # reassembly/trace settings # pylint: disable=line-too-long
            buffer_size: 'int' = io.DEFAULT_BUFFER_SIZE, buffer_save: 'bool' = False, buffer_path: 'Optional[str]' = None, # buffer settings # pylint: disable=line-too-long
            no_eof: 'bool' = False) -> 'Extractor':
    """Extract a PCAP file.

    Arguments:
        fin: file name to be read or a binary IO object;
            if file not exist, raise :exc:`FileNotFound`
        fout: file name to be written
        format: file format of output

        auto: if automatically run till EOF
        extension: if check and append extensions to output file
        store: if store extracted packet info

        files: if split each frame into different files
        nofile: if no output file is to be dumped
        verbose: a :obj:`bool` value or a function takes the :class:`Extractor`
            instance and current parsed frame (depends on engine selected) as
            parameters to print verbose output information

        engine: extraction engine to be used
        layer: extract til which layer
        protocol: extract til which protocol

        reassembly: if perform reassembly
        reasm_strict: if set strict flag for reassembly
        reasm_store: if store reassembled datagrams

        trace: if trace TCP traffic flows
        trace_fout: path name for flow tracer if necessary
        trace_format: output file format of flow tracer
        trace_byteorder: output file byte order
        trace_nanosecond: output nanosecond-resolution file flag

        ip: if record data for IPv4 & IPv6 reassembly (must be used with ``reassembly=True``)
        ipv4: if perform IPv4 reassembly (must be used with ``reassembly=True``)
        ipv6: if perform IPv6 reassembly (must be used with ``reassembly=True``)
        tcp: if perform TCP reassembly and/or flow tracing
            (must be used with ``reassembly=True`` or ``trace=True``)

        buffer_size: buffer size for reading input file (for :class:`~pcapkit.corekit.io.SeekableReader` only)
        buffer_save: if save buffer to file (for :class:`~pcapkit.corekit.io.SeekableReader` only)
        buffer_path: path name for buffer file if necessary (for :class:`~pcapkit.corekit.io.SeekableReader` only)

        no_eof: if not raise :exc:`EOFError` when reach EOF

    Returns:
        An :class:`~pcapkit.foundation.extraction.Extractor` object.

    """
    if isinstance(layer, type) and issubclass(layer, Protocol):
        layer = (layer.__layer__ or 'none').lower()  # type: ignore[assignment]

    return Extractor(fin=fin, fout=fout, format=format,
                     store=store, files=files, nofile=nofile,
                     auto=auto, verbose=verbose, extension=extension,
                     engine=engine, layer=layer, protocol=protocol,  # type: ignore[arg-type]
                     ip=ip, ipv4=ipv4, ipv6=ipv6, tcp=tcp,
                     reassembly=reassembly, reasm_store=reasm_store, reasm_strict=reasm_strict,
                     trace=trace, trace_fout=trace_fout, trace_format=trace_format,
                     trace_byteorder=trace_byteorder, trace_nanosecond=trace_nanosecond,
                     buffer_size=buffer_size, buffer_path=buffer_path, buffer_save=buffer_save,
                     no_eof=no_eof)


def reassemble(protocol: 'str | Type[Protocol]', strict: 'bool' = False) -> 'Reassembly':
    """Reassemble fragmented datagrams.

    Arguments:
        protocol: protocol to be reassembled
        strict: if return all datagrams (including those not implemented) when submit

    Returns:
        A :class:`~pcapkit.foundation.reassembly.reassembly.Reassembly` object of corresponding protocol.

    Raises:
        FormatError: If ``protocol`` is **NOT** any of IPv4, IPv6 or TCP.

    """
    if isinstance(protocol, type) and issubclass(protocol, Protocol):
        protocol = protocol.id()[0]

    if protocol == 'IPv4':
        return IPv4_Reassembly(strict=strict)
    if protocol == 'IPv6':
        return IPv6_Reassembly(strict=strict)
    if protocol == 'TCP':
        return TCP_Reassembly(strict=strict)
    raise FormatError(f'Unsupported reassembly protocol: {protocol}')


def trace(protocol: 'str | Type[Protocol]', fout: 'Optional[str]',
          format: 'Optional[str]',  # pylint: disable=redefined-builtin
          byteorder: 'Literal["little", "big"]' = sys.byteorder,
          nanosecond: bool = False) -> 'TraceFlow':
    """Trace flows.

    Arguments:
        protocol: protocol to be reassembled
        fout: output path
        format: output format
        byteorder: output file byte order
        nanosecond: output nanosecond-resolution file flag

    Returns:
        A :class:`~pcapkit.foundation.traceflow.traceflow.TraceFlow` object.

    Raises:
        FormatError: If ``protocol`` is **NOT** TCP.

    """
    if isinstance(protocol, type) and issubclass(protocol, Protocol):
        protocol = protocol.id()[0]

    if protocol == 'TCP':
        return TCP_TraceFlow(fout=fout, format=format, byteorder=byteorder, nanosecond=nanosecond)
    raise FormatError(f'Unsupported flow tracing protocol: {protocol}')
