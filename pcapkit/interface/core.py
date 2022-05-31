# -*- coding: utf-8 -*-
"""core user interface

:mod:`pcapkit.interface.core` defines core user-oriented
interfaces, variables, and etc., which wraps around the
foundation classes from :mod:`pcapkit.foundation`.

"""
import sys
from typing import TYPE_CHECKING

from pcapkit.foundation.extraction import Extractor
from pcapkit.foundation.reassembly.ipv4 import IPv4_Reassembly
from pcapkit.foundation.reassembly.ipv6 import IPv6_Reassembly
from pcapkit.foundation.reassembly.tcp import TCP_Reassembly
from pcapkit.foundation.traceflow import TraceFlow
from pcapkit.protocols.protocol import Protocol
from pcapkit.utilities.exceptions import FormatError

if TYPE_CHECKING:
    from typing import Any, Callable, Optional, Type, Union

    from typing_extensions import Literal

    from pcapkit.foundation.reassembly.reassembly import Reassembly
    from pcapkit.protocols.misc.pcap.frame import Frame

    Formats = Literal['pcap', 'json', 'tree', 'plist']
    Engines = Literal['default', 'pcapkit', 'dpkt', 'scapy', 'pyshark']
    Layers = Literal['link', 'internet', 'transport', 'application', 'none']

    Protocols = Union[str, Protocol, Type[Protocol]]
    VerboseHandler = Callable[['Extractor', Frame], Any]

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


def extract(fin: 'Optional[str]' = None, fout: 'Optional[str]' = None, format: 'Optional[Formats]' = None,                                  # basic settings  # pylint: disable=redefined-builtin
            auto: 'bool' = True, extension: 'bool' = True, store: 'bool' = True,                                                            # internal settings # pylint: disable=line-too-long
            files: 'bool' = False, nofile: 'bool' = False, verbose: 'bool | VerboseHandler' = False,                                        # output settings # pylint: disable=line-too-long
            engine: 'Optional[Engines]' = None, layer: 'Optional[Layers | Type[Protocol]]' = None, protocol: 'Optional[Protocols]' = None,  # extraction settings # pylint: disable=line-too-long
            ip: 'bool' = False, ipv4: 'bool' = False, ipv6: 'bool' = False, tcp: 'bool' = False, strict: 'bool' = True,                     # reassembly settings # pylint: disable=line-too-long
            trace: 'bool' = False, trace_fout: 'Optional[str]' = None, trace_format: 'Optional[Formats]' = None,                            # trace settings # pylint: disable=line-too-long,redefined-outer-name
            trace_byteorder: 'Literal["big", "little"]' = sys.byteorder, trace_nanosecond: 'bool' = False) -> 'Extractor':                  # trace settings # pylint: disable=line-too-long
    """Extract a PCAP file.

    Arguments:
        fin: file name to be read; if file not exist, raise :exc:`FileNotFound`
        fout: file name to be written
        format: file format of output

        auto: if automatically run till EOF
        extension: if check and append extensions to output file
        store: if store extracted packet info

        files: if split each frame into different files
        nofile: if no output file is to be dumped
        verbose: a :obj:`bool` value or a function takes the :class:`Extract`
            instance and current parsed frame (depends on engine selected) as
            parameters to print verbose output information

        engine: extraction engine to be used
        layer: extract til which layer
        protocol: extract til which protocol

        ip: if record data for IPv4 & IPv6 reassembly
        ipv4: if perform IPv4 reassembly
        ipv6: if perform IPv6 reassembly
        tcp: if perform TCP reassembly
        strict: if set strict flag for reassembly

        trace: if trace TCP traffic flows
        trace_fout: path name for flow tracer if necessary
        trace_format: output file format of flow tracer
        trace_byteorder: output file byte order
        trace_nanosecond: output nanosecond-resolution file flag

    Returns:
        An :class:`~pcapkit.foundation.extraction.Extractor` object.

    """
    if isinstance(layer, type) and issubclass(layer, Protocol):
        layer = (layer.__layer__ or 'none').lower()  # type: ignore[assignment]

    return Extractor(fin=fin, fout=fout, format=format,
                     store=store, files=files, nofile=nofile,
                     auto=auto, verbose=verbose, extension=extension,
                     engine=engine, layer=layer, protocol=protocol,  # type: ignore[arg-type]
                     ip=ip, ipv4=ipv4, ipv6=ipv6, tcp=tcp, strict=strict,
                     trace=trace, trace_fout=trace_fout, trace_format=trace_format,
                     trace_byteorder=trace_byteorder, trace_nanosecond=trace_nanosecond)


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


def trace(fout: 'Optional[str]', format: 'Optional[str]',  # pylint: disable=redefined-builtin
          byteorder: 'Literal["little", "big"]' = sys.byteorder,
          nanosecond: bool = False) -> 'TraceFlow':
    """Trace TCP flows.

    Arguments:
        fout: output path
        format: output format
        byteorder: output file byte order
        nanosecond: output nanosecond-resolution file flag

    Returns:
        A :class:`~pcapkit.foundation.traceflow.TraceFlow` object.

    """
    return TraceFlow(fout=fout, format=format, byteorder=byteorder, nanosecond=nanosecond)
