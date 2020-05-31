# -*- coding: utf-8 -*-
# pylint: disable=bad-continuation
"""user interface

:mod:`pcapkit.interface` defines several user-oriented
interfaces, variables, and etc. These interfaces are
designed to help and simplify the usage of :mod:`pcapkit`.

"""
import io
import sys

from pcapkit.foundation.analysis import analyse as analyse2
from pcapkit.foundation.extraction import Extractor
from pcapkit.foundation.traceflow import TraceFlow
from pcapkit.protocols.protocol import Protocol
from pcapkit.reassembly.ipv4 import IPv4_Reassembly
from pcapkit.reassembly.ipv6 import IPv6_Reassembly
from pcapkit.reassembly.tcp import TCP_Reassembly
from pcapkit.utilities.exceptions import FormatError
from pcapkit.utilities.validations import bool_check, int_check, io_check, str_check

__all__ = [
    'extract', 'analyse', 'reassemble', 'trace',            # interface functions
    'TREE', 'JSON', 'PLIST', 'PCAP',                        # format macros
    'LINK', 'INET', 'TRANS', 'APP', 'RAW',                  # layer macros
    'DPKT', 'Scapy', 'PyShark', 'MPServer', 'MPPipeline', 'PCAPKit',
                                                            # engine macros
]

# output file formats
TREE = 'tree'
JSON = 'json'
PLIST = 'plist'
PCAP = 'pcap'

# layer thresholds
RAW = 'None'
LINK = 'Link'
INET = 'Internet'
TRANS = 'Transport'
APP = 'Application'

# extraction engines
DPKT = 'dpkt'
Scapy = 'scapy'
PCAPKit = 'default'
PyShark = 'pyshark'
MPServer = 'server'
MPPipeline = 'pipeline'


def extract(fin=None, fout=None, format=None,                           # basic settings  # pylint: disable=redefined-builtin
            auto=True, extension=True, store=True,                      # internal settings
            files=False, nofile=False, verbose=False,                   # output settings
            engine=None, layer=None, protocol=None,                     # extraction settings
            ip=False, ipv4=False, ipv6=False, tcp=False, strict=True,   # reassembly settings
            trace=False, trace_fout=None, trace_format=None,            # trace settings  # pylint: disable=redefined-outer-name
            trace_byteorder=sys.byteorder, trace_nanosecond=False):     # trace settings
    """Extract a PCAP file.

    Arguments:
        fin (Optiona[str]): file name to be read; if file not exist, raise :exc:`FileNotFound`
        fout (Optiona[str]): file name to be written
        format (Optional[Literal['plist', 'json', 'tree']]): file format of output

        auto (bool): if automatically run till EOF
        extension (bool): if check and append extensions to output file
        store (bool): if store extracted packet info

        files (bool): if split each frame into different files
        nofile (bool): if no output file is to be dumped
        verbose (bool): if print verbose output information

        engine (Optional[Literal['default', 'pcapkit', 'dpkt', 'scapy', 'pyshark', 'server', 'pipeline']]):
            extraction engine to be used
        layer (Optional[Literal['Link', 'Internet', 'Transport', 'Application']]): extract til which layer
        protocol (Optional[Union[str, Tuple[str], Type[Protocol]]]): extract til which protocol

        ip (bool): if record data for IPv4 & IPv6 reassembly
        ipv4 (bool): if perform IPv4 reassembly
        ipv6 (bool): if perform IPv6 reassembly
        tcp (bool): if perform TCP reassembly
        strict (bool): if set strict flag for reassembly

        trace (bool): if trace TCP traffic flows
        trace_fout (Optional[str]): path name for flow tracer if necessary
        trace_format (Optional[Literal['plist', 'json', 'tree', 'pcap']]): output file
            format of flow tracer
        trace_byteorder (Literal['little', 'big']): output file byte order
        trace_nanosecond (bool): output nanosecond-resolution file flag

    Returns:
        Extractor -- an :class:`~pcapkit.foundation.extraction.Extractor` object

    """
    if isinstance(layer, type) and issubclass(layer, Protocol):
        layer = layer.__layer__
    if isinstance(protocol, type) and issubclass(protocol, Protocol):
        protocol = protocol.id()

    str_check(fin or '', fout or '', format or '',
              trace_fout or '', trace_format or '',
              engine or '', layer or '', *(protocol or ''))
    bool_check(files, nofile, verbose, auto, extension, store,
               ip, ipv4, ipv6, tcp, strict, trace)

    return Extractor(fin=fin, fout=fout, format=format,
                     store=store, files=files, nofile=nofile,
                     auto=auto, verbose=verbose, extension=extension,
                     engine=engine, layer=layer, protocol=protocol,
                     ip=ip, ipv4=ipv4, ipv6=ipv6, tcp=tcp, strict=strict,
                     trace=trace, trace_fout=trace_fout, trace_format=trace_format,
                     trace_byteorder=trace_byteorder, trace_nanosecond=trace_nanosecond)


def analyse(file, length=None):
    """Analyse application layer packets.

    Arguments:
        file (Union[bytes, io.BytesIO]): packet to be analysed
        length (Optional[int]): length of the analysing packet

    Returns:
        Analysis: an :class:`~pcapkit.foundation.analysis.Analysis` object

    """
    if isinstance(file, bytes):
        file = io.BytesIO(file)

    io_check(file)
    int_check(length or sys.maxsize)

    return analyse2(file, length)


def reassemble(protocol, strict=False):
    """Reassemble fragmented datagrams.

    Arguments:
        protocol (Union[str, Type[Protocol]]) protocol to be reassembled
        strict (bool): if return all datagrams (including those not implemented) when submit

    Returns:
        Union[IPv4_Reassembly, IPv6_Reassembly, TCP_Reassembly]: a :class:`~pcapkit.reassembly.reassembly.Reassembly`
        object of corresponding protocol

    Raises:
        FormatError: If ``protocol`` is **NOT** any of IPv4, IPv6 or TCP.

    """
    if isinstance(protocol, type) and issubclass(protocol, Protocol):
        protocol = protocol.id()

    str_check(protocol)
    bool_check(strict)

    if protocol == 'IPv4':
        return IPv4_Reassembly(strict=strict)
    if protocol == 'IPv6':
        return IPv6_Reassembly(strict=strict)
    if protocol == 'TCP':
        return TCP_Reassembly(strict=strict)
    raise FormatError(f'Unsupported reassembly protocol: {protocol}')


def trace(fout=None, format=None, byteorder=sys.byteorder, nanosecond=False):  # pylint: disable=redefined-builtin
    """Trace TCP flows.

    Arguments:
        fout (str): output path
        format (Optional[str]): output format
        byteorder (str): output file byte order
        nanosecond (bool): output nanosecond-resolution file flag

    Returns:
        TraceFlow: a :class:`~pcapkit.foundation.traceflow.TraceFlow` object

    """
    str_check(fout or '', format or '')
    return TraceFlow(fout=fout, format=format, byteorder=byteorder, nanosecond=nanosecond)
