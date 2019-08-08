# -*- coding: utf-8 -*-
"""user interface

`pcapkit.interface` defines several user-oriented
interfaces, variables, and etc. These interfaces are
designed to help and simplify the usage of `pcapkit`.

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
from pcapkit.utilities.validations import (bool_check, int_check, io_check,
                                           str_check)

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


def extract(fin=None, fout=None, format=None,                           # basic settings
            auto=True, extension=True, store=True,                      # internal settings
            files=False, nofile=False, verbose=False,                   # output settings
            engine=None, layer=None, protocol=None,                     # extraction settings
            ip=False, ipv4=False, ipv6=False, tcp=False, strict=True,   # reassembly settings
            trace=False, trace_fout=None, trace_format=None,            # trace settings
            trace_byteorder=sys.byteorder, trace_nanosecond=False):     # trace settings
    """Extract a PCAP file.

    Keyword arguments:
        * fin  -- str, file name to be read; if file not exist, raise an error
        * fout -- str, file name to be written
        * format  -- str, file format of output
                        <keyword> 'plist' / 'json' / 'tree' / 'html'

        * auto -- bool, if automatically run till EOF (default is True)
                        <keyword> True / False
        * extension -- bool, if check and append extensions to output file (default is True)
                        <keyword> True / False
        * store -- bool, if store extracted packet info (default is True)
                        <keyword> True / False

        * files -- bool, if split each frame into different files (default is False)
                        <keyword> True / False
        * nofile -- bool, if no output file is to be dumped (default is False)
                        <keyword> True / False
        * verbose -- bool, if print verbose output information (default is False)
                        <keyword> True / False

        * engine -- str, extraction engine to be used
                        <keyword> 'default | pcapkit'
        * layer -- str, extract til which layer
                        <keyword> 'Link' / 'Internet' / 'Transport' / 'Application'
        * protocol -- str, extract til which protocol
                        <keyword> available protocol name

        * ip -- bool, if record data for IPv4 & IPv6 reassembly (default is False)
                        <keyword> True / False
        * ipv4 -- bool, if perform IPv4 reassembly (default is False)
                        <keyword> True / False
        * ipv6 -- bool, if perform IPv6 reassembly (default is False)
                        <keyword> True / False
        * tcp -- bool, if perform TCP reassembly (default is False)
                        <keyword> True / False
        * strict -- bool, if set strict flag for reassembly (default is True)
                        <keyword> True / False

        * trace -- bool, if trace TCP traffic flows (default is False)
                        <keyword> True / False
        * trace_fout -- str, path name for flow tracer if necessary
        * trace_format -- str, output file format of flow tracer
                        <keyword> 'plist' / 'json' / 'tree' / 'html' / 'pcap'
        * trace_byteorder -- str, output file byte order
                        <keyword> 'little' / 'big'
        * trace_nanosecond -- bool, output nanosecond-resolution file flag
                        <keyword> True / False

    Returns:
        * Extractor -- an Extractor object form `pcapkit.extractor`

    """
    if isinstance(layer, type) and issubclass(layer, Protocol):
        layer = layer.__layer__
    if isinstance(protocol, type) and issubclass(protocol, Protocol):
        protocol = protocol.__index__()

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

    Keyword arguments:
        * file -- bytes or file-like object, packet to be analysed
        * length -- int, length of the analysing packet

    Returns:
        * Analysis -- an Analysis object from `pcapkit.analyser`

    """
    if isinstance(file, bytes):
        file = io.BytesIO(file)

    io_check(file)
    int_check(length or sys.maxsize)

    return analyse2(file, length)


def reassemble(protocol, strict=False):
    """Reassemble fragmented datagrams.

    Keyword arguments:
        * protocol -- str, protocol to be reassembled
        * strict -- bool, if return all datagrams (including those not implemented) when submit (default is False)
                        <keyword> True / False

    Returns:
        * [if protocol is IPv4] IPv4_Reassembly -- a Reassembly object from `pcapkit.reassembly`
        * [if protocol is IPv6] IPv6_Reassembly -- a Reassembly object from `pcapkit.reassembly`
        * [if protocol is TCP] TCP_Reassembly -- a Reassembly object from `pcapkit.reassembly`

    """
    if isinstance(protocol, type) and issubclass(protocol, Protocol):
        protocol = protocol.__index__()

    str_check(protocol)
    bool_check(strict)

    if protocol == 'IPv4':
        return IPv4_Reassembly(strict=strict)
    elif protocol == 'IPv6':
        return IPv6_Reassembly(strict=strict)
    elif protocol == 'TCP':
        return TCP_Reassembly(strict=strict)
    else:
        raise FormatError('Unsupported reassembly protocol: {}'.format(protocol))


def trace(fout=None, format=None, byteorder=sys.byteorder, nanosecond=False):
    """Trace TCP flows.

    Keyword arguments:
        * fout -- str, output path
        * format -- str, output format
        * byteorder -- str, output file byte order
        * nanosecond -- bool, output nanosecond-resolution file flag

    """
    str_check(fout or '', format or '')
    return TraceFlow(fout=fout, format=format, byteorder=byteorder, nanosecond=nanosecond)
