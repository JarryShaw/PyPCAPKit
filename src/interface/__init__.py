# -*- coding: utf-8 -*-
"""user interface

`jspcap.interface` defines several user-oriented
interfaces, variables, and etc. These interfaces are
designed to help and simplify the usage of `jspcap`.

"""
from jspcap.foundation.analysis import Analysis
from jspcap.foundation.extraction import Extractor
from jspcap.foundation.traceflow import TraceFlow
from jspcap.protocols.protocol import Protocol
from jspcap.reassembly.ipv4 import IPv4_Reassembly
from jspcap.reassembly.ipv6 import IPv6_Reassembly
from jspcap.reassembly.tcp import TCP_Reassembly
from jspcap.utilities.exceptions import FormatError
from jspcap.utilities.validations import bool_check, int_check, io_check, str_check


__all__ = [
    'extract', 'analyse', 'reassemble', 'trace',            # functions
    'TREE', 'JSON', 'PLIST', 'PCAP',                        # macros
]


# output file formats
TREE  = 'tree'
JSON  = 'json'
PLIST = 'plist'
PCAP  = 'pcap'


def extract(*, fin=None, fout=None, format=None,                            # basic settings
                auto=True, extension=True, store=True,                      # internal settings
                files=False, nofile=False, verbose=False,                   # output settings
                engine=None, layer=None, protocol=None,                     # extraction settings
                ip=False, ipv4=False, ipv6=False, tcp=False, strict=False,  # reassembly settings
                trace=False, trace_fout=None, trace_format=None):           # trace settings
    """Extract a PCAP file.

    Keyword arguments:
        * fin  -- str, file name to be read; if file not exist, raise an error
        * fout -- str, file name to be written
        * format  -- str, file format of output
                        <keyword> 'plist' / 'json' / 'tree' / 'html'

        * auto -- bool, if automatically run till EOF (default is True)
                        <keyword> True / False
        * extension -- bool, if check and append axtensions to output file (default is True)
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
                        <keyword> 'default | jspcap'
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
        * strict -- bool, if set strict flag for reassembly (default is False)
                        <keyword> True / False

        * trace -- bool, if trace TCP traffic flows (default is False)
                        <keyword> True / False
        * trace_fout -- str, path name for flow tracer if necessary
        * trace_format -- str, output file format of flow tracer
                        <keyword> 'plist' / 'json' / 'tree' / 'html' / 'pcap'

    Returns:
        * Extractor -- an Extractor object form `jspcap.extractor`

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
                        trace=trace, trace_fout=trace_fout, trace_format=trace_format)


def analyse(*, file, length=None):
    """Analyse application layer packets.

    Keyword arguments:
        * file -- file-like object, packet to be analysed
        * length -- int, length of the analysing packet

    Returns:
        * Analysis -- an Analysis object from `jspcap.analyser`

    """
    io_check(file)
    int_check(length)

    return Analysis.analyse(file, length)


def reassemble(*, protocol, strict=False):
    """Reassemble fragmented datagrams.

    Keyword arguments:
        * protocol -- str, protocol to be reassembled
        * strict -- bool, if return all datagrams (including those not implemented) when submit (default is False)
                        <keyword> True / False

    Returns:
        * [if protocol is IPv4] IPv4_Reassembly -- a Reassembly object from `jspcap.reassembly`
        * [if protocol is IPv6] IPv6_Reassembly -- a Reassembly object from `jspcap.reassembly`
        * [if protocol is TCP] TCP_Reassembly -- a Reassembly object from `jspcap.reassembly`

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
        raise FormatError(f'Unsupported reassembly protocol: {protocol}')


def trace(*, fout=None, format=None):
    """Trace TCP flows.

    """
    str_check(fout or '', format or '')
    return TraceFlow(fout, format)
