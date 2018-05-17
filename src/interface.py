# -*- coding: utf-8 -*-
"""interface functions

`jspcap.interface` defines several user-oriented
functions, variables, and etc. These interfaces are
designed to help and simplify the usage of `jspcap`.

"""
# User Interface
# interface functions and variables


from jspcap.analyser import analyse as _analyse
from jspcap.exceptions import FormatError
from jspcap.extractor import Extractor
from jspcap.reassembly import IPv4_Reassembly, IPv6_Reassembly, TCP_Reassembly
from jspcap.validations import bool_check, int_check, io_check, str_check
from jspcap.protocols.protocol import Protocol


__all__ = [
    'extract', 'analyse', 'reassemble',     # functions
    'TREE', 'JSON', 'PLIST',                # variables
]


# output file formats
TREE  = 'tree'
JSON  = 'json'
PLIST = 'plist'


def extract(*, fin=None, fout=None, format=None, 
                store=True, files=False, nofile=False,
                auto=True, verbose=False, extension=True,
                ip=False, ipv4=False, ipv6=False, tcp=False, strict=False):
    """Extract a PCAP file.

    Keyword arguments:
        * fin  -- str, file name to be read; if file not exist, raise an error
        * fout -- str, file name to be written
        * format  -- str, file format of output
                        <keyword> 'plist' / 'json' / 'tree' / 'html'

        * store -- bool, if store extracted packet info (default is True)
                        <keyword> True / False
        * verbose -- bool, if print verbose output information (default is False)
                        <keyword> True / False

        * auto -- bool, if automatically run till EOF (default is True)
                        <keyword> True / False
        * extension -- bool, if check and append axtensions to output file (default is True)
                        <keyword> True / False

        * files -- bool, if split each frame into different files (default is False)
                        <keyword> True / False
        * nofile -- bool, if no output file is to be dumped (default is False)
                        <keyword> True / False

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

    Returns:
        * Extractor -- an Extractor object form `jspcap.extractor`

    """
    str_check(fin or '', fout or '', format or '')
    bool_check(ip, ipv4, ipv6, tcp, auto, extension, files, nofile, verbose, strict, store)

    return Extractor(fin=fin, fout=fout, format=format,
                        store=store, files=files, nofile=nofile,
                        auto=auto, verbose=verbose, extension=extension,
                        ip=ip, ipv4=ipv4, ipv6=ipv6, tcp=tcp, strict=strict)


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

    return _analyse(file, length)


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
        protocol = protocol.__class__.__name__

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
