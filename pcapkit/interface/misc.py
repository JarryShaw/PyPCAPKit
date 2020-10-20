# -*- coding: utf-8 -*-
"""auxiliary interface

:mod:`pcapkit.interface.misc` contains miscellaneous
user interface functions, classes, etc., which are
generally provided per user's requests.

"""
import warnings

from pcapkit.corekit.infoclass import Info
from pcapkit.foundation.extraction import Extractor
from pcapkit.reassembly.tcp import TCP_Reassembly
from pcapkit.utilities.exceptions import stacklevel
from pcapkit.utilities.warnings import EngineWarning


def follow_tcp_stream(fin=None, verbose=False, extension=True, engine=None,      # Extrator options
                      fout=None, format=None, byteorder=None, nanosecond=None):  # TraceFlow options
    """Follow TCP streams.

    Arguments:
        fin (Optiona[str]): file name to be read; if file not exist, raise :exc:`FileNotFound`
        extension (bool): if check and append extensions to output file
        verbose (bool): if print verbose output information
        engine (Optional[Literal['default', 'pcapkit', 'dpkt', 'scapy', 'pyshark', 'server', 'pipeline']]):
            extraction engine to be used

        fout (Optional[str]): path name for flow tracer if necessary
        format (Optional[Literal['plist', 'json', 'tree', 'pcap']]): output file
            format of flow tracer
        byteorder (Literal['little', 'big']): output file byte order
        nanosecond (bool): output nanosecond-resolution file flag

    Returns:
        Tuple[pcapkit.corekit.infoclass.Info]: List of extracted TCP streams.

    """
    if isinstance(engine, str) and engine.casefold() == 'pyshark':
        warnings.warn(f'unsupported extraction engine: {engine}; fallback to default engine',
                      EngineWarning, stacklevel=stacklevel())
        engine = None

    extraction = Extractor(fin=fin, fout=None, format=None, auto=True, extension=extension,
                           store=True, files=False, nofile=True, verbose=verbose, engine=engine,
                           layer=None, protocol=None, ip=False, ipv4=False, ipv6=False, tcp=False,
                           strict=False, trace=True, trace_fout=fout, trace_format=format,
                           trace_byteorder=byteorder, trace_nanosecond=nanosecond)

    fallback = False
    if extraction.engine == 'dpkt':
        from pcapkit.toolkit.dpkt import tcp_reassembly
    elif extraction.engine == 'scapy':
        from pcapkit.toolkit.scapy import tcp_reassembly
    else:
        from pcapkit.toolkit.default import tcp_reassembly
        fallback = True

    streams = list()
    frames = extension.frame
    for stream in extension.trace:
        reassembly = TCP_Reassembly(strict=False)

        packets = list()
        for index in stream.index:
            frame = frames[index]
            packets.append(frame.info)

            if fallback:
                flag, data = tcp_reassembly(frame)
            else:
                flag, data = tcp_reassembly(frame, count=index)

            if flag:
                reassembly(data)

        streams.append(Info(
            filename=stream.fpout,
            packets=tuple(packets),
            conversations=reassembly.datagram.payload,
        ))
    return tuple(streams)
