# -*- coding: utf-8 -*-
# pylint: disable=unused-import, unused-wildcard-import, bad-continuation,wildcard-import
"""index for the library

:mod:`pcapkit` has defined various and numerous functions
and classes, which have different features and purposes.
To make a simple index for this library, :mod:`pcapkit.all`
contains all things from :mod:`pcapkit`.

"""
import pcapkit.const as const
#import pcapkit.vendor as vendor
from pcapkit.corekit import *
from pcapkit.dumpkit import *
from pcapkit.foundation import *
from pcapkit.interface import *
from pcapkit.protocols import *
from pcapkit.reassembly import *
from pcapkit.toolkit import *
from pcapkit.utilities import *  # pylint: disable=redefined-builtin

__all__ = [
    # pcapkit.const
    'const',

    # # pcapkit.vendor
    # 'vendor',

    # pcapkit.corekit
    'Info',                                                 # Info Class
    'ProtoChain',                                           # ProtoChain
    'VersionInfo',                                          # Version

    # pcapkit.dumpkit
    'PCAPIO',                                                 # PCAP Dumper
    'NotImplementedIO',                                     # Simulated I/O

    # pcapkit.foundation
    'Extractor',                                            # Extraction
    'analyse2',                                             # Analysis
    'TraceFlow',                                            # Trace Flow

    # pcapkit.interface
    'extract', 'analyse', 'reassemble', 'trace',            # Interface Functions
    'TREE', 'JSON', 'PLIST', 'PCAP',                        # Format Macros
    'LINK', 'INET', 'TRANS', 'APP', 'RAW',                  # Layer Macros
    'DPKT', 'Scapy', 'PyShark', 'MPServer', 'MPPipeline', 'PCAPKit',
                                                            # Engine Macros

    # pcapkit.protocols
    'LINKTYPE', 'ETHERTYPE', 'TP_PROTO',                    # Protocol Numbers
    'Header', 'Frame',                                      # PCAP Headers
    'NoPayload',                                            # No Payload
    'Raw',                                                  # Raw Packet
    'ARP', 'DRARP', 'Ethernet', 'InARP', 'L2TP', 'OSPF', 'RARP', 'VLAN',
                                                            # Link Layer
    'AH', 'IP', 'IPsec', 'IPv4', 'IPv6', 'IPX',             # Internet Layer
    'HIP', 'HOPOPT', 'IPv6_Frag', 'IPv6_Opts', 'IPv6_Route', 'MH',
                                                            # IPv6 Extension Header
    'TCP', 'UDP',                                           # Transport Layer
    'FTP', 'HTTP',                                          # Application Layer

    # pcapkit.reassembly
    'IPv4_Reassembly', 'IPv6_Reassembly',                   # IP Reassembly
    'TCP_Reassembly',                                       # TCP Reassembly

    # pcapkit.toolkit
    'ipv4_reassembly', 'ipv6_reassembly', 'tcp_reassembly', 'tcp_traceflow',
                                                            # default engine
    'dpkt_ipv6_hdr_len', 'dpkt_packet2chain', 'dpkt_packet2dict',
    'dpkt_ipv4_reassembly', 'dpkt_ipv6_reassembly', 'dpkt_tcp_reassembly', 'dpkt_tcp_traceflow',
                                                            # DPKT engine
    'pyshark_packet2dict', 'pyshark_tcp_traceflow',         # PyShark engine
    'scapy_packet2chain', 'scapy_packet2dict',
    'scapy_ipv4_reassembly', 'scapy_ipv6_reassembly', 'scapy_tcp_reassembly', 'scapy_tcp_traceflow',
                                                            # Scapy engine

    # pcapkit.utilities
    'beholder_ng', 'seekset_ng',                            # Decorators
]
