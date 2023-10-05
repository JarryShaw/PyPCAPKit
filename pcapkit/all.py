# -*- coding: utf-8 -*-
# pylint: disable=unused-import,unused-wildcard-import,wildcard-import
"""Library Index
===================

.. module:: pcapkit.all

:mod:`pcapkit` has defined various and numerous functions
and classes, which have different features and purposes.
To make a simple index for this library, :mod:`pcapkit.all`
contains all things from :mod:`pcapkit`.

"""
from pcapkit import const
from pcapkit.corekit import *
from pcapkit.dumpkit import *
from pcapkit.foundation import *
from pcapkit.interface import *
from pcapkit.protocols import *
from pcapkit.toolkit import *
from pcapkit.utilities import *  # pylint: disable=redefined-builtin

#from pcapkit import vendor

# tools for Scapy engine
from pcapkit.toolkit.scapy import packet2chain as scapy_packet2chain  # isort: skip
from pcapkit.toolkit.scapy import packet2dict as scapy_packet2dict  # isort: skip
from pcapkit.toolkit.scapy import ipv4_reassembly as scapy_ipv4_reassembly  # isort: skip
from pcapkit.toolkit.scapy import ipv6_reassembly as scapy_ipv6_reassembly  # isort: skip
from pcapkit.toolkit.scapy import tcp_reassembly as scapy_tcp_reassembly  # isort: skip
from pcapkit.toolkit.scapy import tcp_traceflow as scapy_tcp_traceflow  # isort: skip

# tools for DPKT engine
from pcapkit.toolkit.dpkt import ipv6_hdr_len as dpkt_ipv6_hdr_len  # isort: skip
from pcapkit.toolkit.dpkt import packet2chain as dpkt_packet2chain  # isort: skip
from pcapkit.toolkit.dpkt import packet2dict as dpkt_packet2dict  # isort: skip
from pcapkit.toolkit.dpkt import ipv4_reassembly as dpkt_ipv4_reassembly  # isort: skip
from pcapkit.toolkit.dpkt import ipv6_reassembly as dpkt_ipv6_reassembly  # isort: skip
from pcapkit.toolkit.dpkt import tcp_reassembly as dpkt_tcp_reassembly  # isort: skip
from pcapkit.toolkit.dpkt import tcp_traceflow as dpkt_tcp_traceflow  # isort: skip

# tools for PyShark engine
from pcapkit.toolkit.pyshark import packet2dict as pyshark_packet2dict  # isort: skip
from pcapkit.toolkit.pyshark import tcp_traceflow as pyshark_tcp_traceflow  # isort: skip

__all__ = [
    # pcapkit.const
    'const',

    # # pcapkit.vendor
    # 'vendor',

    # pcapkit.corekit
    'Info',                                                 # Info Class
    'ProtoChain',                                           # ProtoChain
    'VersionInfo',                                          # Version
    'NumberField', 'Int32Field', 'UInt32Field',             # numeric protocol fields
    'Int16Field', 'UInt16Field', 'Int64Field', 'UInt64Field',
    'Int8Field', 'UInt8Field', 'EnumField',
    'BytesField', 'StringField', 'BitField',                # text protocol fields
    'PaddingField',
    'ConditionalField', 'PayloadField', 'SchemaField',      # misc protocol fields
    'ForwardMatchField', 'NoValueField',
    'IPv4AddressField', 'IPv6AddressField',                 # IP address protocol fields
    'IPv4InterfaceField', 'IPv6InterfaceField',
    'ListField', 'OptionField',                             # container protocol fields
    'SeekableReader',                                       # Seekable Reader

    # pcapkit.dumpkit
    'PCAPIO',                                               # PCAP Dumper
    'NotImplementedIO',                                     # Simulated I/O

    # pcapkit.foundation
    'Extractor',                                            # Extraction
    'TCP_TraceFlow',                                        # Trace Flow

    # pcapkit.foundation.reassembly
    'IPv4_Reassembly', 'IPv6_Reassembly',                   # IP Reassembly
    'TCP_Reassembly',                                       # TCP Reassembly

    # pcapkit.foundation.registry
    'register_protocol',
    'register_linktype',
    'register_pcap', 'register_pcapng',
    'register_ethertype',
    'register_transtype',
    'register_ipv4_option', 'register_hip_parameter', 'register_hopopt_option',
    'register_ipv6_opts_option', 'register_ipv6_route_routing',
    'register_mh_message', 'register_mh_option', 'register_mh_extension',
    'register_apptype',
    'register_tcp', 'register_udp',
    'register_tcp_option', 'register_tcp_mp_option',
    'register_http_frame',
    'register_pcapng_block', 'register_pcapng_option', 'register_pcapng_secrets',
    'register_pcapng_record',
    'register_extractor_engine',
    'register_dumper',
    'register_extractor_dumper', 'register_traceflow_dumper',

    # pcapkit.interface
    'extract', 'reassemble', 'trace',                       # Interface Functions
    'TREE', 'JSON', 'PLIST', 'PCAP',                        # Format Macros
    'LINK', 'INET', 'TRANS', 'APP', 'RAW',                  # Layer Macros
    'DPKT', 'Scapy', 'PyShark', 'PCAPKit',                  # Engine Macros

    # pcapkit.protocols
    'LINKTYPE', 'ETHERTYPE', 'TRANSTYPE', 'APPTYPE',        # Protocol Numbers
    'Header', 'Frame',                                      # PCAP Headers
    'NoPayload',                                            # No Payload
    'Raw',                                                  # Raw Packet
    'ARP', 'DRARP', 'Ethernet', 'InARP', 'L2TP', 'OSPF', 'RARP', 'VLAN',
                                                            # Link Layer
    'AH', 'IP', 'IPsec', 'IPv4', 'IPv6', 'IPX',             # Internet Layer
    'HIP', 'HOPOPT', 'IPv6_Frag', 'IPv6_Opts', 'IPv6_Route', 'MH',
                                                            # IPv6 Extension Header
    'TCP', 'UDP',                                           # Transport Layer
    'FTP', 'FTP_DATA',                                      # Application Layer
    'HTTP',
    'Schema', 'schema',                                     # Protocol Schema
    'Data', 'data',                                         # Protocol Data

    # pcapkit.toolkit
    'ipv4_reassembly', 'ipv6_reassembly', 'tcp_reassembly', 'tcp_traceflow',
    'pcapng_ipv4_reassembly', 'pcapng_ipv6_reassembly', 'pcapng_tcp_reassembly', 'pcapng_tcp_traceflow',
    'pcapng_block2frame',                                   # default engine
    'dpkt_ipv6_hdr_len', 'dpkt_packet2chain', 'dpkt_packet2dict',
    'dpkt_ipv4_reassembly', 'dpkt_ipv6_reassembly', 'dpkt_tcp_reassembly', 'dpkt_tcp_traceflow',
                                                            # DPKT engine
    'pyshark_packet2dict', 'pyshark_tcp_traceflow',         # PyShark engine
    'scapy_packet2chain', 'scapy_packet2dict',
    'scapy_ipv4_reassembly', 'scapy_ipv6_reassembly', 'scapy_tcp_reassembly', 'scapy_tcp_traceflow',
                                                            # Scapy engine

    # pcapkit.utilities
    #'beholder_ng', 'seekset_ng',                            # Decorators
]
