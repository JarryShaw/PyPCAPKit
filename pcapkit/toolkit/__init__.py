# -*- coding: utf-8 -*-
# pylint: disable=unused-import, unused-wildcard-import
"""Compatibility Tools
=========================

.. module:: pcapkit.toolkit

:mod:`pcapkit.toolkit` provides several utility functions for
compatibility of multiple engine support.

"""
# tools for default engine
from pcapkit.toolkit.pcap import ipv4_reassembly, ipv6_reassembly, tcp_reassembly, tcp_traceflow
from pcapkit.toolkit.pcapng import ipv4_reassembly as pcapng_ipv4_reassembly
from pcapkit.toolkit.pcapng import ipv6_reassembly as pcapng_ipv6_reassembly
from pcapkit.toolkit.pcapng import tcp_reassembly as pcapng_tcp_reassembly
from pcapkit.toolkit.pcapng import tcp_traceflow as pcapng_tcp_traceflow
from pcapkit.toolkit.pcapng import block2frame as pcapng_block2frame

# # tools for DPKT engine
# from pcapkit.toolkit.dpkt import ipv6_hdr_len as dpkt_ipv6_hdr_len
# from pcapkit.toolkit.dpkt import packet2chain as dpkt_packet2chain
# from pcapkit.toolkit.dpkt import packet2dict as dpkt_packet2dict
# from pcapkit.toolkit.dpkt import ipv4_reassembly as dpkt_ipv4_reassembly
# from pcapkit.toolkit.dpkt import ipv6_reassembly as dpkt_ipv6_reassembly
# from pcapkit.toolkit.dpkt import tcp_reassembly as dpkt_tcp_reassembly
# from pcapkit.toolkit.dpkt import tcp_traceflow as dpkt_tcp_traceflow

# # tools for PyShark engine
# from pcapkit.toolkit.pyshark import packet2dict as pyshark_packet2dict
# from pcapkit.toolkit.pyshark import tcp_traceflow as pyshark_tcp_traceflow

# # tools for Scapy engine
# from pcapkit.toolkit.scapy import packet2chain as scapy_packet2chain
# from pcapkit.toolkit.scapy import packet2dict as scapy_packet2dict
# from pcapkit.toolkit.scapy import ipv4_reassembly as scapy_ipv4_reassembly
# from pcapkit.toolkit.scapy import ipv6_reassembly as scapy_ipv6_reassembly
# from pcapkit.toolkit.scapy import tcp_reassembly as scapy_tcp_reassembly
# from pcapkit.toolkit.scapy import tcp_traceflow as scapy_tcp_traceflow

__all__ = [
    # default engine
    'ipv4_reassembly', 'ipv6_reassembly', 'tcp_reassembly', 'tcp_traceflow',
    'pcapng_ipv4_reassembly', 'pcapng_ipv6_reassembly', 'pcapng_tcp_reassembly', 'pcapng_tcp_traceflow',
    'pcapng_block2frame',

    # # DPKT engine
    # 'dpkt_ipv6_hdr_len', 'dpkt_packet2chain', 'dpkt_packet2dict',
    # 'dpkt_ipv4_reassembly', 'dpkt_ipv6_reassembly', 'dpkt_tcp_reassembly', 'dpkt_tcp_traceflow',

    # # PyShark engine
    # 'pyshark_packet2dict', 'pyshark_tcp_traceflow',

    # # Scapy engine
    # 'scapy_packet2chain', 'scapy_packet2dict',
    # 'scapy_ipv4_reassembly', 'scapy_ipv6_reassembly', 'scapy_tcp_reassembly', 'scapy_tcp_traceflow',
]
