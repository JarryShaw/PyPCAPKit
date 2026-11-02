# -*- coding: utf-8 -*-
"""Protocol Registries
=========================

.. module:: pcapkit.foundation.registry.protocols

This package provides the protocol registries for :mod:`pcapkit`, one
submodule per layer of :mod:`pcapkit.protocols`, beside
:mod:`~pcapkit.foundation.registry.protocols.protocol` for the registries the
others build on. Every function a submodule exports is exported here as well.

.. versionchanged:: 1.5.0

   ``NULL``, the default of every ``class_`` argument here, is now the
   :data:`pcapkit.corekit.sentinels.NULL` sentinel; in 1.4.x it was the
   string ``'(null)'`` (:issue:`833`).

.. versionchanged:: 1.6.0

   A package of per-layer submodules rather than a single module
   (:issue:`2578`).

"""
# Protocol Base Registries
from pcapkit.foundation.registry.protocols.protocol import *
# Link Layer Protocol Registries
from pcapkit.foundation.registry.protocols.link import *
# Internet Layer Protocol Registries
from pcapkit.foundation.registry.protocols.internet import *
# Transport Layer Protocol Registries
from pcapkit.foundation.registry.protocols.transport import *
# Application Layer Protocol Registries
from pcapkit.foundation.registry.protocols.application import *
# Miscellaneous Protocol Registries
from pcapkit.foundation.registry.protocols.misc import *

__all__ = [
    'register_protocol',
    'register_protocol_code',

    'register_linktype',
    'register_pcap', 'register_pcapng',

    'register_ethertype',
    'register_loopback',
    'register_arphrd', 'register_frad', 'register_netlink', 'register_radiotap',
    'register_radiotap_field',

    'register_transtype',
    'register_ipx',
    'register_icmp_type',
    'register_ipv4_option', 'register_hip_parameter', 'register_hopopt_option',
    'register_ipv6_opts_option', 'register_ipv6_route_routing',
    'register_mh_message', 'register_mh_option', 'register_mh_extension',

    'register_apptype',
    'register_tcp', 'register_udp', 'register_sctp', 'register_dccp',
    'register_tcp_option', 'register_tcp_mp_option',
    'register_sctp_chunk', 'register_sctp_parameter', 'register_sctp_cause',
    'register_dccp_option',

    'register_http_frame',
    'register_tls_extension',

    'register_pcapng_block', 'register_pcapng_option', 'register_pcapng_secrets',
    'register_pcapng_record',
]
