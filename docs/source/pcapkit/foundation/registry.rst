Registry Management
===================

.. module:: pcapkit.foundation.registry

This module (:mod:`pcapkit.foundation.registry`) provides the registry
management for :mod:`pcapkit`, as the module contains various registry
points.

Auxiliary Methods
-----------------

.. autofunction:: pcapkit.foundation.registry.register_output

.. autofunction:: pcapkit.foundation.registry.register_linktype

.. autofunction:: pcapkit.foundation.registry.register_port

Dumper Registries
-----------------

.. autofunction:: pcapkit.foundation.registry.register_extractor

.. autofunction:: pcapkit.foundation.registry.register_traceflow

Protocol Registries
-------------------

.. autofunction:: pcapkit.foundation.registry.register_protocol

.. autofunction:: pcapkit.foundation.registry.register_pcap

Link Layer Registries
---------------------

.. autofunction:: pcapkit.foundation.registry.register_ethertype

Internet Layer Registries
-------------------------

.. autofunction:: pcapkit.foundation.registry.register_transtype

.. autofunction:: pcapkit.foundation.registry.register_hopopt

.. autofunction:: pcapkit.foundation.registry.register_ipv6_opts

.. autofunction:: pcapkit.foundation.registry.register_ipv6_route

Transport Layer Registries
--------------------------

.. autofunction:: pcapkit.foundation.registry.register_tcp_port

.. autofunction:: pcapkit.foundation.registry.register_tcp

.. autofunction:: pcapkit.foundation.registry.register_mptcp

.. autofunction:: pcapkit.foundation.registry.register_udp_port

Application Layer Registries
----------------------------

.. autofunction:: pcapkit.foundation.registry.register_http
