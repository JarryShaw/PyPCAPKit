Registry Management
===================

.. module:: pcapkit.foundation.registry

This module (:mod:`pcapkit.foundation.registry`) provides the registry
management for :mod:`pcapkit`, as the module contains various registry
points.

Protocol Registries
-------------------

.. autofunction:: pcapkit.foundation.registry.register_protocol

.. autofunction:: pcapkit.foundation.registry.register_pcap

.. autofunction:: pcapkit.foundation.registry.register_pcapng

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

Miscellaneous Registries
------------------------

PCAP-NG Registries
~~~~~~~~~~~~~~~~~~

.. autofunction:: pcapkit.foundation.registry.register_pcapng_block

.. autofunction:: pcapkit.foundation.registry.register_pcapng_option

.. autofunction:: pcapkit.foundation.registry.register_pcapng_record

.. autofunction:: pcapkit.foundation.registry.register_pcapng_secrets

Engine Registries
~~~~~~~~~~~~~~~~~

.. autofunction:: pcapkit.foundation.registry.register_extractor_engine

Dumper Registries
~~~~~~~~~~~~~~~~~

.. autofunction:: pcapkit.foundation.registry.register_extractor_dumper

.. autofunction:: pcapkit.foundation.registry.register_traceflow

Auxiliary Methods
~~~~~~~~~~~~~~~~~

.. autofunction:: pcapkit.foundation.registry.register_output

.. autofunction:: pcapkit.foundation.registry.register_linktype

.. autofunction:: pcapkit.foundation.registry.register_port
