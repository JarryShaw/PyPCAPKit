Registry Management
===================

.. module:: pcapkit.foundation.registry

This module (:mod:`pcapkit.foundation.registry`) provides the registry
management for :mod:`pcapkit`, as the module contains various registry
points.

Foundation Registries
---------------------

.. module:: pcapkit.foundation.registry.foundation

Engine Registries
~~~~~~~~~~~~~~~~~

.. autofunction:: pcapkit.foundation.registry.foundation.register_extractor_engine

Dumper Registries
~~~~~~~~~~~~~~~~~

.. autofunction:: pcapkit.foundation.registry.foundation.register_dumper

.. autofunction:: pcapkit.foundation.registry.foundation.register_extractor_dumper

.. autofunction:: pcapkit.foundation.registry.foundation.register_traceflow_dumper

Callback Registries
~~~~~~~~~~~~~~~~~~~

.. autofunction:: pcapkit.foundation.registry.foundation.register_reassembly_ipv4_callback

.. autofunction:: pcapkit.foundation.registry.foundation.register_reassembly_ipv6_callback

.. autofunction:: pcapkit.foundation.registry.foundation.register_reassembly_tcp_callback

.. autofunction:: pcapkit.foundation.registry.foundation.register_traceflow_tcp_callback

Extractor Registries
~~~~~~~~~~~~~~~~~~~~

.. autofunction:: pcapkit.foundation.registry.foundation.register_extractor_reassembly

.. autofunction:: pcapkit.foundation.registry.foundation.register_extractor_traceflow

Protocol Registries
-------------------

.. module:: pcapkit.foundation.registry.protocols

.. autofunction:: pcapkit.foundation.registry.protocols.register_protocol

Top-Level Registries
~~~~~~~~~~~~~~~~~~~~

.. autofunction:: pcapkit.foundation.registry.protocols.register_linktype

.. autofunction:: pcapkit.foundation.registry.protocols.register_pcap

.. autofunction:: pcapkit.foundation.registry.protocols.register_pcapng

Link Layer Registries
~~~~~~~~~~~~~~~~~~~~~

.. autofunction:: pcapkit.foundation.registry.protocols.register_ethertype

Internet Layer Registries
~~~~~~~~~~~~~~~~~~~~~~~~~

.. autofunction:: pcapkit.foundation.registry.protocols.register_transtype

.. autofunction:: pcapkit.foundation.registry.protocols.register_ipv4_option

.. autofunction:: pcapkit.foundation.registry.protocols.register_hip_parameter

.. autofunction:: pcapkit.foundation.registry.protocols.register_hopopt_option

.. autofunction:: pcapkit.foundation.registry.protocols.register_ipv6_opts_option

.. autofunction:: pcapkit.foundation.registry.protocols.register_ipv6_route_routing

.. autofunction:: pcapkit.foundation.registry.protocols.register_mh_message

.. autofunction:: pcapkit.foundation.registry.protocols.register_mh_option

.. autofunction:: pcapkit.foundation.registry.protocols.register_mh_extension

Transport Layer Registries
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. autofunction:: pcapkit.foundation.registry.protocols.register_apptype

.. autofunction:: pcapkit.foundation.registry.protocols.register_tcp

.. autofunction:: pcapkit.foundation.registry.protocols.register_tcp_option

.. autofunction:: pcapkit.foundation.registry.protocols.register_tcp_mp_option

.. autofunction:: pcapkit.foundation.registry.protocols.register_udp

Application Layer Registries
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. autofunction:: pcapkit.foundation.registry.protocols.register_http_frame

Miscellaneous Protocol Registries
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. autofunction:: pcapkit.foundation.registry.protocols.register_pcapng_block

.. autofunction:: pcapkit.foundation.registry.protocols.register_pcapng_option

.. autofunction:: pcapkit.foundation.registry.protocols.register_pcapng_record

.. autofunction:: pcapkit.foundation.registry.protocols.register_pcapng_secrets
