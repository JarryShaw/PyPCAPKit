Registry Management
===================

.. module:: pcapkit.foundation.registry

:mod:`pcapkit.foundation.registry` holds the registration functions for
:mod:`pcapkit`'s engines, dumpers, callbacks and protocols.

A code the shipped enumerations do not define can still be registered: most
constant enumerations return a member-like object for an in-range unknown value
rather than rejecting it (see :ref:`unrecognised-values`), so a newly assigned
number needs no regeneration.

Foundation Registries
---------------------

.. module:: pcapkit.foundation.registry.foundation

.. versionchanged:: 1.5.0

   ``NULL``, the default of every ``class_`` argument here, is now the
   :data:`pcapkit.corekit.sentinels.NULL` sentinel; in 1.4.x it was the
   string ``'(null)'`` (:issue:`833`).

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

.. versionchanged:: 1.5.0

   ``NULL``, the default of every ``class_`` argument here, is now the
   :data:`pcapkit.corekit.sentinels.NULL` sentinel; in 1.4.x it was the
   string ``'(null)'`` (:issue:`833`).

.. autofunction:: pcapkit.foundation.registry.protocols.register_protocol

.. autofunction:: pcapkit.foundation.registry.protocols.register_protocol_code

Top-Level Registries
~~~~~~~~~~~~~~~~~~~~

.. autofunction:: pcapkit.foundation.registry.protocols.register_linktype

.. autofunction:: pcapkit.foundation.registry.protocols.register_pcap

.. autofunction:: pcapkit.foundation.registry.protocols.register_pcapng

Link Layer Registries
~~~~~~~~~~~~~~~~~~~~~

.. autofunction:: pcapkit.foundation.registry.protocols.register_ethertype

.. autofunction:: pcapkit.foundation.registry.protocols.register_loopback

.. autofunction:: pcapkit.foundation.registry.protocols.register_arphrd

.. autofunction:: pcapkit.foundation.registry.protocols.register_frad

.. autofunction:: pcapkit.foundation.registry.protocols.register_netlink

Internet Layer Registries
~~~~~~~~~~~~~~~~~~~~~~~~~

.. autofunction:: pcapkit.foundation.registry.protocols.register_transtype

.. autofunction:: pcapkit.foundation.registry.protocols.register_ipx

.. autofunction:: pcapkit.foundation.registry.protocols.register_ipv4_option

.. autofunction:: pcapkit.foundation.registry.protocols.register_icmp_type

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

.. autofunction:: pcapkit.foundation.registry.protocols.register_sctp

.. autofunction:: pcapkit.foundation.registry.protocols.register_sctp_chunk

.. autofunction:: pcapkit.foundation.registry.protocols.register_sctp_parameter

.. autofunction:: pcapkit.foundation.registry.protocols.register_sctp_cause

.. autofunction:: pcapkit.foundation.registry.protocols.register_dccp

.. autofunction:: pcapkit.foundation.registry.protocols.register_dccp_option

Application Layer Registries
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. autofunction:: pcapkit.foundation.registry.protocols.register_http_frame

Miscellaneous Protocol Registries
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. autofunction:: pcapkit.foundation.registry.protocols.register_pcapng_block

.. autofunction:: pcapkit.foundation.registry.protocols.register_pcapng_option

.. autofunction:: pcapkit.foundation.registry.protocols.register_pcapng_record

.. autofunction:: pcapkit.foundation.registry.protocols.register_pcapng_secrets
