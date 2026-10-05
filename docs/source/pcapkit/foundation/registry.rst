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

.. autofunction:: pcapkit.foundation.registry.protocols.register_sctp

Application Layer Registries
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. autofunction:: pcapkit.foundation.registry.protocols.register_http_frame

Miscellaneous Protocol Registries
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. autofunction:: pcapkit.foundation.registry.protocols.register_pcapng_block

.. autofunction:: pcapkit.foundation.registry.protocols.register_pcapng_option

.. autofunction:: pcapkit.foundation.registry.protocols.register_pcapng_record

.. autofunction:: pcapkit.foundation.registry.protocols.register_pcapng_secrets
