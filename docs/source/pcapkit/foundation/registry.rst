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

:mod:`pcapkit.foundation.registry.protocols` is a package of one submodule per
layer of :mod:`pcapkit.protocols`, beside
:mod:`~pcapkit.foundation.registry.protocols.protocol` for the registries the
others build on. Every function below is exported by the package, and by
:mod:`pcapkit.foundation.registry`, as well as by its own submodule.

.. versionchanged:: 1.5.0

   ``NULL``, the default of every ``class_`` argument here, is now the
   :data:`pcapkit.corekit.sentinels.NULL` sentinel; in 1.4.x it was the
   string ``'(null)'`` (:issue:`833`).

.. versionchanged:: 1.6.0

   A package of per-layer submodules rather than a single module
   (:issue:`2578`).

.. module:: pcapkit.foundation.registry.protocols.protocol

.. autofunction:: pcapkit.foundation.registry.protocols.protocol.register_protocol

.. autofunction:: pcapkit.foundation.registry.protocols.protocol.register_protocol_code

Top-Level Registries
~~~~~~~~~~~~~~~~~~~~

.. module:: pcapkit.foundation.registry.protocols.misc

These are in :mod:`~pcapkit.foundation.registry.protocols.misc` with the
PCAP-NG registries below, as :class:`~pcapkit.protocols.misc.pcap.frame.protocol.Frame`
and :class:`~pcapkit.protocols.misc.pcapng.protocol.PCAPNG` are in
:mod:`pcapkit.protocols.misc`.

.. autofunction:: pcapkit.foundation.registry.protocols.misc.register_linktype

.. autofunction:: pcapkit.foundation.registry.protocols.misc.register_pcap

.. autofunction:: pcapkit.foundation.registry.protocols.misc.register_pcapng

Link Layer Registries
~~~~~~~~~~~~~~~~~~~~~

.. module:: pcapkit.foundation.registry.protocols.link

.. autofunction:: pcapkit.foundation.registry.protocols.link.register_ethertype

.. autofunction:: pcapkit.foundation.registry.protocols.link.register_loopback

.. autofunction:: pcapkit.foundation.registry.protocols.link.register_arphrd

.. autofunction:: pcapkit.foundation.registry.protocols.link.register_frad

.. autofunction:: pcapkit.foundation.registry.protocols.link.register_netlink

.. autofunction:: pcapkit.foundation.registry.protocols.link.register_radiotap

.. autofunction:: pcapkit.foundation.registry.protocols.link.register_radiotap_field

Internet Layer Registries
~~~~~~~~~~~~~~~~~~~~~~~~~

.. module:: pcapkit.foundation.registry.protocols.internet

.. autofunction:: pcapkit.foundation.registry.protocols.internet.register_transtype

.. autofunction:: pcapkit.foundation.registry.protocols.internet.register_ipx

.. autofunction:: pcapkit.foundation.registry.protocols.internet.register_ipv4_option

.. autofunction:: pcapkit.foundation.registry.protocols.internet.register_icmp_type

.. autofunction:: pcapkit.foundation.registry.protocols.internet.register_hip_parameter

.. autofunction:: pcapkit.foundation.registry.protocols.internet.register_hopopt_option

.. autofunction:: pcapkit.foundation.registry.protocols.internet.register_ipv6_opts_option

.. autofunction:: pcapkit.foundation.registry.protocols.internet.register_ipv6_route_routing

.. autofunction:: pcapkit.foundation.registry.protocols.internet.register_mh_message

.. autofunction:: pcapkit.foundation.registry.protocols.internet.register_mh_option

.. autofunction:: pcapkit.foundation.registry.protocols.internet.register_mh_extension

Transport Layer Registries
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. module:: pcapkit.foundation.registry.protocols.transport

.. autofunction:: pcapkit.foundation.registry.protocols.transport.register_apptype

.. autofunction:: pcapkit.foundation.registry.protocols.transport.register_tcp

.. autofunction:: pcapkit.foundation.registry.protocols.transport.register_tcp_option

.. autofunction:: pcapkit.foundation.registry.protocols.transport.register_tcp_mp_option

.. autofunction:: pcapkit.foundation.registry.protocols.transport.register_udp

.. autofunction:: pcapkit.foundation.registry.protocols.transport.register_sctp

.. autofunction:: pcapkit.foundation.registry.protocols.transport.register_sctp_chunk

.. autofunction:: pcapkit.foundation.registry.protocols.transport.register_sctp_parameter

.. autofunction:: pcapkit.foundation.registry.protocols.transport.register_sctp_cause

.. autofunction:: pcapkit.foundation.registry.protocols.transport.register_dccp

.. autofunction:: pcapkit.foundation.registry.protocols.transport.register_dccp_option

Application Layer Registries
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. module:: pcapkit.foundation.registry.protocols.application

.. autofunction:: pcapkit.foundation.registry.protocols.application.register_http_frame

.. autofunction:: pcapkit.foundation.registry.protocols.application.register_tls_extension

Miscellaneous Protocol Registries
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. currentmodule:: pcapkit.foundation.registry.protocols.misc

.. autofunction:: pcapkit.foundation.registry.protocols.misc.register_pcapng_block

.. autofunction:: pcapkit.foundation.registry.protocols.misc.register_pcapng_option

.. autofunction:: pcapkit.foundation.registry.protocols.misc.register_pcapng_record

.. autofunction:: pcapkit.foundation.registry.protocols.misc.register_pcapng_secrets
