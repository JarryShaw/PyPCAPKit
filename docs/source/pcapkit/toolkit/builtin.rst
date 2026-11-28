================
Built-in Support
================

Each reassembly or flow tracing adapter below returns the data its
:mod:`pcapkit.foundation` counterpart consumes, or :data:`None` for a frame it
cannot use.

PCAP Tools
==========

.. module:: pcapkit.toolkit.pcap

:mod:`pcapkit.toolkit.pcap` contains the adapters for the PCAP format. The TCP
adapters here and in
:mod:`pcapkit.toolkit.pcapng` read the segment with
:func:`~pcapkit.toolkit.pcap.tcp_segment`, the UDP flow tracing ones the datagram
with :func:`~pcapkit.toolkit.pcap._carrier`, the DTLS ones the record with
:func:`~pcapkit.toolkit.pcap._dtls_fragments`, and the SCTP ones the packet with
:func:`~pcapkit.toolkit.pcap._sctp_fragments`. The TLS adapters of every engine keep
the TCP ones' records of a TLS stream with :func:`~pcapkit.toolkit.pcap._tls_segment`.

.. autofunction:: pcapkit.toolkit.pcap.ipv4_reassembly

.. autofunction:: pcapkit.toolkit.pcap.ipv6_reassembly

.. autofunction:: pcapkit.toolkit.pcap.tcp_reassembly

.. autofunction:: pcapkit.toolkit.pcap.dtls_reassembly

.. autofunction:: pcapkit.toolkit.pcap.sctp_reassembly

.. autofunction:: pcapkit.toolkit.pcap.tls_reassembly

.. autofunction:: pcapkit.toolkit.pcap.tcp_traceflow

.. autofunction:: pcapkit.toolkit.pcap.udp_traceflow

.. autofunction:: pcapkit.toolkit.pcap.ip_traceflow

Auxiliary Functions
-------------------

.. autofunction:: pcapkit.toolkit.pcap.tcp_segment

.. autofunction:: pcapkit.toolkit.pcap._carrier

.. autofunction:: pcapkit.toolkit.pcap._fragment

.. autofunction:: pcapkit.toolkit.pcap._dtls_fragments

.. autofunction:: pcapkit.toolkit.pcap._sctp_fragments

.. autofunction:: pcapkit.toolkit.pcap._tls_segment

.. autoclass:: pcapkit.toolkit.pcap.TCPSegment
   :members:
   :show-inheritance:

PCAP-NG Tools
=============

.. module:: pcapkit.toolkit.pcapng

:mod:`pcapkit.toolkit.pcapng` contains the adapters for the PCAP-NG format.

.. autofunction:: pcapkit.toolkit.pcapng.ipv4_reassembly

.. autofunction:: pcapkit.toolkit.pcapng.ipv6_reassembly

.. autofunction:: pcapkit.toolkit.pcapng.tcp_reassembly

.. autofunction:: pcapkit.toolkit.pcapng.dtls_reassembly

.. autofunction:: pcapkit.toolkit.pcapng.sctp_reassembly

.. autofunction:: pcapkit.toolkit.pcapng.tls_reassembly

.. autofunction:: pcapkit.toolkit.pcapng.tcp_traceflow

.. autofunction:: pcapkit.toolkit.pcapng.udp_traceflow

.. autofunction:: pcapkit.toolkit.pcapng.ip_traceflow

Auxiliary Functions
-------------------

.. autofunction:: pcapkit.toolkit.pcapng.block2frame
