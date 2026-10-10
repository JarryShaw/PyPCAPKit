================
Built-in Support
================

PCAP Tools
==========

.. module:: pcapkit.toolkit.pcap

:mod:`pcapkit.toolkit.pcap` contains the adapters for the PCAP format.
The reassembly and flow tracing adapters return the data their
:mod:`pcapkit.foundation` counterpart consumes, or :data:`None` if the frame
cannot be used for it. The TCP adapters here and in
:mod:`pcapkit.toolkit.pcapng` read the segment with
:func:`~pcapkit.toolkit.pcap.tcp_segment`.

.. autofunction:: pcapkit.toolkit.pcap.ipv4_reassembly

.. autofunction:: pcapkit.toolkit.pcap.ipv6_reassembly

.. autofunction:: pcapkit.toolkit.pcap.tcp_reassembly

.. autofunction:: pcapkit.toolkit.pcap.tcp_traceflow

Auxiliary Functions
-------------------

.. autofunction:: pcapkit.toolkit.pcap.tcp_segment

.. autoclass:: pcapkit.toolkit.pcap.TCPSegment
   :members:
   :show-inheritance:

PCAP-NG Tools
=============

.. module:: pcapkit.toolkit.pcapng

:mod:`pcapkit.toolkit.pcapng` contains the adapters for the PCAP-NG format.
The reassembly and flow tracing adapters return the data their
:mod:`pcapkit.foundation` counterpart consumes, or :data:`None` if the frame
cannot be used for it.

.. autofunction:: pcapkit.toolkit.pcapng.ipv4_reassembly

.. autofunction:: pcapkit.toolkit.pcapng.ipv6_reassembly

.. autofunction:: pcapkit.toolkit.pcapng.tcp_reassembly

.. autofunction:: pcapkit.toolkit.pcapng.tcp_traceflow

Auxiliary Functions
-------------------

.. autofunction:: pcapkit.toolkit.pcapng.block2frame
