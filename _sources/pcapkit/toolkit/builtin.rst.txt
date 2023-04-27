================
Built-in Support
================

PCAP Tools
==========

.. module:: pcapkit.toolkit.pcap

:mod:`pcapkit.toolkit.pcap` contains all you need for
PCAP file format handling. All functions returns with
a flag to indicate if usable for its caller.

.. autofunction:: pcapkit.toolkit.pcap.ipv4_reassembly

.. autofunction:: pcapkit.toolkit.pcap.ipv6_reassembly

.. autofunction:: pcapkit.toolkit.pcap.tcp_reassembly

.. autofunction:: pcapkit.toolkit.pcap.tcp_traceflow

PCAP-NG Tools
=============

.. module:: pcapkit.toolkit.pcapng

:mod:`pcapkit.toolkit.pcapng` contains all you need for
PCAP-NG file format handling. All functions returns with
a flag to indicate if usable for its caller.

.. autofunction:: pcapkit.toolkit.pcapng.ipv4_reassembly

.. autofunction:: pcapkit.toolkit.pcapng.ipv6_reassembly

.. autofunction:: pcapkit.toolkit.pcapng.tcp_reassembly

.. autofunction:: pcapkit.toolkit.pcapng.tcp_traceflow

.. autofunction:: pcapkit.toolkit.pcapng.block2frame
