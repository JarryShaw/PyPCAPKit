=================
3rd-Party Support
=================

Scapy Tools
===========

.. module:: pcapkit.toolkit.scapy

:mod:`pcapkit.toolkit.scapy` contains all you need for
:mod:`pcapkit` handy usage with `Scapy`_ engine. All reforming
functions returns with a flag to indicate if usable for
its caller.

.. _Scapy: https://scapy.net

.. warning::

   This module requires installed `Scapy`_ engine.

.. autofunction:: pcapkit.toolkit.scapy.ipv4_reassembly

.. autofunction:: pcapkit.toolkit.scapy.ipv6_reassembly

.. autofunction:: pcapkit.toolkit.scapy.tcp_reassembly

.. autofunction:: pcapkit.toolkit.scapy.tcp_traceflow

Auxiliary Functions
-------------------

.. autofunction:: pcapkit.toolkit.scapy.packet2chain

.. autofunction:: pcapkit.toolkit.scapy.packet2dict

DPKT Tools
==========

.. module:: pcapkit.toolkit.dpkt

:mod:`pcapkit.toolkit.dpkt` contains all you need for
:mod:`pcapkit` handy usage with `DPKT`_ engine. All reforming
functions returns with a flag to indicate if usable for
its caller.

.. _DPKT: https://dpkt.readthedocs.io

.. autofunction:: pcapkit.toolkit.dpkt.ipv4_reassembly

.. autofunction:: pcapkit.toolkit.dpkt.ipv6_reassembly

.. autofunction:: pcapkit.toolkit.dpkt.tcp_reassembly

.. autofunction:: pcapkit.toolkit.dpkt.tcp_traceflow

Auxiliary Functions
-------------------

.. autofunction:: pcapkit.toolkit.dpkt.ipv6_hdr_len

.. autofunction:: pcapkit.toolkit.dpkt.packet2chain

.. autofunction:: pcapkit.toolkit.dpkt.packet2dict

PyShark Tools
=============

.. module:: pcapkit.toolkit.pyshark

:mod:`pcapkit.toolkit.pyshark` contains all you need for
:mod:`pcapkit` handy usage with `PyShark`_ engine. All
reforming functions returns with a flag to indicate if
usable for its caller.

.. _PyShark: https://kiminewt.github.io/pyshark

.. note::

   Due to the lack of functionality of `PyShark`_, some
   functions of :mod:`pcapkit` may not be available with
   the `PyShark`_ engine.

.. autofunction:: pcapkit.toolkit.pyshark.tcp_traceflow

Auxiliary Functions
-------------------

.. autofunction:: pcapkit.toolkit.pyshark.packet2dict

PyPCAP Tools
============

.. module:: pcapkit.toolkit.pypcap

:mod:`pcapkit.toolkit.pypcap` contains all you need for
:mod:`pcapkit` handy usage with `PyPCAP`_ engine. All reforming
functions returns with a flag to indicate if usable for
its caller.

.. _PyPCAP: https://github.com/pynetwork/pypcap

.. note::

   `PyPCAP`_ performs no protocol dissection, so the reassembly and flow tracing
   adapters below cannot be implemented. They are defined all the same, so that
   reaching for one fails with an explanatory
   :exc:`~pcapkit.utilities.exceptions.UnsupportedCall` rather than an
   :exc:`ImportError`.

.. autofunction:: pcapkit.toolkit.pypcap.ipv4_reassembly

.. autofunction:: pcapkit.toolkit.pypcap.ipv6_reassembly

.. autofunction:: pcapkit.toolkit.pypcap.tcp_reassembly

.. autofunction:: pcapkit.toolkit.pypcap.tcp_traceflow

Auxiliary Functions
-------------------

.. autofunction:: pcapkit.toolkit.pypcap.packet2chain

.. autofunction:: pcapkit.toolkit.pypcap.packet2dict

pcap-ct Tools
=============

.. module:: pcapkit.toolkit.pcap_ct

:mod:`pcapkit.toolkit.pcap_ct` contains all you need for
:mod:`pcapkit` handy usage with `pcap-ct`_ engine. All reforming
functions returns with a flag to indicate if usable for
its caller.

.. _pcap-ct: https://pypi.org/project/pcap-ct/

.. note::

   `pcap-ct`_ is an independent reimplementation of the `PyPCAP`_ interface, so
   this module is deliberately a sibling of :mod:`pcapkit.toolkit.pypcap` rather
   than an alias of it: each engine names its own adapter, so a change made for
   one cannot quietly alter the other.

   Like `PyPCAP`_ it performs no protocol dissection, so the reassembly and flow
   tracing adapters below cannot be implemented. They are defined all the same,
   so that reaching for one fails with an explanatory
   :exc:`~pcapkit.utilities.exceptions.UnsupportedCall` rather than an
   :exc:`ImportError`.

.. autofunction:: pcapkit.toolkit.pcap_ct.ipv4_reassembly

.. autofunction:: pcapkit.toolkit.pcap_ct.ipv6_reassembly

.. autofunction:: pcapkit.toolkit.pcap_ct.tcp_reassembly

.. autofunction:: pcapkit.toolkit.pcap_ct.tcp_traceflow

Auxiliary Functions
-------------------

.. autofunction:: pcapkit.toolkit.pcap_ct.packet2chain

.. autofunction:: pcapkit.toolkit.pcap_ct.packet2dict

PyPCAPFile Tools
================

.. module:: pcapkit.toolkit.pypcapfile

:mod:`pcapkit.toolkit.pypcapfile` contains all you need for
:mod:`pcapkit` handy usage with `PyPCAPFile`_ engine. All reforming
functions returns with a flag to indicate if usable for
its caller.

.. _PyPCAPFile: https://github.com/kisom/pypcapfile

.. note::

   `PyPCAPFile`_ has no IPv6 decoder, so :func:`~pcapkit.toolkit.pypcapfile.ipv6_reassembly`
   raises :exc:`~pcapkit.utilities.exceptions.UnsupportedCall` rather than returning
   :data:`None` -- which would be indistinguishable from "this frame carries no
   IPv6 fragment".

.. autofunction:: pcapkit.toolkit.pypcapfile.ipv4_reassembly

.. autofunction:: pcapkit.toolkit.pypcapfile.ipv6_reassembly

.. autofunction:: pcapkit.toolkit.pypcapfile.tcp_reassembly

.. autofunction:: pcapkit.toolkit.pypcapfile.tcp_traceflow

Auxiliary Functions
-------------------

.. autofunction:: pcapkit.toolkit.pypcapfile.packet2timestamp

.. autofunction:: pcapkit.toolkit.pypcapfile.ipv4_header

.. autofunction:: pcapkit.toolkit.pypcapfile.packet2chain

.. autofunction:: pcapkit.toolkit.pypcapfile.packet2dict

Internal Definitions
--------------------

.. autodata:: pcapkit.toolkit.pypcapfile.TCP_MIN_HEADER_LEN

.. autodata:: pcapkit.toolkit.pypcapfile.IPV4_FLAG_DF

.. autodata:: pcapkit.toolkit.pypcapfile.IPV4_FLAG_MF
