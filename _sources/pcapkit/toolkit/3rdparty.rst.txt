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
