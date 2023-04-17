:mod:`Scapy <scapy>` Tools
==========================

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

.. autofunction:: pcapkit.toolkit.scapy.packet2chain
.. autofunction:: pcapkit.toolkit.scapy.packet2dict
