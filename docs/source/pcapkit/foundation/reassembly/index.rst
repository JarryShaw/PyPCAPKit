==================
Packets Reassembly
==================

.. module:: pcapkit.foundation.reassembly

:mod:`pcapkit.foundation.reassembly` implements datagram reassembly
of IP and TCP packets, based on the algorithms described in :rfc:`791`
and :rfc:`815`.

.. seealso::

   For more information on customisation and extension, please
   refer to :doc:`../../../ext`.

.. toctree::
   :maxdepth: 2

   reassembly
   ip/index
   tcp

All reassembly classes are implemented as :class:`~pcapkit.foundation.reassembly.reassembly.ReassemblyBase`
subclasses, which are responsible for processing extracted packets and
reassembling the datagrams into unfragmented packets. Below is a brief
diagram of the class hierarchy of :mod:`pcapkit.foundation.reassembly`:

.. mermaid::

   flowchart LR
       A{{ReassemblyMeta}} -.->|metaclass| B(ReassemblyBase)

       B --> IP & TCP
       IP --> IPv4 & IPv6

       B --> C(Reassembly)
       C --> D([user customisation ...])

       click A "reassembly.html#pcapkit.foundation.reassembly.reassembly.ReassemblyMeta"
       click B "reassembly.html#pcapkit.foundation.reassembly.reassembly.ReassemblyBase"
       click C "reassembly.html#pcapkit.foundation.reassembly.reassembly.Reassembly"
       click D "../../../ext.html#reassembly-and-flow-tracing"

       click IP "ip/ip.html#pcapkit.foundation.reassembly.ip.IP"
       click IPv4 "ip/ipv4.html#pcapkit.foundation.reassembly.ipv4.IPv4"
       click IPv6 "ip/ipv6.html#pcapkit.foundation.reassembly.ipv6.IPv6"
       click TCP "tcp.html#pcapkit.foundation.reassembly.tcp.TCP"

Auxiliary Data
==============

.. autoclass:: pcapkit.foundation.reassembly.ReassemblyManager
   :members:
   :show-inheritance:

.. module:: pcapkit.foundation.reassembly.data
.. module:: pcapkit.foundation.reassembly.data.data
.. currentmodule:: pcapkit.foundation.reassembly

.. autoclass:: pcapkit.foundation.reassembly.data.data.ReassemblyData
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.foundation.reassembly.data.data.Completion
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.foundation.reassembly.data.data.Deferred
   :members:
   :show-inheritance:
