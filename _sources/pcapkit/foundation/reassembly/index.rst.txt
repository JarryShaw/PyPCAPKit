==================
Packets Reassembly
==================

.. module:: pcapkit.foundation.reassembly

:mod:`pcapkit.foundation.reassembly` bases on algorithms described
in :rfc:`791` and :rfc:`815`, implements datagram reassembly
of IP and TCP packets.

.. seealso::

   For more information on customisation and extension, please
   refer to :doc:`../../../ext`.

.. toctree::
   :maxdepth: 2

   reassembly
   ip/index
   tcp

All reassembly classes are implemented as :class:`~pcapkit.foundation.reassembly.reassembly.Reassembly`
subclasses, which are responsible for processing extracted packets and
reassemble the datagrams to a nonfragmented packet. Below is a brief
diagram of the class hierarchy of :mod:`pcapkit.foundation.reassembly`:

.. mermaid::

   flowchart LR
       A{{ReassemblyMeta}} -.->|metaclass| B(ReassemblyBase)

       B --> IP & TCP
       IP --> IPv4 & IPv6

       B --> C(Reassembly)
       C --> D([user customisation ...])

       click A "/pcapkit/foundation/reassembly/reassembly.html#pcapkit.foundation.reassembly.reassembly.ReassemblyMeta"
       click B "/pcapkit/foundation/reassembly/reassembly.html#pcapkit.foundation.reassembly.reassembly.ReassemblyBase"
       click C "/pcapkit/foundation/reassembly/reassembly.html#pcapkit.foundation.reassembly.reassembly.Reassembly"
       click D "/ext.html#reassembly-and-flow-tracing"

       click IP "/pcapkit/foundation/reassembly/ip/index.html#pcapkit.foundation.reassembly.ip.IP"
       click IPv4 "/pcapkit/foundation/reassembly/ip/ipv4.html#pcapkit.foundation.reassembly.ip.ipv4.IPv4"
       click IPv6 "/pcapkit/foundation/reassembly/ip/ipv6.html#pcapkit.foundation.reassembly.ip.ipv6.IPv6"
       click TCP "/pcapkit/foundation/reassembly/tcp.html#pcapkit.foundation.reassembly.tcp.TCP"

Auxiliary Data
==============

.. autoclass:: pcapkit.foundation.reassembly.ReassemblyManager
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.foundation.reassembly.data.ReassemblyData
   :members:
   :show-inheritance:
