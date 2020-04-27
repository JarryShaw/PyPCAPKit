.. module:: pcapkit.protocols.link

Link Layer Protocols
====================

:mod:`pcapkit.protocols.link` is collection of all protocols in
link layer, with detailed implementation and methods.

.. toctree::
   :maxdepth: 4

   arp
   ethernet
   l2tp
   ospf
   rarp
   vlan

Base Protocol
-------------

:mod:`pcapkit.protocols.link.link` contains :class:`~pcapkit.protocols.link.link.Link`,
which is a base class for link layer protocols, e.g. :class:`~pcapkit.protocols.link.link.arp.ARP`/InARP,
:class:`~pcapkit.protocols.link.link.ethernet.Ethernet`, :class:`~pcapkit.protocols.link.link.l2tp.L2TP`,
:class:`~pcapkit.protocols.link.link.ospf.OSPF`, :class:`~pcapkit.protocols.link.link.rarp.RARP`/DRARP and etc.

.. automodule:: pcapkit.protocols.link.link
   :members:
   :undoc-members:
   :private-members:
   :show-inheritance:
