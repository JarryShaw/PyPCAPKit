Base Protocol
=============

.. module:: pcapkit.protocols.link.link

:mod:`pcapkit.protocols.link.link` contains :class:`~pcapkit.protocols.link.link.Link`,
which is a base class for link layer protocols, e.g. :class:`~pcapkit.protocols.link.arp.ARP`/InARP,
:class:`~pcapkit.protocols.link.ethernet.Ethernet`, :class:`~pcapkit.protocols.link.l2tp.L2TP`
and :class:`~pcapkit.protocols.link.vlan.VLAN`.

.. autoclass:: pcapkit.protocols.link.link.Link
   :no-members:
   :show-inheritance:

   .. autoproperty:: layer

   .. automethod:: register
   .. automethod:: from_data

   .. automethod:: __post_init__

   .. autoattribute:: __layer__
   .. autoattribute:: __proto__
      :no-value:
