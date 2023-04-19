Base Protocol
=============

.. module:: pcapkit.protocols.link.link

:mod:`pcapkit.protocols.link.link` contains :class:`~pcapkit.protocols.link.link.Link`,
which is a base class for link layer protocols, e.g. :class:`~pcapkit.protocols.link.arp.ARP`/InARP,
:class:`~pcapkit.protocols.link.ethernet.Ethernet`, :class:`~pcapkit.protocols.link.l2tp.L2TP`,
:class:`~pcapkit.protocols.link.ospf.OSPF`, :class:`~pcapkit.protocols.link.rarp.RARP`/DRARP and etc.

.. autoclass:: pcapkit.protocols.link.link.Link
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoproperty:: layer

   .. automethod:: register

   .. autoattribute:: __layer__
   .. autoattribute:: __proto__
      :no-value:
