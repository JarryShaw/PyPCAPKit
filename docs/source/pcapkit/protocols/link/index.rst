Link Layer
==========

.. module:: pcapkit.protocols.link
.. module:: pcapkit.protocols.data.link
.. module:: pcapkit.protocols.schema.link

:mod:`pcapkit.protocols.link` is collection of all protocols in
link layer, with detailed implementation and methods.

.. toctree::
   :maxdepth: 1

   link
   ethernet
   arp
   rarp
   l2tp
   ospf
   vlan

.. todo::

   Implements DSL, EAPOL, FDDI, ISDN, NDP, PPP.

Protocol Registry
-----------------

.. data:: pcapkit.protocols.link.LINKTYPE

   alias of :class:`pcapkit.const.reg.linktype.LinkType`
