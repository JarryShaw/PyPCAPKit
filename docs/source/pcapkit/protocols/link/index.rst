Link Layer
==========

.. module:: pcapkit.protocols.link
.. module:: pcapkit.protocols.data.link
.. module:: pcapkit.protocols.schema.link

:mod:`pcapkit.protocols.link` is the collection of all protocols in
link layer, with detailed implementation and methods.

.. versionremoved:: 1.5.0

   ``pcapkit.protocols.link.OSPF``, ``pcapkit.protocols.link.RARP`` and
   ``pcapkit.protocols.link.DRARP``, and ``OSPF`` and
   ``OSPF_CrytographicAuthentication`` in :mod:`pcapkit.protocols.data.link` and
   :mod:`pcapkit.protocols.schema.link`, with no alias. The protocols moved to
   :mod:`pcapkit.protocols.application` (:issue:`719`); see
   :class:`~pcapkit.protocols.application.ospf.OSPF` and
   :class:`~pcapkit.protocols.application.rarp.RARP`.

.. toctree::
   :maxdepth: 1

   link
   ethernet
   arp
   l2tp
   l2tpv2
   linux_sll
   linux_sll1
   linux_sll2
   loopback
   netlink
   vlan
   c_tag
   s_tag

.. todo::

   Implement DSL, EAPOL, FDDI, ISDN, NDP, PPP.

Protocol Registry
-----------------

.. data:: LINKTYPE
   :module: pcapkit.protocols.link

   alias of :class:`pcapkit.const.reg.linktype.LinkType`
