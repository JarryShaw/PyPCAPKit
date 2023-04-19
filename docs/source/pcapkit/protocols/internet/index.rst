Internet Layer Protocols
========================

.. module:: pcapkit.protocols.internet
.. module:: pcapkit.protocols.data.internet
.. module:: pcapkit.protocols.schema.internet

:mod:`pcapkit.protocols.internet` is collection of all protocols in
internet layer, with detailed implementation and methods.

.. toctree::
   :maxdepth: 2

   internet
   ip
   ipv4
   ipv6
   ipv6_frag
   ipv6_opts
   ipv6_route
   hopopt
   ipsec
   ah
   hip
   mh
   ipx

.. todo::

   Implements ECN, ESP, ICMP, ICMPv6, IGMP, Shim6.

Protocol Registry
-----------------

.. data:: pcapkit.protocols.internet.ETHERTYPE

   Alias of :class:`pcapkit.const.reg.ethertype.EtherType`.
