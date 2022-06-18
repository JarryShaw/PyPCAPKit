Internet Layer Protocols
========================

.. module:: pcapkit.protocols.internet
.. module:: pcapkit.protocols.data.internet

:mod:`pcapkit.protocols.internet` is collection of all protocols in
internet layer, with detailed implementation and methods.

.. toctree::
   :maxdepth: 2

   internet
   ah
   hip
   hopopt
   ip
   ipsec
   ipv4
   ipv6_frag
   ipv6_opts
   ipv6_route
   ipv6
   ipx
   mh

.. todo::

   Implements ECN, ESP, ICMP, ICMPv6, IGMP, Shim6.

Protocol Registry
-----------------

.. data:: pcapkit.protocols.internet.ETHERTYPE

   Alias of :class:`pcapkit.const.reg.ethertype.EtherType`.
