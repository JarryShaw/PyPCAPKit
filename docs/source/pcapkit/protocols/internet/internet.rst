Base Protocol
=============

.. module:: pcapkit.protocols.internet.internet

:mod:`pcapkit.protocols.internet.internet` contains :class:`~pcapkit.protocols.internet.internet.Internet`,
which is a base class for internet layer protocols, eg. :class:`~pcapkit.protocols.internet.ah.AH`,
:class:`~pcapkit.protocols.internet.ipsec.IPsec`, :class:`~pcapkit.protocols.internet.ipv4.IPv4`,
:class:`~pcapkit.protocols.internet.ipv6.IPv6`, :class:`~pcapkit.protocols.internet.ipx.IPX`, and etc.

.. autoclass:: pcapkit.protocols.internet.internet.Internet
   :no-members:
   :show-inheritance:

   .. autoproperty:: layer

   .. automethod:: register

   .. automethod:: _decode_next_layer
   .. automethod:: _import_next_layer
   .. automethod:: _next_layer_class
   .. automethod:: _next_exthdr_depth

   .. autoattribute:: __layer__
      :no-value:
   .. autoattribute:: __proto__
      :no-value:
   .. autoattribute:: _exthdr_depth

Extension Header Chains
-----------------------

A chain of IPv6 extension headers is dissected to at most
:data:`~pcapkit.protocols.internet.internet.EXTENSION_HEADER_LIMIT` headers in
a row, whether it follows IPv6 or another layer such as IPv4. What follows is
kept as :class:`~pcapkit.protocols.misc.raw.Raw`, with one
:exc:`~pcapkit.utilities.warnings.ProtocolWarning` (:issue:`1604`). The
``pypcapfile`` toolkit stops at the same depth. The ``dpkt``, ``scapy`` and
``pyshark`` engines leave the walk to their own parsers, which do not stop
there, so they may still find the upper layer past it (:issue:`1609`).

.. autodata:: pcapkit.protocols.internet.internet.EXTENSION_HEADER_LIMIT
