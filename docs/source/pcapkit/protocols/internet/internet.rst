Base Protocol
=============

.. module:: pcapkit.protocols.internet.internet

:mod:`pcapkit.protocols.internet.internet` contains :class:`~pcapkit.protocols.internet.internet.Internet`,
which is a base class for internet layer protocols, e.g. :class:`~pcapkit.protocols.internet.ah.AH`,
:class:`~pcapkit.protocols.internet.ipsec.IPsec`, :class:`~pcapkit.protocols.internet.ipv4.IPv4`,
:class:`~pcapkit.protocols.internet.ipv6.IPv6` and :class:`~pcapkit.protocols.internet.ipx.IPX`.

.. autoclass:: pcapkit.protocols.internet.internet.Internet
   :no-members:
   :show-inheritance:

   .. autoproperty:: layer

   .. automethod:: register
   .. automethod:: from_data

   .. automethod:: _decode_next_layer
   .. automethod:: _import_next_layer
   .. automethod:: _next_layer_class
   .. automethod:: _next_exthdr_depth
   .. automethod:: _make_payload
   .. automethod:: _rebuilt_exthdr_depth

   .. autoattribute:: __layer__
      :no-value:
   .. autoattribute:: __proto__
      :no-value:
   .. autoattribute:: _exthdr_depth

Extension Header Chains
-----------------------

A chain of IPv6 extension headers is dissected to at most
:data:`~pcapkit.utilities.config.EXTENSION_HEADER_LIMIT` headers in
a row, whether it follows IPv6 or another layer such as IPv4. What follows is
kept as :class:`~pcapkit.protocols.misc.raw.Raw`, with one
:exc:`~pcapkit.utilities.warnings.ProtocolWarning` (:issue:`1604`). The
``pyshark`` engine leaves the walk to its own parser, which does not stop there,
so it may still find the upper layer past it (:issue:`1609`). So may the
``dpkt`` toolkit, which reads the chain as ``dpkt`` decodes it. So does the
``scapy`` engine behind IPv6, where Scapy dissects each extension header itself;
behind IPv4, its toolkit steps over them in the octets to find TCP, up to
:data:`~pcapkit.utilities.config.EXTENSION_HEADER_LIMIT` of them in a row. The
``pypcapfile`` toolkit walks no extension header chain, so it finds no upper
layer behind one.
