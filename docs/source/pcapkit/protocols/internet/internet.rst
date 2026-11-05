Internet Layer Base Protocol
============================

.. module:: pcapkit.protocols.internet.internet

:mod:`pcapkit.protocols.internet.internet` contains :class:`~pcapkit.protocols.internet.internet.Internet`,
which is a base class for internet layer protocols, e.g. :class:`~pcapkit.protocols.internet.ah.protocol.AH`,
:class:`~pcapkit.protocols.internet.ipsec.protocol.IPsec`, :class:`~pcapkit.protocols.internet.ipv4.protocol.IPv4`,
:class:`~pcapkit.protocols.internet.ipv6.protocol.IPv6` and :class:`~pcapkit.protocols.internet.ipx.protocol.IPX`.

.. autoclass:: pcapkit.protocols.internet.internet.Internet
   :no-members:
   :show-inheritance:

   .. autoattribute:: __layer__
      :no-value:

   .. autoattribute:: __proto__
      :no-value:

   .. autoattribute:: __proto_key__
      :no-value:

   .. autoattribute:: _exthdr_depth

   .. autoproperty:: layer

   .. automethod:: register
   .. automethod:: from_data

   .. automethod:: _next_exthdr_depth
   .. automethod:: _rebuilt_exthdr_depth
   .. automethod:: _make_payload
   .. automethod:: _next_layer_class
   .. automethod:: _decode_next_layer
   .. automethod:: _import_next_layer

.. autodata:: pcapkit.protocols.internet.internet._exthdr_rebuilt
   :no-value:

Extension Header Chains
-----------------------

A chain of IPv6 extension headers, behind IPv6 or another layer such as IPv4,
is dissected to at most :data:`~pcapkit.utilities.config.EXTENSION_HEADER_LIMIT`
headers in a row. What follows is kept as
:class:`~pcapkit.protocols.misc.raw.protocol.Raw`, with one
:exc:`~pcapkit.utilities.warnings.ProtocolWarning` (:issue:`1604`). The other
engines and toolkits:

.. list-table::
   :header-rows: 1

   * - Engine or toolkit
     - Behind a chain
   * - ``pyshark`` engine
     - Its own parser walks the chain without that limit, so it may still find
       the upper layer (:issue:`1609`).
   * - ``dpkt`` toolkit
     - Reads the chain as |dpkt|_ decodes it, so it may too.
   * - ``scapy`` engine
     - Behind IPv6, Scapy dissects each extension header itself, so it may too.
       Behind IPv4, its toolkit steps over at most
       :data:`~pcapkit.utilities.config.EXTENSION_HEADER_LIMIT` of them in a row
       in the octets to find TCP.
   * - ``pypcapfile`` toolkit
     - Walks no chain, so it finds no upper layer behind one.
