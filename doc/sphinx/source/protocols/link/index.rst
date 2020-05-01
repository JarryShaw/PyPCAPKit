Link Layer Protocols
====================

.. module:: pcapkit.protocols.link

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

.. autoclass:: pcapkit.protocols.link.link.Link
   :members:
   :undoc-members:
   :private-members:
   :show-inheritance:

   .. autoattribute:: __layer__

   .. attribute:: __proto__
      :type: DefaultDict[int, Tuple[str, str]]

      Protocol index mapping for decoding next layer,
      c.f. :meth:`self._decode_next_layer <pcapkit.protocols.protocol.Protocol._decode_next_layer>`
      & :meth:`self._import_next_layer <pcapkit.protocols.protocol.Protocol._import_next_layer>`.
      The values should be a tuple representing the module name and class name.

      .. list-table::
         :header-rows: 1

         * - Code
           - Module
           - Class
         * - 0x0806
           - :mod:`pcapkit.protocols.link.arp`
           - :class:`~pcapkit.protocols.link.arp.ARP`
         * - 0x8035
           - :mod:`pcapkit.protocols.link.rarp`
           - :class:`~pcapkit.protocols.link.rarp.RARP`
         * - 0x8100
           - :mod:`pcapkit.protocols.link.vlan`
           - :class:`~pcapkit.protocols.link.vlan.VLAN`
         * - 0x0800
           - :mod:`pcapkit.protocols.internet.ipv4`
           - :class:`~pcapkit.protocols.internet.ipv4.IPv4`
         * - 0x86DD
           - :mod:`pcapkit.protocols.internet.ipv6`
           - :class:`~pcapkit.protocols.internet.ipv6.IPv6`
         * - 0x8137
           - :mod:`pcapkit.protocols.internet.ipx`
           - :class:`~pcapkit.protocols.internet.ipx.IPX`
