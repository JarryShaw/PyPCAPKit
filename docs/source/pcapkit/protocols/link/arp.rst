ARP - Address Resolution Protocol
=================================

.. module:: pcapkit.protocols.link.arp
.. module:: pcapkit.protocols.link.arp.protocol

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.link.arp.PAT_MAC_ADDR``, with no alias:
   :meth:`~pcapkit.protocols.protocol.Protocol._read_mac_addr` and
   :meth:`~pcapkit.protocols.protocol.Protocol._make_mac_addr` read and make the address
   (:issue:`2614`).

:mod:`pcapkit.protocols.link.arp.protocol` contains
:class:`~pcapkit.protocols.link.arp.protocol.ARP` only,
which implements an extractor for Address Resolution
Protocol (ARP) [*]_, whose structure is described as
below:

.. table::

   ====== ==== ============= =======================
   Octets Bits Name          Description
   ====== ==== ============= =======================
   0      0    ``arp.htype`` Hardware Type
   ------ ---- ------------- -----------------------
   2      16   ``arp.ptype`` Protocol Type
   ------ ---- ------------- -----------------------
   4      32   ``arp.hlen``  Hardware Address Length
   ------ ---- ------------- -----------------------
   5      40   ``arp.plen``  Protocol Address Length
   ------ ---- ------------- -----------------------
   6      48   ``arp.oper``  Operation
   ------ ---- ------------- -----------------------
   8      64   ``arp.sha``   Sender Hardware Address
   ------ ---- ------------- -----------------------
   14     112  ``arp.spa``   Sender Protocol Address
   ------ ---- ------------- -----------------------
   18     144  ``arp.tha``   Target Hardware Address
   ------ ---- ------------- -----------------------
   24     192  ``arp.tpa``   Target Protocol Address
   ====== ==== ============= =======================

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.link.arp.InARP``, with no alias. The class moved to
   :mod:`pcapkit.protocols.link.inarp.protocol`, since a module holds one protocol
   class, named after it (:issue:`2529`).

.. autoclass:: pcapkit.protocols.link.arp.protocol.ARP
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: alias
   .. autoproperty:: length
   .. autoproperty:: src
   .. autoproperty:: dst
   .. autoproperty:: type

   .. automethod:: id
   .. automethod:: read
   .. automethod:: make

   .. automethod:: __index__

   .. automethod:: _make_data
   .. automethod:: _read_addr_resolve
   .. automethod:: _make_addr_resolve
   .. automethod:: _read_proto_resolve
   .. automethod:: _make_proto_resolve

Header Schemas
--------------

.. module:: pcapkit.protocols.link.arp.schema

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.schema.link.arp``, with no alias: the module moved here
   (:issue:`2534`).

.. autoclass:: pcapkit.protocols.link.arp.schema.ARP
   :members:
   :show-inheritance:

Data Models
-----------

.. module:: pcapkit.protocols.link.arp.data

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.data.link.arp``, with no alias: the module moved here
   (:issue:`2534`).

.. autoclass:: pcapkit.protocols.link.arp.data.ARP
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.arp.data.Address
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.arp.data.Type
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] http://en.wikipedia.org/wiki/Address_Resolution_Protocol
