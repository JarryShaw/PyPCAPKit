Ethernet Protocol
=================

.. module:: pcapkit.protocols.link.ethernet
.. module:: pcapkit.protocols.link.ethernet.protocol

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.link.ethernet.PAT_MAC_ADDR``, with no alias:
   :meth:`~pcapkit.protocols.protocol.Protocol._read_mac_addr` and
   :meth:`~pcapkit.protocols.protocol.Protocol._make_mac_addr` read and make the address
   (:issue:`2614`).

:mod:`pcapkit.protocols.link.ethernet.protocol` contains
:class:`~pcapkit.protocols.link.ethernet.protocol.Ethernet`
only, which implements the extractor for Ethernet
Protocol [*]_, whose structure is:

.. table::

   ====== ===== ================= =========================
   Octets Bits  Name              Description
   ====== ===== ================= =========================
   0          0 ``ethernet.dst``  Destination MAC Address
   ------ ----- ----------------- -------------------------
   6         48 ``ethernet.src``  Source MAC Address
   ------ ----- ----------------- -------------------------
   12        96 ``ethernet.type`` Length/Type
   ====== ===== ================= =========================

The Length/Type field is an EtherType from ``0x0600`` up. Up to ``0x05DC`` it is
the length of an IEEE 802.2 :class:`~pcapkit.protocols.link.llc.protocol.LLC`
PDU, and the octets past it are kept as ``ethernet.trailer``
(:ieee:`802.3-2022` §3.2.6).

.. autoclass:: pcapkit.protocols.link.ethernet.protocol.Ethernet
   :no-members:
   :show-inheritance:

   .. rubric:: Properties

   .. autoproperty:: name
   .. autoproperty:: length
   .. autoproperty:: protocol
   .. autoproperty:: src
   .. autoproperty:: dst

   .. rubric:: Methods

   .. automethod:: read
   .. automethod:: make

   .. rubric:: Data Models

   .. automethod:: __index__

   .. rubric:: Utilities

   .. automethod:: _make_data
   .. automethod:: _import_next_layer

Header Schemas
--------------

.. module:: pcapkit.protocols.link.ethernet.schema

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.schema.link.ethernet``, with no alias: the module moved here
   (:issue:`2534`).

.. autoclass:: pcapkit.protocols.link.ethernet.schema.Ethernet
   :members:
   :show-inheritance:

Auxiliary Functions
~~~~~~~~~~~~~~~~~~~

.. autofunction:: pcapkit.protocols.link.ethernet.schema.callback_payload
.. autofunction:: pcapkit.protocols.link.ethernet.schema.ethernet_payload_length

Data Models
-----------

.. module:: pcapkit.protocols.link.ethernet.data

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.data.link.ethernet``, with no alias: the module moved here
   (:issue:`2534`).

.. autoclass:: pcapkit.protocols.link.ethernet.data.Ethernet
   :members:
   :show-inheritance:

Constants
---------

.. module:: pcapkit.protocols.link.ethernet.const

.. versionadded:: 1.9.0

.. autodata:: pcapkit.protocols.link.ethernet.const.LENGTH_MAX
   :no-value:

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/Ethernet
