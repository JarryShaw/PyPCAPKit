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
   12        96 ``ethernet.type`` Protocol (Internet Layer)
   ====== ===== ================= =========================

.. autoclass:: pcapkit.protocols.link.ethernet.protocol.Ethernet
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: length
   .. autoproperty:: protocol
   .. autoproperty:: src
   .. autoproperty:: dst

   .. automethod:: read
   .. automethod:: make

   .. automethod:: __index__

   .. automethod:: _make_data

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

Data Models
-----------

.. module:: pcapkit.protocols.link.ethernet.data

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.data.link.ethernet``, with no alias: the module moved here
   (:issue:`2534`).

.. autoclass:: pcapkit.protocols.link.ethernet.data.Ethernet
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/Ethernet
