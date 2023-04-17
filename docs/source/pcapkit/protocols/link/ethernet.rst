Ethernet Protocol
=================

.. module:: pcapkit.protocols.link.ethernet
.. module:: pcapkit.protocols.data.link.ethernet

:mod:`pcapkit.protocols.link.ethernet` contains
:class:`~pcapkit.protocols.link.ethernet.Ethernet`
only, which implements extractor for Ethernet
Protocol [*]_, whose structure is described as
below:

.. table::

   ====== ===== ============ =========================
   Octets Bits  Name         Description
   ====== ===== ============ =========================
   0          0 ``eth.dst``  Destination MAC Address
   ------ ----- ------------ -------------------------
   1          8 ``eth.src``  Source MAC Address
   ------ ----- ------------ -------------------------
   2         16 ``eth.type`` Protocol (Internet Layer)
   ====== ===== ============ =========================

.. raw:: html

   <br />

.. autoclass:: pcapkit.protocols.link.ethernet.Ethernet
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. automethod:: __index__

   .. autoproperty:: name
   .. autoproperty:: length
   .. autoproperty:: protocol
   .. autoproperty:: src
   .. autoproperty:: dst

   .. automethod:: read
   .. automethod:: make

   .. .. automethod:: _read_mac_addr

Data Structures
---------------

.. autoclass:: pcapkit.protocols.data.link.ethernet.Ethernet(dst, src, type)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: dst
   .. autoattribute:: src
   .. autoattribute:: type

.. raw:: html

   <hr />

.. [*] https://en.wikipedia.org/wiki/Ethernet
