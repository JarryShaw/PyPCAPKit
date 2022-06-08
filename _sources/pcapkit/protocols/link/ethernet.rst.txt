Ethernet Protocol
=================

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

.. automodule:: pcapkit.protocols.link.ethernet
   :members:
   :undoc-members:
   :private-members:
   :show-inheritance:

Data Structure
--------------

.. important::

   Following classes are only for *documentation* purpose.
   They do **NOT** exist in the :mod:`pcapkit` module.

.. class:: DataType_Ethernet

   :bases: TypedDict

   Ethernet header.

   .. attribute:: dst
      :type: str

      destination MAC address

   .. attribute:: src
      :type: str

      source MAC address

   .. attribute:: type
      :type: pcapkit.const.reg.ethertype.EtherType

      protocol (Internet layer)

.. raw:: html

   <hr />

.. [*] https://en.wikipedia.org/wiki/Ethernet
