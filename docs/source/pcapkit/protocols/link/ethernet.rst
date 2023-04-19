Ethernet Protocol
=================

.. module:: pcapkit.protocols.link.ethernet

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

.. autoclass:: pcapkit.protocols.link.ethernet.Ethernet
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoproperty:: name
   .. autoproperty:: length
   .. autoproperty:: protocol
   .. autoproperty:: src
   .. autoproperty:: dst

   .. automethod:: read
   .. automethod:: make

   .. automethod:: _make_data

   .. automethod:: __index__

Header Schemas
--------------

.. module:: pcapkit.protocols.schema.link.ethernet

.. autoclass:: pcapkit.protocols.schema.link.ethernet.Ethernet
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

Auxiliary Functions
~~~~~~~~~~~~~~~~~~~

.. autofunction:: pcapkit.protocols.schema.link.ethernet.callback_payload

Data Models
-----------

.. module:: pcapkit.protocols.data.link.ethernet

.. autoclass:: pcapkit.protocols.data.link.ethernet.Ethernet
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. raw:: html

   <hr />

.. [*] https://en.wikipedia.org/wiki/Ethernet
