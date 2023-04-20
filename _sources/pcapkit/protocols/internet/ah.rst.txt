AH - Authentication Header
==========================

.. module:: pcapkit.protocols.internet.ah

:mod:`pcapkit.protocols.internet.ah` contains
:class:`~pcapkit.protocols.internet.AH` only,
which implements extractor for Authentication
Header (AH) [*]_, whose structure is described
as below:

======= ========= ======================= ===================================
Octets      Bits        Name                    Description
======= ========= ======================= ===================================
  0           0   ``ah.next``               Next Header
  1           8   ``ah.length``             Payload Length
  2          16                             Reserved (must be zero)
  4          32   ``sah.spi``               Security Parameters Index (SPI)
  8          64   ``sah.seq``               Sequence Number Field
  12         96   ``sah.icv``               Integrity Check Value (ICV)
======= ========= ======================= ===================================

.. autoclass:: pcapkit.protocols.internet.ah.AH
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoproperty:: name
   .. autoproperty:: length
   .. autoproperty:: payload
   .. autoproperty:: protocol
   .. autoproperty:: protochain

   .. automethod:: id

   .. automethod:: read
   .. automethod:: make

   .. automethod:: _make_data

   .. automethod:: __post_init__
   .. automethod:: __index__

Header Schemas
--------------

.. module:: pcapkit.protocols.schema.internet.ah

.. autoclass:: pcapkit.protocols.schema.internet.ah.AH
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

Data Models
-----------

.. module:: pcapkit.protocols.data.internet.ah

.. autoclass:: pcapkit.protocols.data.internet.ah.AH
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. raw:: html

   <hr />

.. [*] https://en.wikipedia.org/wiki/IPsec
