AH - Authentication Header
==========================

.. module:: pcapkit.protocols.internet.ah
.. module:: pcapkit.protocols.internet.ah.protocol

:mod:`pcapkit.protocols.internet.ah.protocol` contains
:class:`~pcapkit.protocols.internet.ah.protocol.AH` only,
which implements the extractor for Authentication
Header (AH) [*]_, whose structure is described
as below:

======= ========= ======================= ===================================
Octets      Bits        Name                    Description
======= ========= ======================= ===================================
  0           0   ``ah.next``               Next Header
  1           8   ``ah.length``             Payload Length
  2          16   ``ah.reserved``           Reserved (must be zero)
  4          32   ``ah.spi``                Security Parameters Index (SPI)
  8          64   ``ah.seq``                Sequence Number Field
  12         96   ``ah.icv``                Integrity Check Value (ICV)
======= ========= ======================= ===================================

.. autoclass:: pcapkit.protocols.internet.ah.protocol.AH
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: alias
   .. autoproperty:: length
   .. autoproperty:: payload
   .. autoproperty:: protocol
   .. autoproperty:: protochain

   .. automethod:: read
   .. automethod:: make
   .. automethod:: id

   .. automethod:: __post_init__
   .. automethod:: __index__

   .. automethod:: _make_data

Header Schemas
--------------

.. module:: pcapkit.protocols.internet.ah.schema

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.schema.internet.ah``, with no alias: the module moved here
   (:issue:`2534`).

.. autodata:: pcapkit.protocols.internet.ah.schema.AH_HEADER_LEN

.. autoclass:: pcapkit.protocols.internet.ah.schema.AH
   :members:
   :show-inheritance:

Data Models
-----------

.. module:: pcapkit.protocols.internet.ah.data

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.data.internet.ah``, with no alias: the module moved here
   (:issue:`2534`).

.. autoclass:: pcapkit.protocols.internet.ah.data.AH
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/IPsec
