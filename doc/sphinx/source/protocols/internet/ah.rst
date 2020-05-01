AH - Authentication Header
==========================

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

.. raw:: html

   <br />

.. automodule:: pcapkit.protocols.internet.ah
   :members:
   :undoc-members:
   :private-members:
   :show-inheritance:

Data Structure
--------------

.. class:: DataType_AH

   :bases: TypedDict

   Authentication header [:rfc:`4302`].

   .. attribute:: next
      :type: pcapkit.const.reg.transtype.TransType

      Next header.

   .. attribute:: length
      :type: int

      Payload length.

   .. attribute:: spi
      :type: int

      Security parameters index (SPI).

   .. attribute:: seq
      :type: int

      Sequence number field.

   .. attribute:: icv
      :type: int

      Integrity check value (ICV).

.. raw:: html

   <hr />

.. [*] https://en.wikipedia.org/wiki/IPsec
