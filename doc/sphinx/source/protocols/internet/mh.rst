MH - Mobility Header
====================

:mod:`pcapkit.protocols.internet.mh` contains
:class:`~pcapkit.protocols.internet.mh.MH` only,
which implements extractor for Mobility Header
(MH) [*]_, whose structure is described as below:

======= ========= ================== ===============================
Octets      Bits        Name                    Description
======= ========= ================== ===============================
  0           0   ``mh.next``                 Next Header
  1           8   ``mh.length``               Header Length
  2          16   ``mh.type``                 Mobility Header Type
  3          24                               Reserved
  4          32   ``mh.chksum``               Checksum
  6          48   ``mh.data``                 Message Data
======= ========= ================== ===============================

.. raw:: html

   <br />

.. automodule:: pcapkit.protocols.internet.mh
   :members:
   :undoc-members:
   :private-members:
   :show-inheritance:

Data Structure
--------------

.. important::

   Following classes are only for *documentation* purpose.
   They do **NOT** exist in the :mod:`pcapkit` module.

.. class:: DataType_MH

   :bases: TypedDict

   .. attribute:: next
      :type: pcapkit.const.reg.transtype.TransType

      Next header.

   .. attribute:: length
      :type: int

      Header length.

   .. attribute:: type
      :type: pcapkit.const.mh.packet.Packet

      Mobility header type.

   .. attribute:: chksum
      :type: bytes

      Checksum.

   .. attribute:: data
      :type: bytes

      Message data.

.. raw:: html

   <hr />

.. [*] https://en.wikipedia.org/wiki/Mobile_IP#Changes_in_IPv6_for_Mobile_IPv6
