MH - Mobility Header
====================

.. module:: pcapkit.protocols.internet.mh
.. module:: pcapkit.protocols.data.internet.mh

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

.. todo::

   Implements extractor for message data of all MH types.

.. autoclass:: pcapkit.protocols.internet.mh.MH
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. automethod:: __post_init__
   .. automethod:: __index__

   .. autoproperty:: name
   .. autoproperty:: length
   .. autoproperty:: payload
   .. autoproperty:: protocol
   .. autoproperty:: protochain

   .. automethod:: read
   .. automethod:: make

Data Structures
---------------

.. autoclass:: pcapkit.protocols.data.internet.mh.MH(next, length, type, chksum, data)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: next
   .. autoattribute:: length
   .. autoattribute:: type
   .. autoattribute:: chksum
   .. autoattribute:: data

.. raw:: html

   <hr />

.. [*] https://en.wikipedia.org/wiki/Mobile_IP#Changes_in_IPv6_for_Mobile_IPv6
