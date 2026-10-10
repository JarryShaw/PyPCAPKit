BSD Loopback Encapsulation
==========================

.. module:: pcapkit.protocols.link.loopback

:mod:`pcapkit.protocols.link.loopback` contains
:class:`~pcapkit.protocols.link.loopback.Loopback`
only, which implements extractor for the BSD loopback
encapsulation [*]_ of ``LINKTYPE_NULL`` and ``LINKTYPE_LOOP``,
whose structure is described as below:

.. table::

   ====== ===== =================== ===================================
   Octets Bits  Name                Description
   ====== ===== =================== ===================================
   0          0 ``loopback.family`` Address Family (Internet Layer)
   ====== ===== =================== ===================================

The address family is in the byte order of the capturing host for
``LINKTYPE_NULL``, which no capture format records, so it is inferred from the
octets; for ``LINKTYPE_LOOP`` it is always in network byte order. Either way it
is kept as ``loopback.byteorder``.

.. autoclass:: pcapkit.protocols.link.loopback.Loopback
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: length
   .. autoproperty:: protocol

   .. automethod:: read
   .. automethod:: make

   .. automethod:: _make_data

   .. automethod:: __index__

   .. autoattribute:: __proto__
      :no-value:

.. autofunction:: pcapkit.protocols.link.loopback.family_byteorder

Header Schemas
--------------

.. module:: pcapkit.protocols.schema.link.loopback

.. autoclass:: pcapkit.protocols.schema.link.loopback.Loopback
   :members:
   :show-inheritance:

Data Models
-----------

.. module:: pcapkit.protocols.data.link.loopback

.. autoclass:: pcapkit.protocols.data.link.loopback.Loopback
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://www.tcpdump.org/linktypes/LINKTYPE_NULL.html
