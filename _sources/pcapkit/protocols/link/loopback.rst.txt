BSD Loopback Encapsulation
==========================

.. module:: pcapkit.protocols.link.loopback
.. module:: pcapkit.protocols.link.loopback.protocol

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.link.loopback.family_byteorder``, with no alias: it is in this
   module, and :mod:`pcapkit.protocols.link.loopback` exports the protocol class alone
   (:issue:`2534`).

:mod:`pcapkit.protocols.link.loopback.protocol` contains
:class:`~pcapkit.protocols.link.loopback.protocol.Loopback`
only, which implements the extractor for the BSD loopback
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

.. autoclass:: pcapkit.protocols.link.loopback.protocol.Loopback
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: length
   .. autoproperty:: protocol

   .. automethod:: read
   .. automethod:: make
   .. automethod:: register

   .. automethod:: _make_data

   .. automethod:: __index__

   .. autoattribute:: __proto__
      :no-value:

.. autofunction:: pcapkit.protocols.link.loopback.protocol.family_byteorder

Header Schemas
--------------

.. module:: pcapkit.protocols.link.loopback.schema

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.schema.link.loopback``, with no alias: the module moved here
   (:issue:`2534`).

.. autoclass:: pcapkit.protocols.link.loopback.schema.Loopback
   :members:
   :show-inheritance:

Data Models
-----------

.. module:: pcapkit.protocols.link.loopback.data

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.data.link.loopback``, with no alias: the module moved here
   (:issue:`2534`).

.. autoclass:: pcapkit.protocols.link.loopback.data.Loopback
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://www.tcpdump.org/linktypes/LINKTYPE_NULL.html
