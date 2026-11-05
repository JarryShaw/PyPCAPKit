OSPF - Open Shortest Path First
===============================

.. module:: pcapkit.protocols.application.ospf
.. module:: pcapkit.protocols.application.ospf.protocol

:mod:`pcapkit.protocols.application.ospf.protocol` contains
:class:`~pcapkit.protocols.application.ospf.protocol.OSPF` only,
which implements an extractor for Open Shortest Path
First (OSPF) [*]_, whose structure is:

.. table::

   ====== ===== ================== ===============================
   Octets Bits  Name               Description
   ====== ===== ================== ===============================
   0          0 ``ospf.version``   Version Number
   ------ ----- ------------------ -------------------------------
   1          8 ``ospf.type``      Type
   ------ ----- ------------------ -------------------------------
   2         16 ``ospf.len``       Packet Length (header included)
   ------ ----- ------------------ -------------------------------
   4         32 ``ospf.router_id`` Router ID
   ------ ----- ------------------ -------------------------------
   8         64 ``ospf.area_id``   Area ID
   ------ ----- ------------------ -------------------------------
   12        96 ``ospf.chksum``    Checksum
   ------ ----- ------------------ -------------------------------
   14       112 ``ospf.autype``    Authentication Type
   ------ ----- ------------------ -------------------------------
   16       128 ``ospf.auth``      Authentication
   ====== ===== ================== ===============================

.. versionadded:: 1.5.0

   Moved here from ``pcapkit.protocols.link.ospf``, with its data model and
   header schema. :class:`~pcapkit.protocols.application.ospf.protocol.OSPF` derives
   from :class:`~pcapkit.protocols.application.application.Application`, so
   its layer is ``'Application'`` (:issue:`719`).

.. versionremoved:: 1.5.0

   ``pcapkit.protocols.link.ospf``, ``pcapkit.protocols.data.link.ospf`` and
   ``pcapkit.protocols.schema.link.ospf``, the ``OSPF`` name that
   :mod:`pcapkit.protocols.link`, ``pcapkit.protocols.data.link`` and
   ``pcapkit.protocols.schema.link`` each exported, and the
   ``OSPF_CrytographicAuthentication`` name that
   ``pcapkit.protocols.data.link`` and ``pcapkit.protocols.schema.link``
   exported, with no alias (:issue:`719`, :issue:`1090`).

.. versionchanged:: 1.5.0

   A rebuild keeps the parsed Packet Length and the octets past it, where
   :meth:`~pcapkit.protocols.application.ospf.protocol.OSPF.make` recomputed the
   length from the payload and dropped those octets; it takes them as
   ``packet_length`` and ``trailer`` (:issue:`1249`, :issue:`1455`).

.. raw:: html

   <br />

.. autoclass:: pcapkit.protocols.application.ospf.protocol.OSPF
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: alias
   .. autoproperty:: length
   .. autoproperty:: type

   .. automethod:: read
   .. automethod:: make

   .. automethod:: __index__

   .. automethod:: _make_data
   .. automethod:: _read_encrypt_auth
   .. automethod:: _make_encrypt_auth
   .. automethod:: _make_id_numbers

Header Schemas
--------------

.. module:: pcapkit.protocols.application.ospf.schema

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.schema.application.ospf``, with no alias: the module moved here
   (:issue:`2534`).

.. autoclass:: pcapkit.protocols.application.ospf.schema.OSPF
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ospf.schema.CryptographicAuthentication
   :members:
   :show-inheritance:

Auxiliary Functions
~~~~~~~~~~~~~~~~~~~

.. autofunction:: pcapkit.protocols.application.ospf.schema.ospf_auth_data_selector

Data Models
-----------

.. module:: pcapkit.protocols.application.ospf.data

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.data.application.ospf``, with no alias: the module moved here
   (:issue:`2534`).

.. autoclass:: pcapkit.protocols.application.ospf.data.OSPF
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ospf.data.CryptographicAuthentication
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/Open_Shortest_Path_First
