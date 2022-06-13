OSPF - Open Shortest Path First
===============================

.. module:: pcapkit.protocols.link.ospf
.. module:: pcapkit.protocols.data.link.ospf

:mod:`pcapkit.protocols.link.ospf` contains
:class:`~pcapkit.protocols.link.ospf.OSPF` only,
which implements extractor for Open Shortest Path
First (OSPF) [*]_, whose structure is described
as below:

.. table::

   ====== ===== ================== ===============================
   Octets Bits  Name               Description
   ====== ===== ================== ===============================
   0          0 ``ospf.version``   Version Number
   ------ ----- ------------------ -------------------------------
   0          0 ``ospf.type``      Type
   ------ ----- ------------------ -------------------------------
   0          1 ``ospf.len``       Packet Length (header included)
   ------ ----- ------------------ -------------------------------
   0          2 ``ospf.router_id`` Router ID
   ------ ----- ------------------ -------------------------------
   0          4 ``ospf.area_id``   Area ID
   ------ ----- ------------------ -------------------------------
   0          6 ``ospf.chksum``    Checksum
   ------ ----- ------------------ -------------------------------
   0          7 ``ospf.autype``    Authentication Type
   ------ ----- ------------------ -------------------------------
   1          8 ``ospf.auth``      Authentication
   ====== ===== ================== ===============================

.. raw:: html

   <br />

.. autoclass:: pcapkit.protocols.link.ospf.OSPF
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. automethod:: __index__

   .. autoproperty:: name
   .. autoproperty:: alias
   .. autoproperty:: length
   .. autoproperty:: type

   .. automethod:: read
   .. automethod:: make

   .. automethod:: _read_encrypt_auth

Data Structures
---------------

.. autoclass:: pcapkit.protocols.data.link.ospf.OSPF(version, type, length, router_id, area_id, chksum, autype)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: version
   .. autoattribute:: type
   .. autoattribute:: len
   .. autoattribute:: router_id
   .. autoattribute:: area_id
   .. autoattribute:: chksum
   .. autoattribute:: autype

   .. autoattribute:: auth

.. autoclass:: pcapkit.protocols.data.link.ospf.CrytographicAuthentication(key_id, len, seq)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: key_id
   .. autoattribute:: len
   .. autoattribute:: seq

.. raw:: html

   <hr />

.. [*] https://en.wikipedia.org/wiki/Open_Shortest_Path_First
