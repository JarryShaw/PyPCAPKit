OSPF - Open Shortest Path First
===============================

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

.. automodule:: pcapkit.protocols.link.ospf
   :members:
   :undoc-members:
   :private-members:
   :show-inheritance:

Data Structure
--------------

.. class:: DataType_OSPF

   :bases: TypedDict

   OSPF header.

   .. attribute:: version
      :type: int

      version number

   .. attribute:: type
      :type: pcapkit.const.ospf.packet.Packet

      type

   .. attribute:: len
      :type: int

      packet length (header included)

   .. attribute:: router_id
      :type: ipaddress.IPv4Address

      router ID

   .. attribute:: area_id
      :type: ipaddress.IPv4Address

      area ID

   .. attribute:: chksum
      :type: bytes

      checksum

   .. attribute:: autype
      :type: pcapkit.const.ospf.authentication.Authentication

      authentication type

   .. attribute:: auth
      :type: Union[bytes, DataType_Auth]

      authentication

Cryptographic Authentication Information
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For cryptographic authentication information as
described in :rfc:`2328`, its structure is described
as below:

.. table::

   ====== ===== ==================== =================================
   Octets Bits  Name                 Description
   ====== ===== ==================== =================================
   0          0                      Reserved (must be zero ``\x00``)
   ------ ----- -------------------- ---------------------------------
   0          0 ``ospf.auth.key_id`` Key ID
   ------ ----- -------------------- ---------------------------------
   0          1 ``ospf.auth.len``    Authentication Data Length
   ------ ----- -------------------- ---------------------------------
   0          2 ``ospf.auth.seq``    Cryptographic Sequence Number
   ====== ===== ==================== =================================

.. raw:: html

   <br />

.. class:: DataType_Auth

   :bases: TypedDict

   Cryptographic authentication.

   .. attribute:: key_id
      :type: int

      key ID

   .. attribute:: len
      :type: int

      authentication data length

   .. attribute:: seq
      :type: int

      cryptographic sequence number

.. raw:: html

   <hr />

.. [*] https://en.wikipedia.org/wiki/Open_Shortest_Path_First
