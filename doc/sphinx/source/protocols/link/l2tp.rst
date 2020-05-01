L2TP - Layer Two Tunnelling Protocol
====================================

:mod:`pcapkit.protocols.link.l2tp` contains
:class:`~pcapkit.protocols.link.l2tp.L2TP` only,
which implements extractor for Layer Two Tunnelling
Protocol (L2TP) [*]_, whose structure is described
as below:

.. table::

   ======= ===== ===================== ==========================================
    Octets Bits  Name                  Description
   ======= ===== ===================== ==========================================
    0          0 ``l2tp.flags``        Flags and Version Info
   ------- ----- --------------------- ------------------------------------------
    0          0 ``l2tp.flags.type``   Type (control / data)
   ------- ----- --------------------- ------------------------------------------
    0          1 ``l2tp.flags.len``    Length
   ------- ----- --------------------- ------------------------------------------
    0          2                       Reserved (must be zero ``x00``)
   ------- ----- --------------------- ------------------------------------------
    0          4 ``l2tp.flags.seq``    Sequence
   ------- ----- --------------------- ------------------------------------------
    0          5                       Reserved (must be zero ``x00``)
   ------- ----- --------------------- ------------------------------------------
    0          6 ``l2tp.flags.offset`` Offset
   ------- ----- --------------------- ------------------------------------------
    0          7 ``l2tp.flags.prio``   Priority
   ------- ----- --------------------- ------------------------------------------
    1          8                       Reserved (must be zero ``x00``)
   ------- ----- --------------------- ------------------------------------------
    1         12 ``l2tp.ver``          Version (``2``)
   ------- ----- --------------------- ------------------------------------------
    2         16 ``l2tp.length``       Length (optional by ``len``)
   ------- ----- --------------------- ------------------------------------------
    4         32 ``l2tp.tunnelid``     Tunnel ID
   ------- ----- --------------------- ------------------------------------------
    6         48 ``l2tp.sessionid``    Session ID
   ------- ----- --------------------- ------------------------------------------
    8         64 ``l2tp.ns``           Sequence Number (optional by ``seq``)
   ------- ----- --------------------- ------------------------------------------
    10        80 ``l2tp.nr``           Next Sequence Number (optional by ``seq``)
   ------- ----- --------------------- ------------------------------------------
    12        96 ``l2tp.offset``       Offset Size (optional by ``offset``)
   ======= ===== ===================== ==========================================

.. raw:: html

   <br />

.. automodule:: pcapkit.protocols.link.l2tp
   :members:
   :undoc-members:
   :private-members:
   :show-inheritance:

Data Structure
--------------

.. class:: DataType_L2TP

   :bases: TypedDict

   L2TP header.

   .. attribute:: flags
      :type: DataTYpe_Flags

      flags & versoion info

   .. attribute:: version
      :type: Literal[2]

      version (``2``)

   .. attribute:: length
      :type: Optional[int]

      length (optional by :attr:`~DataType_Flags.len`)

   .. attribute:: tunnelid
      :type: int

      tunnel ID

   .. attribute:: sessionid
      :type: int

      session ID

   .. attribute:: ns
      :type: Optional[int]

      sequence number (optional by :attr:`~DataType_Flags.seq`)

   .. attribute:: nr
      :type: Optional[int]

      next sequence number (optional by :attr:`~DataType_Flags.seq`)

   .. attribute:: offset
      :type: Optional[int]

      offset (optional by :attr:`~DataType_Flags.offset`)

.. class:: DataType_Flags

   :bases: TypedDict

   Flags and version info.

   .. attribute:: type
      :type: Literal['Control', 'Data']

      type (control / data)

   .. attribute:: len
      :type: bool

      length

   .. attribute:: seq
      :type: bool

      sequence

   .. attribute:: offset
      :type: bool

      offset

   .. attribute:: prio
      :type: bool

      priority

.. raw:: html

   <hr />

.. [*] https://en.wikipedia.org/wiki/Layer_2_Tunneling_Protocol
