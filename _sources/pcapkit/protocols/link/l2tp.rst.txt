L2TP - Layer Two Tunnelling Protocol
====================================

.. module:: pcapkit.protocols.link.l2tp
.. module:: pcapkit.protocols.data.link.l2tp

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

.. autoclass:: pcapkit.protocols.link.l2tp.L2TP
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. automethod:: __index__

   .. autoproperty:: name
   .. autoproperty:: length
   .. autoproperty:: type

   .. automethod:: read
   .. automethod:: make

Data Structures
---------------

.. autoclass:: pcapkit.protocols.data.link.l2tp.L2TP(flags, version, length, tunnelid, sessionid, ns, nr, offset)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: flags
   .. autoattribute:: version
   .. autoattribute:: length
   .. autoattribute:: tunnelid
   .. autoattribute:: sessionid
   .. autoattribute:: ns
   .. autoattribute:: nr
   .. autoattribute:: offset

   .. autoattribute:: hdr_len

.. autoclass:: pcapkit.protocols.data.link.l2tp.Flags(type, len, seq, offset, prio)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: type
   .. autoattribute:: len
   .. autoattribute:: seq
   .. autoattribute:: offset
   .. autoattribute:: prio

.. raw:: html

   <hr />

.. [*] https://en.wikipedia.org/wiki/Layer_2_Tunneling_Protocol
