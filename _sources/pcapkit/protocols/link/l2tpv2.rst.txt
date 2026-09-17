L2TPv2 - Layer Two Tunnelling Protocol version 2
================================================

.. module:: pcapkit.protocols.link.l2tpv2

:mod:`pcapkit.protocols.link.l2tpv2` contains
:class:`~pcapkit.protocols.link.l2tpv2.L2TPv2` only, which implements extractor
for the Layer Two Tunnelling Protocol version 2 (L2TPv2) [*]_ as specified by
:rfc:`2661` -- a 16-bit tunnel ID and a 16-bit session ID, with the version nibble
reading ``2``. It is dispatched from
:attr:`UDP.__proto__ <pcapkit.protocols.transport.udp.UDP.__proto__>` at port
1701. Its structure is described as below:

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
    1         12 ``l2tp.version``      Version (``2``)
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

.. note::

   The parsed datagram appears under ``l2tp``, not ``l2tpv2``:
   :attr:`~pcapkit.protocols.link.l2tp.L2TP.info_name` is declared on the
   version-agnostic base so that a consumer finds the data at the same key
   whichever version was on the wire. The version is reported by
   :attr:`~pcapkit.protocols.link.l2tpv2.L2TPv2.alias` instead.

   IANA protocol number 115 (``L2TP``) is deliberately left unbound. It
   references :rfc:`3931`, i.e. **L2TPv3**, whose session and control message
   headers are a different shape -- so the binding waits on an ``L2TPv3`` class
   rather than on this one. See :mod:`pcapkit.protocols.link.l2tp`.

.. autoclass:: pcapkit.protocols.link.l2tpv2.L2TPv2
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: alias
   .. autoproperty:: version
   .. autoproperty:: length
   .. autoproperty:: type

   .. automethod:: id
   .. automethod:: read
   .. automethod:: make

   .. automethod:: _make_data

   .. automethod:: __index__

Header Schemas
--------------

.. module:: pcapkit.protocols.schema.link.l2tp

.. autoclass:: pcapkit.protocols.schema.link.l2tp.L2TP
   :members:
   :show-inheritance:

Type Stubs
~~~~~~~~~~

.. autoclass:: pcapkit.protocols.schema.link.l2tp.FlagsType
   :members:
   :show-inheritance:

Data Models
-----------

.. module:: pcapkit.protocols.data.link.l2tp

.. autoclass:: pcapkit.protocols.data.link.l2tp.L2TP
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.link.l2tp.Flags
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/Layer_2_Tunneling_Protocol
