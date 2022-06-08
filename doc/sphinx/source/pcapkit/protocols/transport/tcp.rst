TCP - Transmission Control Protocol
===================================

.. module:: pcapkit.protocols.transport.tcp

:mod:`pcapkit.protocols.transport.tcp` contains
:class:`~pcapkit.protocols.transport.tcp.TCP` only,
which implements extractor for Transmission Control
Protocol (TCP) [*]_, whose structure is described as
below:

======= ========= ========================= =======================================
Octets      Bits        Name                    Description
======= ========= ========================= =======================================
  0           0   ``tcp.srcport``           Source Port
  2          16   ``tcp.dstport``           Destination Port
  4          32   ``tcp.seq``               Sequence Number
  8          64   ``tcp.ack``               Acknowledgement Number (if ACK set)
  12         96   ``tcp.hdr_len``           Data Offset
  12        100                             Reserved (must be ``\x00``)
  12        103   ``tcp.flags.ns``          ECN Concealment Protection (NS)
  13        104   ``tcp.flags.cwr``         Congestion Window Reduced (CWR)
  13        105   ``tcp.flags.ece``         ECN-Echo (ECE)
  13        106   ``tcp.flags.urg``         Urgent (URG)
  13        107   ``tcp.flags.ack``         Acknowledgement (ACK)
  13        108   ``tcp.flags.psh``         Push Function (PSH)
  13        109   ``tcp.flags.rst``         Reset Connection (RST)
  13        110   ``tcp.flags.syn``         Synchronize Sequence Numbers (SYN)
  13        111   ``tcp.flags.fin``         Last Packet from Sender (FIN)
  14        112   ``tcp.window_size``       Size of Receive Window
  16        128   ``tcp.checksum``          Checksum
  18        144   ``tcp.urgent_pointer``    Urgent Pointer (if URG set)
  20        160   ``tcp.opt``               TCP Options (if data offset > 5)
======= ========= ========================= =======================================

.. raw:: html

   <br />

.. autoclass:: pcapkit.protocols.transport.tcp.TCP
   :members:
   :undoc-members:
   :private-members:
   :show-inheritance:

   .. attribute:: _syn
      :type: bool

      SYN flag.

   .. attribute:: _ack
      :type: bool

      ACK flag.

.. data:: pcapkit.protocols.transport.tcp.TCP_OPT
   :type: DataType_TCP_OPT

   TCP option :obj:`dict` parsing mapping.

   ===== ====== ======= ======= ============ =======================================================
   kind  length  type   process  comment            name
   ===== ====== ======= ======= ============ =======================================================
     0                                       [:rfc:`793`] End of Option List
     1                                       [:rfc:`793`] No-Operation
     2      4   ``H``     1                  [:rfc:`793`] Maximum Segment Size
     3      3   ``B``     1                  [:rfc:`7323`] Window Scale
     4      2   ``?``           :data:`True` [:rfc:`2018`] SACK Permitted
     5      ?   ``P``     0     ``2+8*N``    [:rfc:`2018`] SACK
     6      6   ``P``     0                  [:rfc:`1072`][:rfc:`6247`] Echo
     7      6   ``P``     0                  [:rfc:`1072`][:rfc:`6247`] Echo Reply
     8     10   ``II``    2                  [:rfc:`7323`] Timestamps
     9      2   ``?``           :data:`True` [:rfc:`1693`][:rfc:`6247`] POC Permitted
    10      3   ``??P``   3                  [:rfc:`1693`][:rfc:`6247`] POC-Serv Profile
    11      6   ``P``     0                  [:rfc:`1693`][:rfc:`6247`] Connection Count
    12      6   ``P``     0                  [:rfc:`1693`][:rfc:`6247`] CC.NEW
    13      6   ``P``     0                  [:rfc:`1693`][:rfc:`6247`] CC.ECHO
    14      3   ``B``     4                  [:rfc:`1146`][:rfc:`6247`] Alt-Chksum Request
    15      ?   ``P``     0                  [:rfc:`1146`][:rfc:`6247`] Alt-Chksum Data
    19     18   ``P``     0                  [:rfc:`2385`] MD5 Signature Option
    27      8   ``P``     5                  [:rfc:`4782`] Quick-Start Response
    28      4   ``P``     6                  [:rfc:`5482`] User Timeout Option
    29      ?   ``P``     7                  [:rfc:`5925`] TCP Authentication Option
    30      ?   ``P``     8                  [:rfc:`6824`] Multipath TCP
    34      ?   ``P``     0                  [:rfc:`7413`] Fast Open
   ===== ====== ======= ======= ============ =======================================================

   .. seealso::

      :class:`pcapkit.protocols.transport.tcp.DataType_TCP_OPT`

.. data:: pcapkit.protocols.transport.tcp.process_opt
   :type: Dict[int, Callable[[pcapkit.protocols.transport.tcp.TCP, int, int], DataType_TCP_Opt]]

   Process method for TCP options.

   .. list-table::
      :header-rows: 1

      * - Code
        - Method
        - Description
      * - 0
        - :meth:`~pcapkit.protocols.transport.tcp.TCP._read_mode_donone`
        - do nothing
      * - 1
        - :meth:`~pcapkit.protocols.transport.tcp.TCP._read_mode_unpack`
        - unpack according to size
      * - 2
        - :meth:`~pcapkit.protocols.transport.tcp.TCP._read_mode_tsopt`
        - timestamps
      * - 3
        - :meth:`~pcapkit.protocols.transport.tcp.TCP._read_mode_pocsp`
        - POC service profile
      * - 4
        - :meth:`~pcapkit.protocols.transport.tcp.TCP._read_mode_acopt`
        - alternate checksum request
      * - 5
        - :meth:`~pcapkit.protocols.transport.tcp.TCP._read_mode_qsopt`
        - Quick-Start response
      * - 6
        - :meth:`~pcapkit.protocols.transport.tcp.TCP._read_mode_utopt`
        - user timeout option
      * - 7
        - :meth:`~pcapkit.protocols.transport.tcp.TCP._read_mode_tcpao`
        - TCP authentication option
      * - 8
        - :meth:`~pcapkit.protocols.transport.tcp.TCP._read_mode_mptcp`
        - multipath TCP

.. data:: pcapkit.protocols.transport.tcp.mptcp_opt
   :type: Dict[int, Callable[[pcapkit.protocols.transport.tcp.TCP, str, int, int], DataType_TCP_MP_Opt]]

   Process method for multipath TCP options [:rfc:`6824`].

   .. list-table::
      :header-rows: 1

      * - Code
        - Method
        - Description
      * - 0
        - :meth:`~pcapkit.protocols.transport.tcp.TCP._read_mptcp_capable`
        - ``MP_CAPABLE``
      * - 1
        - :meth:`~pcapkit.protocols.transport.tcp.TCP._read_mptcp_join`
        - ``MP_JOIN``
      * - 2
        - :meth:`~pcapkit.protocols.transport.tcp.TCP._read_mptcp_dss`
        - ``DSS``
      * - 3
        - :meth:`~pcapkit.protocols.transport.tcp.TCP._read_mptcp_add`
        - ``ADD_ADDR``
      * - 4
        - :meth:`~pcapkit.protocols.transport.tcp.TCP._read_mptcp_remove`
        - ``REMOVE_ADDR``
      * - 5
        - :meth:`~pcapkit.protocols.transport.tcp.TCP._read_mptcp_prio`
        - ``MP_PRIO``
      * - 6
        - :meth:`~pcapkit.protocols.transport.tcp.TCP._read_mptcp_fail`
        - ``MP_FAIL``
      * - 7
        - :meth:`~pcapkit.protocols.transport.tcp.TCP._read_mptcp_fastclose`
        - ``MP_FASTCLOSE``

Data Structure
--------------

.. important::

   Following classes are only for *documentation* purpose.
   They do **NOT** exist in the :mod:`pcapkit` module.

.. class:: DataType_TCP

   :bases: TypedDict

   Structure of TCP header [:rfc:`793`].

   .. attribute:: srcport
      :type: int

      Source port.

   .. attribute:: dstport
      :type: int

      Description port.

   .. attribute:: seq
      :type: int

      Sequence number.

   .. attribute:: ack
      :type: int

      Acknowledgement number.

   .. attribute:: hdr_len
      :type: int

      Data offset.

   .. attribute:: flags
      :type: DataType_TCP_Flags

      Flags.

   .. attribute:: window_size
      :type: int

      Size of receive window.

   .. attribute:: checksum
      :type: bytes

      Checksum.

   .. attribute:: urgent_pointer
      :type: int

      Urgent pointer.

   .. attribute:: opt
      :type: Tuple[pcapkit.const.tcp.option.Option]

      Array of TCP options.

   .. attribute:: packet
      :type: bytes

      Raw packet data.

.. class:: DataType_TCP_Flags

   :bases: TypedDict

   Flags.

   .. attribute:: ns
      :type: bool

      ECN concealment  protection.

   .. attribute:: cwr
      :type: bool

      Congestion window reduced.

   .. attribute:: ece
      :type: bool

      ECN-Echo.

   .. attribute:: urg
      :type: bool

      Urgent.

   .. attribute:: ack
      :type: bool

      Acknowledgement.

   .. attribute:: psh
      :type: bool

      Push function.

   .. attribute:: rst
      :type: bool

      Reset connection.

   .. attribute:: syn
      :type: bool

      Synchronize sequence numbers.

   .. attribute:: fin
      :type: bool

      Last packet from sender.

.. class:: DataType_TCP_Opt

   :bases: TypedDict

   Structure of TCP options.

   .. attribute:: kind
      :type: int

      Option kind value.

   .. attribute:: length
      :type: int

      Length of option.

.. class:: DataType_TCP_OPT

   :bases: TypedDict

   TCP option :obj:`dict` parsing mapping.

   .. attribute:: flag
      :type: bool

      If the length of option is **GREATER THAN** ``1``.

   .. attribute:: desc
      :type: str

      Description string, also attribute name.

   .. attribute:: func
      :type: Optional[Callable[[int], int]]

      Function, length of data bytes.

   .. attribute:: proc
      :type: Optional[int]

      Process method that data bytes need (when :attr:`flag` is :data:`True`).

      .. seealso::

         :data:`pcapkit.protocols.transport.tcp.process_opt`

TCP Miscellaneous Options
~~~~~~~~~~~~~~~~~~~~~~~~~

No Process Options
++++++++++++++++++

For TCP options require no process, its structure is described as below:

======== ========= ==================== ==========================
Octets      Bits        Name                    Description
======== ========= ==================== ==========================
  0           0    ``tcp.opt.kind``          Kind
  1           8    ``tcp.opt.length``        Length
  2          16    ``tcp.opt.data``          Kind-specific Data
======== ========= ==================== ==========================

.. raw:: html

   <br />

.. class:: DataType_TCP_Opt_DONONE

   :bases:  DataType_TCP_Opt

   Structure of TCP options.

   .. attribute:: data
      :type: bytes

      Kind-specific data.

Unpack Process Options
++++++++++++++++++++++

For TCP options require unpack process, its structure is described as below:

======== ========= ==================== ==========================
Octets      Bits        Name                    Description
======== ========= ==================== ==========================
  0           0    ``tcp.opt.kind``          Kind
  1           8    ``tcp.opt.length``        Length
  2          16    ``tcp.opt.data``          Kind-specific Data
======== ========= ==================== ==========================

.. raw:: html

   <br />

.. class:: DataType_TCP_Opt_UNPACK

   :bases:  DataType_TCP_Opt

   Structure of TCP options.

   .. attribute:: data
      :type: bytes

      Kind-specific data.

Timestamps Option
~~~~~~~~~~~~~~~~~

For TCP Timestamps (``TS``) option as described in :rfc:`7323`,
its structure is described as below:

======== ========= ==================== ==========================
Octets      Bits        Name                    Description
======== ========= ==================== ==========================
  0           0    ``tcp.ts.kind``       Kind (``8``)
  1           8    ``tcp.ts.length``     Length (``10``)
  2          16    ``tcp.ts.val``        Timestamp Value
  6          48    ``tcp.ts.ecr``        Timestamps Echo Reply
======== ========= ==================== ==========================

.. raw:: html

   <br />

.. class:: DataType_TCP_Opt_TS

   :bases:  DataType_TCP_Opt

   Structure of TCP ``TSopt`` [:rfc:`7323`].

   .. attribute:: val
      :type: int

      Timestamp value.

   .. attribute:: ecr
      :type: int

      Timestamps echo reply.

Partial Order Connection Service Profile Option
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For TCP Partial Order Connection Service Profile (``POC-SP``) option as described in :rfc:`1693` and :rfc:`6247`,
its structure is described as below:

======== ========= ==================== ==========================
Octets      Bits        Name                    Description
======== ========= ==================== ==========================
  0           0    ``tcp.pocsp.kind``       Kind (``10``)
  1           8    ``tcp.pocsp.length``     Length (``3``)
  2          16    ``tcp.pocsp.start``      Start Flag
  2          17    ``tcp.pocsp.end``        End Flag
  2          18    ``tcp.pocsp.filler``     Filler
======== ========= ==================== ==========================

.. raw:: html

   <br />

.. class:: DataType_TCP_Opt_POCSP

   :bases:  DataType_TCP_Opt

   Structure of TCP ``POC-SP`` Option [:rfc:`1693`][:rfc:`6247`].

   .. attribute:: start
      :type: bool

      Start flag.

   .. attribute:: end
      :type: bool

      End flag.

   .. attribute:: filler
      :type: bytes

      Filler.

Alternate Checksum Request Option
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For TCP Alternate Checksum Request (``CHKSUM-REQ``) option as described in :rfc:`1146` and :rfc:`6247`,
its structure is described as below:

======== ========= ======================== ==========================
Octets      Bits        Name                    Description
======== ========= ======================== ==========================
  0           0    ``tcp.chksumreq.kind``      Kind (``14``)
  1           8    ``tcp.chksumreq.length``    Length (``3``)
  2          16    ``tcp.chksumreq.ac``        Checksum Algorithm
======== ========= ======================== ==========================

.. raw:: html

   <br />

.. class:: DataType_TCP_Opt_ACOPT

   :bases:  DataType_TCP_Opt

   Structure of TCP ``CHKSUM-REQ`` [:rfc:`1146`][:rfc:`6247`].

   .. attribute:: ac
      :type: pcapkit.const.tcp.checksum.Checksum

      Checksum algorithm.

Quick-Start Response Option
~~~~~~~~~~~~~~~~~~~~~~~~~~~

For TCP Quick-Start Response (``QS``) option as described in :rfc:`4782`,
its structure is described as below:

======== ========= ======================== ===========================
Octets      Bits        Name                    Description
======== ========= ======================== ===========================
  0           0    ``tcp.qs.kind``          Kind (``27``)
  1           8    ``tcp.qs.length``        Length (``8``)
  2          16                             Reserved (must be ``\x00``)
  2          20    ``tcp.qs.req_rate``      Request Rate
  3          24    ``tcp.qs.ttl_diff``      TTL Difference
  4          32    ``tcp.qs.nounce``        QS Nounce
  7          62                             Reserved (must be ``\x00``)
======== ========= ======================== ===========================

.. raw:: html

   <br />

.. class:: DataType_TCP_Opt_QSOPT

   :bases:  DataType_TCP_Opt

   Structure of TCP ``QSopt`` [:rfc:`4782`].

   .. attribute:: req_rate
      :type: int

      Request rate.

   .. attribute:: ttl_diff
      :type: int

      TTL difference.

   .. attribute::  nounce
      :type: int

      QS nounce.

User Timeout Option
~~~~~~~~~~~~~~~~~~~

For TCP User Timeout (``TIMEOUT``) option as described in :rfc:`5482`,
its structure is described as below:

======== ========= =========================== ===========================
Octets      Bits        Name                    Description
======== ========= =========================== ===========================
  0           0    ``tcp.timeout.kind``        Kind (``28``)
  1           8    ``tcp.timeout.length``      Length (``4``)
  2          16    ``tcp.timeout.granularity`` Granularity
  2          17    ``tcp.timeout.timeout``     User Timeout
======== ========= =========================== ===========================

.. raw:: html

   <br />

.. class:: DataType_TCP_Opt_UTOPT

   :bases:  DataType_TCP_Opt

   Structure of TCP ``TIMEOUT`` [:rfc:`5482`].

   .. attribute:: granularity
      :type: Literal['minutes', 'seconds']

      Granularity.

   .. attribute:: timeout
      :type: datetime.timedelta

      User timeout.

Authentication Option
~~~~~~~~~~~~~~~~~~~~~

For Authentication (``AO``) option as described in :rfc:`5925`,
its structure is described as below:

======== ========= =========================== ===========================
Octets      Bits        Name                    Description
======== ========= =========================== ===========================
  0           0    ``tcp.ao.kind``             Kind (``29``)
  1           8    ``tcp.ao.length``           Length
  2          16    ``tcp.ao.key_id``           KeyID
  3          24    ``tcp.ao.r_next_key_id``    RNextKeyID
  4          32    ``tcp.ao.mac``              Message Authentication Code
======== ========= =========================== ===========================

.. raw:: html

   <br />

.. class:: DataType_TCP_Opt_TCPAO

   :bases:  DataType_TCP_Opt

   Structure of TCP ``AOopt`` [:rfc:`5925`].

   .. attribute:: key_id
      :type: int

      KeyID.

   .. attribute:: r_next_key_id
      :type: int

      RNextKeyID.

   .. attribute:: mac
      :type: bytes

      Message authentication code.

Multipath TCP Options
~~~~~~~~~~~~~~~~~~~~~

For Multipath TCP (``MP-TCP``) options as described in :rfc:`6824`,
its structure is described as below:

======== ========= =========================== ===========================
Octets      Bits        Name                    Description
======== ========= =========================== ===========================
  0           0    ``tcp.mp.kind``             Kind (``30``)
  1           8    ``tcp.mp.length``           Length
  2          16    ``tcp.mp.subtype``          Subtype
  2          20    ``tcp.mp.data``             Subtype-specific Data
======== ========= =========================== ===========================

.. raw:: html

   <br />

.. class:: DataType_TCP_Opt_MPTCP

   :bases:  DataType_TCP_Opt

   Structure of ``MP-TCP`` [:rfc:`6824`].

   .. attribute:: subtype
      :type: pcapkit.const.tcp.mp_tcp_option.MPTCPOption

      Subtype.

   .. attribute:: data
      :type: Optional[bytes]

      Subtype-specific data.

Multipath Capable Option
++++++++++++++++++++++++

For Multipath Capable (``MP_CAPABLE``) options as described in :rfc:`6824`,
its structure is described as below:

======== ========= ============================ =================================
Octets      Bits        Name                    Description
======== ========= ============================ =================================
  0           0    ``tcp.mp.kind``              Kind (``30``)
  1           8    ``tcp.mp.length``            Length (``12``/``20``)
  2          16    ``tcp.mp.subtype``           Subtype (``0``)
  2          20    ``tcp.mp.capable.version``   Version
  3          24    ``tcp.mp.capable.flags.req`` Checksum Require Flag (``A``)
  3          25    ``tcp.mp.capable.flags.ext`` Extensibility Flag (``B``)
  3          26    ``tcp.mp.capable.flags.res`` Unassigned (``C`` - ``G``)
  3          31    ``tcp.mp.capable.flags.hsa`` HMAC-SHA1 Flag (``H``)
  4          32    ``tcp.mp.capable.skey``      Option Sender's Key
  12         96    ``tcp.mp.capable.rkey``      Option Receiver's Key
                                                (only if option length is ``20``)
======== ========= ============================ =================================

.. raw:: html

   <br />

.. class:: DataType_TCP_Opt_MP_CAPABLE

   :bases: DataType_TCP_Opt_MPTCP

   Structure of ``MP_CAPABLE`` [:rfc:`6824`].

   .. attribute:: capable
      :type: DataType_TCP_Opt_MP_CAPABLE_Data

      Subtype-specific data.

.. class:: DataType_TCP_Opt_MP_CAPABLE_Data

   :bases: TypedDict

   Structure of ``MP_CAPABLE`` [:rfc:`6824`].

   .. attribute:: version
      :type: int

      Version.

   .. attribute:: flags
      :type: DataType_TCP_Opt_MP_CAPABLE_Flags

      Flags.

   .. attribute:: skey
      :type: int

      Option sender's key.

   .. attribute:: rkey
      :type: Optional[int]

      Option receiver's key.

.. class:: DataType_TCP_Opt_MP_CAPABLE_Flags

   :bases: TypedDict

   Flags.

   .. attribute:: req
      :type: bool

      Checksum require flag.

   .. attribute:: ext
      :type: bool

      Extensibility flag.

   .. attribute:: res
      :type: Tuple[bool, bool, bool, bool, bool]

      Unassigned flags.

   .. attribute:: hsa
      :type: bool

      HMAC-SHA1 flag.

Join Connection Option
++++++++++++++++++++++

For Join Connection (``MP_JOIN``) options as described in :rfc:`6824`,
its structure is described as below:

======== ========= ============================ =================================
Octets      Bits        Name                    Description
======== ========= ============================ =================================
  0           0    ``tcp.mp.kind``                 Kind (``30``)
  1           8    ``tcp.mp.length``               Length
  2          16    ``tcp.mp.subtype``              Subtype (``1``)
  2          20    ``tcp.mp.data``                 Handshake-specific Data
======== ========= ============================ =================================

.. raw:: html

   <br />

.. class:: DataType_TCP_Opt_MP_JOIN

   :bases: DataType_TCP_Opt_MPTCP

   Structure of ``MP_JOIN`` [:rfc:`6824`].

   .. attribute:: connection
      :type: Optional[Literal['SYN/ACK', 'SYN', 'ACK']]

      Join connection type.

   .. attribute:: join
      :type: DataType_TCP_Opt_MP_JOIN_Data

      Subtype-specific data.

.. class:: DataType_TCP_Opt_MP_JOIN_Data

   :bases: TypedDict

   Structure of ``MP_JOIN`` [:rfc:`6824`].

   .. attribute:: data
      :type: Optional[bytes]

      Unknown type data.

``MP_JOIN-SYN``
:::::::::::::::

For Join Connection (``MP_JOIN-SYN``) option for Initial SYN as described in :rfc:`6824`,
its structure is described as below:

======== ========= ============================ =================================
Octets      Bits        Name                    Description
======== ========= ============================ =================================
  0           0    ``tcp.mp.kind``              Kind (``30``)
  1           8    ``tcp.mp.length``            Length (``12``)
  2          16    ``tcp.mp.subtype``           Subtype (``1`` | ``SYN``)
  2          20                                 Reserved (must be ``\x00``)
  2          23    ``tcp.mp.join.syn.backup``   Backup Path (``B``)
  3          24    ``tcp.mp.join.syn.addr_id``  Address ID
  4          32    ``tcp.mp.join.syn.token``    Receiver's Token
  8          64    ``tcp.mp.join.syn.rand_num`` Sender's Random Number
======== ========= ============================ =================================

.. raw:: html

   <br />

.. class:: DataType_TCP_Opt_MP_JOIN_SYN

   :bases: DataType_TCP_Opt_MP_JOIN_Data

   Structure of ``MP_JOIN-SYN`` [:rfc:`6824`].

   .. attribute:: syn
      :type: DataType_TCP_Opt_MP_JOIN_SYN_Data

      Subtype-specific data.

.. class:: DataType_TCP_Opt_MP_JOIN_SYN_Data

   :bases: TypedDict

   Structure of ``MP_JOIN-SYN`` [:rfc:`6824`].

   .. attribute:: backup
      :type: bool

      Backup path.

   .. attribute:: addr_id
      :type: int

      Address ID.

   .. attribute:: token
      :type: int

      Receiver's token.

   .. attribute:: rand_num
      :type: int

      Sender's random number.

``MP_JOIN-SYN/ACK``
:::::::::::::::::::

For Join Connection (``MP_JOIN-SYN/ACK``) option for Responding SYN/ACK as described in :rfc:`6824`,
its structure is described as below:

======== ========= =============================== =================================
Octets      Bits        Name                       Description
======== ========= =============================== =================================
  0           0    ``tcp.mp.kind``                 Kind (``30``)
  1           8    ``tcp.mp.length``               Length (``16``)
  2          16    ``tcp.mp.subtype``              Subtype (``1`` | ``SYN/ACK``)
  2          20                                    Reserved (must be ``\x00``)
  2          23    ``tcp.mp.join.synack.backup``   Backup Path (``B``)
  3          24    ``tcp.mp.join.synack.addr_id``  Address ID
  4          32    ``tcp.mp.join.synack.hmac``     Sender's Truncated HMAC
  12         96    ``tcp.mp.join.synack.rand_num`` Sender's Random Number
======== ========= =============================== =================================

.. raw:: html

   <br />

.. class:: DataType_TCP_Opt_MP_JOIN_SYNACK

   :bases: DataType_TCP_Opt_MP_JOIN_Data

   Structure of ``MP_JOIN-SYN/ACK`` [:rfc:`6824`].

   .. attribute:: syn
      :type: DataType_TCP_Opt_MP_JOIN_SYNACK_Data

      Subtype-specific data.

.. class:: DataType_TCP_Opt_MP_JOIN_SYNACK_Data

   :bases: TypedDict

   Structure of ``MP_JOIN-SYN/ACK`` [:rfc:`6824`].

   .. attribute:: backup
      :type: bool

      Backup path.

   .. attribute:: addr_id
      :type: int

      Address ID.

   .. attribute:: hmac
      :type: bytes

      Sender's truncated HMAC.

   .. attribute:: rand_num
      :type: int

      Sender's random number.

``MP_JOIN-ACK``
:::::::::::::::

For Join Connection (``MP_JOIN-ACK``) option for Third ACK as described in :rfc:`6824`,
its structure is described as below:

======== ========= =============================== =================================
Octets      Bits        Name                       Description
======== ========= =============================== =================================
  0           0    ``tcp.mp.kind``                 Kind (``30``)
  1           8    ``tcp.mp.length``               Length (``16``)
  2          16    ``tcp.mp.subtype``              Subtype (``1`` | ``ACK``)
  2          20                                    Reserved (must be ``\x00``)
  4          32    ``tcp.mp.join.ack.hmac``        Sender's HMAC
======== ========= =============================== =================================

.. raw:: html

   <br />

.. class:: DataType_TCP_Opt_MP_JOIN_ACK

   :bases: DataType_TCP_Opt_MP_JOIN_Data

   Structure of ``MP_JOIN-ACK`` [:rfc:`6824`].

   .. attribute:: syn
      :type: DataType_TCP_Opt_MP_JOIN_ACK_Data

      Subtype-specific data.

.. class:: DataType_TCP_Opt_MP_JOIN_ACK_Data

   :bases: TypedDict

   Structure of ``MP_JOIN-ACK`` [:rfc:`6824`].

   .. attribute:: hmac
      :type: bytes

      Sender's HMAC.

Data Sequence Signal Option
+++++++++++++++++++++++++++

For Data Sequence Signal (``DSS``) options as described in :rfc:`6824`,
its structure is described as below:

======= ========= ============================= =========================================================
Octets      Bits        Name                    Description
======= ========= ============================= =========================================================
  0           0   ``tcp.mp.kind``                 Kind (``30``)
  1           8   ``tcp.mp.length``               Length
  2          16   ``tcp.mp.subtype``              Subtype (``2``)
  2          20                                   Reserved (must be ``\x00``)
  3          27   ``tcp.mp.dss.flags.fin``        DATA_FIN (``F``)
  3          28   ``tcp.mp.dss.flags.dsn_len``    DSN Length (``m``)
  3          29   ``tcp.mp.dss.flags.data_pre``   DSN, SSN, Data-Level Length, CHKSUM Present (``M``)
  3          30   ``tcp.mp.dss.flags.ack_len``    ACK Length (``a``)
  3          31   ``tcp.mp.dss.flags.ack_pre``    Data ACK Present (``A``)
  4          32   ``tcp.mp.dss.ack``              Data ACK (``4`` / ``8`` octets)
  8/12    64/96   ``tcp.mp.dss.dsn``              DSN (``4`` / ``8`` octets)
  12/20  48/160   ``tcp.mp.dss.ssn``              Subflow Sequence Number
  16/24 128/192   ``tcp.mp.dss.dl_len``           Data-Level Length
  18/26 144/208   ``tcp.mp.dss.checksum``         Checksum
======= ========= ============================= =========================================================

.. raw:: html

   <br />

.. class:: DataType_TCP_Opt_DSS

   :bases: DataType_TCP_Opt_MPTCP

   Structure of ``DSS`` [:rfc:`6824`].

   .. attribute:: dss
      :type: DataType_TCP_Opt_DSS_Data

      Subtype-specific data.

.. class:: DataType_TCP_Opt_DSS_Data

   :bases: TypedDict

   Structure of ``DSS`` [:rfc:`6824`].

   .. attribute:: flags
      :type: DataType_TCP_Opt_DSS_Flags

      Flags.

   .. attribute:: ack
      :type: Optional[int]

      Data ACK.

   .. attribute:: dsn
      :type: Optional[int]

      DSN.

   .. attribute:: ssn
      :type: Optional[int]

      Subflow sequence number.

   .. attribute:: dl_len
      :type: int

      Data-level length.

   .. attribute:: checksum
      :type: bytes

      Checksum.

.. class:: DataType_TCP_Opt_DSS_Flags

   :bases: TypedDict

   Flags.

   .. attribute:: fin
      :type: bool

      ``DATA_FIN``.

   .. attribute:: dsn_len
      :type: int

      DSN length.

   .. attribute:: data_pre
      :type: int

      DSN, SSN, data-level length, checksum present.

   .. attribute:: ack_len
      :type: int

      ACK length.

   .. attribute:: ack_pre
      :type: bool

      ACK present.

Add Address Option
++++++++++++++++++

For Add Address (``ADD_ADDR``) options as described in :rfc:`6824`,
its structure is described as below:

======= ========= ============================= =========================================================
Octets      Bits        Name                    Description
======= ========= ============================= =========================================================
  0           0    ``tcp.mp.kind``                  Kind (``30``)
  1           8    ``tcp.mp.length``                Length
  2          16    ``tcp.mp.subtype``               Subtype (``3``)
  2          20    ``tcp.mp.add_addr.ip_ver``       IP Version
  3          24    ``tcp.mp.add_addr.addr_id``      Address ID
  4          32    ``tcp.mp.add_addr.addr``         IP Address (``4`` / ``16``)
  8/20   64/160    ``tcp.mp.add_addr.port``         Port (optional)
======= ========= ============================= =========================================================

.. raw:: html

   <br />

.. class:: DataType_TCP_Opt_ADD_ADDR

   :bases: DataType_TCP_Opt_MPTCP

   Structure of ``ADD_ADDR`` [:rfc:`6824`].

   .. attribute:: add_addr
      :type: DataType_TCP_Opt_ADD_ADDR_Data

      Subtype-specific data.

.. class:: DataType_TCP_Opt_ADD_ADDR_Data

   :bases: TypedDict

   Structure of ``ADD_ADDR`` [:rfc:`6824`].

   .. attribute:: ip_ver
      :type: Literal[4, 6]

      IP version.

   .. attribute:: addr_id
      :type: int

      Address ID.

   .. attribute:: addr
      :type: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

      IP address.

   .. attribute:: port
      :type: Optional[int]

      Port.

Remove Address Option
+++++++++++++++++++++

For Remove Address (``REMOVE_ADDR``) options as described in :rfc:`6824`,
its structure is described as below:

======= ========= ============================== =========================================================
Octets      Bits        Name                     Description
======= ========= ============================== =========================================================
  0           0   ``tcp.mp.kind``                    Kind (``30``)
  1           8   ``tcp.mp.length``                  Length
  2          16   ``tcp.mp.subtype``                 Subtype (``4``)
  2          20                                      Reserved (must be ``\x00``)
  3          24   ``tcp.mp.remove_addr.addr_id``     Address ID (optional list)
======= ========= ============================== =========================================================

.. raw:: html

   <br />

.. class:: DataType_TCP_Opt_REMOVE_ADDR

   :bases: DataType_TCP_Opt_MPTCP

   Structure of ``REMOVE_ADDR`` [:rfc:`6824`].

   .. attribute:: remove_addr
      :type: DataType_TCP_Opt_REMOVE_ADDR_Data

      Subtype-specific data.

.. class:: DataType_TCP_Opt_REMOVE_ADDR_Data

   :bases: TypedDict

   Structure of ``REMOVE_ADDR`` [:rfc:`6824`].

   .. attribute:: addr_id
      :type: Tuple[int]

      Array of address IDs.

Change Subflow Priority Option
++++++++++++++++++++++++++++++

For Change Subflow Priority (``MP_PRIO``) options as described in :rfc:`6824`,
its structure is described as below:

======= ========= ============================== =========================================================
Octets      Bits        Name                     Description
======= ========= ============================== =========================================================
  0           0   ``tcp.mp.kind``                    Kind (``30``)
  1           8   ``tcp.mp.length``                  Length
  2          16   ``tcp.mp.subtype``                 Subtype (``4``)
  2          23   ``tcp.mp.prio.backup``             Backup Path (``B``)
  3          24   ``tcp.mp.prio.addr_id``            Address ID (optional)
======= ========= ============================== =========================================================

.. raw:: html

   <br />

.. class:: DataType_TCP_Opt_MP_PRIO

   :bases: DataType_TCP_Opt_MPTCP

   Structure of ``MP_PRIO`` [:rfc:`6824`].

   .. attribute:: prio
      :type: DataType_TCP_Opt_MP_PRIO_Data

      Subtype-specific data.

.. class:: DataType_TCP_Opt_MP_PRIO_Data

   :bases: TypedDict

   Structure of ``MP_PRIO`` [:rfc:`6824`].

   .. attribute:: backup
      :type: bool

      Backup path.

   .. attribute:: addr_id
      :type: Optional[int]

      Address ID.

Fallback Option
+++++++++++++++

For Fallback (``MP_FAIL``) options as described in :rfc:`6824`,
its structure is described as below:

======= ========= ============================== =========================================================
Octets      Bits        Name                     Description
======= ========= ============================== =========================================================
  0           0   ``tcp.mp.kind``                    Kind (``30``)
  1           8   ``tcp.mp.length``                  Length
  2          16   ``tcp.mp.subtype``                 Subtype (``4``)
  2          23                                      Reserved (must be ``\x00``)
  4          32   ``tcp.mp.fail.dsn``                Data Sequence Number
======= ========= ============================== =========================================================

.. raw:: html

   <br />

.. class:: DataType_TCP_Opt_MP_FAIL

   :bases: DataType_TCP_Opt_MPTCP

   Structure of ``MP_FAIL`` [:rfc:`6824`].

   .. attribute:: fail
      :type: DataType_TCP_Opt_MP_FAIL_Data

      Subtype-specific data.

.. class:: DataType_TCP_Opt_MP_FAIL_Data

   :bases: TypedDict

   Structure of ``MP_FAIL`` [:rfc:`6824`].

   .. attribute:: dsn
      :type: int

      Data sequence number.

Fast Close Option
+++++++++++++++++

For Fast Close (``MP_FASTCLOSE``) options as described in :rfc:`6824`,
its structure is described as below:

======= ========= ============================== =========================================================
Octets      Bits        Name                     Description
======= ========= ============================== =========================================================
  0           0   ``tcp.mp.kind``                    Kind (``30``)
  1           8   ``tcp.mp.length``                  Length
  2          16   ``tcp.mp.subtype``                 Subtype (``4``)
  2          23                                      Reserved (must be ``\x00``)
  4          32   ``tcp.mp.fastclose.rkey``          Option Receiver's Key
======= ========= ============================== =========================================================

.. raw:: html

   <br />

.. class:: DataType_TCP_Opt_MP_FASTCLOSE

   :bases: DataType_TCP_Opt_MPTCP

   Structure of ``MP_FASTCLOSE`` [:rfc:`6824`].

   .. attribute:: fastclose
      :type: DataType_TCP_Opt_MP_FASTCLOSE_Data

      Subtype-specific data.

.. class:: DataType_TCP_Opt_MP_FASTCLOSE_Data

   :bases: TypedDict

   Structure of ``MP_FASTCLOSE`` [:rfc:`6824`].

   .. attribute:: rkey
      :type: int

      Option receiver's key.

.. raw:: html

   <hr />

.. [*] https://en.wikipedia.org/wiki/Transmission_Control_Protocol
