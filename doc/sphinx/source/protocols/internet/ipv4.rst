IPv4 - Internet Protocol version 4
==================================

.. module:: pcapkit.protocols.internet.ipv4

:mod:`pcapkit.protocols.internet.ipv4` contains
:class:`~pcapkit.protocols.internet.ipv4.IPv4` only,
which implements extractor for Internet Protocol
version 4 (IPv4) [*]_, whose structure is described
as below:

======= ========= ====================== =============================================
Octets      Bits        Name                    Description
======= ========= ====================== =============================================
  0           0   ``ip.version``              Version (``4``)
  0           4   ``ip.hdr_len``              Internal Header Length (IHL)
  1           8   ``ip.dsfield.dscp``         Differentiated Services Code Point (DSCP)
  1          14   ``ip.dsfield.ecn``          Explicit Congestion Notification (ECN)
  2          16   ``ip.len``                  Total Length
  4          32   ``ip.id``                   Identification
  6          48                               Reserved Bit (must be ``\x00``)
  6          49   ``ip.flags.df``             Don't Fragment (DF)
  6          50   ``ip.flags.mf``             More Fragments (MF)
  6          51   ``ip.frag_offset``          Fragment Offset
  8          64   ``ip.ttl``                  Time To Live (TTL)
  9          72   ``ip.proto``                Protocol (Transport Layer)
  10         80   ``ip.checksum``             Header Checksum
  12         96   ``ip.src``                  Source IP Address
  16        128   ``ip.dst``                  Destination IP Address
  20        160   ``ip.options``              IP Options (if IHL > ``5``)
======= ========= ====================== =============================================

.. raw:: html

   <br />

.. autoclass:: pcapkit.protocols.internet.ipv4.IPv4
   :members:
   :undoc-members:
   :private-members:
   :show-inheritance:

.. data:: pcapkit.protocols.internet.ipv4.IPv4_OPT
   :type: DataType_IPv4_OPT

   IPv4 option :data:`dict` parsing mapping.

   ===== ====== ======= ===== ======= ======== ===============================================
   copy  class  number  kind  length  process          name
   ===== ====== ======= ===== ======= ======== ===============================================
     0     0       0      0                    [:rfc:`791`] End of Option List
     0     0       1      1                    [:rfc:`791`] No-Operation
     0     0       7      7      ?       2     [:rfc:`791`] Record Route
     0     0      11     11      4       1     [:rfc:`1063`][:rfc:`1191`] MTU Probe
     0     0      12     12      4       1     [:rfc:`1063`][:rfc:`1191`] MTU Reply
     0     0      25     25      8       3     [:rfc:`4782`] Quick-Start
     0     2       4     68      ?       4     [:rfc:`791`] Time Stamp
     0     2      18     82      ?       5     [:rfc:`1393`][:rfc:`6814`] Traceroute
     1     0       2    130      ?       6     [:rfc:`1108`] Security
     1     0       3    131      ?       2     [:rfc:`791`] Loose Source Route
     1     0       5    133      ?       6     [:rfc:`1108`] Extended Security
     1     0       8    136      4       1     [:rfc:`791`][:rfc:`6814`] Stream ID
     1     0       9    137      ?       2     [:rfc:`791`] Strict Source Route
     1     0      17    145      ?       0     [:rfc:`1385`][:rfc:`6814`] Ext. Inet. Protocol
     1     0      20    148      4       7     [:rfc:`2113`] Router Alert
   ===== ====== ======= ===== ======= ======== ===============================================

   .. seealso::

      :class:`pcapkit.protocols.internet.ipv4.DataType_IPv4_OPT`

.. data:: pcapkit.protocols.internet.ipv4.process_opt
   :type: Dict[int, Callable[[pcapkit.protocols.internet.ipv4.IPv4,  int, int], DataType_Opt]]

   Process method for IPv4 options.

   .. list-table::
      :header-rows: 1

      * - Code
        - Method
        - Description
      * - 0
        - :meth:`~pcapkit.protocols.internet.ipv4.IPv4._read_mode_donone`
        - do nothing
      * - 1
        - :meth:`~pcapkit.protocols.internet.ipv4.IPv4._read_mode_unpack`
        - unpack according to size
      * - 2
        - :meth:`~pcapkit.protocols.internet.ipv4.IPv4._read_mode_route`
        - unpack route data options
      * - 3
        - :meth:`~pcapkit.protocols.internet.ipv4.IPv4._read_mode_qs`
        - unpack Quick-Start
      * - 4
        - :meth:`~pcapkit.protocols.internet.ipv4.IPv4._read_mode_ts`
        - unpack Time Stamp
      * - 5
        - :meth:`~pcapkit.protocols.internet.ipv4.IPv4._read_mode_tr`
        - unpack Traceroute
      * - 6
        - :meth:`~pcapkit.protocols.internet.ipv4.IPv4._read_mode_sec`
        - unpack (Extended) Security
      * - 7
        - :meth:`~pcapkit.protocols.internet.ipv4.IPv4._read_mode_rsralt`
        - unpack Router Alert

Data Structure
--------------

.. important::

   Following classes are only for *documentation* purpose.
   They do **NOT** exist in the :mod:`pcapkit` module.

.. class:: DataType_IPv4

   :bases: TypedDict

   Structure of IPv4 header [:rfc:`791`].

   .. attribute:: version
      :type: Literal[4]

      Version (``4``).

   .. attribute:: hdr_len
      :type: int

      Internal header length (IHL).

   .. attribute:: dsfield
      :type: DataType_DS_Field

      Type of services.

   .. attribute:: len
      :type: int

      Total length.

   .. attribute:: id
      :type: int

      Identification.

   .. attribute:: flags
      :type: DataType_IPv4_Flags

      Flags.

   .. attribute:: frag_offset
      :type: int

      Fragment offset.

   .. attribute:: ttl
      :type: int

      Time to live (TTL).

   .. attribute:: proto
      :type: pcapkit.const.reg.transtype.TransType

      Protocol (transport layer).

   .. attribute:: checksum
      :type: bytes

      Header checksum.

   .. attribute:: src
      :type: ipaddress.IPv4Address

      Source IP address.

   .. attribute:: dst
      :type: ipaddress.IPv4Address

      Destination IP address.

   .. attribute:: opt
      :type: Tuple[pcapkit.const.ipv4.option_number.OptionNumber]

      Tuple of option acronyms.

   .. attribute:: packet
      :type: bytes

      Rase packet data.

.. class:: DataType_DS_Field

   :bases: TypedDict

   IPv4 DS fields.

   .. attribute:: dscp
      :type: DataType_IPv4_DSCP

      Differentiated services code point (DSCP).

   .. attribute:: ecn
      :type: pcapkit.const.ipv4.tos_ecn.ToSECN

      Explicit congestion notification (ECN).

.. class:: DataType_IPv4_DSCP

   :bases: TypedDict

   Differentiated services code point (DSCP).

   .. attribute:: pre
      :type: pcapkit.const.ipv4.tos_pre.ToSPrecedence

      ToS precedence.

   .. attribute:: del
      :type: pcapkit.const.ipv4.tos_del.ToSDelay

      ToS delay.

   .. attribute:: thr
      :type: pcapkit.const.ipv4.tos_thr.ToSThroughput

      ToS throughput.

   .. attribute:: rel
      :type: pcapkit.const.ipv4.tos_rel.ToSReliability

      ToS reliability.

.. class:: DataType_IPv4_Flags

   :bases: TypedDict

   IPv4 flags.

   .. attribute:: df
      :type: bool

      Dont's fragment (DF).

   .. attribute:: mf
      :type: bool

      More fragments (MF).

.. class:: DataType_Opt

   :bases: TypedDict

   IPv4 option data.

   .. attribute:: kind
      :type: int

      Option kind.

   .. attribute:: type
      :type: DataType_IPv4_Option_Type

      Option type info.

   .. attribute:: length
      :type: int

      Option length.

.. class:: DataType_IPv4_OPT

   :bases: TypedDict

   IPv4 option :data:`dict` parsing mapping.

   .. attribute:: flag
      :type: bool

      If the length of option is **GREATER THAN** ``1``.

   .. attribute:: desc
      :type: str

      Description string, also attribute name.

   .. attribute:: proc
      :type: Optional[int]

      Process method that data bytes need (when :attr:`flag` is :data:`True`).

      .. seealso::

         :data:`pcapkit.protocols.internet.ipv4.process_opt`

IPv4 Option Type
~~~~~~~~~~~~~~~~

For IPv4 option type field as described in :rfc:`791`,
its structure is described as below:

======= ========= ======================== ===========================
Octets      Bits        Name                    Descriptions
======= ========= ======================== ===========================
  0           0   ``ip.opt.type.copy``      Copied Flag (``0``/``1``)
  0           1   ``ip.opt.type.class``     Option Class (``0``-``3``)
  0           3   ``ip.opt.type.number``    Option Number
======= ========= ======================== ===========================

.. raw:: html

   <br />

.. class:: DataType_IPv4_Option_Type

   :bases: TypedDict

   Structure of option type field [:rfc:`791`].

   .. attribute:: copy
      :type: bool

      Copied flag.

   .. attribute:: class
      :type: pcapkit.const.ipv4.option_class.OptionClass

      Option class.

   .. attribute:: number
      :type: int

      Option number.

IPv4 Miscellaneous Options
~~~~~~~~~~~~~~~~~~~~~~~~~~

1-Byte Options
++++++++++++++

.. class:: DataType_Opt_1_Byte

   :bases: DataType_Opt

   1-byte options.

   .. attribute:: length
      :type: Literal[1]

      Option length.

Permission Options
++++++++++++++++++

.. class:: DataType_Opt_Permission

   :bases: DataType_Opt

   Permission options (:attr:`length` is ``2``).

   .. attribute:: length
      :type: Literal[2]

      Option length.

   .. attribute:: flag
      :type: Literal[True]

      Permission flag.

No Process Options
++++++++++++++++++

For IPv4 options require no process,
its structure is described as below:

======= ========= ======================== ===========================
Octets      Bits        Name                    Description
======= ========= ======================== ===========================
  0           0   ``ip.opt.kind``             Kind
  0           0   ``ip.opt.type.copy``        Copied Flag
  0           1   ``ip.opt.type.class``       Option Class
  0           3   ``ip.opt.type.number``      Option Number
  1           8   ``ip.opt.length``           Length
  2          16   ``ip.opt.data``             Kind-specific Data
======= ========= ======================== ===========================

.. raw:: html

   <br />

.. class:: DataType_Opt_Do_None

   :bases: DataType_Opt

   Structure of IPv4 options.

   .. attribute:: data
      :type: bytes

      Kind-specific data.

Unpack Process Options
++++++++++++++++++++++

For IPv4 options require unpack process,
its structure is described as below:

======= ========= ======================== ===========================
Octets      Bits        Name                    Description
======= ========= ======================== ===========================
  0           0   ``ip.opt.kind``             Kind
  0           0   ``ip.opt.type.copy``        Copied Flag
  0           1   ``ip.opt.type.class``       Option Class
  0           3   ``ip.opt.type.number``      Option Number
  1           8   ``ip.opt.length``           Length
  2          16   ``ip.opt.data``             Kind-specific Data
======= ========= ======================== ===========================

.. raw:: html

   <br />

.. class:: DataType_Opt_Unpack

   :bases: DataType_Opt

   Structure of IPv4 options.

   .. attribute:: data
      :type: int

      Kind-specific data.

IPv4 Options with Route Data
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For IPv4 options with route data as described in :rfc:`791`,
its structure is described as below:

======= ========= ======================== =====================================
Octets      Bits        Name                    Description
======= ========= ======================== =====================================
  0           0   ``ip.opt.kind``             Kind (``7``/``131``/``137``)
  0           0   ``ip.opt.type.copy``        Copied Flag (``0``)
  0           1   ``ip.opt.type.class``       Option Class (``0``/``1``)
  0           3   ``ip.opt.type.number``      Option Number (``3``/``7``/``9``)
  1           8   ``ip.opt.length``           Length
  2          16   ``ip.opt.pointer``          Pointer (``≥4``)
  3          24   ``ip.opt.data``             Route Data
======= ========= ======================== =====================================

.. raw:: html

   <br />

.. class:: DataType_Opt_Route_Data

   :bases: DataType_Opt

   Structure of IPv4 options with route data [:rfc:`791`].

   .. attribute:: pointer
      :type: int

      Pointer.

   .. attribute:: data
      :type: Optional[Tuple[ipaddress.IPv4Address]]

      Route data.

IPv4 Quick Start Options
~~~~~~~~~~~~~~~~~~~~~~~~

For IPv4 Quick Start options as described in :rfc:`4782`,
its structure is described as below:

======= ========= ======================== =====================================
Octets      Bits        Name                    Description
======= ========= ======================== =====================================
  0           0   ``ip.qs.kind``              Kind (``25``)
  0           0   ``ip.qs.type.copy``         Copied Flag (``0``)
  0           1   ``ip.qs.type.class``        Option Class (``0``)
  0           3   ``ip.qs.type.number``       Option Number (``25``)
  1           8   ``ip.qs.length``            Length (``8``)
  2          16   ``ip.qs.func``              Function (``0``/``8``)
  2          20   ``ip.qs.rate``              Rate Request / Report (in Kbps)
  3          24   ``ip.qs.ttl``               QS TTL / :data:`None`
  4          32   ``ip.qs.nounce``            QS Nounce
  7          62                               Reserved (``\x00\x00``)
======= ========= ======================== =====================================

.. raw:: html

   <br />

.. class:: DataType_Opt_QuickStart

   :bases: DataType_Opt

   Structure of Quick-Start (QS) option [:rfc:`4782`].

   .. attribute:: func
      :type: pcapkit.const.ipv4.qs_function.QSFunction

      Function.

   .. attribute:: rate
      :type: int

      Rate request / report (in Kbps).

   .. attribute:: ttl
      :type: Optional[int]

      QS TTL.

   .. attribute:: nounce
      :type: int

      QS nounce.

IPv4 Time Stamp Option
~~~~~~~~~~~~~~~~~~~~~~

For IPv4 Time Stamp option as described in :rfc:`791`,
its structure is described as below:

======= ========= ======================== =====================================
Octets      Bits        Name                    Description
======= ========= ======================== =====================================
  0           0   ``ip.ts.kind``              Kind (``25``)
  0           0   ``ip.ts.type.copy``         Copied Flag (``0``)
  0           1   ``ip.ts.type.class``        Option Class (``0``)
  0           3   ``ip.ts.type.number``       Option Number (``25``)
  1           8   ``ip.ts.length``            Length (``≤40``)
  2          16   ``ip.ts.pointer``           Pointer (``≥5``)
  3          24   ``ip.ts.overflow``          Overflow Octets
  3          28   ``ip.ts.flag``              Flag
  4          32   ``ip.ts.ip``                Internet Address
  8          64   ``ip.ts.timestamp``         Timestamp
======= ========= ======================== =====================================

.. raw:: html

   <br />

.. class:: DataType_Opt_TimeStamp

   :bases: DataType_Opt

   Structure of Timestamp (TS) option [:rfc:`791`].

   .. attribute:: pointer
      :type: int

      Pointer.

   .. attribute:: overflow
      :type: int

      Overflow octets.

   .. attribute:: flag
      :type: int

      Flag.

   .. attribute:: ip
      :type: Optional[Tuple[ipaddress.IPv4Address]]

      Array of Internet addresses (if :attr:`flag` is ``1``/``3``).

   .. attribute:: timestamp
      :type: Optional[Tuple[datetime.datetime]]

      Array of timestamps (if :attr:`flag` is ``0``/``1``/``3``).

   .. attribute:: data
      :type: Optional[bytes]

      Timestamp data (if :attr:`flag` is unknown).

IPv4 Traceroute Option
~~~~~~~~~~~~~~~~~~~~~~

For IPv4 Traceroute option as described in :rfc:`6814`,
its structure is described as below:

======= ========= ======================== =====================================
Octets      Bits        Name                    Description
======= ========= ======================== =====================================
  0           0     ip.tr.kind              Kind (82)
  0           0     ip.tr.type.copy         Copied Flag (0)
  0           1     ip.tr.type.class        Option Class (0)
  0           3     ip.tr.type.number       Option Number (18)
  1           8     ip.tr.length            Length (12)
  2          16     ip.tr.id                ID Number
  4          32     ip.tr.ohc               Outbound Hop Count
  6          48     ip.tr.rhc               Return Hop Count
  8          64     ip.tr.ip                Originator IP Address
======= ========= ======================== =====================================

.. raw:: html

   <br />

.. class:: DataType_Opt_Traceroute

   :bases: DataType_Opt

   Structure of Traceroute (TR) option [:rfc:`6814`].

   .. attribute:: id
      :type: int

      ID number.

   .. attribute:: ohc
      :type: int

      Outbound hop count.

   .. attribute:: rhc
      :type: int

      Return hop count.

   .. attribute:: ip
      :type: ipaddress.IPv4Address

      Originator IP address.

IPv4 Options with Security Info
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For IPv4 options with security info as described in :rfc:`1108`,
its structure is described as below:

======= ========= ======================== =====================================
Octets      Bits        Name                    Description
======= ========= ======================== =====================================
  0           0   ``ip.sec.kind``             Kind (``130``/``133``)
  0           0   ``ip.sec.type.copy``        Copied Flag (``1``)
  0           1   ``ip.sec.type.class``       Option Class (``0``)
  0           3   ``ip.sec.type.number``      Option Number (``2``)
  1           8   ``ip.sec.length``           Length (``≥3``)
  2          16   ``ip.sec.level``            Classification Level
  3          24   ``ip.sec.flags``            Protection Authority Flags
======= ========= ======================== =====================================

.. raw:: html

   <br />

.. class:: DataType_Opt_Security_Info

   :bases: DataType_Opt

   Structure of IPv4 options with security info [:rfc:`791`].

   .. attribute:: level
      :type: pcapkit.const.ipv4.classification_level.ClassificationLevel

      Classification level.

   .. attribute:: flags
      :type: Tuple[DataType_SEC_Flags]

      Array of protection authority flags.

.. class:: DataType_SEC_Flags

   :bases: pcapkit.corekit.infoclass.Info

   Protection authority flags, as mapping of protection authority bit assignments
   :class:`enumeration <pcapkit.const.ipv4.protection_authority.ProtectionAuthority>`
   and :data:`bool` flags.

IPv4 Traceroute Option
~~~~~~~~~~~~~~~~~~~~~~

For IPv4 Router Alert option as described in :rfc:`2113`,
its structure is described as below:

======= ========= ========================= =====================================
Octets      Bits        Name                    Description
======= ========= ========================= =====================================
  0           0   ``ip.rsralt.kind``          Kind (``148``)
  0           0   ``ip.rsralt.type.copy``     Copied Flag (``1``)
  0           1   ``ip.rsralt.type.class``    Option Class (``0``)
  0           3   ``ip.rsralt.type.number``   Option Number (``20``)
  1           8   ``ip.rsralt.length``        Length (``4``)
  2          16   ``ip.rsralt.alert``         Alert
  2          16   ``ip.rsralt.code``          Alert Code
======= ========= ========================= =====================================

.. raw:: html

   <br />

.. class:: DataType_Opt_RouterAlert

   :bases: DataType_Opt

   Structure of Router Alert (RTRALT) option [:rfc:`2113`].

   .. attribute:: alert
      :type: pcapkit.const.ipv4.router_alert.RouterAlert

      Alert.

   .. attribute:: code
      :type: int

      Alert code.

.. raw:: html

   <hr />

.. [*] https://en.wikipedia.org/wiki/IPv4
