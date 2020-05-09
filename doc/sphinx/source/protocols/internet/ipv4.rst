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

.. .. autoclass:: pcapkit.protocols.internet.ipv4.IPv4
..    :members:
..    :undoc-members:
..    :private-members:
..    :show-inheritance:

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



.. raw:: html

   <hr />

.. [*] https://en.wikipedia.org/wiki/IPv4
