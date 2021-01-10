IPv6-Opts - Destination Options for IPv6
========================================

.. module:: pcapkit.protocols.internet.ipv6_opts

:mod:`pcapkit.protocols.internet.ipv6_opts` contains
:class:`~pcapkit.protocols.internet.ipv6_opts.IPv6_Opts`
only, which implements extractor for Destination Options
for IPv6 (IPv6-Opts) [*]_, whose structure is described
as below:

======= ========= =================== =================================
Octets      Bits        Name                    Description
======= ========= =================== =================================
  0           0   ``opt.next``              Next Header
  1           8   ``opt.length``            Header Extensive Length
  2          16   ``opt.options``           Options
======= ========= =================== =================================

.. raw:: html

   <br />

.. autoclass:: pcapkit.protocols.internet.ipv6_opts.IPv6_Opts
   :members:
   :undoc-members:
   :private-members:
   :show-inheritance:

.. data:: pcapkit.protocols.internet.ipv6_opts._IPv6_Opts_ACT
   :type: Dict[str, str]

   IPv6-Opts unknown option actions.

   .. list-table::
      :header-rows: 1

      * - Code
        - Action
      * - ``00``
        - skip over this option and continue processing the header
      * - ``01``
        - discard the packet
      * - ``10``
        - discard the packet and, regardless of whether or not the
          packet's Destination Address was a multicast address, send
          an ICMP Parameter Problem, Code 2, message to the packet's
          Source Address, pointing to the unrecognized Option Type
      * - ``11``
        - discard the packet and, only if the packet's Destination
          Address was not a multicast address, send an ICMP Parameter
          Problem, Code 2, message to the packet's Source Address,
          pointing to the unrecognized Option Type

.. data:: pcapkit.protocols.internet.ipv6_opts._IPv6_Opts_OPT
   :type: Dict[int, Tuple[str, str]]

   IPv6-Opts options.

   .. list-table::
      :header-rows: 1

      * - Code
        - Acronym
        - Option
        - Reference
      * - 0x00
        - ``pad``
        - Pad1
        - [:rfc:`8200`] 0
      * - 0x01
        - ``pad``
        - PadN
        - [:rfc:`8200`]
      * - 0x04
        - ``tun``
        - Tunnel Encapsulation Limit
        - [:rfc:`2473`] 1
      * - 0x05
        - ``ra``
        - Router Alert
        - [:rfc:`2711`] 2
      * - 0x07
        - ``calipso``
        - Common Architecture Label IPv6 Security Option
        - [:rfc:`5570`]
      * - 0x08
        - ``smf_dpd``
        - Simplified Multicast Forwarding
        - [:rfc:`6621`]
      * - 0x0F
        - ``pdm``
        - Performance and Diagnostic Metrics
        - [:rfc:`8250`] 10
      * - 0x26
        - ``qs``
        - Quick-Start
        - [:rfc:`4782`][`RFC Errata 2034`_] 6
      * - 0x63
        - ``rpl``
        - Routing Protocol for Low-Power and Lossy Networks
        - [:rfc:`6553`]
      * - 0x6D
        - ``mpl``
        - Multicast Protocol for Low-Power and Lossy Networks
        - [:rfc:`7731`]
      * - 0x8B
        - ``ilnp``
        - Identifier-Locator Network Protocol Nonce
        - [:rfc:`6744`]
      * - 0x8C
        - ``lio``
        - Line-Identification Option
        - [:rfc:`6788`]
      * - 0xC2
        - ``jumbo``
        - Jumbo Payload
        - [:rfc:`2675`]
      * - 0xC9
        - ``home``
        - Home Address
        - [:rfc:`6275`]
      * - 0xEE
        - ``ip_dff``
        - Depth-First Forwarding
        - [:rfc:`6971`]

.. _RFC Errata 2034: https://www.rfc-editor.org/errata_search.php?eid=2034

.. data:: pcapkit.protocols.internet.ipv6_opts._IPv6_Opts_NULL
   :type: Dict[int, str]

   IPv6-Opts unknown option descriptions.

   .. list-table::
      :header-rows: 1

      * - Code
        - Description
        - Reference
      * - 0x1E
        - RFC3692-style Experiment
        - [:rfc:`4727`]
      * - 0x3E
        - RFC3692-style Experiment
        - [:rfc:`4727`]
      * - 0x4D
        - Deprecated
        - [:rfc:`7731`]
      * - 0x5E
        - RFC3692-style Experiment
        - [:rfc:`4727`]
      * - 0x7E
        - RFC3692-style Experiment
        - [:rfc:`4727`]
      * - 0x8A
        - Endpoint Identification
        - **DEPRECATED**
      * - 0x9E
        - RFC3692-style Experiment
        - [:rfc:`4727`]
      * - 0xBE
        - RFC3692-style Experiment
        - [:rfc:`4727`]
      * - 0xDE
        - RFC3692-style Experiment
        - [:rfc:`4727`]
      * - 0xFE
        - RFC3692-style Experiment
        - [:rfc:`4727`]

Data Structure
--------------

.. important::

   Following classes are only for *documentation* purpose.
   They do **NOT** exist in the :mod:`pcapkit` module.

.. class:: DataType_IPv6_Opts

   :bases: TypedDict

   Structure of IPv6-Opts header [:rfc:`8200`].

   .. attribute:: next
      :type: pcapkit.const.reg.transtype.TransType

      Next header.

   .. attribute:: length
      :type: int

      Header extensive length.

   .. attribute:: options
      :type: Tuple[pcapkit.const.ipv6.option.Option]

      Array of option acronyms.

   .. attribute:: packet
      :type: bytes

      Packet data.

.. class:: DataType_Option

   :bases: TypedDict

   IPv6_Opts option.

   .. attribute:: desc
      :type: str

      Option description.

   .. attribute:: type
      :type: DataType_IPv6_Opts_Option_Type

      Option type.

   .. attribute:: length
      :type: int

      Option length.

      .. note::

         This attribute is **NOT** the length specified in the IPv6-Opts optiona data,
         rather the *total* length of the current option.

IPv6-Opts Option Type
~~~~~~~~~~~~~~~~~~~~~

For IPv6-Opts option type field as described in :rfc:`791`,
its structure is described as below:

======= ========= ============================= ========================
Octets      Bits        Name                    Descriptions
======= ========= ============================= ========================
  0           0   ``ipv6_opts.opt.type.value``   Option Number
  0           0   ``ipv6_opts.opt.type.action``  Action (``00``-``11``)
  0           2   ``ipv6_opts.opt.type.change``  Change Flag (``0``/``1``)
======= ========= ============================= ========================

.. raw:: html

   <br />

.. class:: DataType_IPv6_Opts_Option_Type

   :bases: TypedDict

   Structure of option type field [:rfc:`791`].

   .. attribute:: value
      :type: int

      Option number.

   .. attribute:: action
      :type: str

      Action.

   .. attribute:: change
      :type: bool

      Change flag.

IPv6-Opts Unassigned Options
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For IPv6-Opts unassigned options as described in :rfc:`8200`,
its structure is described as below:

======= ========= ============================= =========================
Octets      Bits        Name                    Description
======= ========= ============================= =========================
  0           0   ``ipv6_opts.opt.type``         Option Type
  0           0   ``ipv6_opts.opt.type.value``   Option Number
  0           0   ``ipv6_opts.opt.type.action``  Action (``00``-``11``)
  0           2   ``ipv6_opts.opt.type.change``  Change Flag (``0``/``1``)
  1           8   ``ipv6_opts.opt.length``       Length of Option Data
  2          16   ``ipv6_opts.opt.data``         Option Data
======= ========= ============================= =========================

.. raw:: html

   <br />

.. class:: DataType_Dest_Opt_None

   :bases: DataType_Option

   Structure of IPv6-Opts unassigned options [:rfc:`8200`].

   .. attribute:: data
      :type: bytes

      Option data.

IPv6-Opts Padding Options
~~~~~~~~~~~~~~~~~~~~~~~~~

``Pad1`` Option
+++++++++++++++

For IPv6-Opts ``Pad1`` option as described in :rfc:`8200`,
its structure is described as below:

======= ========= ============================= =========================
Octets      Bits        Name                    Description
======= ========= ============================= =========================
  0           0   ``ipv6_opts.pad.type``         Option Type
  0           0   ``ipv6_opts.pad.type.value``   Option Number
  0           0   ``ipv6_opts.pad.type.action``  Action (``00``)
  0           2   ``ipv6_opts.pad.type.change``  Change Flag (``0``)
======= ========= ============================= =========================

.. raw:: html

   <br />

.. class:: DataType_Dest_Opt_Pad1

   :bases: DataType_Option

   Structure of IPv6-Opts padding options [:rfc:`8200`].

   .. attribute:: length
      :type: Literal[1]

      Option length.

``PadN`` Option
+++++++++++++++

For IPv6-Opts ``PadN`` option as described in :rfc:`8200`,
its structure is described as below:

======= ========= ============================= =========================
Octets      Bits        Name                    Description
======= ========= ============================= =========================
  0           0   ``ipv6_opts.pad.type``         Option Type
  0           0   ``ipv6_opts.pad.type.value``   Option Number
  0           0   ``ipv6_opts.pad.type.action``  Action (``00``)
  0           2   ``ipv6_opts.pad.type.change``  Change Flag (``0``)
  1           8   ``ipv6_opts.opt.length``       Length of Option Data
  2          16   ``ipv6_opts.pad.padding``      Padding
======= ========= ============================= =========================

.. raw:: html

   <br />

.. class:: DataType_Dest_Opt_PadN

   :bases: DataType_Option

   Structure of IPv6-Opts padding options [:rfc:`8200`].

   .. attribute:: padding
      :type: bytes

      Padding data.

IPv6-Opts Tunnel Encapsulation Limit Option
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For IPv6-Opts Tunnel Encapsulation Limit option as described in :rfc:`2473`,
its structure is described as below:

======= ========= ============================= =========================
Octets      Bits        Name                    Description
======= ========= ============================= =========================
  0           0   ``ipv6_opts.tun.type``         Option Type
  0           0   ``ipv6_opts.tun.type.value``   Option Number
  0           0   ``ipv6_opts.tun.type.action``  Action (``00``)
  0           2   ``ipv6_opts.tun.type.change``  Change Flag (``0``)
  1           8   ``ipv6_opts.tun.length``       Length of Option Data
  2          16   ``ipv6_opts.tun.limit``        Tunnel Encapsulation Limit
======= ========= ============================= =========================

.. raw:: html

   <br />

.. class:: DataType_Dest_Opt_TUN

   :bases: DataType_Option

   Structure of IPv6-Opts Tunnel Encapsulation Limit option [:rfc:`2473`].

   .. attribute:: limit
      :type: int

      Tunnel encapsulation limit.

IPv6-Opts Router Alert Option
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For IPv6-Opts Router Alert option as described in :rfc:`2711`,
its structure is described as below:

======= ========= ============================= =========================
Octets      Bits        Name                    Description
======= ========= ============================= =========================
  0           0   ``ipv6_opts.ra.type``          Option Type
  0           0   ``ipv6_opts.ra.type.value``    Option Number
  0           0   ``ipv6_opts.ra.type.action``   Action (``00``)
  0           2   ``ipv6_opts.ra.type.change``   Change Flag (``0``)
  1           8   ``ipv6_opts.opt.length``       Length of Option Data
  2          16   ``ipv6_opts.ra.value``         Value
======= ========= ============================= =========================

.. raw:: html

   <br />

.. class:: DataType_Dest_Opt_RA

   :bases: DataType_Option

   Structure of IPv6-Opts Router Alert option [:rfc:`2711`].

   .. attribute:: value
      :type: int

      Router alert code value.

   .. attribute:: alert
      :type: pcapkit.const.ipv6.router_alter.RouterAlert

      Router alert enumeration.

IPv6-Opts ``CALIPSO`` Option
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For IPv6-Opts ``CALIPSO`` option as described in :rfc:`5570`,
its structure is described as below:

======= ========= ================================= ==================================
Octets      Bits        Name                        Description
======= ========= ================================= ==================================
  0           0   ``ipv6_opts.calipso.type``         Option Type
  0           0   ``ipv6_opts.calipso.type.value``   Option Number
  0           0   ``ipv6_opts.calipso.type.action``  Action (00)
  0           2   ``ipv6_opts.calipso.type.change``  Change Flag (0)
  1           8   ``ipv6_opts.calipso.length``       Length of Option Data
  2          16   ``ipv6_opts.calipso.domain``       CALIPSO Domain of Interpretation
  6          48   ``ipv6_opts.calipso.cmpt_len``     Cmpt Length
  7          56   ``ipv6_opts.calipso.level``        Sens Level
  8          64   ``ipv6_opts.calipso.chksum``       Checksum (CRC-16)
  9          72   ``ipv6_opts.calipso.bitmap``       Compartment Bitmap
======= ========= ================================= ==================================

.. raw:: html

   <br />

.. class:: DataType_Dest_Opt_CALIPSO

   :bases: DataType_Option

   Structure of IPv6-Opts ``CALIPSO`` option [:rfc:`5570`].

   .. attribute:: domain
      :type: int

      ``CALIPSO`` domain of interpretation.

   .. attribute:: cmpt_len
      :type: int

      Compartment length.

   .. attribute:: level
      :type: int

      Sene level.

   .. attribute:: chksum
      :type: bytes

      Checksum (CRC-16).

   .. attribute:: bitmap
      :type: Tuple[str]

      Compartment bitmap.

IPv6-Opts ``SMF_DPD`` Option
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

I-DPD Mode
++++++++++

For IPv6 ``SMF_DPD`` option header in I-DPD mode as described in :rfc:`5570`,
its structure is described as below:

======= ========= ================================= =======================
Octets      Bits        Name                        Description
======= ========= ================================= =======================
  0           0   ``ipv6_opts.smf_dpd.type``         Option Type
  0           0   ``ipv6_opts.smf_dpd.type.value``   Option Number
  0           0   ``ipv6_opts.smf_dpd.type.action``  Action (``00``)
  0           2   ``ipv6_opts.smf_dpd.type.change``  Change Flag (``0``)
  1           8   ``ipv6_opts.smf_dpd.length``       Length of Option Data
  2          16   ``ipv6_opts.smf_dpd.dpd_type``     DPD Type (``0``)
  2          17   ``ipv6_opts.smf_dpd.tid_type``     TaggerID Type
  2          20   ``ipv6_opts.smf_dpd.tid_len``      TaggerID Length
  3          24   ``ipv6_opts.smf_dpd.tid``          TaggerID
  ?           ?   ``ipv6_opts.smf_dpd.id``           Identifier
======= ========= ================================= =======================

.. raw:: html

   <br />

.. class:: DataType_Dest_Opt_SMF_I_PDP

   :bases: DataType_Option

   Structure of IPv6-Opts ``SMF_DPD`` option in **I-DPD** mode [:rfc:`5570`].

   .. attribute:: dpd_type
      :type: Literal['I-DPD']

      DPD type.

   .. attribute:: tid_type
      :type: pcapkit.const.ipv6.tagger_id.TaggerID

      TaggerID type.

   .. attribute:: tid_len
      :type: int

      TaggerID length.

   .. attribute:: tid
      :type: int

      TaggerID.

   .. attribute:: id
      :type: bytes

      Identifier.

H-DPD Mode
++++++++++

For IPv6 ``SMF_DPD`` option header in H-DPD mode as described in :rfc:`5570`,
its structure is described as below:

======= ========= ================================= =======================
Octets      Bits        Name                        Description
======= ========= ================================= =======================
  0           0   ``ipv6_opts.smf_dpd.type``         Option Type
  0           0   ``ipv6_opts.smf_dpd.type.value``   Option Number
  0           0   ``ipv6_opts.smf_dpd.type.action``  Action (``00``)
  0           2   ``ipv6_opts.smf_dpd.type.change``  Change Flag (``0``)
  1           8   ``ipv6_opts.smf_dpd.length``       Length of Option Data
  2          16   ``ipv6_opts.smf_dpd.dpd_type``     DPD Type (``1``)
  2          17   ``ipv6_opts.smf_dpd.hav``          Hash Assist Value
======= ========= ================================= =======================

.. raw:: html

   <br />

.. class:: DataType_Dest_Opt_SMF_H_PDP

   :bases: DataType_Option

   Structure of IPv6-Opts ``SMF_DPD`` option in **H-DPD** mode [:rfc:`5570`].

   .. attribute:: dpd_type
      :type: Literal['H-DPD']

      DPD type.

   .. attribute:: hav
      :type: str

      Hash assist value (as *binary* string).

IPv6-Opts ``PDM`` Option
~~~~~~~~~~~~~~~~~~~~~~~~

For IPv6-Opts ``PDM`` option as described in :rfc:`8250`,
its structure is described as below:

======= ========= =============================== ======================================
Octets      Bits        Name                      Description
======= ========= =============================== ======================================
  0           0   ``ipv6_opts.pdm.type``             Option Type
  0           0   ``ipv6_opts.pdm.type.value``       Option Number
  0           0   ``ipv6_opts.pdm.type.action``      Action (``00``)
  0           2   ``ipv6_opts.pdm.type.change``      Change Flag (``0``)
  1           8   ``ipv6_opts.pdm.length``           Length of Option Data
  2          16   ``ipv6_opts.pdm.scaledtlr``        Scale Delta Time Last Received
  3          24   ``ipv6_opts.pdm.scaledtls``        Scale Delta Time Last Sent
  4          32   ``ipv6_opts.pdm.psntp``            Packet Sequence Number This Packet
  6          48   ``ipv6_opts.pdm.psnlr``            Packet Sequence Number Last Received
  8          64   ``ipv6_opts.pdm.deltatlr``         Delta Time Last Received
  10         80   ``ipv6_opts.pdm.deltatls``         Delta Time Last Sent
======= ========= =============================== ======================================

.. raw:: html

   <br />

.. class:: DataType_Dest_Opt_PDM

   :bases: DataType_Option

   Structure of IPv6-Opts ``PDM`` option [:rfc:`8250`].

   .. attribute:: scaledtlr
      :type: datetime.timedelta

      Scale delta time last received.

   .. attribute:: scaledtls
      :type: datetime.timedelta

      Scale delta time last sent.

   .. attribute:: psntp
      :type: int

      Packet sequence number this packet.

   .. attribute:: psnlr
      :type: int

      Packet sequence number last received.

   .. attribute:: deltatlr
      :type: datetime.timedelta

      Delta time last received.

   .. attribute:: deltatls
      :type: datetime.timedelta

      Delta time last sent.

IPv6-Opts Quick Start Option
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For IPv6-Opts Quick Start option as described in :rfc:`4782`,
its structure is described as below:

======= ========= =============================== ======================================
Octets      Bits        Name                      Description
======= ========= =============================== ======================================
  0           0   ``ipv6_opts.qs.type``              Option Type
  0           0   ``ipv6_opts.qs.type.value``        Option Number
  0           0   ``ipv6_opts.qs.type.action``       Action (``00``)
  0           2   ``ipv6_opts.qs.type.change``       Change Flag (``1``)
  1           8   ``ipv6_opts.qs.length``            Length of Option Data
  2          16   ``ipv6_opts.qs.func``              Function (``0``/``8``)
  2          20   ``ipv6_opts.qs.rate``              Rate Request / Report (in Kbps)
  3          24   ``ipv6_opts.qs.ttl``               QS TTL / :data:`None`
  4          32   ``ipv6_opts.qs.nounce``            QS Nounce
  7          62                                      Reserved
======= ========= =============================== ======================================

.. raw:: html

   <br />

.. class:: DataType_Dest_Opt_QS

   :bases: DataType_Option

   Structure of IPv6-Opts Quick Start option [:rfc:`8250`].

   .. attribute:: func
      :type: pcapkit.const.ipv6.qs_function.QSFunction

      Function.

   .. attribute:: rate
      :type: float

      Rate request and/or report (in *Kbps*).

   .. attribute:: ttl
      :type: Optional[int]

      QS TTL.

   .. attribute:: nounce
      :type: int

      QS nounce.

IPv6-Opts ``RPL`` Option
~~~~~~~~~~~~~~~~~~~~~~~~

For IPv6-Opts ``RPL`` option as described in :rfc:`6553`,
its structure is described as below:

======= ========= ================================== ======================================
Octets      Bits        Name                         Description
======= ========= ================================== ======================================
  0           0   ``ipv6_opts.rpl.type``             Option Type
  0           0   ``ipv6_opts.rpl.type.value``       Option Number
  0           0   ``ipv6_opts.rpl.type.action``      Action (``01``)
  0           2   ``ipv6_opts.rpl.type.change``      Change Flag (``1``)
  1           8   ``ipv6_opts.rpl.length``           Length of Option Data
  2          16   ``ipv6_opts.rpl.flags``            RPL Option Flags
  2          16   ``ipv6_opts.rpl.flags.down``       Down Flag
  2          17   ``ipv6_opts.rpl.flags.rank_error`` Rank-Error Flag
  2          18   ``ipv6_opts.rpl.flags.fwd_error``  Forwarding-Error Flag
  3          24   ``ipv6_opts.rpl.id``               RPL Instance ID
  4          32   ``ipv6_opts.rpl.rank``             SenderRank
  6          48   ``ipv6_opts.rpl.data``             Sub-TLVs
======= ========= ================================== ======================================

.. raw:: html

   <br />

.. class:: DataType_Dest_Opt_RPL

   :bases: DataType_Option

   Structure of IPv6-Opts ``RPL`` option [:rfc:`6553`].

   .. attribute:: flags
      :type: DataType_RPL_Flags

      RPL option flags.

   .. attribute:: id
      :type: int

      RPL instance ID.

   .. attribute:: rank
      :type: int

      Sender rank.

   .. attribute:: data
      :type: Optional[bytes]

      Sub-TLVs (if ``ipv6_opts.rpl.length`` is **GREATER THAN** ``4``).

.. class:: DataType_RPL_Flags

   :bases: TypedDict

   RPL option flags.

   .. attribute:: down
      :type: bool

      Down flag.

   .. attribute:: rank_error
      :type: bool

      Rank-Error flag.

   .. attribute:: fwd_error
      :type: bool

      Forwarding-Error flag.

IPv6-Opts ``MPL`` Option
~~~~~~~~~~~~~~~~~~~~~~~~

For IPv6-Opts ``MPL`` option as described in :rfc:`7731`,
its structure is described as below:

======= ========= =============================== ======================================
Octets      Bits        Name                        Description
======= ========= =============================== ======================================
  0           0   ``ipv6_opts.mpl.type``             Option Type
  0           0   ``ipv6_opts.mpl.type.value``       Option Number
  0           0   ``ipv6_opts.mpl.type.action``      Action (``01``)
  0           2   ``ipv6_opts.mpl.type.change``      Change Flag (``1``)
  1           8   ``ipv6_opts.mpl.length``           Length of Option Data
  2          16   ``ipv6_opts.mpl.seed_len``         Seed-ID Length
  2          18   ``ipv6_opts.mpl.flags``            MPL Option Flags
  2          18   ``ipv6_opts.mpl.max``              Maximum SEQ Flag
  2          19   ``ipv6_opts.mpl.verification``     Verification Flag
  2          20                                   Reserved
  3          24   ``ipv6_opts.mpl.seq``              Sequence
  4          32   ``ipv6_opts.mpl.seed_id``          Seed-ID
======= ========= =============================== ======================================

.. raw:: html

   <br />

.. class:: DataType_Dest_Opt_MPL

   :bases: DataType_Option

   Structure of IPv6-Opts ``MPL`` option [:rfc:`7731`].

   .. attribute:: seed_len
      :type: pcapkit.const.ipv6.seed_id.SeedID

      Seed-ID length.

   .. attribute:: flags
      :type: DataType_MPL_Flags

      MPL option flags.

   .. attribute:: seq
      :type: int

      Sequence.

   .. attribute:: seed_id
      :type: Optional[int]

      Seed-ID.

.. class:: DataType_MPL_Flags

   :bases: TypedDict

   MPL option flags.

   .. attribute:: max
      :type: bool

      Maximum sequence flag.

   .. attribute:: verification
      :type: bool

      Verification flag.

IPv6-Opts ``ILNP`` Nounce Option
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For IPv6-Opts ``ILNP`` Nounce option as described in :rfc:`6744`,
its structure is described as below:

======= ========= =============================== ======================================
Octets      Bits        Name                        Description
======= ========= =============================== ======================================
  0           0   ``ipv6_opts.ilnp.type``            Option Type
  0           0   ``ipv6_opts.ilnp.type.value``      Option Number
  0           0   ``ipv6_opts.ilnp.type.action``     Action (``10``)
  0           2   ``ipv6_opts.ilnp.type.change``     Change Flag (``0``)
  1           8   ``ipv6_opts.ilnp.length``          Length of Option Data
  2          16   ``ipv6_opts.ilnp.value``           Nonce Value
======= ========= =============================== ======================================

.. raw:: html

   <br />

.. class:: DataType_Dest_Opt_ILNP

   :bases: DataType_Option

   Structure of IPv6-Opts ``ILNP`` Nonce option [:rfc:`6744`].

   .. attribute:: value
      :type: bytes

      Nonce value.

IPv6-Opts Line-Identification Option
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For IPv6-Opts Line-Identification option as described in :rfc:`6788`,
its structure is described as below:

======= ========= =============================== ======================================
Octets      Bits        Name                        Description
======= ========= =============================== ======================================
  0           0   ``ipv6_opts.lio.type``             Option Type
  0           0   ``ipv6_opts.lio.type.value``       Option Number
  0           0   ``ipv6_opts.lio.type.action``      Action (``10``)
  0           2   ``ipv6_opts.lio.type.change``      Change Flag (``0``)
  1           8   ``ipv6_opts.lio.length``           Length of Option Data
  2          16   ``ipv6_opts.lio.lid_len``          Line ID Length
  3          24   ``ipv6_opts.lio.lid``              Line ID
======= ========= =============================== ======================================

.. raw:: html

   <br />

.. class:: DataType_Dest_Opt_LIO

   :bases: DataType_Option

   Structure of IPv6-Opts Line-Identification option [:rfc:`6788`].

   .. attribute:: lid_len
      :type: int

      Line ID length.

   .. attribute:: lid
      :type: bytes

      Line ID.

IPv6-Opts Jumbo Payload Option
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For IPv6-Opts Jumbo Payload option as described in :rfc:`2675`,
its structure is described as below:

======= ========= =============================== ======================================
Octets      Bits        Name                        Description
======= ========= =============================== ======================================
  0           0   ``ipv6_opts.jumbo.type``           Option Type
  0           0   ``ipv6_opts.jumbo.type.value``     Option Number
  0           0   ``ipv6_opts.jumbo.type.action``    Action (``11``)
  0           2   ``ipv6_opts.jumbo.type.change``    Change Flag (``0``)
  1           8   ``ipv6_opts.jumbo.length``         Length of Option Data
  2          16   ``ipv6_opts.jumbo.payload_len``    Jumbo Payload Length
======= ========= =============================== ======================================

.. raw:: html

   <br />

.. class:: DataType_Dest_Opt_Jumbo

   :bases: DataType_Option

   Structure of IPv6-Opts Jumbo Payload option [:rfc:`2675`].

   .. attribute:: payload_len
      :type: int

      Jumbo payload length.

IPv6-Opts Home Address Option
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For IPv6-Opts Home Address option as described in :rfc:`6275`,
its structure is described as below:

======= ========= =============================== ======================================
Octets      Bits        Name                        Description
======= ========= =============================== ======================================
  0           0   ``ipv6_opts.home.type``            Option Type
  0           0   ``ipv6_opts.home.type.value``      Option Number
  0           0   ``ipv6_opts.home.type.action``     Action (``11``)
  0           2   ``ipv6_opts.home.type.change``     Change Flag (``0``)
  1           8   ``ipv6_opts.home.length``          Length of Option Data
  2          16   ``ipv6_opts.home.ip``              Home Address
======= ========= =============================== ======================================

.. raw:: html

   <br />

.. class:: DataType_Dest_Opt_Home

   :bases: DataType_Option

   Structure of IPv6-Opts Home Address option [:rfc:`6275`].

   .. attribute:: ip
      :type: ipaddress.IPv6Address

      Home address.

IPv6-Opts ``IP_DFF`` Option
~~~~~~~~~~~~~~~~~~~~~~~~~~~

For IPv6-Opts ``IP_DFF`` option as described in :rfc:`6971`,
its structure is described as below:

======= ========= ================================= ======================================
Octets      Bits        Name                        Description
======= ========= ================================= ======================================
  0           0   ``ipv6_opts.ip_dff.type``          Option Type
  0           0   ``ipv6_opts.ip_dff.type.value``    Option Number
  0           0   ``ipv6_opts.ip_dff.type.action``   Action (``11``)
  0           2   ``ipv6_opts.ip_dff.type.change``   Change Flag (``1``)
  1           8   ``ipv6_opts.ip_dff.length``        Length of Option Data
  2          16   ``ipv6_opts.ip_dff.version``       Version
  2          18   ``ipv6_opts.ip_dff.flags``         Flags
  2          18   ``ipv6_opts.ip_dff.flags.dup``     ``DUP`` Flag
  2          19   ``ipv6_opts.ip_dff.flags.ret``     ``RET`` Flag
  2          20                                      Reserved
  3          24   ``ipv6_opts.ip_dff.seq``           Sequence Number
======= ========= ================================= ======================================

.. raw:: html

   <br />

.. class:: DataType_Dest_Opt_IP_DFF

   :bases: DataType_Option

   Structure of IPv6-Opts ``IP_DFF`` option [:rfc:`6971`].

   .. attribute:: version
      :type: int

      Version.

   .. attribute:: flags
      :type: DataType_IP_DFF_Flags

      Flags.

   .. attribute:: seq
      :type: int

      Sequence number.

.. class:: DataType_IP_DFF_Flags

   :bases: TypedDict

   Flags.

   .. attribute:: dup
      :type: bool

      ``DUP`` flag.

   .. attribute:: ret
      :type: bool

      ``RET`` flag.

.. raw:: html

   <hr />

.. [*] https://en.wikipedia.org/wiki/IPv6_packet#Hop-by-hop_options_and_destination_options
