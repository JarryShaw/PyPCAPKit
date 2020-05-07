HOPOPT - IPv6 Hop-by-Hop Options
================================

.. module:: pcapkit.protocols.internet.hopopt

:mod:`pcapkit.protocols.internet.hopopt` contains
:class:`~pcapkit.protocols.internet.hopopt.HOPOPT`
only, which implements extractor for IPv6 Hop-by-Hop
Options header (HOPOPT) [*]_, whose structure is
described as below:

======= ========= =================== =================================
Octets      Bits        Name                    Description
======= ========= =================== =================================
  0           0   ``hopopt.next``             Next Header
  1           8   ``hopopt.length``           Header Extensive Length
  2          16   ``hopopt.options``          Options
======= ========= =================== =================================

.. raw:: html

   <br />

.. .. autoclass:: pcapkit.protocols.internet.hopopt.HOPOPT
..    :members:
..    :undoc-members:
..    :private-members:
..    :show-inheritance:

.. data:: pcapkit.protocols.internet.hopopt._HOPOPT_ACT
   :type: Dict[str, str]

   HOPOPT unknown option actions.

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

.. data:: pcapkit.protocols.internet.hopopt._HOPOPT_OPT
   :type: Dict[int, Tuple[str, str]]

   HOPOPT options.

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

.. data:: pcapkit.protocols.internet.hopopt._HOPOPT_NULL
   :type: Dict[int, str]

   HOPOPT unknown option descriptions.

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

.. class:: DataType_HOPOPT

   :bases: TypedDict

    Structure of HOPOPT header [:rfc:`8200`].

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

   HOPOPT option.

   .. attribute:: desc
      :type: str

      Option description.

   .. attribute:: type
      :type: DataType_Option_Type

      Option type.

   .. attribute:: length
      :type: int

      Option length.

      .. note::

         This attribute is **NOT** the length specified in the HOPOPT optiona data,
         rather the *total* length of the current option.

HOPOPT Option Type
~~~~~~~~~~~~~~~~~~

For HOPOPT option type field as described in :rfc:`791`,
its structure is described as below:

======= ========= ========================== ========================
Octets      Bits        Name                    Descriptions
======= ========= ========================== ========================
  0           0   ``hopopt.opt.type.value``   Option Number
  0           0   ``hopopt.opt.type.action``  Action (``00``-``11``)
  0           2   ``hopopt.opt.type.change``  Change Flag (``0``/``1``)
======= ========= ========================== ========================

.. raw:: html

   <br />

.. class:: DataType_Option_Type

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

HOPOPT Unassigned Options
~~~~~~~~~~~~~~~~~~~~~~~~~

For HOPOPT unassigned options as described in :rfc:`8200`,
its structure is described as below:

======= ========= =========================== =========================
Octets      Bits        Name                    Description
======= ========= =========================== =========================
  0           0   ``hopopt.opt.type``         Option Type
  0           0   ``hopopt.opt.type.value``   Option Number
  0           0   ``hopopt.opt.type.action``  Action (``00``-``11``)
  0           2   ``hopopt.opt.type.change``  Change Flag (``0``/``1``)
  1           8   ``hopopt.opt.length``       Length of Option Data
  2          16   ``hopopt.opt.data``         Option Data
======= ========= =========================== =========================

.. raw:: html

   <br />

.. class:: DataType_Opt_None

   :bases: DataType_Option

   Structure of HOPOPT unassigned options [:rfc:`8200`].

   .. attribute:: data
      :type: bytes

      Option data.

HOPOPT Padding Options
~~~~~~~~~~~~~~~~~~~~~~

``Pad1`` Option
+++++++++++++++

For HOPOPT ``Pad1`` option as described in :rfc:`8200`,
its structure is described as below:

======= ========= =========================== =========================
Octets      Bits        Name                    Description
======= ========= =========================== =========================
  0           0   ``hopopt.pad.type``         Option Type
  0           0   ``hopopt.pad.type.value``   Option Number
  0           0   ``hopopt.pad.type.action``  Action (``00``)
  0           2   ``hopopt.pad.type.change``  Change Flag (``0``)
======= ========= =========================== =========================

.. raw:: html

   <br />

.. class:: DataType_Opt_Pad1

   :bases: DataType_Option

   Structure of HOPOPT padding options [:rfc:`8200`].

   .. attribute:: length
      :type: Literal[1]

      Option length.

``PadN`` Option
+++++++++++++++

For HOPOPT ``PadN`` option as described in :rfc:`8200`,
its structure is described as below:

======= ========= =========================== =========================
Octets      Bits        Name                    Description
======= ========= =========================== =========================
  0           0   ``hopopt.pad.type``         Option Type
  0           0   ``hopopt.pad.type.value``   Option Number
  0           0   ``hopopt.pad.type.action``  Action (``00``)
  0           2   ``hopopt.pad.type.change``  Change Flag (``0``)
  1           8   ``hopopt.opt.length``       Length of Option Data
  2          16   ``hopopt.pad.padding``      Padding
======= ========= =========================== =========================

.. raw:: html

   <br />

.. class:: DataType_Opt_PadN

   :bases: DataType_Option

   Structure of HOPOPT padding options [:rfc:`8200`].

   .. attribute:: padding
      :type: bytes

      Padding data.

HOPOPT Tunnel Encapsulation Limit Option
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For HOPOPT Tunnel Encapsulation Limit option as described in :rfc:`2473`,
its structure is described as below:

======= ========= =========================== =========================
Octets      Bits        Name                    Description
======= ========= =========================== =========================
  0           0   ``hopopt.tun.type``         Option Type
  0           0   ``hopopt.tun.type.value``   Option Number
  0           0   ``hopopt.tun.type.action``  Action (``00``)
  0           2   ``hopopt.tun.type.change``  Change Flag (``0``)
  1           8   ``hopopt.tun.length``       Length of Option Data
  2          16   ``hopopt.tun.limit``        Tunnel Encapsulation Limit
======= ========= =========================== =========================

.. raw:: html

   <br />

.. class:: DataType_Opt_TUN

   :bases: DataType_Option

   Structure of HOPOPT Tunnel Encapsulation Limit option [:rfc:`2473`].

   .. attribute:: limit
      :type: int

      Tunnel encapsulation limit.

HOPOPT Router Alert Option
~~~~~~~~~~~~~~~~~~~~~~~~~~

For HOPOPT Router Alert option as described in :rfc:`2711`,
its structure is described as below:

======= ========= =========================== =========================
Octets      Bits        Name                    Description
======= ========= =========================== =========================
  0           0   ``hopopt.ra.type``          Option Type
  0           0   ``hopopt.ra.type.value``    Option Number
  0           0   ``hopopt.ra.type.action``   Action (``00``)
  0           2   ``hopopt.ra.type.change``   Change Flag (``0``)
  1           8   ``hopopt.opt.length``       Length of Option Data
  2          16   ``hopopt.ra.value``         Value
======= ========= =========================== =========================

.. raw:: html

   <br />

.. class:: DataType_Opt_RA

   :bases: DataType_Option

   Structure of HOPOPT Router Alert option [:rfc:`2711`].

   .. attribute:: value
      :type: int

      Router alert code value.

   .. attribute:: alert
      :type: pcapkit.const.ipv6.router_alter.RouterAlert

      Router alert enumeration.

HOPOPT ``CALIPSO`` Option
~~~~~~~~~~~~~~~~~~~~~~~~~

For HOPOPT ``CALIPSO`` option as described in :rfc:`5570`,
its structure is described as below:

======= ========= =============================== ==================================
Octets      Bits        Name                        Description
======= ========= =============================== ==================================
  0           0   ``hopopt.calipso.type``         Option Type
  0           0   ``hopopt.calipso.type.value``   Option Number
  0           0   ``hopopt.calipso.type.action``  Action (00)
  0           2   ``hopopt.calipso.type.change``  Change Flag (0)
  1           8   ``hopopt.calipso.length``       Length of Option Data
  2          16   ``hopopt.calipso.domain``       CALIPSO Domain of Interpretation
  6          48   ``hopopt.calipso.cmpt_len``     Cmpt Length
  7          56   ``hopopt.calipso.level``        Sens Level
  8          64   ``hopopt.calipso.chksum``       Checksum (CRC-16)
  9          72   ``hopopt.calipso.bitmap``       Compartment Bitmap
======= ========= =============================== ==================================

.. raw:: html

   <br />

.. class:: DataType_Opt_CALIPSO

   :bases: DataType_Option

   Structure of HOPOPT ``CALIPSO`` option [:rfc:`5570`].

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

HOPOPT ``SMF_DPD`` Option
~~~~~~~~~~~~~~~~~~~~~~~~~

I-DPD Mode
++++++++++

For IPv6 ``SMF_DPD`` option header in I-DPD mode as described in :rfc:`5570`,
its structure is described as below:

======= ========= =============================== =======================
Octets      Bits        Name                        Description
======= ========= =============================== =======================
  0           0   ``hopopt.smf_dpd.type``         Option Type
  0           0   ``hopopt.smf_dpd.type.value``   Option Number
  0           0   ``hopopt.smf_dpd.type.action``  Action (``00``)
  0           2   ``hopopt.smf_dpd.type.change``  Change Flag (``0``)
  1           8   ``hopopt.smf_dpd.length``       Length of Option Data
  2          16   ``hopopt.smf_dpd.dpd_type``     DPD Type (``0``)
  2          17   ``hopopt.smf_dpd.tid_type``     TaggerID Type
  2          20   ``hopopt.smf_dpd.tid_len``      TaggerID Length
  3          24   ``hopopt.smf_dpd.tid``          TaggerID
  ?           ?   ``hopopt.smf_dpd.id``           Identifier
======= ========= =============================== =======================

.. raw:: html

   <br />

.. class:: DataType_Opt_SMF_I_PDP

   :bases: DataType_Option

   Structure of HOPOPT ``SMF_DPD`` option in **I-DPD** mode [:rfc:`5570`].

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

======= ========= =============================== =======================
Octets      Bits        Name                        Description
======= ========= =============================== =======================
  0           0   ``hopopt.smf_dpd.type``         Option Type
  0           0   ``hopopt.smf_dpd.type.value``   Option Number
  0           0   ``hopopt.smf_dpd.type.action``  Action (``00``)
  0           2   ``hopopt.smf_dpd.type.change``  Change Flag (``0``)
  1           8   ``hopopt.smf_dpd.length``       Length of Option Data
  2          16   ``hopopt.smf_dpd.dpd_type``     DPD Type (``1``)
  2          17   ``hopopt.smf_dpd.hav``          Hash Assist Value
======= ========= =============================== =======================

.. raw:: html

   <br />

.. class:: DataType_Opt_SMF_H_PDP

   :bases: DataType_Option

   Structure of HOPOPT ``SMF_DPD`` option in **H-DPD** mode [:rfc:`5570`].

   .. attribute:: dpd_type
      :type: Literal['H-DPD']

      DPD type.

   .. attribute:: hav
      :type: str

      Hash assist value (as *binary* string).

HOPOPT ``PDM`` Option
~~~~~~~~~~~~~~~~~~~~~

For HOPOPT ``PDM`` option as described in :rfc:`8250`,
its structure is described as below:

======= ========= =============================== ======================================
Octets      Bits        Name                      Description
======= ========= =============================== ======================================
  0           0   ``hopopt.pdm.type``             Option Type
  0           0   ``hopopt.pdm.type.value``       Option Number
  0           0   ``hopopt.pdm.type.action``      Action (``00``)
  0           2   ``hopopt.pdm.type.change``      Change Flag (``0``)
  1           8   ``hopopt.pdm.length``           Length of Option Data
  2          16   ``hopopt.pdm.scaledtlr``        Scale Delta Time Last Received
  3          24   ``hopopt.pdm.scaledtls``        Scale Delta Time Last Sent
  4          32   ``hopopt.pdm.psntp``            Packet Sequence Number This Packet
  6          48   ``hopopt.pdm.psnlr``            Packet Sequence Number Last Received
  8          64   ``hopopt.pdm.deltatlr``         Delta Time Last Received
  10         80   ``hopopt.pdm.deltatls``         Delta Time Last Sent
======= ========= =============================== ======================================

.. raw:: html

   <br />

.. class:: DataType_Opt_PDM

   :bases: DataType_Option

   Structure of HOPOPT ``PDM`` option [:rfc:`8250`].

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

======= ========= =============================== ======================================
Octets      Bits        Name                      Description
======= ========= =============================== ======================================
  0           0   ``hopopt.qs.type``              Option Type
  0           0   ``hopopt.qs.type.value``        Option Number
  0           0   ``hopopt.qs.type.action``       Action (``00``)
  0           2   ``hopopt.qs.type.change``       Change Flag (``1``)
  1           8   ``hopopt.qs.length``            Length of Option Data
  2          16   ``hopopt.qs.func``              Function (``0``/``8``)
  2          20   ``hopopt.qs.rate``              Rate Request / Report (in Kbps)
  3          24   ``hopopt.qs.ttl``               QS TTL / :data:`None`
  4          32   ``hopopt.qs.nounce``            QS Nounce
  7          62                                   Reserved
======= ========= =============================== ======================================

.. raw:: html

   <br />

.. class:: DataType_Opt_QS

   :bases: DataType_Option

   Structure of HOPOPT ``PDM`` option [:rfc:`8250`].

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

HOPOPT ``RPL`` Option
~~~~~~~~~~~~~~~~~~~~~~~~~

For HOPOPT ``RPL`` option as described in :rfc:`6553`,
its structure is described as below:

======= ========= =============================== ======================================
Octets      Bits        Name                        Description
======= ========= =============================== ======================================
  0           0   ``hopopt.rpl.type``             Option Type
  0           0   ``hopopt.rpl.type.value``       Option Number
  0           0   ``hopopt.rpl.type.action``      Action (``01``)
  0           2   ``hopopt.rpl.type.change``      Change Flag (``1``)
  1           8   ``hopopt.rpl.length``           Length of Option Data
  2          16   ``hopopt.rpl.flags``            RPL Option Flags
  2          16   ``hopopt.rpl.flags.down``       Down Flag
  2          17   ``hopopt.rpl.flags.rank_error`` Rank-Error Flag
  2          18   ``hopopt.rpl.flags.fwd_error``  Forwarding-Error Flag
  3          24   ``hopopt.rpl.id``               RPLInstanceID
  4          32   ``hopopt.rpl.rank``             SenderRank
  6          48   ``hopopt.rpl.data``             Sub-TLVs
======= ========= =============================== ======================================

.. raw:: html

   <br />

.. class:: DataType_Opt_RPL

   :bases: DataType_Option

   Structure of HOPOPT ``RPL`` option [:rfc:`6553`].



.. raw:: html

   <hr />

.. [*] https://en.wikipedia.org/wiki/IPv6_packet#Hop-by-hop_options_and_destination_options
