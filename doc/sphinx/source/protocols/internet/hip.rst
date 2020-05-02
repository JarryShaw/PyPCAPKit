HIP - Host Identity Protocol
============================

:mod:`pcapkit.protocols.internet.hip` contains
:class:`~pcapkit.protocols.internet.hip.HIP` only,
which implements extractor for Host Identity
Protocol (HIP) [*]_, whose structure is described
as below:

======= ========= ====================== ==================================
Octets      Bits        Name                    Description
======= ========= ====================== ==================================
  0           0   ``hip.next``              Next Header
  1           8   ``hip.length``            Header Length
  2          16                             Reserved (``\x00``)
  2          17   ``hip.type``              Packet Type
  3          24   ``hip.version``           Version
  3          28                             Reserved
  3          31                             Reserved (``\x01``)
  4          32   ``hip.chksum``            Checksum
  6          48   ``hip.control``           Controls
  8          64   ``hip.shit``              Sender's Host Identity Tag
  24        192   ``hip.rhit``              Receiver's Host Identity Tag
  40        320   ``hip.parameters``        HIP Parameters
======= ========= ====================== ==================================

.. raw:: html

   <br />

.. .. automodule:: pcapkit.protocols.internet.hip
..    :members:
..    :undoc-members:
..    :private-members:
..    :show-inheritance:

Data Structure
--------------

.. class:: DataType_HIP

   :bases: TypedDict

   HIP header [:rfc:`5201`][:rfc:`7401`].

   .. attribute:: next
      :type: pcapkit.const.reg.transtype.TransType

      Next header.

   .. attribute:: length
      :type: int

      Header length.

   .. attribute:: type
      :type: pcapkit.const.hip.packet.Packet

      Packet type.

   .. attribute:: version
      :type: Literal[1, 2]

      Version.

   .. attribute:: chksum
      :type: bytes

      Checksum.

   .. attribute:: control
      :type: DataType_Control

      Controls.

   .. attribute:: shit
      :type: int

      Sender's host identity tag.

   .. attribute:: rhit
      :type: int

      Receiver's host identity tag.

   .. attribute:: parameters
      :type: Optional[Tuple[pcapkit.const.hip.parameter.Parameter]]

      HIP parameters.

.. class:: DataType_Control

   :bases: TypedDict

   HIP controls.

   .. attribute:: anonymous
      :type: bool

      Anonymous.

.. class:: DataType_Parameter

   :bases: TypedDict

   HIP parameters.

   .. attribute:: type
      :type: pcapkit.const.hip.parameter.Parameter

      Parameter type.

   .. attribute:: critical
      :type: bool

      Critical bit.

   .. attribute:: length
      :type: int

      Length of contents.

HIP Unassigned Parameters
~~~~~~~~~~~~~~~~~~~~~~~~~

For HIP unassigned parameters as described in :rfc:`5201`
and :rfc:`7401`, its structure is described as below:

======= ========= ==================== ========================
Octets      Bits        Name                    Description
======= ========= ==================== ========================
 0           0    ``para.type``            Parameter Type
 1          15    ``para.critical``        Critical Bit
 2          16    ``para.length``          Length of Contents
 4          32    ``para.contents``        Contents
                                           Padding
======= ========= ==================== ========================

.. raw:: html

   <br />

.. class:: DataType_Param_Unassigned

   :bases: DataType_Parameter

   Structure of HIP unassigned parameters [:rfc:`5201`][:rfc:`7401`].

   .. attribute:: contents
      :type: bytes

      Contents.

HIP ``ESP_INFO`` Parameter
~~~~~~~~~~~~~~~~~~~~~~~~~~

For HIP ``ESP_INFO`` parameter as described in :rfc:`7402`,
its structure is described as below:

======= ========= ====================== =======================
Octets      Bits        Name                    Description
======= ========= ====================== =======================
  0           0   ``esp_info.type``         Parameter Type
  1          15   ``esp_info.critical``     Critical Bit
  2          16   ``esp_info.length``       Length of Contents
  4          32                             Reserved
  6          48   ``esp_info.index``        KEYMAT Index
  8          64   ``esp_info.old_spi``      OLD SPI
  12         96   ``esp_info.new_spi``      NEW SPI
======= ========= ====================== =======================

.. raw:: html

   <br />

.. class:: DataType_Param_ESP_Info

   :bases: DataType_Parameter

   Structure of HIP ``ESP_INFO`` parameter [:rfc:`7402`].

   .. attribute:: index
      :type: int

      ``KEYMAT`` index.

   .. attribute:: old_spi
      :type: int

      Old SPI.

   .. attribute:: new_spi
      :type: int

      New SPI.

HIP ``R1_COUNTER`` Parameter
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For HIP ``R1_COUNTER`` parameter as described in :rfc:`5201` and :rfc:`7401`,
its structure is described as below:

======= ========= ======================= ===============================
Octets      Bits        Name                    Description
======= ========= ======================= ===============================
  0           0   ``ri_counter.type``       Parameter Type
  1          15   ``ri_counter.critical``   Critical Bit
  2          16   ``ri_counter.length``     Length of Contents
  4          32                             Reserved
  8          64   ``ri_counter.count``      Generation of Valid Puzzles
======= ========= ======================= ===============================

.. raw:: html

   <br />

.. class:: DataType_Param_R1_Counter

   :bases: DataType_Parameter

   Structure of HIP ``R1_COUNTER`` parameter [:rfc:`5201`][:rfc:`7401`].

   .. attribute:: count
      :type: int

      Generation of valid puzzles.

HIP ``LOCATOR_SET`` Parameter
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For HIP ``LOCATOR_SET`` parameter as described in :rfc:`8046`,
its structure is described as below:

======= ========= =========================== =======================
Octets      Bits        Name                    Description
======= ========= =========================== =======================
  0           0     ``locator_set.type``       Parameter Type
  1          15     ``locator_set.critical``   Critical Bit
  2          16     ``locator_set.length``     Length of Contents
  ?           ?     ...                        ...
  4          32     ``locator.traffic``        Traffic Type
  5          40     ``locator.type``           Locator Type
  6          48     ``locator.length``         Locator Length
  7          56                                Reserved
  7          63     ``locator.preferred``      Preferred Locator
  8          64     ``locator.lifetime``       Locator Lifetime
  12         96     ``locator.object``         Locator
  ?           ?     ...                        ...
======= ========= =========================== =======================

.. raw:: html

   <br />

.. class:: DataType_Param_Locator_Set

   :bases: DataType_Parameter

   Structure of HIP ``LOCATOR_SET`` parameter [:rfc:`8046`].

   .. attribute:: locator
      :type: Tuple[DataType_Locator]

      Locator set.

.. class:: DataType_Locator

   :bases: TypedDict

   Locator.

   .. attribute:: traffic
      :type: int

      Traffic type.

   .. attribute:: type
      :type: int

      Locator type.

   .. attribute:: length
      :type: int

      Locator length.

   .. attribute:: preferred
      :type: int

      Preferred length.

   .. attribute:: lifetime
      :type: int

      Locator lifetime.

   .. attribute:: object
      :type: DataType_Locator_Dict

      Locator.

.. class:: DataType_Locator_Dict

   :bases: TypedDict

   Locator type 2.

   .. attribute:: spi
      :type: int

      SPI.

   .. attribute:: ip
      :type: ipaddress.IPv4Address

HIP ``PUZZLE`` Parameter
~~~~~~~~~~~~~~~~~~~~~~~~

For HIP ``PUZZLE`` parameter as described in :rfc:`5201` and :rfc:`7401`,
its structure is described as below:

======= ========= ===================== ==============================
Octets      Bits        Name                    Description
======= ========= ===================== ==============================
  0           0   ``puzzle.type``           Parameter Type
  1          15   ``puzzle.critical``       Critical Bit
  2          16   ``puzzle.length``         Length of Contents
  4          32   ``puzzle.number``         Number of Verified Bits
  5          40   ``puzzle.lifetime``       Lifetime
  6          48   ``puzzle.opaque``         Opaque
  8          64   ``puzzle.random``         Random Number
======= ========= ===================== ==============================

.. raw:: html

   <br />

.. class:: DataType_Param_Puzzle

   :bases: DataType_Parameter

   Structure of HIP ``PUZZLE`` parameter [:rfc:`5201`][:rfc:`7401`].

   .. attribute:: number
      :type: int

      Number of verified bits.

   .. attribute:: lifetime
      :type: int

      Lifetime.

   .. attribute:: opaque
      :type: bytes

      Opaque.

   .. attribute:: random
      :type: int

      Random number.

HIP ``SOLUTION`` Parameter
~~~~~~~~~~~~~~~~~~~~~~~~~~

For HIP ``SOLUTION`` parameter as described in :rfc:`5201` and :rfc:`7401`,
its structure is described as below:

======= ========= ===================== =============================
Octets      Bits        Name                    Description
======= ========= ===================== =============================
  0           0   ``solution.type``         Parameter Type
  1          15   ``solution.critical``     Critical Bit
  2          16   ``solution.length``       Length of Contents
  4          32   ``solution.number``       Number of Verified Bits
  5          40   ``solution.lifetime``     Lifetime
  6          48   ``solution.opaque``       Opaque
  8          64   ``solution.random``       Random Number
  ?           ?   ``solution.solution``     Puzzle Solution
======= ========= ===================== =============================

.. raw:: html

   <br />

.. class:: DataType_Param_Solution

   :bases: DataType_Parameter

   Structure of HIP ``SOLUTION`` parameter [:rfc:`5201`][:rfc:`7401`].

   .. attribute:: number
      :type: number

      Number of verified bits.

   .. attribute:: lifetime
      :type: int

      Lifetime.

   .. attribute:: opaque
      :type: bytes

      Opaque.

   .. attribute:: random
      :type: int

      Random number.

   .. attribute:: solution
      :type: int

      Puzzle solution.

HIP ``SEQ`` Parameter
~~~~~~~~~~~~~~~~~~~~~

For HIP ``SEQ`` parameter as described in :rfc:`7401`,
its structure is described as below:

======= ========= ================= =================================
Octets      Bits        Name                    Description
======= ========= ================= =================================
  0           0   ``seq.type``              Parameter Type
  1          15   ``seq.critical``          Critical Bit
  2          16   ``seq.length``            Length of Contents
  4          32   ``seq.id``                Update ID
======= ========= ================= =================================

.. raw:: html

   <br />

.. class:: DataType_Param_SEQ

   :bases: DataType_Parameter

   Structure of HIP ``SEQ`` parameter [:rfc:`7401`].

   .. attribute:: id
      :type: int

      Update ID.

HIP ``ACK`` Parameter
~~~~~~~~~~~~~~~~~~~~~

For HIP ``ACK`` parameter as described in :rfc:`7401`,
its structure is described as below:

======= ========= ================== =============================
Octets      Bits        Name                    Description
======= ========= ================== =============================
  0           0   ``ack.type``              Parameter Type
  1          15   ``ack.critical``          Critical Bit
  2          16   ``ack.length``            Length of Contents
  4          32   ``ack.id``                Peer Update ID
======= ========= ================== =============================

.. raw:: html

   <br />

.. class:: DataType_Param_ACK

   :bases: DataType_Parameter

   .. attribute:: id
      :type: Tuple[int]

      Array of peer update IDs.

HIP ``DH_GROUP_LIST`` Parameter
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For HIP ``DH_GROUP_LIST`` parameter as described in :rfc:`7401`,
its structure is described as below:

======= ========= ========================== ===================
Octets      Bits        Name                    Description
======= ========= ========================== ===================
  0           0   ``dh_group_list.type``     Parameter Type
  1          15   ``dh_group_list.critical`` Critical Bit
  2          16   ``dh_group_list.length``   Length of Contents
  4          32   ``dh_group_list.id``       DH GROUP ID
======= ========= ========================== ===================

.. raw:: html

   <br />

.. class:: DataType_Param_DH_Group_List

   :bases: DataType_Parameter

   Structure of HIP ``DH_GROUP_LIST`` parameter [:rfc:`7401`].

   .. attribute:: id
      :type: Tuple[pcapkit.const.hip.group.Group]

      Array of DH group IDs.

HIP ``DEFFIE_HELLMAN`` Parameter
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For HIP ``DEFFIE_HELLMAN`` parameter as described in :rfc:`7401`,
its structure is described as below:

======= ========= =========================== ===================
Octets      Bits        Name                    Description
======= ========= =========================== ===================
  0           0   ``diffie_hellman.type``     Parameter Type
  1          15   ``diffie_hellman.critical`` Critical Bit
  2          16   ``diffie_hellman.length``   Length of Contents
  4          32   ``diffie_hellman.id``       Group ID
  5          40   ``diffie_hellman.pub_len``  Public Value Length
  6          48   ``diffie_hellman.pub_val``  Public Value
  ?           ?                               Padding
======= ========= =========================== ===================

.. raw:: html

   <br />

.. class:: DataType_Param_Deffie_Hellman

   :bases: DataType_Parameter

   Structure of HIP ``DEFFIE_HELLMAN`` parameter [:rfc:`7401`].

   .. attribute:: id
      :type: pcapkit.const.hip.group.Group

      Group ID.

   .. attribute:: pub_len
      :type: int

      Public value length.

   .. attribute:: pub_val
      :type: bytes

      Public value.

HIP ``HIP_TRANSFORM`` Parameter
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For HIP ``HIP_TRANSFORM`` parameter as described in :rfc:`5201`,
its structure is described as below:

======= ========= ========================== ====================
Octets      Bits        Name                    Description
======= ========= ========================== ====================
  0           0   ``hip_transform.type``      Parameter Type
  1          15   ``hip_transform.critical``  Critical Bit
  2          16   ``hip_transform.length``    Length of Contents
  4          32   ``hip_transform.id``        Group ID
  ?           ?   ...                         ...
  ?           ?                               Padding
======= ========= ========================== ====================

.. raw:: html

   <br />

.. class:: DataType_Param_Transform

   :bases: DataType_Parameter

   Structure of HIP ``HIP_TRANSFORM`` parameter [:rfc:`5201`].

   .. attribute:: id
      :type: Tuple[pcapkit.const.hip.suite.Suite]

      Array of group IDs.

HIP ``HIP_CIPHER`` Parameter
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For HIP ``HIP_CIPHER`` parameter as described in :rfc:`7401`,
its structure is described as below:

======= ========= ======================== ======================
Octets      Bits        Name                    Description
======= ========= ======================== ======================
  0           0     hip_cipher.type         Parameter Type
  1          15     hip_cipher.critical     Critical Bit
  2          16     hip_cipher.length       Length of Contents
  4          32     hip_cipher.id           Cipher ID
  ?           ?     ...                     ...
  ?           ?     -                       Padding
======= ========= ======================== ======================

.. raw:: html

   <br />

.. class:: DataType_Param_Cipher

   :bases: DataType_Parameter

   Structure of HIP ``HIP_CIPHER`` parameter [:rfc:`7401`].

   .. attribute:: id
      :type: Tuple[pcapkit.const.hip.cipher.Cipher]

      Array of cipher IDs.

HIP ``NAT_TRAVERSAL_MODE`` Parameter
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For HIP ``NAT_TRAVERSAL_MODE`` parameter as described in :rfc:`5770`,
its structure is described as below:

======= ========= =============================== ====================
Octets      Bits        Name                        Description
======= ========= =============================== ====================
  0           0   ``nat_traversal_mode.type``      Parameter Type
  1          15   ``nat_traversal_mode.critical``  Critical Bit
  2          16   ``nat_traversal_mode.length``    Length of Contents
  4          32                                    Reserved
  6          48   ``nat_traversal_mode.id``        Mode ID
  ?           ?     ...                            ...
  ?           ?                                    Padding
======= ========= =============================== ====================

.. raw:: html

   <br />

.. class:: DataType_Param_NET_Traversal_Mode

   :bases: DataType_Parameter

   Structure of HIP ``NAT_TRAVERSAL_MODE`` parameter [:rfc:`5770`].

   .. attribute:: id
      :type: Tuple[pcapkit.const.hip.nat_traversal.NETTraversal]

      Array of mode IDs.

HIP ``TRANSACTION_PACING`` Parameter
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For HIP ``TRANSACTION_PACING`` parameter as described in :rfc:`5770`,
its structure is described as below:

======= ========= =============================== ====================
Octets      Bits        Name                        Description
======= ========= =============================== ====================
  0           0   ``transaction_pacing.type``     Parameter Type
  1          15   ``transaction_pacing.critical`` Critical Bit
  2          16   ``transaction_pacing.length``   Length of Contents
  4          32   ``transaction_pacing.min_ta``   Min Ta
======= ========= =============================== ====================

.. raw:: html

   <br />

.. class:: DataType_Param_Transaction_Pacing

   :bases: DataType_Parameter

   Structure of HIP ``TRANSACTION_PACING`` parameter [:rfc:`5770`].

   .. attribute:: min_ta
      :type: int

      Min Ta.

HIP ``ENCRYPTED`` Parameter
~~~~~~~~~~~~~~~~~~~~~~~~~~~

For HIP ``ENCRYPTED`` parameter as described in :rfc:`7401`,
its structure is described as below:

======= ========= ======================= ====================
Octets      Bits        Name                Description
======= ========= ======================= ====================
  0           0   ``encrypted.type``      Parameter Type
  1          15   ``encrypted.critical``  Critical Bit
  2          16   ``encrypted.length``    Length of Contents
  4          32                           Reserved
  8          48   ``encrypted.iv``        Initialization Vector
  ?           ?   ``encrypted.data``      Encrypted data
  ?           ?                           Padding
======= ========= ======================= ====================

.. raw:: html

   <br />

.. class:: DataType_Param_Encrypted

   :bases: DataType_Parameter

   Structure of HIP ``ENCRYPTED`` parameter [:rfc:`7401`].

   .. attribute:: raw
      :type: bytes

      Raw content data.

HIP ``HOST_ID`` Parameter
~~~~~~~~~~~~~~~~~~~~~~~~~

For HIP ``HOST_ID`` parameter as described in :rfc:`7401`,
its structure is described as below:

======= ========= ======================= ====================
Octets      Bits        Name                Description
======= ========= ======================= ====================
  0           0   ``host_id.type``        Parameter Type
  1          15   ``host_id.critical``    Critical Bit
  2          16   ``host_id.length``      Length of Contents
  4          32   ``host_id.id_len``      Host Identity Length
  6          48   ``host_id.di_type``     Domain Identifier Type
  6          52   ``host_id.di_len``      Domain Identifier Length
  8          64   ``host_id.algorithm``   Algorithm
  10         80   ``host_id.host_id``     Host Identity
  ?           ?   ``host_id.domain_id``   Domain Identifier
  ?           ?                           Padding
======= ========= ======================= ====================

.. raw:: html

   <br />

.. class:: DataType_Param_Host_ID

   :bases: DataType_Parameter

   Structure of HIP ``HOST_ID`` parameter [:rfc:`7401`].

   .. attribute:: id_len
      :type: int

      Host identity length.

   .. attribute:: di_type
      :type: pcapkit.const.hip.di_type.DIType

      Domain identifier type.

   .. attribute:: di_len
      :type: int

      Domain identifier length.

   .. attribute:: algorithm
      :type: pcapkit.const.hip.hi_algorithm.HIAlgorithm

      Algorithm.

   .. attribute:: host_id
      :type: Union[bytes, DataType_Host_ID_ECDSA_Curve, DataType_Host_ID_ECDSA_LOW_Curve]

      Host identity.

   .. attribute:: domain_id
      :type: bytes

      Domain identifier.

.. class:: DataType_Host_ID_ECDSA_Curve

   :bases: TypedDict

   Host identity data.

   .. attribute:: curve
      :type: pcapkit.const.hip.ecdsa_curve.ECDSACurve

      ECDSA curve.

   .. attribute:: pubkey
      :type: bytes

      Public key.

.. class:: DataType_Host_ID_ECDSA_LOW_Curve

   :bases: TypedDict

   Host identity data.

   .. attribute:: curve
      :type: pcapkit.const.hip.ecdsa_low_curve.ECDSALowCurve

      ECDSA_Low curve.

   .. attribute:: pubkey
      :type: bytes

      Public key.

.. raw:: html

   <hr />

.. [*] https://en.wikipedia.org/wiki/Host_Identity_Protocol
