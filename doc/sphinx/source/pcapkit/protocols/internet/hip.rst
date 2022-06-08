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

.. automodule:: pcapkit.protocols.internet.hip
   :members:
   :undoc-members:
   :private-members:
   :show-inheritance:

Data Structure
--------------

.. important::

   Following classes are only for *documentation* purpose.
   They do **NOT** exist in the :mod:`pcapkit` module.

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

HIP ``HIT_SUITE_LIST`` Parameter
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For HIP ``HIT_SUITE_LIST`` parameter as described in :rfc:`7401`,
its structure is described as below:

======= ========= ============================== =====================
Octets      Bits        Name                     Description
======= ========= ============================== =====================
  0           0   ``hit_suite_list.type``        Parameter Type
  1          15   ``hit_suite_list.critical``    Critical Bit
  2          16   ``hit_suite_list.length``      Length of Contents
  4          32   ``hit_suite_list.id``          HIT Suite ID
  ?           ?   ...                            ...
  ?           ?                                  Padding
======= ========= ============================== =====================

.. raw:: html

   <br />

.. class:: DataType_Param_HIT_Suite_List

   :bases: DataType_Parameter

   Structure of HIP ``HIT_SUITE_LIST`` parameter [:rfc:`7401`].

   .. attribute:: id
      :type: Tuple[pcapkit.const.hip.hit_suite.HITSuite]

      Array of HIT suite IDs.

HIP ``CERT`` Parameter
~~~~~~~~~~~~~~~~~~~~~~

For HIP ``CERT`` parameter as described in :rfc:`7401`,
its structure is described as below:

======= ======== ===================== ======================
Octets      Bits        Name                Description
======= ======== ===================== ======================
  0           0   ``cert.type``         Parameter Type
  1          15   ``cert.critical``     Critical Bit
  2          16   ``cert.length``       Length of Contents
  4          32   ``cert.group``        ``CERT`` Group
  5          40   ``cert.count``        ``CERT`` Count
  6          48   ``cert.id``           ``CERT`` ID
  7          56   ``cert.cert_type``    ``CERT`` Type
  8          64   ``cert.certificate``  Certificate
  ?           ?                         Padding
======= ======== ===================== ======================

.. raw:: html

   <br />

.. class:: DataType_Param_Cert

   :bases: DataType_Parameter

   Structure of HIP ``CERT`` parameter [:rfc:`7401`].

   .. attribute:: group
      :type: pcapkit.const.hip.group.Group

      ``CERT`` group.

   .. attribute:: count
      :type: int

      ``CERT`` count.

   .. attribute:: id
      :type: int

      ``CERT`` ID.

   .. attribute:: cert_type
      :type: pcapkit.const.hip.certificate.Certificate

   .. attribute:: certificate
      :type: bytes

      Certificate.

HIP ``NOTIFICATION`` Parameter
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For HIP ``NOTIFICATION`` parameter as described in :rfc:`7401`,
its structure is described as below:

======= ======== ========================== =====================
Octets      Bits        Name                    Description
======= ======== ========================== =====================
  0           0   ``notification.type``     Parameter Type
  1          15   ``notification.critical`` Critical Bit
  2          16   ``notification.length``   Length of Contents
  4          32                             Reserved
  6          48   ``notification.msg_type`` Notify Message Type
  8          64   ``notification.data``     Notification Data
  ?           ?                             Padding
======= ======== ========================== =====================

.. raw:: html

   <br />

.. class:: DataType_Param_Notification

   :bases: DataType_Parameter

   Structure of HIP ``NOTIFICATION`` parameter [:rfc:`7401`].

   .. attribute:: msg_type
      :type: pcapkit.const.hip.notify_message.NotifyMessage

      Notify message type.

   .. attribute:: data
      :type: bytes

      Notification data.

HIP ``ECHO_REQUEST_SIGNED`` Parameter
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For HIP ``ECHO_REQUEST_SIGNED`` parameter as described in :rfc:`7401`,
its structure is described as below:

======= ========= ================================ ====================
Octets      Bits        Name                            Description
======= ========= ================================ ====================
  0           0   ``echo_request_signed.type``      Parameter Type
  1          15   ``echo_request_signed.critical``  Critical Bit
  2          16   ``echo_request_signed.length``    Length of Contents
  4          32   ``echo_request_signed.data``      Opaque Data
======= ========= ================================ ====================

.. raw:: html

   <br />

.. class:: DataType_Param_Echo_Request_Signed

   :bases: DataType_Parameter

   Structure of HIP ``ECHO_REQUEST_SIGNED`` parameter [:rfc:`7401`].

   .. attribute:: data
      :type: bytes

      Opaque data.

HIP ``REG_INFO`` Parameter
~~~~~~~~~~~~~~~~~~~~~~~~~~

For HIP ``REG_INFO`` parameter as described in :rfc:`8003`,
its structure is described as below:

====== ========= ========================== ========================
Octets      Bits        Name                            Description
====== ========= ========================== ========================
  0           0   ``reg_info.type``           Parameter Type
  1          15   ``reg_info.critical``       Critical Bit
  2          16   ``reg_info.length``         Length of Contents
  4          32   ``reg_info.lifetime``       Lifetime
  4          32   ``reg_info.lifetime.min``   Min Lifetime
  5          40   ``reg_info.lifetime.max``   Max Lifetime
  6          48   ``reg_info.reg_type``       Reg Type
  ?           ?     ...                       ...
  ?           ?                               Padding
====== ========= ========================== ========================

.. raw:: html

   <br />

.. class:: DataType_Param_Reg_Info

   :bases: DataType_Parameter

   Structure of HIP ``REG_INFO`` parameter [:rfc:`8003`].

   .. attribute:: lifetime
      :type: DataType_Lifetime

      Lifetime.

   .. attribute:: reg_type
      :type: Tuple[pcapkit.const.hip.registration.Registration]

      Array of registration type.

.. class:: DataType_Lifetime

   :bases: NamedTuple

   Lifetime.

   .. attribute:: min
      :type: int

      Minimum lifetime.

   .. attribute:: maz
      :type: int

      Maximum lifetime.

HIP ``REG_REQUEST`` Parameter
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For HIP ``REG_REQUEST`` parameter as described in :rfc:`8003`,
its structure is described as below:

======= ========= ============================ ========================
Octets      Bits        Name                            Description
======= ========= ============================ ========================
  0           0   ``reg_request.type``            Parameter Type
  1          15   ``reg_request.critical``        Critical Bit
  2          16   ``reg_request.length``          Length of Contents
  4          32   ``reg_request.lifetime``        Lifetime
  4          32   ``reg_request.lifetime.min``    Min Lifetime
  5          40   ``reg_request.lifetime.max``    Max Lifetime
  6          48   ``reg_request.reg_type``        Reg Type
  ?           ?     ...                           ...
  ?           ?                                   Padding
======= ========= ============================ ========================

.. raw:: html

   <br />

.. class:: DataType_Param_Reg_Request

   :bases: DataType_Parameter

   Structure of HIP ``REG_REQUEST`` parameter [:rfc:`8003`].

   .. attribute:: lifetime
      :type: DataType_Lifetime

      Lifetime.

   .. attribute:: reg_type
      :type: Tuple[pcapkit.const.hip.registration.Registration]

      Array of registration type.

HIP ``REG_RESPONSE`` Parameter
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For HIP ``REG_RESPONSE`` parameter as described in :rfc:`8003`,
its structure is described as below:

======= ========= ============================= =======================
Octets      Bits        Name                            Description
======= ========= ============================= =======================
  0           0   ``reg_response.type``           Parameter Type
  1          15   ``reg_response.critical``       Critical Bit
  2          16   ``reg_response.length``         Length of Contents
  4          32   ``reg_response.lifetime``       Lifetime
  4          32   ``reg_response.lifetime.min``   Min Lifetime
  5          40   ``reg_response.lifetime.max``   Max Lifetime
  6          48   ``reg_response.reg_type``       Reg Type
  ?           ?     ...                           ...
  ?           ?                                   Padding
======= ========= ============================= =======================

.. raw:: html

   <br />

.. class:: DataType_Param_Reg_Response

   :bases: DataType_Parameter

   Structure of HIP ``REG_RESPONSE`` parameter [:rfc:`8003`].

   .. attribute:: lifetime
      :type: DataType_Lifetime

      Lifetime.

   .. attribute:: reg_type
      :type: Tuple[pcapkit.const.hip.registration.Registration]

      Array of registration type.

HIP ``REG_FAILED`` Parameter
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For HIP ``REG_FAILED`` parameter as described in :rfc:`8003`,
its structure is described as below:

======= ========= ============================= =======================
Octets      Bits        Name                            Description
======= ========= ============================= =======================
  0           0   ``reg_failed.type``             Parameter Type
  1          15   ``reg_failed.critical``         Critical Bit
  2          16   ``reg_failed.length``           Length of Contents
  4          32   ``reg_failed.lifetime``         Lifetime
  4          32   ``reg_failed.lifetime.min``     Min Lifetime
  5          40   ``reg_failed.lifetime.max``     Max Lifetime
  6          48   ``reg_failed.reg_type``         Reg Type
  ?           ?     ...                           ...
  ?           ?                                   Padding
======= ========= ============================= =======================

.. raw:: html

   <br />

.. class:: DataType_Param_Reg_Failed

   :bases: DataType_Parameter

   Structure of HIP ``REG_FAILED`` parameter [:rfc:`8003`].

   .. attribute:: lifetime
      :type: DataType_Lifetime

      Lifetime.

   .. attribute:: reg_type
      :type: Tuple[pcapkit.const.hip.registration.Registration]

      Array of registration type.

HIP ``REG_FROM`` Parameter
~~~~~~~~~~~~~~~~~~~~~~~~~~

For HIP ``REG_FROM`` parameter as described in :rfc:`5770`,
its structure is described as below:

======= ======== ======================== =============================
Octets      Bits        Name                            Description
======= ======== ======================== =============================
  0           0   ``reg_from.type``             Parameter Type
  1          15   ``reg_from.critical``         Critical Bit
  2          16   ``reg_from.length``           Length of Contents
  4          32   ``reg_from.port``             Port
  6          48   ``reg_from.protocol``         Protocol
  7          56                                 Reserved
  8          64   ``reg_from.ip``               Address (IPv6)
======= ======== ======================== =============================

.. raw:: html

   <br />

.. class:: DataType_Param_Reg_From

   :bases: DataType_Parameter

   Structure of HIP ``REG_FROM`` parameter [:rfc:`5770`].

   .. attribute:: port
      :type: int

      Port.

   .. attribute:: protocol
      :type: pcapkit.const.reg.transtype.TransType

      Protocol.

   .. attribute:: ip
      :type: ipaddress.IPv6Address

      IPv6 address.

HIP ``ECHO_RESPONSE_SIGNED`` Parameter
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For HIP ``ECHO_RESPONSE_SIGNED`` parameter as described in :rfc:`7401`,
its structure is described as below:

======= ========= ================================= ===================
Octets      Bits        Name                            Description
======= ========= ================================= ===================
  0           0   ``echo_response_signed.type``     Parameter Type
  1          15   ``echo_response_signed.critical`` Critical Bit
  2          16   ``echo_response_signed.length``   Length of Contents
  4          32   ``echo_response_signed.data``     Opaque Data
======= ========= ================================= ===================

.. raw:: html

   <br />

.. class:: DataType_Param_Echo_Response_Signed

   :bases: DataType_Parameter

   Structure of HIP ``ECHO_RESPONSE_SIGNED`` parameter [:rfc:`7401`].

   .. attribute:: data
      :type: bytes

      Opaque data.

HIP ``TRANSPORT_FORMAT_LIST`` Parameter
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For HIP ``TRANSPORT_FORMAT_LIST`` parameter as described in :rfc:`7401`,
its structure is described as below:

======= ========= =================================== =====================
Octets      Bits        Name                            Description
======= ========= =================================== =====================
  0           0   ``transport_format_list.type``      Parameter Type
  1          15   ``transport_format_list.critical``  Critical Bit
  2          16   ``transport_format_list.length``    Length of Contents
  4          32   ``transport_format_list.tf_type``   TF Type
  ?           ?     ...                               ...
  ?           ?                                       Padding
======= ========= =================================== =====================

.. raw:: html

   <br />

.. class:: DataType_Param_Transform_Format_List

   :bases: DataType_Parameter

   Structure of HIP ``TRANSPORT_FORMAT_LIST`` parameter [:rfc:`7401`].

   .. attribute:: tf_type
      :type: Tuple[int]

      Array of TF types.

HIP ``ESP_TRANSFORM`` Parameter
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For HIP ``ESP_TRANSFORM`` parameter as described in :rfc:`7402`,
its structure is described as below:

======= ========= =================================== =====================
Octets      Bits        Name                            Description
======= ========= =================================== =====================
  0           0   ``esp_transform.type``              Parameter Type
  1          15   ``esp_transform.critical``          Critical Bit
  2          16   ``esp_transform.length``            Length of Contents
  4          32                                       Reserved
  6          48   ``esp_transform.id``                Suite ID
  ?           ?   ...                                 ...
  ?           ?                                       Padding
======= ========= =================================== =====================

.. raw:: html

   <br />

.. class:: DataType_Param_ESP_Transform

   :bases: DataType_Parameter

   Structure of HIP ``ESP_TRANSFORM`` parameter [:rfc:`7402`].

   .. attribute:: id
      :type: Tuple[pcapkit.const.hip.esp_transform_suite.ESPTransformSuite]

      Array of suite IDs.

HIP ``SEQ_DATA`` Parameter
~~~~~~~~~~~~~~~~~~~~~~~~~~

For HIP ``SEQ_DATA`` parameter as described in :rfc:`6078`,
its structure is described as below:

======= ========= =================================== =====================
Octets      Bits        Name                            Description
======= ========= =================================== =====================
  0           0   ``seq_data.type``                   Parameter Type
  1          15   ``seq_data.critical``               Critical Bit
  2          16   ``seq_data.length``                 Length of Contents
  4          32   ``seq_data.seq``                    Sequence number
======= ========= =================================== =====================

.. raw:: html

   <br />

.. class:: DataType_Param_SEQ_Data

   :bases: DataType_Parameter

   Structure of HIP ``SEQ_DATA`` parameter [:rfc:`6078`].

   .. attribute:: seq
      :type: int

      Sequence number.

HIP ``ACK_DATA`` Parameter
~~~~~~~~~~~~~~~~~~~~~~~~~~

For HIP ``ACK_DATA`` parameter as described in :rfc:`6078`,
its structure is described as below:

======= ========= ======================= ================================
Octets      Bits        Name                            Description
======= ========= ======================= ================================
  0           0   ``ack_data.type``                 Parameter Type
  1          15   ``ack_data.critical``             Critical Bit
  2          16   ``ack_data.length``               Length of Contents
  4          32   ``ack_data.ack``                  Acked Sequence number
======= ========= ======================= ================================

.. raw:: html

   <br />

.. class:: DataType_Param_ACK_Data

   :bases: DataType_Parameter

   Structure of HIP ``ACK_DATA`` parameter [:rfc:`6078`].

   .. attribute:: ack
      :type: Tuple[int]

      Array of ACKed sequence number.

HIP ``PAYLOAD_MIC`` Parameter
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For HIP ``PAYLOAD_MIC`` parameter as described in :rfc:`6078`,
its structure is described as below:

======= ========= ======================== ================================
Octets      Bits        Name                            Description
======= ========= ======================== ================================
  0           0   ``payload_mic.type``                Parameter Type
  1          15   ``payload_mic.critical``            Critical Bit
  2          16   ``payload_mic.length``              Length of Contents
  4          32   ``payload_mic.next``                Next Header
  5          40                                       Reserved
  8          64   ``payload_mic.data``                Payload Data
  12         96   ``payload_mic.value``               MIC Value
  ?           ?                                       Padding
======= ========= ======================== ================================

.. raw:: html

   <br />

.. class:: DataType_Param_Payload_MIC

   :bases: DataType_Parameter

   Structure of HIP ``PAYLOAD_MIC`` parameter [:rfc:`6078`].

   .. attribute:: next
      :type: pcapkit.const.reg.transtype.TransType

      Next header.

   .. attribute:: data
      :type: bytes

      Payload data.

   .. attribute:: value
      :type: bytes

      MIC value.

HIP ``TRANSACTION_ID`` Parameter
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For HIP ``TRANSACTION_ID`` parameter as described in :rfc:`6078`,
its structure is described as below:

======= ========= =========================== ================================
Octets      Bits        Name                            Description
======= ========= =========================== ================================
  0           0   ``transaction_id.type``             Parameter Type
  1          15   ``transaction_id.critical``         Critical Bit
  2          16   ``transaction_id.length``           Length of Contents
  4          32   ``transaction_id.id``               Identifier
======= ========= =========================== ================================

.. raw:: html

   <br />

.. class:: DataType_Param_Transaction_ID

   :bases: DataType_Parameter

   Structure of HIP ``TRANSACTION_ID`` parameter [:rfc:`6078`].

   .. attribute:: id
      :type: int

      Identifier.

HIP ``OVERLAY_ID`` Parameter
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For HIP ``OVERLAY_ID`` parameter as described in :rfc:`6079`,
its structure is described as below:

======= ========= =========================== ================================
Octets      Bits        Name                            Description
======= ========= =========================== ================================
  0           0   ``overlay_id.type``                 Parameter Type
  1          15   ``overlay_id.critical``             Critical Bit
  2          16   ``overlay_id.length``               Length of Contents
  4          32   ``overlay_id.id``                   Identifier
======= ========= =========================== ================================

.. raw:: html

   <br />

.. class:: DataType_Param_Overlay_ID

   :bases: DataType_Parameter

   Structure of HIP ``OVERLAT_ID`` parameter [:rfc:`6079`].

   .. attribute:: id
      :type: int

      Identifier.

HIP ``ROUTE_DST`` Parameter
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For HIP ``ROUTE_DST`` parameter as described in :rfc:`6079`,
its structure is described as below:

======= ========= ================================ ================================
Octets      Bits        Name                            Description
======= ========= ================================ ================================
  0           0   ``route_dst.type``                  Parameter Type
  1          15   ``route_dst.critical``              Critical Bit
  2          16   ``route_dst.length``                Length of Contents
  4          32   ``route_dst.flags``                 Flags
  4          32   ``route_dst.flags.symmetric``       SYMMETRIC [:rfc:`6028`]
  4          33   ``route_dst.flags.must_follow``     MUST_FOLLOW [:rfc:`6028`]
  6          48                                       Reserved
  8          64   ``route_dst.ip``                    HIT
  ?           ?   ...                                 ...
======= ========= ================================ ================================

.. raw:: html

   <br />

.. class:: DataType_Param_Route_Dst

   :bases: DataType_Parameter

   Structure of HIP ``ROUTE_DST`` parameter [:rfc:`6028`].

   .. attribute:: flags
      :type: DataType_Flags

      Flags.

   .. attribute:: ip
      :type: Tuple[ipaddress.IPv6Address]

      Array of HIT addresses.

.. class:: DataType_Flags

   :bases: TypedDict

   Flags.

   .. attribute:: symmetric
      :type: bool

      ``SYMMETRIC`` flag [:rfc:`6028`].

   .. attribute:: must_follow
      :type: bool

      ``MUST_FOLLOW`` flag [:rfc:`6028`].

HIP ``HIP_TRANSPORT_MODE`` Parameter
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For HIP ``HIP_TRANSPORT_MODE`` parameter as described in :rfc:`6261`,
its structure is described as below:

======= ========= ================================ =====================
Octets      Bits        Name                            Description
======= ========= ================================ =====================
  0           0   ``hip_transport_mode.type``       Parameter Type
  1          15   ``hip_transport_mode.critical``   Critical Bit
  2          16   ``hip_transport_mode.length``     Length of Contents
  4          32   ``hip_transport_mode.port``       Port
  6          48   ``hip_transport_mode.id``         Mode ID
  ?           ?   ...                               ...
  ?           ?                                     Padding
======= ========= ================================ =====================

.. raw:: html

   <br />

.. class:: DataType_Param_Transport_Mode

   :bases: DataType_Parameter

   Structure of HIP ``HIP_TRANSPORT_MODE`` parameter [:rfc:`6261`].

   .. attribute:: port
      :type: int

      Port.

   .. attribute:: id
      :type: Tuple[pcapkit.const.hip.transport.Transport]

      Array of transport mode IDs.

HIP ``HIP_MAC`` Parameter
~~~~~~~~~~~~~~~~~~~~~~~~~

For HIP ``HIP_MAC`` parameter as described in :rfc:`7401`,
its structure is described as below:

======= ========= ================================ =====================
Octets      Bits        Name                            Description
======= ========= ================================ =====================
  0           0   ``hip_mac.type``                  Parameter Type
  1          15   ``hip_mac.critical``              Critical Bit
  2          16   ``hip_mac.length``                Length of Contents
  4          32   ``hip_mac.hmac``                  HMAC
  ?           ?                                     Padding
======= ========= ================================ =====================

.. raw:: html

   <br />

.. class:: DataType_Param_HMAC

   :bases: DataType_Parameter

   Structure of HIP ``HIP_MAC`` parameter [:rfc:`7401`].

   .. attribute:: hmac
      :type: bytes

      HMAC.

HIP ``HIP_MAC_2`` Parameter
~~~~~~~~~~~~~~~~~~~~~~~~~~~

For HIP ``HIP_MAC_2`` parameter as described in :rfc:`7401`,
its structure is described as below:

======= ========= ================================ =====================
Octets      Bits        Name                            Description
======= ========= ================================ =====================
  0           0   ``hip_mac_2.type``                Parameter Type
  1          15   ``hip_mac_2.critical``            Critical Bit
  2          16   ``hip_mac_2.length``              Length of Contents
  4          32   ``hip_mac_2.hmac``                HMAC
  ?           ?                                     Padding
======= ========= ================================ =====================

.. raw:: html

   <br />

.. class:: DataType_Param_HMAC_2

   :bases: DataType_Parameter

   Structure of HIP ``HIP_MAC_2`` parameter [:rfc:`7401`].

   .. attribute:: hmac
      :type: bytes

      HMAC.

HIP ``HIP_SIGNATURE_2`` Parameter
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For HIP ``HIP_SIGNATURE_2`` parameter as described in :rfc:`7401`,
its structure is described as below:

======= ========= ================================ =====================
Octets      Bits        Name                            Description
======= ========= ================================ =====================
  0           0   ``hip_signature_2.type``          Parameter Type
  1          15   ``hip_signature_2.critical``      Critical Bit
  2          16   ``hip_signature_2.length``        Length of Contents
  4          32   ``hip_signature_2.algorithm``     SIG Algorithm
  6          48   ``hip_signature_2.signature``     Signature
  ?           ?                                     Padding
======= ========= ================================ =====================

.. raw:: html

   <br />

.. class:: DataType_Param_Signature_2

   :bases: DataType_Parameter

   Structure of HIP ``HIP_SIGNATURE_2`` parameter [:rfc:`7401`].

   .. attribute:: algorithm
      :type: pcapkit.const.hip.hi_algorithm.HIAlgorithm

      SIG algorithm.

   .. attribute:: signature
      :type: bytes

      Signature.

HIP ``HIP_SIGNATURE`` Parameter
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For HIP ``HIP_SIGNATURE`` parameter as described in :rfc:`7401`,
its structure is described as below:

======= ========= ============================== =====================
Octets      Bits        Name                          Description
======= ========= ============================== =====================
  0           0   ``hip_signature.type``          Parameter Type
  1          15   ``hip_signature.critical``      Critical Bit
  2          16   ``hip_signature.length``        Length of Contents
  4          32   ``hip_signature.algorithm``     SIG Algorithm
  6          48   ``hip_signature.signature``     Signature
  ?           ?                                   Padding
======= ========= ============================== =====================

.. raw:: html

   <br />

.. class:: DataType_Param_Signature

   :bases: DataType_Parameter

   Structure of HIP ``HIP_SIGNATURE`` parameter [:rfc:`7401`].

   .. attribute:: algorithm
      :type: pcapkit.const.hip.hi_algorithm.HIAlgorithm

      SIG algorithm.

   .. attribute:: signature
      :type: bytes

      Signature.

HIP ``ECHO_REQUEST_UNSIGNED`` Parameter
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For HIP ``ECHO_REQUEST_UNSIGNED`` parameter as described in :rfc:`7401`,
its structure is described as below:

======= ========= ================================== =====================
Octets      Bits        Name                            Description
======= ========= ================================== =====================
  0           0   ``echo_request_unsigned.type``      Parameter Type
  1          15   ``echo_request_unsigned.critical``  Critical Bit
  2          16   ``echo_request_unsigned.length``    Length of Contents
  4          32   ``echo_request_unsigned.data``      Opaque Data
======= ========= ================================== =====================

.. raw:: html

   <br />

.. class:: DataType_Param_Echo_Request_Unsigned

   :bases: DataType_Parameter

   Structure of HIP ``ECHO_REQUEST_UNSIGNED`` parameter [:rfc:`7401`].

   .. attribute:: data
      :type: bytes

      Opaque data.

HIP ``ECHO_RESPONSE_UNSIGNED`` Parameter
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For HIP ``ECHO_RESPONSE_UNSIGNED`` parameter as described in :rfc:`7401`,
its structure is described as below:

======= ========= =================================== =====================
Octets      Bits        Name                            Description
======= ========= =================================== =====================
  0           0   ``echo_response_unsigned.type``     Parameter Type
  1          15   ``echo_response_unsigned.critical`` Critical Bit
  2          16   ``echo_response_unsigned.length``   Length of Contents
  4          32   ``echo_response_unsigned.data``     Opaque Data
======= ========= =================================== =====================

.. raw:: html

   <br />

.. class:: DataType_Param_Echo_Response_Unsigned

   :bases: DataType_Parameter

   Structure of HIP ``ECHO_RESPONSE_UNSIGNED`` parameter [:rfc:`7401`].

   .. attribute:: data
      :type: bytes

      Opaque data.

HIP ``RELAY_FROM`` Parameter
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For HIP ``RELAY_FROM`` parameter as described in :rfc:`5770`,
its structure is described as below:

======= ========= ======================== =============================
Octets      Bits        Name                            Description
======= ========= ======================== =============================
  0           0   ``relay_from.type``             Parameter Type
  1          15   ``relay_from.critical``         Critical Bit
  2          16   ``relay_from.length``           Length of Contents
  4          32   ``relay_from.port``             Port
  6          48   ``relay_from.protocol``         Protocol
  7          56                                   Reserved
  8          64   ``relay_from.ip``               Address (IPv6)
======= ========= ======================== =============================

.. raw:: html

   <br />

.. class:: DataType_Param_Relay_From

   :bases: DataType_Parameter

   Structure of HIP ``RELAY_FROM`` parameter [:rfc:`5770`].

   .. attribute:: port
      :type: int

      Port.

   .. attribute:: protocol
      :type: pcapkit.const.reg.transtype.TransType

      Protocol.

   .. attribute:: ip
      :type: ipaddress.IPv6Address

      IPv6 address.

HIP ``RELAY_TO`` Parameter
~~~~~~~~~~~~~~~~~~~~~~~~~~

For HIP ``RELAY_TO`` parameter as described in :rfc:`5770`,
its structure is described as below:

======= ========= ======================== =============================
Octets      Bits        Name                            Description
======= ========= ======================== =============================
  0           0   ``relay_to.type``             Parameter Type
  1          15   ``relay_to.critical``         Critical Bit
  2          16   ``relay_to.length``           Length of Contents
  4          32   ``relay_to.port``             Port
  6          48   ``relay_to.protocol``         Protocol
  7          56                                 Reserved
  8          64   ``relay_to.ip``               Address (IPv6)
======= ========= ======================== =============================

.. raw:: html

   <br />

.. class:: DataType_Param_Relay_To

   :bases: DataType_Parameter

   Structure of HIP ``RELAY_TO`` parameter [:rfc:`5770`].

   .. attribute:: port
      :type: in

      Port.

   .. attribute:: protocol
      :type: pcapkit.const.reg.transtype.TransType

      Protocol.

   .. attribute:: ip
      :type: ipaddress.IPv6Address

      IPv6 address.

HIP ``OVERLAY_TTL`` Parameter
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For HIP ``OVERLAY_TTL`` parameter as described in :rfc:`6078`,
its structure is described as below:

======= ========= ======================== =============================
Octets      Bits        Name                            Description
======= ========= ======================== =============================
  0           0   ``overlay_ttl.type``              Parameter Type
  1          15   ``overlay_ttl.critical``          Critical Bit
  2          16   ``overlay_ttl.length``            Length of Contents
  4          32   ``overlay_ttl.ttl``               TTL
  6          48                                     Reserved
======= ========= ======================== =============================

.. raw:: html

   <br />

.. class:: DataType_Param_Overlay_TTL

   :bases: DataType_Parameter

   .. attribute:: ttl
      :type: int

      TTL.

HIP ``ROUTE_VIA`` Parameter
~~~~~~~~~~~~~~~~~~~~~~~~~~~

For HIP ``ROUTE_VIA`` parameter as described in :rfc:`6028`,
its structure is described as below:

======= ========= ================================ ===============================
Octets      Bits        Name                            Description
======= ========= ================================ ===============================
  0           0   ``route_via.type``                Parameter Type
  1          15   ``route_via.critical``            Critical Bit
  2          16   ``route_via.length``              Length of Contents
  4          32   ``route_via.flags``               Flags
  4          32   ``route_via.flags.symmetric``     ``SYMMETRIC`` [:rfc:`6028`]
  4          33   ``route_via.flags.must_follow``   ``MUST_FOLLOW`` [:rfc:`6028`]
  6          48     -                               Reserved
  8          64   ``route_dst.ip``                  HIT
  ?           ?   ...                               ...
======= ========= ================================ ===============================

.. raw:: html

   <br />

.. class:: DataType_Param_Route_Via

   :bases: DataType_Parameter

   Structure of HIP ``ROUTE_VIA`` parameter [:rfc:`6028`].

   .. attribute:: flags
      :type: DataType_Flags

      Flags.

   .. attribute:: ip
      :type: Tuple[ipaddress.IPv6Address]

      Array of HITs.

HIP ``FROM`` Parameter
~~~~~~~~~~~~~~~~~~~~~~

For HIP ``FROM`` parameter as described in :rfc:`8004`,
its structure is described as below:

======= ========= ================================ ===============================
Octets      Bits        Name                            Description
======= ========= ================================ ===============================
  0           0   ``from.type``                     Parameter Type
  1          15   ``from.critical``                 Critical Bit
  2          16   ``from.length``                   Length of Contents
  4          32   ``from.ip``                       Address
======= ========= ================================ ===============================

.. raw:: html

   <br />

.. class:: DataType_Param_From

   :bases: DataType_Parameter

   Structure of HIP ``FROM`` parameter [:rfc:`8004`].

   .. attribute:: ip
      :type: ipaddress.IPv6Address

      IPv6 address.

HIP ``RVS_HMAC`` Parameter
~~~~~~~~~~~~~~~~~~~~~~~~~~

For HIP ``RVS_HMAC`` parameter as described in :rfc:`8004`,
its structure is described as below:

======= ========= ================================ ===============================
Octets      Bits        Name                            Description
======= ========= ================================ ===============================
  0           0   ``rvs_hmac.type``                   Parameter Type
  1          15   ``rvs_hmac.critical``               Critical Bit
  2          16   ``rvs_hmac.length``                 Length of Contents
  4          32   ``rvs_hmac.hmac``                   HMAC
  ?           ?                                       Padding
======= ========= ================================ ===============================

.. raw:: html

   <br />

.. class:: DataType_Param_RVS_HMAC

   :bases: DataType_Parameter

   Structure of HIP ``RVS_HMAC`` parameter [:rfc:`8004`].

   .. attribute:: hmac
      :type: bytes

      HMAC.

HIP ``VIA_RVS`` Parameter
~~~~~~~~~~~~~~~~~~~~~~~~~

For HIP ``VIA_RVS`` parameter as described in :rfc:`6028`,
its structure is described as below:

======= ========= ================================ ===============================
Octets      Bits        Name                            Description
======= ========= ================================ ===============================
  0           0   ``via_rvs.type``                    Parameter Type
  1          15   ``via_rvs.critical``                Critical Bit
  2          16   ``via_rvs.length``                  Length of Contents
  4          32   ``via_rvs.ip``                      Address
  ?           ?   ...                                 ...
======= ========= ================================ ===============================

.. raw:: html

   <br />

.. class:: DataType_Param_Via_RVS

   :bases: DataType_Parameter

   Structure of HIP ``VIA_RVS`` parameter [:rfc:`6028`].

   .. attribute:: ip
      :type: Tuple[ipaddress.IPv6]

      Array of IPv6 addresses.

HIP ``RELAY_HMAC`` Parameter
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For HIP ``RELAY_HMAC`` parameter as described in :rfc:`5770`,
its structure is described as below:

======= ========= ================================ ===============================
Octets      Bits        Name                            Description
======= ========= ================================ ===============================
  0           0   ``relay_hmac.type``                 Parameter Type
  1          15   ``relay_hmac.critical``             Critical Bit
  2          16   ``relay_hmac.length``               Length of Contents
  4          32   ``relay_hmac.hmac``                 HMAC
  ?           ?                                       Padding
======= ========= ================================ ===============================

.. raw:: html

   <br />

.. class:: DataType_Param_Relay_HMAC

   :bases: DataType_Parameter

   .. attribute:: hmac
      :type: bytes

      HMAC.

.. raw:: html

   <hr />

.. [*] https://en.wikipedia.org/wiki/Host_Identity_Protocol
