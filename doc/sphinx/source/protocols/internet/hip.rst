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
  4          32     ``locator.traffic``        Traffic Type
  5          40     ``locator.type``           Locator Type
  6          48     ``locator.length``         Locator Length
  7          56                                Reserved
  7          63     ``locator.preferred``      Preferred Locator
  8          64     ``locator.lifetime``       Locator Lifetime
  12         96     ``locator.object``         Locator
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

.. raw:: html

   <hr />

.. [*] https://en.wikipedia.org/wiki/Host_Identity_Protocol
