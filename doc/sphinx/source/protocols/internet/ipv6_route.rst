IPv6-Route - Routing Header for IPv6
====================================

.. module:: pcapkit.protocols.internet.ipv6_route

:mod:`pcapkit.protocols.internet.ipv6_route` contains
:class:`~pcapkit.protocols.internet.ipv6_route.IPv6_Route`
only, which implements extractor for Routing Header for IPv6
(IPv6-Route) [*]_, whose structure is described as below:

======= ========= ==================== ===============================
Octets      Bits        Name                    Description
======= ========= ==================== ===============================
  0           0   ``route.next``            Next Header
  1           8   ``route.length``          Header Extensive Length
  2          16   ``route.type``            Routing Type
  3          24   ``route.seg_left``        Segments Left
  4          32   ``route.data``            Type-Specific Data
======= ========= ==================== ===============================

.. raw:: html

   <br />

.. autoclass:: pcapkit.protocols.internet.ipv6_route.IPv6_Route
   :members:
   :undoc-members:
   :private-members:
   :show-inheritance:

.. data:: pcapkit.protocols.internet.ipv6_route._ROUTE_PROC
   :type: Dict[int, str]

   IPv6 routing processors.

   ==== ============================================================================= ============================
   Code Processor                                                                     Note
   ==== ============================================================================= ============================
   0    :meth:`~pcapkit.protocols.internet.ipv6_route.IPv6_Route._read_data_type_src` [:rfc:`5095`] **DEPRECATED**
   2    :meth:`~pcapkit.protocols.internet.ipv6_route.IPv6_Route._read_data_type_2`   [:rfc:`6275`]
   3    :meth:`~pcapkit.protocols.internet.ipv6_route.IPv6_Route._read_data_type_rpl` [:rfc:`6554`]
   ==== ============================================================================= ============================

Data Structure
--------------

.. important::

   Following classes are only for *documentation* purpose.
   They do **NOT** exist in the :mod:`pcapkit` module.

.. class:: DataType_IPv6_Route

   Structure of IPv6-Route header [:rfc:`8200`][:rfc:`5095`].

   .. attribute:: next
      :type: pcapkit.const.reg.transtype.TransType

      Next header.

   .. attribute:: length
      :type: int

      Header extensive length.

   .. attribute:: type
      :type: pcapkit.const.ipv6.routing.Routing

      Routing type.

   .. attribute:: seg_left
      :type: int

      Segments left.

   .. attribute:: packet
      :type: bytes

      Raw packet data.

IPv6-Route Unknown Type
~~~~~~~~~~~~~~~~~~~~~~~

For IPv6-Route unknown type data as described in :rfc:`8200` and :rfc:`5095`,
its structure is described as below:

======= ========= ============================= ========================
Octets      Bits        Name                    Description
======= ========= ============================= ========================
  0           0   ``route.next``                Next Header
  1           8   ``route.length``              Header Extensive Length
  2          16   ``route.type``                Routing Type
  3          24   ``route.seg_left``            Segments Left
  4          32   ``route.data``                Type-Specific Data
======= ========= ============================= ========================

.. raw:: html

   <br />

.. class:: DataType_IPv6_Route_None

   :bases: TypedDict

   Structure of IPv6-Route unknown type data [:rfc:`8200`][:rfc:`5095`].

   .. attribute:: data
      :type: bytes

      Type-specific data.

IPv6-Route Source Route
~~~~~~~~~~~~~~~~~~~~~~~

For IPv6-Route Source Route data as described in :rfc:`5095`,
its structure is described as below:

======= ========= ============================= ========================
Octets      Bits        Name                    Description
======= ========= ============================= ========================
  0           0   ``route.next``                Next Header
  1           8   ``route.length``              Header Extensive Length
  2          16   ``route.type``                Routing Type
  3          24   ``route.seg_left``            Segments Left
  4          32                                 Reserved
  8          64   ``route.ip``                  Address
======= ========= ============================= ========================

.. raw:: html

   <br />

.. class:: DataType_IPv6_Route_Source

   :bases: TypedDict

   Structure of IPv6-Route Source Route data [:rfc:`5095`].

   .. attribute:: ip
      :type: Tuple[ipaddress.IPv6Address]

      Array of IPv6 addresses.

IPv6-Route Type 2
~~~~~~~~~~~~~~~~~

For IPv6-Route Type 2 data as described in :rfc:`6275`,
its structure is described as below:

======= ========= ============================= ========================
Octets      Bits        Name                    Description
======= ========= ============================= ========================
  0           0   ``route.next``                Next Header
  1           8   ``route.length``              Header Extensive Length
  2          16   ``route.type``                Routing Type
  3          24   ``route.seg_left``            Segments Left
  4          32                                 Reserved
  8          64   ``route.ip``                  Home Address
======= ========= ============================= ========================

.. raw:: html

   <br />

.. class:: DataType_IPv6_Route_2

   :bases: TypedDict

   Structure of IPv6-Route Type 2 data [:rfc:`6275`].

   .. attribute:: ip
      :type: ipaddress.IPv6Address

      Home IPv6 addresses.

IPv6-Route RPL Source
~~~~~~~~~~~~~~~~~~~~~

For IPv6-Route RPL Source data as described in :rfc:`6554`,
its structure is described as below:

======= ========= ============================= ========================
Octets      Bits        Name                    Description
======= ========= ============================= ========================
  0           0   ``route.next``                Next Header
  1           8   ``route.length``              Header Extensive Length
  2          16   ``route.type``                Routing Type
  3          24   ``route.seg_left``            Segments Left
  4          32   ``route.cmpr_i``              CmprI
  4          36   ``route.cmpr_e``              CmprE
  5          40   ``route.pad``                 Pad Size
  5          44                                 Reserved
  8          64   ``route.ip``                  Addresses
======= ========= ============================= ========================

.. raw:: html

   <br />

.. class:: DataType_IPv6_Route_RPL

   :bases: TypedDict

   Structure of IPv6-Route RPL Source data [:rfc:`6554`].

   .. attribute:: cmpr_i
      :type: int

      CmprI.

   .. attribute:: cmpr_e
      :type: int

      CmprE.

   .. attribute:: pad
      :type: int

      Pad size.

   .. attribute:: ip
      :type: Tuple[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]

      Array of IPv4 and/or IPv6 addresses.

.. raw:: html

   <hr />

.. [*] https://en.wikipedia.org/wiki/IPv6_packet#Routing
