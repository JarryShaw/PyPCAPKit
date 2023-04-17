IPv6-Route - Routing Header for IPv6
====================================

.. module:: pcapkit.protocols.internet.ipv6_route
.. module:: pcapkit.protocols.data.internet.ipv6_route

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
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. automethod:: __post_init__
   .. automethod:: __index__

   .. autoproperty:: name
   .. autoproperty:: alias
   .. autoproperty:: length
   .. autoproperty:: payload
   .. autoproperty:: protocol
   .. autoproperty:: protochain

   .. automethod:: read
   .. automethod:: make
   .. automethod:: register_routing

   .. automethod:: _read_data_type_none
   .. automethod:: _read_data_type_src
   .. automethod:: _read_data_type_2
   .. automethod:: _read_data_type_rpl

Data Structures
---------------

.. autoclass:: pcapkit.protocols.data.internet.ipv6_route.IPv6_Route(next, length, type, seg_left)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: next
   .. autoattribute:: length
   .. autoattribute:: type
   .. autoattribute:: seg_left

.. autoclass:: pcapkit.protocols.data.internet.ipv6_route.RoutingType()
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.internet.ipv6_route.UnknownType(data)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: data

.. autoclass:: pcapkit.protocols.data.internet.ipv6_route.SourceRoute(ip)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: ip

.. autoclass:: pcapkit.protocols.data.internet.ipv6_route.Type2(ip)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: ip

.. autoclass:: pcapkit.protocols.data.internet.ipv6_route.RPL(cmpr_i, cmpr_e, pad, ip)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: cmpr_i
   .. autoattribute:: cmpr_e
   .. autoattribute:: pad
   .. autoattribute:: ip

.. raw:: html

   <hr />

.. [*] https://en.wikipedia.org/wiki/IPv6_packet#Routing
