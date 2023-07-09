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

.. autoclass:: pcapkit.protocols.internet.ipv6_route.IPv6_Route
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoproperty:: name
   .. autoproperty:: alias
   .. autoproperty:: length
   .. autoproperty:: payload
   .. autoproperty:: protocol
   .. autoproperty:: protochain

   .. automethod:: register_routing

   .. automethod:: read
   .. automethod:: make

   .. automethod:: _make_data

   .. automethod:: _read_data_type_none
   .. automethod:: _read_data_type_src
   .. automethod:: _read_data_type_2
   .. automethod:: _read_data_type_rpl

   .. automethod:: _make_data_type_none
   .. automethod:: _make_data_type_src
   .. automethod:: _make_data_type_2
   .. automethod:: _make_data_type_rpl

   .. automethod:: __post_init__
   .. automethod:: __index__

Header Schemas
--------------

.. module:: pcapkit.protocols.schema.internet.ipv6_route

.. autoclass:: pcapkit.protocols.schema.internet.ipv6_route.IPv6_Route
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.internet.ipv6_route.RoutingType
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.internet.ipv6_route.UnknownType
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.internet.ipv6_route.SourceRoute
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.internet.ipv6_route.Type2
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.schema.internet.ipv6_route.RPL
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

Type Stubs
~~~~~~~~~~

.. autoclass:: pcapkit.protocols.schema.internet.ipv6_route.PadInfo
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

Auxiliary Functions
~~~~~~~~~~~~~~~~~~~

.. autofunction:: pcapkit.protocols.schema.internet.ipv6_route.ipv6_route_data_selector

Data Models
-----------

.. module:: pcapkit.protocols.data.internet.ipv6_route

.. autoclass:: pcapkit.protocols.data.internet.ipv6_route.IPv6_Route
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.internet.ipv6_route.UnknownType
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.internet.ipv6_route.SourceRoute
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.internet.ipv6_route.Type2
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.internet.ipv6_route.RPL
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. raw:: html

   <hr />

.. [*] https://en.wikipedia.org/wiki/IPv6_packet#Routing
