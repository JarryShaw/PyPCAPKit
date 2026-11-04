IPv6-Route - Routing Header for IPv6
====================================

.. module:: pcapkit.protocols.internet.ipv6_route
.. module:: pcapkit.protocols.internet.ipv6_route.protocol

:mod:`pcapkit.protocols.internet.ipv6_route.protocol` contains
:class:`~pcapkit.protocols.internet.ipv6_route.protocol.IPv6_Route`
only, which implements the extractor for Routing Header for IPv6
(IPv6-Route) [*]_, whose structure is described as below:

======= ========= ==================== ===============================
Octets      Bits        Name                    Description
======= ========= ==================== ===============================
  0           0   ``route.next``            Next Header
  1           8   ``route.length``          Header Extension Length
  2          16   ``route.type``            Routing Type
  3          24   ``route.seg_left``        Segments Left
  4          32   ``route.data``            Type-Specific Data
======= ========= ==================== ===============================

.. autoclass:: pcapkit.protocols.internet.ipv6_route.protocol.IPv6_Route
   :no-members:
   :show-inheritance:

   .. autoattribute:: __routing__
      :no-value:

   .. autoproperty:: name
   .. autoproperty:: alias
   .. autoproperty:: length
   .. autoproperty:: payload
   .. autoproperty:: protocol
   .. autoproperty:: protochain

   .. automethod:: read
   .. automethod:: make
   .. automethod:: register_routing
   .. automethod:: id

   .. automethod:: __post_init__
   .. automethod:: __index__

   .. automethod:: _make_data
   .. automethod:: _make_hdr_ext_len
   .. automethod:: _read_data_type_none
   .. automethod:: _read_data_type_src
   .. automethod:: _read_data_type_2
   .. automethod:: _read_data_type_rpl
   .. automethod:: _make_data_type_none
   .. automethod:: _make_data_type_src
   .. automethod:: _make_data_type_2
   .. automethod:: _make_data_type_rpl

Header Schemas
--------------

.. module:: pcapkit.protocols.internet.ipv6_route.schema

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.schema.internet.ipv6_route``, with no alias: the module moved
   here (:issue:`2534`).

.. autoclass:: pcapkit.protocols.internet.ipv6_route.schema.IPv6_Route
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_route.schema.RoutingType
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_route.schema.UnknownType
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_route.schema.SourceRoute
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_route.schema.Type2
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_route.schema.RPL
   :members:
   :show-inheritance:

Type Stubs
~~~~~~~~~~

.. autoclass:: pcapkit.protocols.internet.ipv6_route.schema.CmprInfo
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_route.schema.PadInfo
   :members:
   :show-inheritance:

Auxiliary Functions
~~~~~~~~~~~~~~~~~~~

.. autofunction:: pcapkit.protocols.internet.ipv6_route.schema.ipv6_route_data_selector
.. autofunction:: pcapkit.protocols.internet.ipv6_route.schema.ipv6_route_data_length
.. autofunction:: pcapkit.protocols.internet.ipv6_route.schema.ipv6_route_header_length

Data Models
-----------

.. module:: pcapkit.protocols.internet.ipv6_route.data

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.data.internet.ipv6_route``, with no alias: the module moved here
   (:issue:`2534`).

.. autoclass:: pcapkit.protocols.internet.ipv6_route.data.IPv6_Route
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_route.data.UnknownType
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_route.data.SourceRoute
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_route.data.Type2
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.ipv6_route.data.RPL
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/IPv6_packet#Routing
