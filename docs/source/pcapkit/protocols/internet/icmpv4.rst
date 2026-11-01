ICMPv4 - Internet Control Message Protocol
==========================================

.. module:: pcapkit.protocols.internet.icmpv4

:mod:`pcapkit.protocols.internet.icmpv4` contains
:class:`~pcapkit.protocols.internet.icmpv4.ICMPv4` only,
which implements extractor for Internet Control
Message Protocol (ICMP) [*]_, whose structure is
described as below:

======= ========= ======================= ===================================
Octets      Bits        Name                    Description
======= ========= ======================= ===================================
  0           0   ``icmpv4.type``           Type
  1           8   ``icmpv4.code``           Code
  2          16   ``icmpv4.checksum``       Checksum
  4          32   ``icmpv4.data``           Message Body
======= ========= ======================= ===================================

.. autoclass:: pcapkit.protocols.internet.icmpv4.ICMPv4
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: alias
   .. autoproperty:: length

   .. automethod:: id
   .. automethod:: register_type

   .. automethod:: read
   .. automethod:: make

   .. automethod:: _make_data

   .. automethod:: _read_data_type_none
   .. automethod:: _read_data_type_echo
   .. automethod:: _read_data_type_destination_unreachable
   .. automethod:: _read_data_type_time_exceeded
   .. automethod:: _read_data_type_parameter_problem

   .. automethod:: _make_data_type_none
   .. automethod:: _make_data_type_echo
   .. automethod:: _make_data_type_destination_unreachable
   .. automethod:: _make_data_type_time_exceeded
   .. automethod:: _make_data_type_parameter_problem

   .. autoattribute:: __type__
      :no-value:

   .. automethod:: __length_hint__
   .. automethod:: __index__

Header Schemas
--------------

.. module:: pcapkit.protocols.schema.internet.icmpv4

.. autoclass:: pcapkit.protocols.schema.internet.icmpv4.ICMPv4
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.icmpv4.ICMPv4Type
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.icmpv4.Unknown
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.icmpv4.Echo
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.icmpv4.DestinationUnreachable
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.icmpv4.TimeExceeded
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.internet.icmpv4.ParameterProblem
   :members:
   :show-inheritance:

Auxiliary Functions
~~~~~~~~~~~~~~~~~~~~

.. autofunction:: pcapkit.protocols.schema.internet.icmpv4.icmpv4_data_selector

Data Models
-----------

.. module:: pcapkit.protocols.data.internet.icmpv4

.. autoclass:: pcapkit.protocols.data.internet.icmpv4.ICMPv4
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.icmpv4.Unknown
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.icmpv4.Echo
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.icmpv4.DestinationUnreachable
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.icmpv4.TimeExceeded
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.internet.icmpv4.ParameterProblem
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
