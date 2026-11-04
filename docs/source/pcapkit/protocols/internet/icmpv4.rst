ICMPv4 - Internet Control Message Protocol
==========================================

.. module:: pcapkit.protocols.internet.icmpv4
.. module:: pcapkit.protocols.internet.icmpv4.protocol

:mod:`pcapkit.protocols.internet.icmpv4.protocol` contains
:class:`~pcapkit.protocols.internet.icmpv4.protocol.ICMPv4` only,
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

.. autoclass:: pcapkit.protocols.internet.icmpv4.protocol.ICMPv4
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

.. module:: pcapkit.protocols.internet.icmpv4.schema

.. autoclass:: pcapkit.protocols.internet.icmpv4.schema.ICMPv4
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.icmpv4.schema.ICMPv4Type
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.icmpv4.schema.Unknown
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.icmpv4.schema.Echo
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.icmpv4.schema.DestinationUnreachable
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.icmpv4.schema.TimeExceeded
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.icmpv4.schema.ParameterProblem
   :members:
   :show-inheritance:

Auxiliary Functions
~~~~~~~~~~~~~~~~~~~~

.. autofunction:: pcapkit.protocols.internet.icmpv4.schema.icmpv4_data_selector

Data Models
-----------

.. module:: pcapkit.protocols.internet.icmpv4.data

.. autoclass:: pcapkit.protocols.internet.icmpv4.data.ICMPv4
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.icmpv4.data.Unknown
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.icmpv4.data.Echo
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.icmpv4.data.DestinationUnreachable
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.icmpv4.data.TimeExceeded
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.icmpv4.data.ParameterProblem
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
