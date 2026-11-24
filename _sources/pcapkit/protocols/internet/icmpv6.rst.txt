ICMPv6 - Internet Control Message Protocol for IPv6
=======================================================

.. module:: pcapkit.protocols.internet.icmpv6
.. module:: pcapkit.protocols.internet.icmpv6.protocol

:mod:`pcapkit.protocols.internet.icmpv6.protocol` contains
:class:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6` only,
which implements the extractor for Internet Control
Message Protocol for IPv6 (ICMPv6) [*]_, whose structure
is:

======= ========= ======================= ===================================
Octets      Bits        Name                    Description
======= ========= ======================= ===================================
  0           0   ``icmpv6.type``           Type
  1           8   ``icmpv6.code``           Code
  2          16   ``icmpv6.checksum``       Checksum
  4          32   ``icmpv6.data``           Message Body
======= ========= ======================= ===================================

.. versionadded:: 1.6.0

.. autoclass:: pcapkit.protocols.internet.icmpv6.protocol.ICMPv6
   :no-members:
   :show-inheritance:

   .. rubric:: Defaults

   .. autoattribute:: __type__
      :no-value:

   .. rubric:: Properties

   .. autoproperty:: name
   .. autoproperty:: alias
   .. autoproperty:: length

   .. rubric:: Methods

   .. automethod:: id
   .. automethod:: read
   .. automethod:: make
   .. automethod:: register_type

   .. rubric:: Data Models

   .. automethod:: __length_hint__
   .. automethod:: __index__

   .. rubric:: Utilities

   .. automethod:: _make_data
   .. automethod:: _read_data_type_none
   .. automethod:: _read_data_type_destination_unreachable
   .. automethod:: _read_data_type_packet_too_big
   .. automethod:: _read_data_type_time_exceeded
   .. automethod:: _read_data_type_parameter_problem
   .. automethod:: _read_data_type_echo
   .. automethod:: _read_data_type_mld_query
   .. automethod:: _read_data_type_mldv1
   .. automethod:: _read_data_type_mldv2_report
   .. automethod:: _make_data_type_none
   .. automethod:: _make_data_type_destination_unreachable
   .. automethod:: _make_data_type_packet_too_big
   .. automethod:: _make_data_type_time_exceeded
   .. automethod:: _make_data_type_parameter_problem
   .. automethod:: _make_data_type_echo
   .. automethod:: _make_data_type_mld_query
   .. automethod:: _make_data_type_mldv1
   .. automethod:: _make_data_type_mldv2_report
   .. automethod:: _make_address_record
   .. automethod:: _verify_pseudo_checksum

Header Schemas
--------------

.. module:: pcapkit.protocols.internet.icmpv6.schema

.. autoclass:: pcapkit.protocols.internet.icmpv6.schema.ICMPv6
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.icmpv6.schema.ICMPv6Type
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.icmpv6.schema.Unknown
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.icmpv6.schema.DestinationUnreachable
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.icmpv6.schema.PacketTooBig
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.icmpv6.schema.TimeExceeded
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.icmpv6.schema.ParameterProblem
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.icmpv6.schema.Echo
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.icmpv6.schema.MLDQuery
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.icmpv6.schema.MLDv2QueryExtension
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.icmpv6.schema.MLDv1
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.icmpv6.schema.MLDv2Report
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.icmpv6.schema.MulticastAddressRecord
   :members:
   :show-inheritance:

Auxiliary Functions
~~~~~~~~~~~~~~~~~~~~

.. autofunction:: pcapkit.protocols.internet.icmpv6.schema.icmpv6_data_selector
.. autofunction:: pcapkit.protocols.internet.icmpv6.schema.mldv2_query_present
.. autofunction:: pcapkit.protocols.internet.icmpv6.schema.mldv2_record_count

Type Stubs
~~~~~~~~~~

.. autoclass:: pcapkit.protocols.internet.icmpv6.schema.MLDv2QueryFlags
   :members:
   :show-inheritance:

Data Models
-----------

.. module:: pcapkit.protocols.internet.icmpv6.data

.. autoclass:: pcapkit.protocols.internet.icmpv6.data.ICMPv6
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.icmpv6.data.Unknown
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.icmpv6.data.DestinationUnreachable
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.icmpv6.data.PacketTooBig
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.icmpv6.data.TimeExceeded
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.icmpv6.data.ParameterProblem
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.icmpv6.data.Echo
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.icmpv6.data.MLDv1
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.icmpv6.data.MLDv2Query
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.icmpv6.data.MLDv2Report
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.icmpv6.data.MulticastAddressRecord
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol_for_IPv6
