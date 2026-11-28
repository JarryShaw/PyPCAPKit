DHCPv4 - Dynamic Host Configuration Protocol
==================================================

.. module:: pcapkit.protocols.application.dhcpv4
.. module:: pcapkit.protocols.application.dhcpv4.protocol

:mod:`pcapkit.protocols.application.dhcpv4.protocol` holds
:class:`~pcapkit.protocols.application.dhcpv4.protocol.DHCPv4`, the extractor for
Dynamic Host Configuration Protocol (DHCP) messages [:rfc:`2131`], laid out as
:mod:`~pcapkit.protocols.application.dhcp.protocol` gives. Its last field,
``options``, opens with the magic cookie, and the ``sname`` and ``file`` fields
hold options too where the Option Overload option says so
(:rfc:`2131#section-4.1`).

.. versionadded:: 1.10.0

.. autoclass:: pcapkit.protocols.application.dhcpv4.protocol.DHCPv4
   :no-members:
   :show-inheritance:

   .. rubric:: Properties

   .. autoproperty:: name
   .. autoproperty:: message_type

   .. rubric:: Methods

   .. automethod:: id
   .. automethod:: read
   .. automethod:: make

   .. rubric:: Utilities

   .. automethod:: _make_data

Data Models
-----------

.. module:: pcapkit.protocols.application.dhcpv4.data

.. autoclass:: pcapkit.protocols.application.dhcpv4.data.DHCPv4
   :members:
   :show-inheritance:
