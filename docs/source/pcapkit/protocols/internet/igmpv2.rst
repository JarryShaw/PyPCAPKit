IGMPv2 - Internet Group Management Protocol Version 2
=============================================================

.. module:: pcapkit.protocols.internet.igmpv2
.. module:: pcapkit.protocols.internet.igmpv2.protocol

:mod:`pcapkit.protocols.internet.igmpv2.protocol` contains
:class:`~pcapkit.protocols.internet.igmpv2.protocol.IGMPv2`, which implements an
extractor for Internet Group Management Protocol version 2 (IGMPv2)
[:rfc:`2236`]. It shares its header schema and data model with
:class:`IGMPv1 <pcapkit.protocols.internet.igmpv1.protocol.IGMPv1>` -- see
:mod:`~pcapkit.protocols.internet.igmp.protocol` for both.

.. versionadded:: 1.6.0

.. autoclass:: pcapkit.protocols.internet.igmpv2.protocol.IGMPv2
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: version
   .. autoproperty:: alias

   .. automethod:: id

   .. automethod:: read
