IGMPv1 - Internet Group Management Protocol version 1
=============================================================

.. module:: pcapkit.protocols.internet.igmpv1

:mod:`pcapkit.protocols.internet.igmpv1` contains
:class:`~pcapkit.protocols.internet.igmpv1.IGMP`, which implements an
extractor for Internet Group Management Protocol version 1 (IGMPv1)
[:rfc:`1112`]. It shares its header schema and data model with
:class:`IGMPv2 <pcapkit.protocols.internet.igmpv2.IGMP>` -- see
:mod:`~pcapkit.protocols.internet.igmp` for both.

.. autoclass:: pcapkit.protocols.internet.igmpv1.IGMP
   :no-members:
   :show-inheritance:

   .. autoproperty:: version
   .. autoproperty:: alias

   .. automethod:: id

   .. automethod:: read
