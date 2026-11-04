InARP - Inverse Address Resolution Protocol
===========================================

.. module:: pcapkit.protocols.link.inarp
.. module:: pcapkit.protocols.link.inarp.protocol

:mod:`pcapkit.protocols.link.inarp.protocol` contains
:class:`~pcapkit.protocols.link.inarp.protocol.InARP` only,
which implements an extractor for Inverse Address
Resolution Protocol (InARP) [*]_, whose frame is the one
:mod:`pcapkit.protocols.link.arp.protocol` describes.

Nothing dispatches to :class:`~pcapkit.protocols.link.inarp.protocol.InARP`:
under EtherType ``0x0806``, an InARP operation parses as
:class:`~pcapkit.protocols.link.arp.protocol.ARP` with alias ``InARP``.

.. versionadded:: 1.6.0

   Moved here from :mod:`pcapkit.protocols.link.arp.protocol`, which keeps
   :class:`~pcapkit.protocols.link.arp.protocol.ARP` alone, since a module holds one
   protocol class, named after it (:issue:`2529`).

.. autoclass:: pcapkit.protocols.link.inarp.protocol.InARP
   :no-members:
   :show-inheritance:

   .. automethod:: id

.. rubric:: Footnotes

.. [*] https://datatracker.ietf.org/doc/html/rfc2390
