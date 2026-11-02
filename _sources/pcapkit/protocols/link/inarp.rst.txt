InARP - Inverse Address Resolution Protocol
===========================================

.. module:: pcapkit.protocols.link.inarp

:mod:`pcapkit.protocols.link.inarp` contains
:class:`~pcapkit.protocols.link.inarp.InARP` only,
which implements an extractor for Inverse Address
Resolution Protocol (InARP) [*]_, whose frame is the one
:mod:`pcapkit.protocols.link.arp` describes.

Nothing dispatches to :class:`~pcapkit.protocols.link.inarp.InARP`:
under EtherType ``0x0806``, an InARP operation parses as
:class:`~pcapkit.protocols.link.arp.ARP` with alias ``InARP``.

.. versionadded:: 1.6.0

   Moved here from :mod:`pcapkit.protocols.link.arp`, which keeps
   :class:`~pcapkit.protocols.link.arp.ARP` alone, since a module holds one
   protocol class, named after it (:issue:`2529`).

.. autoclass:: pcapkit.protocols.link.inarp.InARP
   :no-members:
   :show-inheritance:

   .. automethod:: id

.. rubric:: Footnotes

.. [*] https://datatracker.ietf.org/doc/html/rfc2390
