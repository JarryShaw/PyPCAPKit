RARP - Reverse Address Resolution Protocol
==========================================

.. module:: pcapkit.protocols.application.rarp

:mod:`pcapkit.protocols.application.rarp` contains
:class:`~pcapkit.protocols.application.rarp.RARP` only,
which implements an extractor for Reverse Address
Resolution Protocol (RARP) [*]_, whose structure is
described as below:

====== ========= ========================= =========================
Octets      Bits        Name                    Description
====== ========= ========================= =========================
  0           0   ``rarp.htype``            Hardware Type
  2          16   ``rarp.ptype``            Protocol Type
  4          32   ``rarp.hlen``             Hardware Address Length
  5          40   ``rarp.plen``             Protocol Address Length
  6          48   ``rarp.oper``             Operation
  8          64   ``rarp.sha``              Sender Hardware Address
  14        112   ``rarp.spa``              Sender Protocol Address
  18        144   ``rarp.tha``              Target Hardware Address
  24        192   ``rarp.tpa``              Target Protocol Address
====== ========= ========================= =========================

.. versionadded:: 1.5.0

   Moved here from ``pcapkit.protocols.link.rarp``.
   :class:`~pcapkit.protocols.application.rarp.RARP` and
   :class:`~pcapkit.protocols.application.drarp.DRARP` derive from
   :class:`~pcapkit.protocols.application.application.Application` as well as
   :class:`~pcapkit.protocols.link.arp.ARP`, so their layer is
   ``'Application'`` (:issue:`719`).

.. versionremoved:: 1.5.0

   ``pcapkit.protocols.link.rarp``, and the ``RARP`` and ``DRARP`` names
   that :mod:`pcapkit.protocols.link` exported, with no alias (:issue:`719`).

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.application.rarp.DRARP``, with no alias. The class
   moved to :mod:`pcapkit.protocols.application.drarp`, since a module holds
   one protocol class, named after it (:issue:`2529`).

.. autoclass:: pcapkit.protocols.application.rarp.RARP
   :no-members:
   :show-inheritance:

   .. automethod:: id

   .. automethod:: __index__

.. rubric:: Footnotes

.. [*] http://en.wikipedia.org/wiki/Address_Resolution_Protocol
