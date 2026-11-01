DRARP - Dynamic Reverse Address Resolution Protocol
===================================================

.. module:: pcapkit.protocols.application.drarp

:mod:`pcapkit.protocols.application.drarp` contains
:class:`~pcapkit.protocols.application.drarp.DRARP` only,
which implements an extractor for Dynamic Reverse Address
Resolution Protocol (DRARP) [*]_, whose frame is the one
:mod:`pcapkit.protocols.application.rarp` describes.

Nothing dispatches to :class:`~pcapkit.protocols.application.drarp.DRARP`:
under EtherType ``0x8035``, a DRARP operation parses as
:class:`~pcapkit.protocols.application.rarp.RARP` with alias ``DRARP``.

.. versionadded:: 1.6.0

   Moved here from :mod:`pcapkit.protocols.application.rarp`, which keeps
   :class:`~pcapkit.protocols.application.rarp.RARP` alone, since a module
   holds one protocol class, named after it (:issue:`2529`).

.. autoclass:: pcapkit.protocols.application.drarp.DRARP
   :no-members:
   :show-inheritance:

   .. automethod:: id

.. rubric:: Footnotes

.. [*] https://datatracker.ietf.org/doc/html/rfc1931
