DRARP - Dynamic Reverse Address Resolution Protocol
===================================================

.. module:: pcapkit.protocols.application.drarp
.. module:: pcapkit.protocols.application.drarp.protocol

:mod:`pcapkit.protocols.application.drarp.protocol` contains
:class:`~pcapkit.protocols.application.drarp.protocol.DRARP` only,
which implements an extractor for Dynamic Reverse Address
Resolution Protocol (DRARP) [*]_, whose frame is the one
:mod:`pcapkit.protocols.application.rarp.protocol` describes.

Nothing dispatches to :class:`~pcapkit.protocols.application.drarp.protocol.DRARP`:
under EtherType ``0x8035``, a DRARP operation parses as
:class:`~pcapkit.protocols.application.rarp.protocol.RARP` with alias ``DRARP``.

.. versionadded:: 1.6.0

   Moved here from :mod:`pcapkit.protocols.application.rarp.protocol`, which keeps
   :class:`~pcapkit.protocols.application.rarp.protocol.RARP` alone, since a module
   holds one protocol class, named after it (:issue:`2529`).

.. autoclass:: pcapkit.protocols.application.drarp.protocol.DRARP
   :no-members:
   :show-inheritance:

   .. automethod:: id

.. rubric:: Footnotes

.. [*] https://datatracker.ietf.org/doc/html/rfc1931
