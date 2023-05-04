Auxiliary Protocols
===================

.. module:: pcapkit.protocols.misc
.. module:: pcapkit.protocols.data.misc
.. module:: pcapkit.protocols.schema.misc

:mod:`pcapkit.protocols.misc` contains the auxiliary protocol implementations.
Such includes the :class:`~pcapkit.protocols.misc.raw.Raw` class for not-supported
protocols, the :class:`~pcapkit.protocols.misc.null.NoPayload` class for
indication of empty payload, and PCAP header classes.

.. toctree::
   :maxdepth: 2

   pcap
   pcapng
   raw
   null
