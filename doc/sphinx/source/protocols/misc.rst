Miscellaneous Protocols
=======================

Raw Packet Data
---------------

:mod:`pcapkit.protocols.raw` contains
:class:`~pcapkit.protocols.raw.Raw` only, which implements
extractor for unknown protocol, and constructs a
:class:`~pcapkit.protocols.protocol.Protocol` like object.

.. automodule:: pcapkit.protocols.raw
   :members:
   :undoc-members:
   :private-members:
   :show-inheritance:

No-Payload Packet
-----------------

:mod:`pcapkit.protocols.null` contains
:class:`~pcapkit.protocols.null.NoPayload` only, which
implements a :class:`~pcapkit.protocols.protocol.Protocol` like
object whose payload is recursively
:class:`~pcapkit.protocols.null.NoPayload` itself.

.. automodule:: pcapkit.protocols.null
   :members:
   :undoc-members:
   :private-members:
   :show-inheritance:
