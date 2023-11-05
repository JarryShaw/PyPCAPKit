No-Payload Packet
=================

.. module:: pcapkit.protocols.misc.null

:mod:`pcapkit.protocols.null` contains
:class:`~pcapkit.protocols.null.NoPayload` only, which
implements a :class:`~pcapkit.protocols.protocol.Protocol` like
object whose payload is recursively
:class:`~pcapkit.protocols.null.NoPayload` itself.

.. autoclass:: pcapkit.protocols.misc.null.NoPayload
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: length
   .. autoproperty:: protocol

   .. automethod:: read
   .. automethod:: make

   .. automethod:: __post_init__
   .. automethod:: __index__

Header Schemas
--------------

.. module:: pcapkit.protocols.schema.misc.null

.. autoclass:: pcapkit.protocols.schema.misc.null.NoPayload
   :members:
   :show-inheritance:

Data Models
-----------

.. module:: pcapkit.protocols.data.misc.null

.. autoclass:: pcapkit.protocols.data.misc.null.NoPayload
   :members:
   :show-inheritance:
