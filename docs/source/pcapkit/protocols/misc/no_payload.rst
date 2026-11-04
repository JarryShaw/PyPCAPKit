No-Payload Packet
=================

.. module:: pcapkit.protocols.misc.no_payload
.. module:: pcapkit.protocols.misc.no_payload.protocol

:mod:`pcapkit.protocols.misc.no_payload.protocol` contains
:class:`~pcapkit.protocols.misc.no_payload.protocol.NoPayload` only, which
implements a :class:`~pcapkit.protocols.protocol.Protocol` like
object whose payload is recursively
:class:`~pcapkit.protocols.misc.no_payload.protocol.NoPayload` itself.

.. versionadded:: 1.6.0

   Moved here from ``pcapkit.protocols.misc.null``, with its data model and
   header schema, since a protocol class is named after its module
   (:issue:`2529`).

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.misc.null``, ``pcapkit.protocols.data.misc.null`` and
   ``pcapkit.protocols.schema.misc.null``, with no alias (:issue:`2529`).

.. autoclass:: pcapkit.protocols.misc.no_payload.protocol.NoPayload
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

.. module:: pcapkit.protocols.misc.no_payload.schema

.. autoclass:: pcapkit.protocols.misc.no_payload.schema.NoPayload
   :members:
   :show-inheritance:

Data Models
-----------

.. module:: pcapkit.protocols.misc.no_payload.data

.. autoclass:: pcapkit.protocols.misc.no_payload.data.NoPayload
   :members:
   :show-inheritance:
