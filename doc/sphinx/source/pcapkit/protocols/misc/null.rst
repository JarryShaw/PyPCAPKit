No-Payload Packet
=================

.. module:: pcapkit.protocols.misc.null
.. module:: pcapkit.protocols.data.misc.null

:mod:`pcapkit.protocols.null` contains
:class:`~pcapkit.protocols.null.NoPayload` only, which
implements a :class:`~pcapkit.protocols.protocol.Protocol` like
object whose payload is recursively
:class:`~pcapkit.protocols.null.NoPayload` itself.

.. autoclass:: pcapkit.protocols.misc.null.NoPayload
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. automethod:: __post_init__
   .. automethod:: __index__

   .. autoproperty:: name
   .. autoproperty:: length
   .. autoproperty:: protocol

   .. automethod:: read
   .. automethod:: make

Data Structures
---------------

.. autoclass:: pcapkit.protocols.data.misc.null.NoPayload()
   :no-members:
   :show-inheritance:

   .. :param \*args: Arbitrary positional arguments.
   .. :param \*\*kwargs: Arbitrary keyword arguments.
