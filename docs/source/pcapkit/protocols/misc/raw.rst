Raw Packet Data
===============

.. module:: pcapkit.protocols.misc.raw

:mod:`pcapkit.protocols.misc.raw` contains
:class:`~pcapkit.protocols.misc.raw.Raw` only, which implements
extractor for unknown protocol, and constructs a
:class:`~pcapkit.protocols.protocol.Protocol` like object.

.. autoclass:: pcapkit.protocols.misc.raw.Raw
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoproperty:: name
   .. autoproperty:: length
   .. autoproperty:: protocol

   .. automethod:: read
   .. automethod:: make

   .. automethod:: _make_data

   .. automethod:: __post_init__
   .. automethod:: __index__

Header Schemas
--------------

.. module:: pcapkit.protocols.schema.misc.raw

.. autoclass:: pcapkit.protocols.schema.misc.raw.Raw
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

Data Models
-----------

.. module:: pcapkit.protocols.data.misc.raw

.. autoclass:: pcapkit.protocols.data.misc.raw.Raw
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.
