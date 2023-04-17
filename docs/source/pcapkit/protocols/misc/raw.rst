Raw Packet Data
===============

.. module:: pcapkit.protocols.misc.raw
.. module:: pcapkit.protocols.data.misc.raw

:mod:`pcapkit.protocols.misc.raw` contains
:class:`~pcapkit.protocols.misc.raw.Raw` only, which implements
extractor for unknown protocol, and constructs a
:class:`~pcapkit.protocols.protocol.Protocol` like object.

.. autoclass:: pcapkit.protocols.misc.raw.Raw
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

.. autoclass:: pcapkit.protocols.data.misc.raw.Raw(protocol, packet, error)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: protocol
   .. autoattribute:: packet
   .. autoattribute:: error
