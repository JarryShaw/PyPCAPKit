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

Data Structure
~~~~~~~~~~~~~~

.. important::

   Following classes are only for *documentation* purpose.
   They do **NOT** exist in the :mod:`pcapkit` module.

.. class:: DataType_Raw

   :bases: typing.TypedDict

   Raw packet data.

   .. attribute:: packet
      :type: bytes

      raw packet data

   .. attribute:: error
      :type: Optional[str]

      optional error message

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
