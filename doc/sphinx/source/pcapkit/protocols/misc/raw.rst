Raw Packet Data
---------------

:mod:`pcapkit.protocols.misc.raw` contains
:class:`~pcapkit.protocols.misc.raw.Raw` only, which implements
extractor for unknown protocol, and constructs a
:class:`~pcapkit.protocols.protocol.Protocol` like object.

.. automodule:: pcapkit.protocols.misc.raw
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

   :bases: TypedDict

   Raw packet data.

   .. attribute:: packet
      :type: bytes

      raw packet data

   .. attribute:: error
      :type: Optional[str]

      optional error message
