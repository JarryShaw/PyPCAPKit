Root Protocol
=============

.. module:: pcapkit.protocols.protocol
.. module:: pcapkit.protocols.data.protocol

:mod:`pcapkit.protocols.protocol` contains
:class:`~pcapkit.protocols.protocol.Protocol` only, which is
an abstract base class for all protocol family, with pre-defined
utility arguments and methods of specified protocols.

.. autoclass:: pcapkit.protocols.protocol.Protocol
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoproperty:: name
   .. autoproperty:: alias
   .. autoproperty:: info_name
   .. autoproperty:: info
   .. autoproperty:: data
   .. autoproperty:: length
   .. autoproperty:: payload
   .. autoproperty:: protocol
   .. autoproperty:: protochain
   .. autoproperty:: packet
   .. autoproperty:: schema

   .. automethod:: id
   .. automethod:: register
   .. automethod:: analyze

   .. automethod:: from_schema
   .. automethod:: from_data

   .. automethod:: read
   .. automethod:: make

   .. automethod:: unpack
   .. automethod:: pack

   .. automethod:: decode
   .. automethod:: unquote

   .. automethod:: expand_comp

   .. automethod:: _read_packet
   .. automethod:: _get_payload

   .. automethod:: _make_data
   .. automethod:: _make_index
   .. automethod:: _make_payload

   .. automethod:: _decode_next_layer
   .. automethod:: _import_next_layer

   .. autoattribute:: __layer__
      :no-value:
   .. autoattribute:: __proto__
      :no-value:

   .. autoattribute:: __data__
   .. autoattribute:: _info

   .. autoattribute:: __schema__
   .. autoattribute:: __header__

   .. automethod:: __init__
   .. automethod:: __post_init__
   .. automethod:: __init_subclass__

   .. automethod:: __repr__
   .. automethod:: __str__

   .. automethod:: __getitem__
   .. automethod:: __contains__
   .. automethod:: __index__

Data Models
-----------

.. autoclass:: pcapkit.protocols.data.protocol.Packet
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.
