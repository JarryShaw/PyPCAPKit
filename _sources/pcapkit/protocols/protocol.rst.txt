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

   .. automethod:: __init__
   .. automethod:: __post_init__
   .. automethod:: __repr__
   .. automethod:: __str__
   .. automethod:: __iter__
   .. automethod:: __getitem__
   .. automethod:: __contains__
   .. automethod:: __index__
   .. automethod:: __hash__

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

   .. automethod:: id
   .. automethod:: read
   .. automethod:: make
   .. automethod:: decode
   .. automethod:: unquote
   .. automethod:: expand_comp
   .. automethod:: analyze

   .. automethod:: _read_protos
   .. automethod:: _read_fileng
   .. automethod:: _read_unpack
   .. automethod:: _read_binary
   .. automethod:: _read_packet

   .. automethod:: _make_pack
   .. automethod:: _make_index

   .. automethod:: _decode_next_layer
   .. automethod:: _import_next_layer

   .. autoattribute:: __layer__
      :no-value:
   .. autoattribute:: __proto__
      :no-value:

   .. autoattribute:: _info
   .. autoattribute:: _data
   .. autoattribute:: _file
   .. autoattribute:: _next

   .. autoattribute:: _seekset
   .. autoattribute:: _exlayer
   .. autoattribute:: _exproto
   .. autoattribute:: _sigterm

Data Structures
---------------

.. autoclass:: pcapkit.protocols.data.protocol.Packet(header, payload)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: header
   .. autoattribute:: payload
