Root Protocol
=============

.. module:: pcapkit.protocols.protocol
.. module:: pcapkit.protocols.data.protocol
.. currentmodule:: pcapkit.protocols.protocol

:mod:`pcapkit.protocols.protocol` contains
:class:`~pcapkit.protocols.protocol.Protocol`, an abstract base class with
pre-defined utility arguments and methods. Inherit it directly only to create a
new protocol stack; a new protocol in an existing layer subclasses that layer's
base class -- :class:`~pcapkit.protocols.link.link.Link`,
:class:`~pcapkit.protocols.internet.internet.Internet`,
:class:`~pcapkit.protocols.transport.transport.Transport` or
:class:`~pcapkit.protocols.application.application.Application` -- instead, c.f.
:doc:`/ext`. The built-in protocol families, those layer classes included,
derive from :class:`~pcapkit.protocols.protocol.ProtocolBase`, whose metaclass
is :class:`~pcapkit.protocols.protocol.ProtocolMeta`; both are listed under
Internal Definitions below.

.. autoclass:: pcapkit.protocols.protocol.Protocol
   :no-members:
   :show-inheritance:

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

   .. autoattribute:: __layer__
      :no-value:
   .. autoattribute:: __proto__
      :no-value:

   .. autoattribute:: __schema__
      :no-value:
   .. autoattribute:: __header__
      :no-value:

   .. automethod:: _read_packet
   .. automethod:: _get_payload

   .. automethod:: _make_data
   .. automethod:: _make_index
   .. automethod:: _make_payload

   .. automethod:: _lookup_registry
   .. automethod:: _lookup_next_layer
   .. automethod:: _decode_next_layer
   .. automethod:: _import_next_layer
   .. automethod:: _parse_next_layer
   .. automethod:: _get_context

   .. autoattribute:: _data
   .. autoattribute:: _file
   .. autoattribute:: _info
   .. autoattribute:: _next
   .. autoattribute:: _protos
   .. autoattribute:: _seekset
   .. autoattribute:: _sigterm
   .. autoattribute:: _past_layer_limit
   .. autoattribute:: __data__

   .. automethod:: __init__
   .. automethod:: __post_init__
   .. automethod:: __init_subclass__

   .. automethod:: __repr__
   .. automethod:: __str__

   .. automethod:: __getitem__
   .. automethod:: __contains__
   .. automethod:: __index__

   .. autoattribute:: _exlayer
   .. autoattribute:: _exproto
   .. autoattribute:: _exctx

Layers per Frame
----------------

A frame is dissected to at most
:data:`~pcapkit.protocols.protocol.FRAME_LAYER_LIMIT` layers of its protocol
chain, counted from the first layer the frame record carries, through tunnels,
VLAN tags and IPv6 extension headers alike. What follows is kept as
:class:`~pcapkit.protocols.misc.raw.Raw`, with one
:exc:`~pcapkit.utilities.warnings.ProtocolWarning` (:issue:`1610`), and is
marked :attr:`~pcapkit.protocols.protocol.Protocol._past_layer_limit`, so the
default engine's TCP reassembly and flow tracing do not read a TCP segment
there back out, as they do one the TCP parser rejected (:issue:`1518`). A
protocol constructed from its own octets is not counted itself, so the count
starts at the first layer it dissects. One chain of extension headers is also bounded on
its own, by :data:`~pcapkit.protocols.internet.internet.EXTENSION_HEADER_LIMIT`.
The ``dpkt``, ``scapy``, ``pyshark`` and ``pypcapfile`` engines dissect with
their own parsers, which do not apply this bound (:issue:`1609`).

.. autodata:: pcapkit.protocols.protocol.FRAME_LAYER_LIMIT

Data Models
-----------

.. autoclass:: pcapkit.protocols.data.protocol.Packet
   :members:
   :show-inheritance:

Internal Definitions
--------------------

.. autoclass:: pcapkit.protocols.protocol.ProtocolBase
   :no-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.protocol.ProtocolMeta
   :no-members:
   :show-inheritance:

Type Variables
--------------

.. data:: pcapkit.protocols.protocol._PT
   :type: pcapkit.protocols.data.data.Data

.. data:: pcapkit.protocols.protocol._ST
   :type: pcapkit.protocols.schema.schema.Schema
