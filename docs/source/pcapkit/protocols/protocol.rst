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
:class:`~pcapkit.protocols.application.application.Application` -- instead; see
:doc:`/ext`. The built-in protocol families, those layer classes included,
derive from :class:`~pcapkit.protocols.protocol.ProtocolBase`, whose metaclass
is :class:`~pcapkit.protocols.protocol.ProtocolMeta`; both are listed under
Internal Definitions below.

.. versionchanged:: 1.5.0

   Constructing a protocol with a keyword that none of its signatures
   declares raises :exc:`~pcapkit.utilities.exceptions.UnsupportedCall`,
   where it was discarded (:issue:`617`). A next layer captured shorter than
   its header is kept as :class:`~pcapkit.protocols.misc.raw.Raw`, where it
   was parsed with zero-filled fields (:issue:`1170`).

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
   .. autoattribute:: __keywords__
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
   .. automethod:: _packing_target

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
   .. automethod:: __length_hint__

   .. autoattribute:: _exlayer
   .. autoattribute:: _exproto
   .. autoattribute:: _exctx

Layers per Frame
----------------

A frame is dissected to at most
:data:`~pcapkit.utilities.config.FRAME_LAYER_LIMIT` layers of its protocol
chain, counted from the first layer the frame record carries, through tunnels,
VLAN tags and IPv6 extension headers alike. What follows is kept as
:class:`~pcapkit.protocols.misc.raw.Raw`, with one
:exc:`~pcapkit.utilities.warnings.ProtocolWarning` (:issue:`1610`), and is
marked :attr:`~pcapkit.protocols.protocol.Protocol._past_layer_limit`, so the
default engine's TCP reassembly and flow tracing do not read a TCP segment
there back out, as they do one the TCP parser rejected (:issue:`1518`). A
protocol constructed from its own octets is not counted itself, so the count
starts at the first layer it dissects. One chain of extension headers is also bounded on
its own, by :data:`~pcapkit.utilities.config.EXTENSION_HEADER_LIMIT`.
The ``pyshark``, ``scapy`` and ``pypcapfile`` engines dissect with their own
parsers, which do not apply the frame's layer bound (:issue:`1609`). The
``dpkt`` toolkit reads what |dpkt|_ decodes, which applies neither bound.

Data Models
-----------

.. autoclass:: pcapkit.protocols.data.protocol.Protocol
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.protocol.Packet
   :members:
   :show-inheritance:

Internal Definitions
--------------------

.. autoclass:: pcapkit.protocols.protocol.ProtocolBase
   :no-members:
   :show-inheritance:

   .. automethod:: __init_subclass__

   :class:`Protocol` inherits the other members of this class, and they are
   documented under it above; each group below links to its entries.

   .. py:property:: name
                    alias
                    info_name
                    info
                    data
                    length
                    payload
                    protocol
                    protochain
                    packet
                    schema
      :no-index-entry:
      :no-contents-entry:

      :attr:`~Protocol.name`, :attr:`~Protocol.alias`,
      :attr:`~Protocol.info_name`, :attr:`~Protocol.info`,
      :attr:`~Protocol.data`, :attr:`~Protocol.length`,
      :attr:`~Protocol.payload`, :attr:`~Protocol.protocol`,
      :attr:`~Protocol.protochain`, :attr:`~Protocol.packet`,
      :attr:`~Protocol.schema`

   .. py:method:: id
                  register
                  analyze
                  from_schema
                  from_data
                  read
                  make
                  unpack
                  pack
                  decode
                  unquote
                  expand_comp
                  _read_packet
                  _get_payload
                  _make_data
                  _make_index
                  _make_payload
                  _packing_target
                  _lookup_registry
                  _lookup_next_layer
                  _decode_next_layer
                  _import_next_layer
                  _parse_next_layer
                  _get_context
                  __init__
                  __post_init__
                  __repr__
                  __str__
                  __getitem__
                  __contains__
                  __index__
                  __length_hint__
      :no-index-entry:
      :no-contents-entry:

      :meth:`~Protocol.id`, :meth:`~Protocol.register`,
      :meth:`~Protocol.analyze`, :meth:`~Protocol.from_schema`,
      :meth:`~Protocol.from_data`, :meth:`~Protocol.read`,
      :meth:`~Protocol.make`, :meth:`~Protocol.unpack`, :meth:`~Protocol.pack`,
      :meth:`~Protocol.decode`, :meth:`~Protocol.unquote`,
      :meth:`~Protocol.expand_comp`, :meth:`~Protocol._read_packet`,
      :meth:`~Protocol._get_payload`, :meth:`~Protocol._make_data`,
      :meth:`~Protocol._make_index`, :meth:`~Protocol._make_payload`,
      :meth:`~Protocol._packing_target`,
      :meth:`~Protocol._lookup_registry`, :meth:`~Protocol._lookup_next_layer`,
      :meth:`~Protocol._decode_next_layer`,
      :meth:`~Protocol._import_next_layer`,
      :meth:`~Protocol._parse_next_layer`, :meth:`~Protocol._get_context`,
      :meth:`~Protocol.__init__`, :meth:`~Protocol.__post_init__`,
      :meth:`~Protocol.__repr__`, :meth:`~Protocol.__str__`,
      :meth:`~Protocol.__getitem__`, :meth:`~Protocol.__contains__`,
      :meth:`~Protocol.__index__`, :meth:`~Protocol.__length_hint__`

   .. py:attribute:: __layer__
                     __proto__
                     __keywords__
                     __schema__
                     __header__
                     _data
                     _file
                     _info
                     _next
                     _protos
                     _seekset
                     _sigterm
                     _past_layer_limit
                     __data__
                     _exlayer
                     _exproto
                     _exctx
      :no-index-entry:
      :no-contents-entry:

      :attr:`~Protocol.__layer__`, :attr:`~Protocol.__proto__`,
      :attr:`~Protocol.__keywords__`, :attr:`~Protocol.__schema__`,
      :attr:`~Protocol.__header__`, :attr:`~Protocol._data`,
      :attr:`~Protocol._file`, :attr:`~Protocol._info`,
      :attr:`~Protocol._next`, :attr:`~Protocol._protos`,
      :attr:`~Protocol._seekset`, :attr:`~Protocol._sigterm`,
      :attr:`~Protocol._past_layer_limit`, :attr:`~Protocol.__data__`,
      :attr:`~Protocol._exlayer`, :attr:`~Protocol._exproto`,
      :attr:`~Protocol._exctx`

.. autoclass:: pcapkit.protocols.protocol.ProtocolMeta
   :no-members:
   :show-inheritance:

.. autodata:: pcapkit.protocols.protocol.OUT_OF_BAND_KEYWORDS
   :no-value:

.. autodata:: pcapkit.protocols.protocol._KEYWORD_CONSUMERS
   :no-value:

.. autofunction:: pcapkit.protocols.protocol._declared_keywords

Type Variables
--------------

.. data:: _PT
   :type: pcapkit.protocols.data.data.Data

.. data:: _ST
   :type: pcapkit.protocols.schema.schema.Schema
