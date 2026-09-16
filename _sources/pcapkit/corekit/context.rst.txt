Parsing Context
===============

.. module:: pcapkit.corekit.context

:mod:`pcapkit.corekit.context` provides a *protocol keyed* channel for
caller supplied information that a protocol needs in order to parse a
packet, but that is **not** carried on the wire.

Most protocols are self describing -- every length, offset and type that
:mod:`pcapkit` needs to walk a packet is present in the packet itself. A
few are not. :class:`~pcapkit.protocols.internet.esp.ESP` is the
motivating example: :rfc:`4303` deliberately leaves the payload length,
the position of the ``Pad Length`` / ``Next Header`` trailer and the
length of the ``Integrity Check Value`` to be derived from the Security
Association (SA), which is negotiated out of band and is therefore
knowable only to the caller.

Rather than adding protocol specific keyword arguments to
:class:`~pcapkit.foundation.extraction.Extractor`, such information is passed
as a :class:`~pcapkit.corekit.context.ContextRegistry` -- a mapping of
protocol index ID (c.f. :meth:`Protocol.id
<pcapkit.protocols.protocol.ProtocolBase.id>`) to a
:class:`~pcapkit.corekit.context.ProtocolContext` instance. The registry is
handed to :class:`~pcapkit.foundation.extraction.Extractor` once, and is then
propagated down the protocol stack by
:meth:`Protocol._import_next_layer <pcapkit.protocols.protocol.ProtocolBase._import_next_layer>`,
so that a protocol nested arbitrarily deep can reach it through
:meth:`Protocol._get_context <pcapkit.protocols.protocol.ProtocolBase._get_context>`.

Decoding an ESP tunnel end to end:

.. code-block:: python

   >>> import pcapkit
   >>> from pcapkit.protocols.internet.esp import (Cipher, ESPContext,
   ...                                            Integrity, SecurityAssociation)
   >>> sa = SecurityAssociation(
   ...     spi=0x4321,
   ...     encryption=Cipher.AES_CBC,
   ...     encryption_key=bytes.fromhex('90d382b410eeba7ad938c46cec1a82bf'),
   ... )
   >>> extraction = pcapkit.extract('esp.pcap', context=ESPContext(sa))

.. important::

   A context object frequently holds secrets -- ESP encryption and
   integrity keys, for instance. Contexts are therefore held as plain
   instance attributes on the protocol object and are **never** written
   into the protocol's data model, which is the only thing that reaches
   :meth:`Info.to_dict <pcapkit.corekit.infoclass.Info.to_dict>` and,
   from there, the output dumpers. Implementations of
   :class:`~pcapkit.corekit.context.ProtocolContext` are expected to keep
   secrets out of their :meth:`~object.__repr__` as well.

.. autoclass:: pcapkit.corekit.context.ProtocolContext
   :no-members:
   :show-inheritance:

   .. automethod:: protocol
   .. automethod:: __repr__

.. autoclass:: pcapkit.corekit.context.ContextRegistry
   :no-members:
   :show-inheritance:

   .. automethod:: register
   .. automethod:: make
   .. automethod:: match

   .. automethod:: __getitem__
   .. automethod:: __iter__
   .. automethod:: __len__
   .. automethod:: __contains__
   .. automethod:: __bool__
   .. automethod:: __repr__

Type Variables
--------------

.. data:: pcapkit.corekit.context._CT
   :type: pcapkit.corekit.context.ProtocolContext
