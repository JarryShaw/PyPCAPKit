Parsing Context
===============

.. module:: pcapkit.corekit.context

:mod:`pcapkit.corekit.context` provides a *protocol-keyed* channel for
caller-supplied information that a protocol needs to parse a packet but that
is **not** carried on the wire.

Most protocols are self-describing: every length, offset and type needed to
walk a packet is in the packet. A few are not, such as
:class:`~pcapkit.protocols.internet.esp.protocol.ESP`:
:rfc:`4303` leaves the payload length, the position of the
``Pad Length`` / ``Next Header`` trailer and the length of the ``Integrity
Check Value`` to the Security Association (SA), which is negotiated out of band
and known only to the caller.

Rather than as protocol-specific keyword arguments to
:class:`~pcapkit.foundation.extraction.Extractor`, such information is passed
as a :class:`~pcapkit.corekit.context.ContextRegistry` -- a mapping of protocol
index ID (cf. :meth:`Protocol.id <pcapkit.protocols.protocol.Protocol.id>`) to
a :class:`~pcapkit.corekit.context.ProtocolContext` instance. The extractor
takes it once, and
:meth:`Protocol._import_next_layer <pcapkit.protocols.protocol.Protocol._import_next_layer>`
passes it down the stack, so a protocol at any depth reaches it through
:meth:`Protocol._get_context <pcapkit.protocols.protocol.Protocol._get_context>`.

Decoding an ESP tunnel end to end:

.. code-block:: python

   >>> import pcapkit
   >>> from pcapkit.protocols.internet.esp.protocol import (Cipher, ESPContext,
   ...                                            Integrity, SecurityAssociation)
   >>> sa = SecurityAssociation(
   ...     spi=0x4321,
   ...     encryption=Cipher.AES_CBC,
   ...     encryption_key=bytes.fromhex('90d382b410eeba7ad938c46cec1a82bf'),
   ... )
   >>> extraction = pcapkit.extract('esp.pcap', context=ESPContext(sa))

.. important::

   A context often holds secrets, such as ESP encryption and integrity keys, so
   it is a plain instance attribute on the protocol object and is **never**
   written into its data model, the only thing that reaches
   :meth:`Info.to_dict <pcapkit.corekit.infoclass.Info.to_dict>` and the output
   dumpers. A :class:`~pcapkit.corekit.context.ProtocolContext` implementation
   should keep secrets out of its :meth:`~object.__repr__` too.

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

.. data:: _CT
   :type: pcapkit.corekit.context.ProtocolContext
