IPv6-Ext - IPv6 Extension Header
================================

.. module:: pcapkit.protocols.internet.ipv6_ext
.. module:: pcapkit.protocols.internet.ipv6_ext.protocol

:mod:`pcapkit.protocols.internet.ipv6_ext.protocol` contains
:class:`~pcapkit.protocols.internet.ipv6_ext.protocol.IPv6_Ext`
only, in a double role:

* the **base class** of every IPv6 extension header this package implements,
  supplying the ``extension``-mode guards that make
  :attr:`~pcapkit.protocols.internet.ipv6_ext.protocol.IPv6_Ext.payload` and
  :attr:`~pcapkit.protocols.internet.ipv6_ext.protocol.IPv6_Ext.protochain`
  unavailable on a header parsed as part of an IPv6 chain. Each subclass guards
  its own ``protocol`` the same way; this class's
  :attr:`~pcapkit.protocols.internet.ipv6_ext.protocol.IPv6_Ext.protocol`
  deliberately does not.
* a **generic** extractor [*]_ for a header with no dedicated parser.
  :rfc:`6564#section-4` requires, with an RFC 2119 **MUST**, that any IPv6
  extension header defined since April 2012 carry the same first two octets, so
  those are parseable without knowing anything else about the header:

======= ========= ===================== =====================================
Octets      Bits        Name                    Description
======= ========= ===================== =====================================
  0           0   ``next``                    Next Header
  1           8   ``len``                     Hdr Ext Len (8-octet units,
                                              excluding the first 8 octets)
  2          16   ``payload``                 Header-specific content
======= ========= ===================== =====================================

.. autoclass:: pcapkit.protocols.internet.ipv6_ext.protocol.IPv6_Ext
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: alias
   .. autoproperty:: length
   .. autoproperty:: protocol
   .. autoproperty:: next
   .. autoproperty:: payload
   .. autoproperty:: protochain

   .. automethod:: id
   .. automethod:: read
   .. automethod:: make

   .. automethod:: __post_init__
   .. automethod:: __index__

   .. automethod:: _make_data

.. _ipv6-ext-length-rules:

Length Rules
------------

The generic layout is **not retroactive** (:rfc:`6564#section-5`), so the
headers that predate it get the closed exception table below rather than being
assumed to conform. :rfc:`8200#section-4.8` restates the layout without a MUST
and mislabels its length field as the Destination Options header's; cite
:rfc:`6564#section-4` instead.

The exception table, verified against IANA's ``protocol-numbers-1.csv``
*IPv6 Extension Header* column and each cited RFC:

===================================================================== =================================================
Header(s)                                                             Length rule
===================================================================== =================================================
``HOPOPT``, ``IPv6-Route``, ``IPv6-Opts``, ``MH``, ``HIP``, ``Shim6`` ``(octet[1] + 1) * 8`` -- the :rfc:`6564`
                                                                      generic rule
``IPv6-Frag``                                                         constant ``8``; octet[1] is Reserved, not a
                                                                      length (:rfc:`8200#section-4.5`)
``AH``                                                                ``(octet[1] + 2) * 4`` -- :rfc:`4302#section-2.2`
                                                                      counts in 4-octet units with a bias of 2,
                                                                      not :rfc:`6564`'s 8-octet units and bias of 1
``ESP``                                                               terminal -- has a dedicated, registered parser
                                                                      (:class:`~pcapkit.protocols.internet.esp.protocol.ESP`),
                                                                      but its Next Header byte is inside the
                                                                      encrypted trailer (:rfc:`4303`), so the walk
                                                                      cannot step past it on the wire
``253``, ``254``                                                      terminal -- no dedicated parser exists, so no
                                                                      next header field is ever read at all, either
===================================================================== =================================================

This table classifies by *wire format* alone, over every code
:class:`~pcapkit.const.ipv6.extension_header.ExtensionHeader` enumerates,
which match IANA's *IPv6 Extension Header Types* registry exactly
(:issue:`925`).

``Shim6`` conforms to the generic rule but has no dedicated parser; it reaches
this class as :ref:`ipv6-ext-entry-paths` describes.

:rfc:`8200#section-4.5` counts ESP among upper-layer headers, not extension
headers, and 253 and 254 are reserved for experimentation (:rfc:`3692`), with no
wire format at all. None of them reaches this class, by
construction (:meth:`IPv6._import_next_layer
<pcapkit.protocols.internet.ipv6.protocol.IPv6._import_next_layer>`). Each is still
an :class:`~pcapkit.const.ipv6.extension_header.ExtensionHeader` member, so it enters
the walk below, where they part ways:

* ``ESP`` resolves to its own parser, which decodes any plaintext it recovers
  itself and reports a ``next`` of :data:`None` while the payload stays opaque,
  so ``ExtensionHeader(None)`` fails at the next membership check and the walk
  ends.
* ``253`` and ``254`` resolve to plain
  :class:`~pcapkit.protocols.misc.raw.protocol.Raw`, whose info has no ``next``
  *attribute*. For these, and any future IANA code without an implementation,
  the walk stops on that *structural* check rather than on a list of codes.

.. _ipv6-ext-walk:

The Extension Header Walk
-------------------------

The walk :meth:`IPv6._decode_next_layer
<pcapkit.protocols.internet.ipv6.protocol.IPv6._decode_next_layer>` runs over the
header chain, and where it stops:

.. mermaid::

   flowchart TD
       S["proto = the IPv6 Next Header"] --> Q1
       Q1{"proto an ExtensionHeader member?"}
       Q1 -->|yes| Q2{"EXTENSION\_HEADER\_LIMIT headers walked?"}
       Q2 -->|no| Q3{"the frame at FRAME\_LAYER\_LIMIT layers?"}
       Q3 -->|no| IMP["\_import\_next\_layer(proto, extension=True)<br/>its dedicated class; Raw for 253, 254,<br/>or a parser that raises"]
       IMP --> Q4{"its info has a next attribute?"}
       Q4 -->|no| STOP["walk ends<br/>a plain Raw is reused as the upper layer"]
       Q4 -->|yes| REC["recorded among the extension headers<br/>payload moves past it; proto = its next"]
       REC --> Q5{"an IPv6-Frag header?"}
       Q5 -->|no| Q1
       Q5 -->|yes| J{"the first Fragment header,<br/>in a jumbogram?"}
       J -->|yes| ERR["ProtocolError"]
       J -->|no| Q6{"Fragment Offset zero?"}
       Q6 -->|yes| Q1
       Q6 -->|no| OPQ["walk ends opaque<br/>the upper layer gets no code, so Raw"]
       Q1 -->|no| EXIT
       Q2 -->|"yes: the rest kept Raw, one warning"| EXIT
       Q3 -->|"yes: the rest kept Raw, one warning"| EXIT
       STOP --> EXIT
       OPQ --> EXIT
       EXIT["Internet.\_decode\_next\_layer<br/>the upper layer, with the extension header chain"]

       click S "ipv6.html#pcapkit.protocols.internet.ipv6.protocol.IPv6._decode_next_layer"
       click IMP "ipv6.html#pcapkit.protocols.internet.ipv6.protocol.IPv6._import_next_layer"
       click EXIT "../protocol.html#protocol-next-layer-dispatch"

.. _ipv6-ext-entry-paths:

Entry Paths
-----------

This class is reached by direct dispatch only.
:attr:`~pcapkit.const.ipv6.extension_header.ExtensionHeader.Shim6` (:rfc:`5533`)
has no dedicated parser, so
:meth:`Internet._lookup_next_layer <pcapkit.protocols.protocol.Protocol._lookup_next_layer>`
would default it to plain :class:`~pcapkit.protocols.misc.raw.protocol.Raw`, whose
missing ``next`` would end the walk (:issue:`891`); this module registers this
class for that code instead. The registration is global, shared by every
:class:`~pcapkit.protocols.internet.internet.Internet` subclass, so
:meth:`~pcapkit.protocols.internet.ipv6_ext.protocol.IPv6_Ext.__post_init__` gates on
``version == 6`` to keep an IPv4 payload of protocol number 140 out.

A header with a dedicated class whose parser raises does not reach this class.
:func:`~pcapkit.corekit.decorators.beholder` makes it plain
:class:`~pcapkit.protocols.misc.raw.protocol.Raw`, and the walk stops there, as
:rfc:`8200#section-4` has a node discard such a packet (:issue:`2477`).

.. _ipv6-ext-overrun-guard:

The Overrun Guard
-----------------

The house convention for a declared length that does not fit what remains
is warn-and-clip: warn, naming what was declared against what is left, then read
only what is left -- as :func:`pcapkit.protocols.misc.pcapng.schema.bounded_area`
and :meth:`pcapkit.protocols.misc.pcapng.protocol.PCAPNG.read` do.

This class keeps the *warning* -- a
:class:`~pcapkit.utilities.warnings.SchemaWarning`, in
:func:`~pcapkit.protocols.misc.pcapng.schema.bounded_area`'s form -- and
deliberately diverges on the *action*. Clipping is right where the declared
length governs only how much of the current object to read. Here it also
decides *where the next header starts*, and a clipped skip points at whatever
bytes end the buffer, which are not a header: continuing would fabricate a layer
and record a false :class:`~pcapkit.corekit.protochain.ProtoChain` entry, which
reads as a parsed fact. So :meth:`~pcapkit.protocols.internet.ipv6_ext.protocol.IPv6_Ext.read`
warns, then **stops the walk**: this instance absorbs every remaining octet and
reports a ``next`` of :data:`None`, which the walk already reads as no more
extension headers.

Header Schemas
--------------

.. module:: pcapkit.protocols.internet.ipv6_ext.schema

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.schema.internet.ipv6_ext`` and
   ``pcapkit.protocols.schema.internet.ipv6_option``, with no alias: the modules merged
   here (:issue:`2534`).

.. autoclass:: pcapkit.protocols.internet.ipv6_ext.schema.IPv6_Ext
   :members:
   :show-inheritance:

Data Models
-----------

.. module:: pcapkit.protocols.internet.ipv6_ext.data

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.data.internet.ipv6_ext``, with no alias: the module moved here
   (:issue:`2534`).

.. autoclass:: pcapkit.protocols.internet.ipv6_ext.data.IPv6_Ext
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] :rfc:`6564`
