IPv6-Ext - IPv6 Extension Header
================================

.. module:: pcapkit.protocols.internet.ipv6_ext

:mod:`pcapkit.protocols.internet.ipv6_ext` contains
:class:`~pcapkit.protocols.internet.ipv6_ext.IPv6_Ext`
only, which plays a double role. It is the shared **base class** of every
IPv6 extension header this package implements, supplying the
``extension``-mode contract: the guards that make
:attr:`~pcapkit.protocols.internet.ipv6_ext.IPv6_Ext.payload` and
:attr:`~pcapkit.protocols.internet.ipv6_ext.IPv6_Ext.protochain`
unavailable on a header parsed as part of an IPv6 chain. Each subclass guards
its own ``protocol`` the same way; this class's
:attr:`~pcapkit.protocols.internet.ipv6_ext.IPv6_Ext.protocol` deliberately
does not. It also implements a
**generic** extractor for IPv6 extension headers [*]_, standing in whenever a
header's own dedicated parser is unavailable or has failed. :rfc:`6564#section-4`
requires, with an RFC 2119 **MUST**, that any IPv6 extension header defined since
April 2012 carry the same first two octets:

======= ========= ===================== =====================================
Octets      Bits        Name                    Description
======= ========= ===================== =====================================
  0           0   ``next``                    Next Header
  1           8   ``len``                     Hdr Ext Len (8-octet units,
                                              excluding the first 8 octets)
  2          16   ``payload``                 Header-specific content
======= ========= ===================== =====================================

so those two octets are parseable without knowing anything else about the
header. The sections below the class give the headers that depart from that
rule, the ways this class is dispatched to, and why an overrun stops the walk
instead of clipping it.

.. autoclass:: pcapkit.protocols.internet.ipv6_ext.IPv6_Ext
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: alias
   .. autoproperty:: length
   .. autoproperty:: protocol
   .. autoproperty:: next
   .. autoproperty:: payload
   .. autoproperty:: protochain

   .. automethod:: read
   .. automethod:: make

   .. automethod:: _make_data

   .. automethod:: __post_init__
   .. automethod:: __index__

.. _ipv6-ext-length-rules:

Length Rules
------------

:rfc:`6564#section-5` is explicit that the generic layout is **not
retroactive** -- it applies only to newly defined extension headers -- which is
why the pre-existing headers need the closed exception table below rather than
being assumed to conform. (:rfc:`8200#section-4.8` restates the layout without
a MUST and mislabels the generic length field as the length of the Destination
Options header; cite :rfc:`6564#section-4` instead.)

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
                                                                      (:class:`~pcapkit.protocols.internet.esp.ESP`),
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

``Shim6`` conforms to the generic rule (:rfc:`5533`) but has no dedicated parser class; see
:ref:`ipv6-ext-entry-paths` for how it reaches this class by direct dispatch.

:rfc:`8200#section-4.5` sets Encapsulating Security Payload aside: ESP is not
an extension header, and the RFC lists it among upper-layer headers.
:rfc:`4303` puts its Next Header inside the encrypted trailer, with no length
field in the cleartext part. 253 and 254 are reserved for private
experimentation (:rfc:`3692`) with no wire format at all. None of them is
reachable through this class, by construction; see
:meth:`IPv6._import_next_layer
<pcapkit.protocols.internet.ipv6.IPv6._import_next_layer>`. Each still enters
:meth:`IPv6._decode_next_layer
<pcapkit.protocols.internet.ipv6.IPv6._decode_next_layer>`'s walk, being a real
:class:`~pcapkit.const.ipv6.extension_header.ExtensionHeader` member, but they
part ways there. ``ESP`` resolves to its own dedicated parser, which decodes
any plaintext it recovers itself and whose info carries a ``next`` of
:data:`None` whenever the payload stays opaque, so the walk ends the ordinary
way with ``ExtensionHeader(None)`` failing at the top of the next iteration.
``253`` and ``254`` have no dedicated parser and resolve to plain
:class:`~pcapkit.protocols.misc.raw.Raw`, whose info has no ``next``
*attribute*. For these two, and any future IANA code without an
implementation, the walk stops on a *structural* check (does the parsed layer
carry a ``next`` at all?) rather than on a list of codes.

.. _ipv6-ext-entry-paths:

Entry Paths
-----------

This class is reached in these ways:

1. **An unrecognised protocol number.**
   :attr:`~pcapkit.const.ipv6.extension_header.ExtensionHeader.Shim6` is a real
   IANA extension header (:rfc:`5533`) with no dedicated parser, so
   :meth:`Internet._lookup_next_layer <pcapkit.protocols.protocol.ProtocolBase._lookup_next_layer>`
   would default it to plain :class:`~pcapkit.protocols.misc.raw.Raw`. That
   has no ``next`` field, so the walk in
   :meth:`IPv6._decode_next_layer <pcapkit.protocols.internet.ipv6.IPv6._decode_next_layer>` would
   crash on it (:issue:`891`). This module registers this class for that code
   instead, at the bottom of the module, so dispatch reaches a working generic
   parser directly. The registration is global, shared by every
   :class:`~pcapkit.protocols.internet.internet.Internet` subclass, so
   :meth:`~pcapkit.protocols.internet.ipv6_ext.IPv6_Ext.__post_init__` gates on ``version == 6`` to
   keep it from also activating for an IPv4 payload that carries protocol
   number 140; see its docstring.
2. **A recognised header whose own parser raises.** ``HOPOPT``,
   ``IPv6-Route``, ``IPv6-Opts``, ``MH``, ``HIP``, ``IPv6-Frag`` and ``AH`` all
   have dedicated classes. When one of *those* raises,
   :func:`~pcapkit.corekit.decorators.beholder`
   (:meth:`ProtocolBase._import_next_layer <pcapkit.protocols.protocol.ProtocolBase._import_next_layer>`)
   would substitute plain :class:`~pcapkit.protocols.misc.raw.Raw`, which loses
   ``next`` and crashes the walk as in path 1.
   :meth:`IPv6._import_next_layer <pcapkit.protocols.internet.ipv6.IPv6._import_next_layer>` catches
   the failure itself, one layer in from ``beholder``, and substitutes this
   class: the bad header costs only itself, not the rest of the chain.

.. _ipv6-ext-overrun-guard:

The Overrun Guard
-----------------

The house convention for a declared length that does not fit what remains
is warn-and-clip: emit a warning naming what was declared against what is
left, then read only what is left. See
:func:`pcapkit.protocols.schema.misc.pcapng.bounded_area` and
:meth:`pcapkit.protocols.misc.pcapng.PCAPNG.read`.

This class follows that convention's *warning* -- a
:class:`~pcapkit.utilities.warnings.SchemaWarning`, as
:func:`~pcapkit.protocols.schema.misc.pcapng.bounded_area` emits -- and
deliberately diverges on the *action*. Clipping is right when the declared
length only governs how much of the current object to read, since there is
always a well-defined "what is left" to fall back to. Here the declared length
also decides *where the next header starts*; a clipped skip distance points at
whatever bytes end the buffer, which are not a header. Continuing from there
would fabricate a layer and record a false entry in
:class:`~pcapkit.corekit.protochain.ProtoChain`, which reads as a parsed fact
rather than a guess. So :meth:`~pcapkit.protocols.internet.ipv6_ext.IPv6_Ext.read`
warns in the same form as
:func:`~pcapkit.protocols.schema.misc.pcapng.bounded_area`, then **stops the
walk**: this instance absorbs every remaining octet and reports :data:`None`
for ``next``, which the caller's loop already reads as "no more extension
headers". The chain ends honestly at the bad header instead of inventing what
follows it.

Header Schemas
--------------

.. module:: pcapkit.protocols.schema.internet.ipv6_ext

.. autoclass:: pcapkit.protocols.schema.internet.ipv6_ext.IPv6_Ext
   :members:
   :show-inheritance:

Data Models
-----------

.. module:: pcapkit.protocols.data.internet.ipv6_ext

.. autoclass:: pcapkit.protocols.data.internet.ipv6_ext.IPv6_Ext
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] :rfc:`6564`
