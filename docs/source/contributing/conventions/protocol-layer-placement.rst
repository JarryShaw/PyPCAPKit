.. _protocol-layer-placement:

Protocol Layer Placement
------------------------

Which subpackage of :mod:`pcapkit.protocols` a new dissector belongs in, and which
base classes it names. Settled by the owner on
:issue:`719`.

The Rule
~~~~~~~~

#. **Layer is decided by designed function, not by encapsulation.** What carries a
   protocol on the wire is a separate question from what the protocol is *for*.
#. **The IETF is the single source of truth** -- :rfc:`1122#section-1.1.3` and
   :rfc:`1812#section-7`. Where they place a protocol, so does this package.
#. **The operative question for a new protocol** is: *is this protocol a user of the
   stack, or part of its forwarding path?* A user is application-layer; the
   forwarding path is link, internet or transport by its own function.
#. **In the inheritance chain the layer base comes first, then the protocol family.**
#. **Encapsulation is the last tie-break**, never the first.

The subpackages, functionally rather than by carrier:

.. list-table::
   :header-rows: 1
   :widths: 22 78

   * - Subpackage
     - What it holds
   * - :mod:`~pcapkit.protocols.link`
     - frames, and link-address or tagging protocols
   * - :mod:`~pcapkit.protocols.internet`
     - layer-3 addressing and the forwarding path itself --
       :rfc:`1812#section-4.1` confines it to IP, ICMP and IGMP
   * - :mod:`~pcapkit.protocols.transport`
     - IANA transport protocols
   * - :mod:`~pcapkit.protocols.application`
     - protocols that are **users of the stack rather than part of its forwarding
       path**
   * - :mod:`~pcapkit.protocols.misc`
     - file formats and layerless sentinels

.. important::

   :mod:`~pcapkit.protocols.application` is **not** "payloads reached by port or SCTP
   PPID". :class:`~pcapkit.protocols.application.ospf.OSPF` is reached by IANA protocol
   number and :class:`~pcapkit.protocols.application.rarp.RARP` by EtherType, and
   neither has a port.

Why Function and Not Encapsulation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

:rfc:`1122` settles this inside one document. It lists **RARP in the application
layer** at :rfc:`1122#section-1.1.3`, among the *"support protocols, used for host
name mapping, booting, and management"*, while **ARP** sits in the Link Layer chapter
at :rfc:`1122#section-2.3.2`. Two sibling protocols, one frame format, one EtherType,
two layers -- decided on function alone.

OSI says the same by construction. ITU-T X.200 §9.2.4.4 has a protocol declare its own
layer in terms of *"functions which pertain to a particular layer"*, and clause 7
defines every layer by its purpose rather than by what encapsulates it.

IANA Assignments Carry No Layer Claim
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

All three registries this package dispatches on -- *Protocol Numbers*, *Ether Types*,
and *Service Name and Transport Protocol Port Number* -- have **no layer field**.
*Protocol Numbers* frames itself as identifying *"the next level protocol"*, i.e. the
**encapsulated** one. A registry assignment is evidence of encapsulation and of
nothing else.

.. caution::

   This **retires the registration grid at** :file:`docs/source/ext.rst` (the
   Protocol Type → Registry Function table) **as a placement rule.** It is a guide to
   which registrar to call when extending the library, and it was never a layer
   taxonomy. Read literally as one it makes ARP, RARP and both VLAN tags
   internet-layer and all eight IPv6 extension headers transport-layer. A
   contributor looking for a placement rule will find that grid first, which is why
   this page says so explicitly.

Routing Protocols: Control Plane, Not Data Plane
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

:rfc:`1812` is Standards Track and organises itself by layer. Its §7 is titled
**"APPLICATION LAYER - ROUTING PROTOCOLS"**, with OSPF at §7.2.2, while
:rfc:`1812#section-4.1` reads *"This chapter and chapter 5 discuss the protocols used
at the Internet Layer: IP, ICMP, and IGMP."* So a routing protocol is application-layer
and the internet layer holds three protocols.

**X.200 does not contradict this, and must not be cited as though it did.** X.200
§7.5.2.1 says the Network Layer provides transport *"independence of routing and relay
considerations"* -- that is the network layer **performing forwarding** so transport
need not care, which is the data plane. X.200 treats routing as a *generic* function
parameterised by layer: §5.4.1.4 defines it as *"a function within a layer"*, and §5.9
as *"a routing function within the (N)-layer enables communication to be relayed by a
chain of (N)-entities."* An (N)-layer function is not a layer assignment, and **X.200
assigns none**.

The distinction that dissolves the apparent conflict: computing a forwarding table is
the **control plane** and makes the protocol a user of the stack; forwarding packets is
the **data plane** and is internet-layer. OSPF does the former.

Tunnelling Protocols Follow Their Payload
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A tunnelling protocol is placed by what it carries, not by what carries it. So
:class:`~pcapkit.protocols.link.l2tp.L2TP` and
:class:`~pcapkit.protocols.link.l2tpv2.L2TPv2` stay in
:mod:`~pcapkit.protocols.link` and are **not** application-layer, even though L2TP is
commonly seen over UDP.

:rfc:`4949`'s ``$ tunnel`` entry is the citation: a tunnel is *"a logical
point-to-point link -- i.e., an OSIRM Layer 2 connection"*, and a tunnelling protocol
*"e.g., L2TP"* is *"layered below the tunneled Layer 2 protocol and above the
encapsulating protocol."* :rfc:`2473#section-3` and :rfc:`4213#section-3.4` (*"the
tunnel is a link"*) agree.

The carrier was never single-valued for L2TP anyway: :rfc:`3931#section-4.1` makes
L2TP-over-IP (protocol 115) a **MUST** and UDP/1701 only a **SHOULD**.

The Inheritance Convention
~~~~~~~~~~~~~~~~~~~~~~~~~~

**Layer base first, protocol family second.** Where a protocol's layer and its parsing
family disagree, it names both, in that order.

The order is load-bearing, and the mechanism is checkable. ``__layer__`` is resolved by
the MRO, so whichever base owns it *earliest* wins:

.. code-block:: pycon

   >>> from pcapkit.protocols.link.link import Link
   >>> from pcapkit.protocols.misc.raw import Raw
   >>> '__layer__' in vars(Link), '__layer__' in vars(Raw)
   (True, False)

:class:`~pcapkit.protocols.misc.raw.Raw` does **not** own ``__layer__`` -- it inherits
:obj:`None` from :class:`~pcapkit.protocols.protocol.ProtocolBase` -- so
:class:`~pcapkit.protocols.application.ftp.FTP_DATA` would report ``'Application'`` in
either base order. :class:`~pcapkit.protocols.link.arp.ARP`'s chain reaches
:class:`~pcapkit.protocols.link.link.Link`, which **does** own it, so
``class RARP(ARP, Application)`` would report ``'Link'`` and be wrong.

Ordering layer-first is correct in both cases, which is the point: a contributor does
not have to work out which case they are in.

Two Things That Will Look Like Mistakes
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Both are deliberate. Do not "fix" either.

**A parsing base may live in another subpackage.**
:mod:`pcapkit.protocols.application.rarp` imports
:class:`~pcapkit.protocols.link.arp.ARP` from :mod:`pcapkit.protocols.link.arp`. This
is the first ``application/ → link/`` dependency in the package, and it is the honest
consequence of letting layer and parser disagree.

**The dispatch tier is decoupled from the subpackage.** A protocol's subpackage says
nothing about which registry reaches it, and the move did not touch any dispatch key:

.. list-table::
   :header-rows: 1
   :widths: 24 38 38

   * - Class
     - Dispatched from
     - Subpackage
   * - :class:`~pcapkit.protocols.application.ospf.OSPF`
     - ``Internet.__proto__`` by
       :attr:`~pcapkit.const.reg.transtype.TransType.OSPFIGP`
     - :mod:`~pcapkit.protocols.application`
   * - :class:`~pcapkit.protocols.application.rarp.RARP`
     - ``Link.__proto__`` by EtherType
     - :mod:`~pcapkit.protocols.application`

Nothing else needs overriding. :class:`~pcapkit.protocols.application.application.Application`
accepts the ``-1`` sentinel (the undissected remainder) and resolves it to
:class:`~pcapkit.protocols.misc.raw.Raw`, so OSPF's body and the padding Ethernet adds
to a short RARP frame attach without either class touching
``__post_init__``, ``_decode_next_layer`` or ``_import_next_layer``. Only a real
protocol number is refused.

**Swapping** :class:`~pcapkit.protocols.link.link.Link` **for**
:class:`~pcapkit.protocols.application.application.Application` **is not name-for-name.**
Counting the names each class body sets, whether new or overriding
:class:`~pcapkit.protocols.protocol.ProtocolBase`'s, ``Link`` has
seven -- ``__data__``, ``__layer__``, ``__proto__``, ``__schema__``,
``_read_protos``, ``register`` and ``layer`` -- and ``Application`` eight: the four
they share (``__data__``, ``__layer__``, ``__schema__``, ``layer``) plus
``__index__``, ``__post_init__``, ``_decode_next_layer`` and ``_import_next_layer``.
``Link`` overrides three of those that ``Application`` does not -- ``__proto__``,
``register`` and ``_read_protos`` -- but all three also exist on ``ProtocolBase``, so
the strict difference ``Link`` minus ``Application`` minus ``ProtocolBase`` is **empty**
and every one of them still resolves on ``OSPF``. What changes is which registry it
resolves *to*: ``OSPF.__proto__`` is now ``ProtocolBase.__proto__`` rather than
``Link.__proto__``, so OSPF no longer sees Link's EtherType entries. That is inert --
nothing reaches OSPF by EtherType, and a ``-1`` lookup misses in both registries alike
and resolves to :class:`~pcapkit.protocols.misc.raw.Raw`, inserting nothing on the miss.
``RARP`` keeps ``Link``'s through ``ARP``.

Tie-Break Order
~~~~~~~~~~~~~~~

For a genuinely ambiguous protocol, in this order:

#. the protocol's own RFC's **functional self-description**;
#. the placement of its **closest functional peers** already in this package;
#. **encapsulation**, last.

Why Not OSI's Seven Layers
~~~~~~~~~~~~~~~~~~~~~~~~~~

Asked and declined on :issue:`719`. The
four-layer Internet model is what the public API already declares --
``Layers = Literal['link', 'internet', 'transport', 'application', 'none']`` in
:mod:`pcapkit.foundation.extraction` -- and the session and presentation layers have
no header on the wire and no IANA registry to dispatch on, so as subpackages they
would be structurally empty rather than merely sparse. OSI also resolves neither of
the cases that prompted this page: routing's control/data-plane split and L2TP's
carrier/payload split exist identically in both models.
