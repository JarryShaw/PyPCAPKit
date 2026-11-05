.. _protocol-layer-placement:

Protocol Layer Placement
------------------------

Which subpackage of :mod:`pcapkit.protocols` a new dissector belongs in, and which
base classes it names. Settled by the owner on :issue:`719`.

The Rule
~~~~~~~~

#. **Layer is decided by designed function, not by encapsulation**: what a protocol
   is *for*, not what carries it on the wire.
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
     - layer-3 addressing and the forwarding path itself: IP, ICMP and IGMP, the
       Internet Layer protocols :rfc:`1812#section-4.1` names, and with them IPX and
       the IPsec and IPv6 extension headers (:ref:`extension-header-subclassing`)
   * - :mod:`~pcapkit.protocols.transport`
     - IANA transport protocols
   * - :mod:`~pcapkit.protocols.application`
     - protocols that are **users of the stack rather than part of its forwarding
       path**
   * - :mod:`~pcapkit.protocols.misc`
     - file formats, layerless sentinels, and the checksum pseudo-headers in
       :mod:`~pcapkit.protocols.misc.checksum`

The rule and the sections below it, as a decision:

.. mermaid::

   flowchart TD
       NEW["a new dissector"] --> WIRE{"a layer on the wire?"}
       WIRE -->|"no: a file format, a layerless sentinel<br/>or a checksum pseudo-header"| MISC["misc"]
       WIRE -->|yes| FN{"by its designed function, per RFC 1122<br/>and RFC 1812: a user of the stack,<br/>or part of its forwarding path?"}
       REG["an IANA assignment: Protocol Numbers,<br/>Ether Types or a port"] -.->|"encapsulation only,<br/>not evidence"| FN
       TIE["tie-break, in order: its RFC's<br/>functional self-description,<br/>its closest functional peers here,<br/>encapsulation last"] -.->|"an ambiguous case"| FN
       FN -->|"a user, routing's<br/>control plane included"| APP["application<br/>e.g. OSPF, RARP"]
       FN -->|"forwarding path"| FWD{"by its own function"}
       FWD -->|"frames, link-address, tagging;<br/>a tunnel, by its payload"| LINK["link<br/>e.g. L2TP, L2TPv2"]
       FWD -->|"layer-3 addressing,<br/>the forwarding path itself"| INET["internet<br/>IP, ICMP, IGMP, IPX,<br/>IPsec, IPv6 extension headers"]
       FWD -->|"an IANA transport protocol"| TRANS["transport"]
       APP --> BASES
       LINK --> BASES
       INET --> BASES
       TRANS --> BASES
       BASES["bases: the layer base first, then the family<br/>e.g. FTP\_DATA(Application, Raw)"]

.. important::

   :mod:`~pcapkit.protocols.application` is **not** "payloads reached by port or SCTP
   PPID". :class:`~pcapkit.protocols.application.ospf.protocol.OSPF` is reached by IANA protocol
   number and :class:`~pcapkit.protocols.application.rarp.protocol.RARP` by EtherType, and
   neither has a port.

Why Function and Not Encapsulation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

:rfc:`1122` settles this inside one document. It lists **RARP in the application
layer** at :rfc:`1122#section-1.1.3`, among the *"support protocols, used for host
name mapping, booting, and management"*, while **ARP** sits in the Link Layer chapter
at :rfc:`1122#section-2.3.2`. Sibling protocols sharing one frame format, each under
its own EtherType, in different layers -- decided on function alone.

OSI agrees by construction: ITU-T X.200 §9.2.4.4 has a protocol declare its layer in
terms of *"functions which pertain to a particular layer"*, and clause 7 defines every
layer by its purpose, not its encapsulation.

IANA Assignments: Encapsulation, Not Layer
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Every registry this package dispatches on -- *Protocol Numbers*, *Ether Types*,
and *Service Name and Transport Protocol Port Number* -- has **no layer field**.
*Protocol Numbers* frames itself as identifying *"the next level protocol"*, i.e. the
**encapsulated** one. A registry assignment is evidence of encapsulation and of
nothing else.

.. caution::

   **The registration grid on** :doc:`/ext` (the Protocol Type → Registry Function
   table) **is not a placement rule.** It says which registrar to call when extending
   the library; read as a layer taxonomy it makes ARP, RARP and both VLAN tags
   internet-layer and every IPv6 extension header transport-layer. It is named here
   because a contributor looking for a placement rule finds it first.

Routing Protocols: Control Plane, Not Data Plane
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

:rfc:`1812` is Standards Track and organises itself by layer. Its §7 is titled
**"APPLICATION LAYER - ROUTING PROTOCOLS"**, with OSPF at §7.2.2, while
:rfc:`1812#section-4.1` reads *"This chapter and chapter 5 discuss the protocols used
at the Internet Layer: IP, ICMP, and IGMP."* So a routing protocol is application-layer,
not one of the Internet Layer protocols §4.1 names.

**X.200 does not contradict this, and must not be cited as though it did.** X.200
§7.5.2.1 says the Network Layer provides transport *"independence of routing and relay
considerations"* -- the network layer **performing forwarding** so transport need not
care: the data plane. X.200 treats routing as a *generic* function
parameterised by layer: §5.4.1.4 defines it as *"a function within a layer"*, and §5.9
as *"a routing function within the (N)-layer enables communication to be relayed by a
chain of (N)-entities."* An (N)-layer function is not a layer assignment, and **X.200
assigns none**.

Computing a forwarding table is the **control plane** and makes a protocol a user of
the stack; forwarding packets is the **data plane** and is internet-layer. OSPF does
the former.

Tunnelling Protocols: Payload, Not Carrier
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A tunnelling protocol is placed by what it carries, not by what carries it. So
:class:`~pcapkit.protocols.link.l2tp.protocol.L2TP` and
:class:`~pcapkit.protocols.link.l2tpv2.protocol.L2TPv2` stay in
:mod:`~pcapkit.protocols.link` and are **not** application-layer, even though L2TP is
commonly seen over UDP.

:rfc:`4949`'s ``$ tunnel`` entry is the citation: a tunnel is *"a logical
point-to-point link -- i.e., an OSIRM Layer 2 connection"*, and a tunnelling protocol
*"e.g., L2TP"* is *"layered below the tunneled Layer 2 protocol and above the
encapsulating protocol."* :rfc:`2473#section-3` and :rfc:`4213#section-3.4` (*"the
tunnel is a link"*) agree.

L2TP's carrier is not single-valued anyway: :rfc:`3931#section-4.1` makes L2TP-over-IP
(protocol 115) a **MUST** and UDP/1701 only a **SHOULD**.

The Inheritance Convention
~~~~~~~~~~~~~~~~~~~~~~~~~~

**Layer base first, protocol family second.** Where a protocol's layer and its parsing
family disagree, it names both, in that order.

The order is load-bearing: ``__layer__`` resolves through the MRO, so the *earliest*
base that owns it wins:

.. code-block:: pycon

   >>> from pcapkit.protocols.link.link import Link
   >>> from pcapkit.protocols.misc.raw.protocol import Raw
   >>> '__layer__' in vars(Link), '__layer__' in vars(Raw)
   (True, False)

:class:`~pcapkit.protocols.misc.raw.protocol.Raw` does **not** own ``__layer__`` -- it inherits
:obj:`None` from :class:`~pcapkit.protocols.protocol.ProtocolBase` -- so a class
naming both :class:`~pcapkit.protocols.application.application.Application` and
:class:`~pcapkit.protocols.misc.raw.protocol.Raw` reports ``'Application'`` in either base order.
So :class:`~pcapkit.protocols.application.ftp_data.protocol.FTP_DATA`, declared
``class FTP_DATA(Application, Raw)``, reports ``'Application'``.
:class:`~pcapkit.protocols.link.arp.protocol.ARP`'s chain reaches
:class:`~pcapkit.protocols.link.link.Link`, which **does** own it, so
``class RARP(ARP, Application)`` would report ``'Link'`` and be wrong.

Layer-first is correct in both cases, so a contributor need not work out which applies.

Apparent Mistakes
~~~~~~~~~~~~~~~~~

Each is deliberate; do not "fix" it.

**A parsing base may live in another subpackage.**
:mod:`pcapkit.protocols.application.rarp.protocol` imports
:class:`~pcapkit.protocols.link.arp.protocol.ARP` from :mod:`pcapkit.protocols.link.arp.protocol`. That
``application/ → link/`` dependency follows from letting layer and parser disagree.

**A pseudo-header protocol is in** :mod:`~pcapkit.protocols.misc`, **not beside the
layer it is built from.** :class:`~pcapkit.protocols.misc.checksum.ip_pseudo.protocol.IP_Pseudo`
is built from an IPv4 or IPv6 layer but is no layer on the wire, and its ``__layer__``
is :obj:`None`. Pseudo-header protocols share :mod:`pcapkit.protocols.misc.checksum`,
ruled in review of the IP pseudo-header, :pr:`2479` (:issue:`2471`), whose issue does
not hold it.

**The dispatch tier is decoupled from the subpackage**: no dispatch key depends on
the subpackage:

.. list-table::
   :header-rows: 1
   :widths: 24 38 38

   * - Class
     - Dispatched from
     - Subpackage
   * - :class:`~pcapkit.protocols.application.ospf.protocol.OSPF`
     - :attr:`Internet.__proto__ <pcapkit.protocols.internet.internet.Internet.__proto__>` by
       :attr:`~pcapkit.const.reg.transtype.TransType.OSPFIGP`
     - :mod:`~pcapkit.protocols.application`
   * - :class:`~pcapkit.protocols.application.rarp.protocol.RARP`
     - :attr:`Link.__proto__ <pcapkit.protocols.link.link.Link.__proto__>` by EtherType
     - :mod:`~pcapkit.protocols.application`

Nothing else needs overriding. :class:`~pcapkit.protocols.application.application.Application`
accepts the ``-1`` sentinel (the undissected remainder) and resolves it to
:class:`~pcapkit.protocols.misc.raw.protocol.Raw`, so OSPF's body and the padding Ethernet adds
to a short RARP frame attach without either class touching
``__post_init__``, ``_decode_next_layer`` or ``_import_next_layer``. Only a real
protocol number is refused.

**Swapping** :class:`~pcapkit.protocols.link.link.Link` **for**
:class:`~pcapkit.protocols.application.application.Application` **is not name-for-name.**
Counting the names in each class's own namespace, whether new or overriding
:class:`~pcapkit.protocols.protocol.ProtocolBase`'s, and including those
:meth:`ProtocolBase.__init_subclass__ <pcapkit.protocols.protocol.ProtocolBase.__init_subclass__>`
sets there, :class:`~pcapkit.protocols.link.link.Link` has ``__data__``, ``__layer__``,
``__post_init__``, ``__proto__``, ``__proto_key__``, ``__schema__``, ``_read_protos``,
``_shipped_proto``, ``from_data``, ``register`` and ``layer``, and
:class:`~pcapkit.protocols.application.application.Application` has what they share
(``__data__``, ``__layer__``, ``__post_init__``, ``__schema__``, ``from_data``, ``layer``)
plus ``__index__``, ``_decode_next_layer`` and ``_import_next_layer``.
:class:`~pcapkit.protocols.link.link.Link` overrides names that
:class:`~pcapkit.protocols.application.application.Application` does not -- ``__proto__``,
``register``, ``_read_protos`` and ``_shipped_proto``, the last set because
:class:`~pcapkit.protocols.link.link.Link` defines its own ``__proto__`` -- and each of
those also exists on :class:`~pcapkit.protocols.protocol.ProtocolBase`, so each still
resolves on :class:`~pcapkit.protocols.application.ospf.protocol.OSPF`. The strict difference
:class:`~pcapkit.protocols.link.link.Link` minus
:class:`~pcapkit.protocols.application.application.Application` minus
:class:`~pcapkit.protocols.protocol.ProtocolBase` is ``__proto_key__`` alone, which
:class:`~pcapkit.protocols.link.link.Link` declares, as asked for on :pr:`2392` (no
issue holds the ruling), and neither of the others does, so it does **not** resolve on
:class:`~pcapkit.protocols.application.ospf.protocol.OSPF`. Nothing turns on that:
:func:`~pcapkit.foundation.registry.protocols.protocol.register_protocol_code` reads the pairing
out of the registry owner's own namespace rather than off the class, and reads its
absence as *declares no pairing*, not an error. What changes is the registry it
resolves *to*: ``OSPF.__proto__`` is
:attr:`ProtocolBase.__proto__ <pcapkit.protocols.protocol.ProtocolBase.__proto__>` rather
than :attr:`Link.__proto__ <pcapkit.protocols.link.link.Link.__proto__>`, so OSPF does not
see Link's EtherType entries. That is inert: nothing reaches OSPF by EtherType, and a
``-1`` lookup misses in both registries and resolves to
:class:`~pcapkit.protocols.misc.raw.protocol.Raw`, inserting nothing.
:class:`~pcapkit.protocols.application.rarp.protocol.RARP` keeps
:class:`~pcapkit.protocols.link.link.Link`'s through
:class:`~pcapkit.protocols.link.arp.protocol.ARP`.

Tie-Break Order
~~~~~~~~~~~~~~~

For a genuinely ambiguous protocol, in this order:

#. the protocol's own RFC's **functional self-description**;
#. the placement of its **closest functional peers** already in this package;
#. **encapsulation**, last.

Why Not OSI's Seven Layers
~~~~~~~~~~~~~~~~~~~~~~~~~~

Asked and declined on :issue:`719`. The public API already declares the four-layer
Internet model --
``Layers = Literal['link', 'internet', 'transport', 'application', 'none']`` in
:mod:`pcapkit.foundation.extraction` -- and the session and presentation layers have
no header on the wire and no IANA registry to dispatch on, so as subpackages they
would be empty. OSI also resolves neither case that prompted this
page: routing's control/data-plane split and L2TP's carrier/payload split exist
identically in both models.
