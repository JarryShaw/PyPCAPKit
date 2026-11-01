.. _protocol-family-grouping:

Protocol Family Grouping
------------------------

A protocol family is a base class named after the family plus its member classes.
What each class returns from :meth:`~pcapkit.protocols.protocol.Protocol.id` is what
the selectors on :class:`~pcapkit.protocols.protocol.Protocol` match against. The
rulings were set on :pr:`2441`, :pr:`2443`, :pr:`2446`, :issue:`2462` and :issue:`2517`.

The ``id()`` Criterion
~~~~~~~~~~~~~~~~~~~~~~

**A family base lists its direct concrete subclasses.** An abstract intermediate is
left out, and so is everything beneath it. :pr:`2441`.

The member list takes either of these forms:

* **Members only.** :meth:`IP.id() <pcapkit.protocols.internet.ip.IP.id>` is
  ``('IPv4', 'IPv6')``; :class:`~pcapkit.protocols.internet.ah.AH` and
  :class:`~pcapkit.protocols.internet.esp.ESP` are not in it, since they belong to
  the separate abstract :class:`~pcapkit.protocols.internet.ipsec.IPsec`, whose
  :meth:`~pcapkit.protocols.internet.ipsec.IPsec.id` is ``('AH', 'ESP')``.
  :meth:`HTTP.id() <pcapkit.protocols.application.http.HTTP.id>` is
  ``('HTTP/1', 'HTTP/2')``.
* **The base's own name, then the members.**
  :meth:`VLAN.id() <pcapkit.protocols.link.vlan.VLAN.id>` is
  ``('VLAN', 'C_Tag', 'S_Tag')`` and
  :meth:`L2TP.id() <pcapkit.protocols.link.l2tp.L2TP.id>` is ``('L2TP', 'L2TPv2')``.

:meth:`ARP.id() <pcapkit.protocols.link.arp.ARP.id>` is ``('ARP',)`` alone; see
:ref:`protocol-family-shapes`.

Abstract Family Names
~~~~~~~~~~~~~~~~~~~~~

**An abstract family name composes its members.** The ruling on :issue:`2462` is that
:class:`~pcapkit.protocols.internet.ipv6_ext.IPv6_Ext` lists its direct concrete
members in its ``id()``, and that each member narrows its own ``id()`` to itself.

Grouping by Name
~~~~~~~~~~~~~~~~

**Members share a base because they share a name, not a wire format.** HTTP/1 and
HTTP/2 share :class:`~pcapkit.protocols.application.http.HTTP`, IPv4 and IPv6 share
:class:`~pcapkit.protocols.internet.ip.IP`, and AH and ESP share
:class:`~pcapkit.protocols.internet.ipsec.IPsec`. :pr:`2441`.

:class:`~pcapkit.protocols.internet.ip.IP` and
:class:`~pcapkit.protocols.internet.ipsec.IPsec` define no ``read()``. The HTTP class
does, and a parsed HTTP/1.1 or HTTP/2 layer is the HTTP class itself.

.. _protocol-family-shapes:

Member Shapes
~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 22 38 40

   * - Shape
     - ``id()``
     - In the tree
   * - Narrow to self
     - the member's own name only
     - :class:`~pcapkit.protocols.internet.ah.AH` ``('AH',)``,
       :class:`~pcapkit.protocols.internet.esp.ESP` ``('ESP',)``;
       :class:`IGMPv2 <pcapkit.protocols.internet.igmpv2.IGMPv2>` ``('IGMPv2',)`` and
       :class:`IGMPv3 <pcapkit.protocols.internet.igmpv3.IGMPv3>` ``('IGMPv3',)`` --
       :class:`IGMPv1 <pcapkit.protocols.internet.igmpv1.IGMPv1>` narrows the same way,
       but to the RFC canonical name rather than a versioned one
       (:ref:`protocol-family-canonical-names`);
       :class:`HTTPv1 <pcapkit.protocols.application.httpv1.HTTP>` ``('HTTP/1',)``
       and :class:`HTTPv2 <pcapkit.protocols.application.httpv2.HTTP>`
       ``('HTTP/2',)``
   * - Family-inclusive
     - the member's label plus the family name
     - :class:`~pcapkit.protocols.link.c_tag.C_Tag` ``('C_Tag', 'VLAN')``,
       :class:`~pcapkit.protocols.link.s_tag.S_Tag` ``('S_Tag', 'VLAN')``;
       :class:`~pcapkit.protocols.link.l2tpv2.L2TPv2` ``('L2TP', 'L2TPv2')``
   * - One parser, dynamic alias
     - fixed, whichever protocol was read
     - :class:`~pcapkit.protocols.link.arp.ARP` ``('ARP',)`` reads the operation
       code and reports ARP, RARP, DRARP or InARP through
       :attr:`~pcapkit.protocols.protocol.Protocol.alias`

Nothing dispatches to :class:`~pcapkit.protocols.link.arp.InARP` ``('InARP',)``:
under EtherType ``0x0806``, operation 8 parses as ARP with alias ``InARP``.
Only :class:`~pcapkit.protocols.application.rarp.RARP` ``('RARP', 'DRARP')`` is bound
to EtherType ``0x8035``
(:attr:`~pcapkit.const.reg.ethertype.EtherType.Reverse_Address_Resolution_Protocol`).
A parsed RARP takes ``DRARP`` as its alias for operation 5, and
:class:`~pcapkit.protocols.application.drarp.DRARP` ``('DRARP',)`` inherits the
``__index__`` of RARP.

A family-inclusive member is selected by any sibling's registry key (a key of
``pcapkit.protocols.__proto__``), because each expands to the shared family name
(:ref:`below <protocol-family-selectors>`). A narrow member is selected by its own name
and by the key of each family whose ``id()`` lists it: ``AH`` and ``ESP`` by ``IPsec``
and by ``IPv6_Ext``, ``HTTPv1`` and ``HTTPv2`` by ``HTTP``.

Chained Records
~~~~~~~~~~~~~~~

**TLS records sharing a TCP segment are chained layers, not a list on one layer**
(:issue:`2517`): each record dissected after the first is the previous record's payload,
so its dynamic alias names its own version -- a ``ServerHello`` then a
``ChangeCipherSpec`` read ``TCP:TLS 1.3:TLS 1.2``. DTLS and SSLv2 do not chain: two DTLS
records in one datagram read ``DTLS 1.2:Raw`` (:issue:`2535`), and an SSLv2 hello
followed by a further record reads ``SSLv2:Raw``.

.. _protocol-family-canonical-names:

Canonical Names
~~~~~~~~~~~~~~~

**A versioned protocol's display name includes its version.** This is the stated
preference on :pr:`2444`, not a settled rule.
:class:`~pcapkit.protocols.link.l2tpv2.L2TPv2`'s ``name`` is
``Layer 2 Tunnelling Protocol version 2``. The HTTP/1.1 and HTTP/2 classes define no
``name`` of their own, so they report ``Hypertext Transfer Protocol``, which carries
no version.

**ICMPv4 is the case where the RFC's own name carries no version.** The ruling on
:pr:`2446`: ``ICMPv4`` keeps its versioned class and module name, but its ``id()``
drops the version for the RFC canonical name (:rfc:`792` names it plain ``ICMP``),
and its ``name`` carries no "version 4". ``ICMPv6`` keeps its own version, since
:rfc:`4443` names it with one.

**IGMPv1 follows the same shape, by the same reasoning** (:issue:`2439`, :pr:`2506`).
:rfc:`1112` names IGMPv1's protocol plain ``IGMP``, so
:meth:`IGMPv1.id() <pcapkit.protocols.internet.igmpv1.IGMPv1.id>` is ``('IGMP',)`` and
its ``alias`` is ``'IGMP'``, while
:meth:`IGMPv2.id() <pcapkit.protocols.internet.igmpv2.IGMPv2.id>` and
:meth:`IGMPv3.id() <pcapkit.protocols.internet.igmpv3.IGMPv3.id>` keep their own
versions, ``('IGMPv2',)`` and ``('IGMPv3',)``, since :rfc:`2236` and :rfc:`3376` name
them with one. The family base's ``id()`` follows:
:meth:`IGMP.id() <pcapkit.protocols.internet.igmp.IGMP.id>` is
``('IGMP', 'IGMPv2', 'IGMPv3')``, the family-inclusive shape, because IGMPv1's
canonical name and the family's own name are the same string -- the same shape
:meth:`ICMP.id() <pcapkit.protocols.internet.icmp.ICMP.id>` takes, ``('ICMP', 'ICMPv6')``.

**HTTP takes the RFC names as well** (:issue:`2524`). :rfc:`9113` names its protocol
``HTTP/2``, so :meth:`HTTPv2.id() <pcapkit.protocols.application.httpv2.HTTP.id>` is
``('HTTP/2',)``. :rfc:`9112` names ``HTTP/1.1``, but the HTTP/1 class also reads
messages declaring 1.0 or 0.9, so
:meth:`HTTPv1.id() <pcapkit.protocols.application.httpv1.HTTP.id>` is the major
version, ``('HTTP/1',)``, and ``alias`` carries the exact one. No member's name
is the family's, so :meth:`HTTP.id() <pcapkit.protocols.application.http.HTTP.id>`
lists the members alone, ``('HTTP/1', 'HTTP/2')``, the shape of
:meth:`IP.id() <pcapkit.protocols.internet.ip.IP.id>`.

.. _protocol-family-selectors:

Selector Matching
~~~~~~~~~~~~~~~~~

**A family name selects every version, and each version name selects its own.**
:pr:`2443`. On an IPv4 frame, ``'IP' in`` is ``True`` and ``'IPv6' in`` is ``False``.
On an IPv6 frame, ``'IP' in`` is ``True`` and ``'IPv4' in`` is ``False``.

HTTP does not separate its versions this way. A parsed HTTP/1.1 or HTTP/2 layer is
the family base, whose ``id()`` lists every member, so on either frame ``'HTTP/1' in``,
``'HTTP/2' in`` and the ``HTTPv1`` and ``HTTPv2`` keys are all ``True``; ``alias``
and ``version`` tell the versions apart.

What a selector on a frame or a layer reaches is defined by
:meth:`~pcapkit.protocols.protocol.Protocol.expand_comp`,
:meth:`~pcapkit.protocols.protocol.Protocol.__contains__`,
:meth:`~pcapkit.protocols.protocol.Protocol.__getitem__` and ``Protocol.__eq__``.
Selectors are case-insensitive: ``'ipv4' in`` an IPv4 frame is ``True``.

* **String** ``==`` compares against the class and its own ``id()`` only; the selector
  is not expanded. On a parsed IPv4 layer, ``ipv4 == 'IPv4'`` is ``True`` and
  ``ipv4 == 'IP'`` is ``False``. On a parsed C-Tag layer, ``== 'VLAN'`` is ``True``,
  since ``VLAN`` is in its ``id()``, and ``== 'S_Tag'`` is ``False``, though
  ``'S_Tag' in`` the layer is ``True``. On a parsed HTTP layer, ``== 'HTTP'`` is
  ``False``, since the base's ``id()`` lists only its members, though ``'HTTP' in``
  the layer is ``True``.
* ``in`` **and** ``[]`` expand the selector first. A registry key becomes its class
  plus that class's ``id()``, as does a class object, and a layer matches when any of
  those appears among its own class and ``id()``. So ``'S_Tag' in`` a C-Tag frame is
  ``True``: ``S_Tag`` expands to ``S_Tag`` and ``VLAN``, and the C-Tag layer's
  ``id()`` carries ``VLAN``.
* A string that is **not** a registry key is matched by name alone against each
  layer's class and ``id()``, so an alias such as ``'HTTP/1.1'`` selects no layer:
  ``'HTTP/1.1' in frame`` is ``False``.

:class:`~pcapkit.corekit.protochain.ProtoChain` matches more widely: its
:meth:`~pcapkit.corekit.protochain.ProtoChain.index`,
:meth:`~pcapkit.corekit.protochain.ProtoChain.count` and ``in`` also compare each
layer's alias, so ``'HTTP/1.1' in frame.protochain`` is ``True``.

No Invented Suffixes
~~~~~~~~~~~~~~~~~~~~

**The family base takes the family's own name.**
:class:`~pcapkit.protocols.internet.ip.IP`,
:class:`~pcapkit.protocols.internet.ipsec.IPsec`,
:class:`~pcapkit.protocols.application.http.HTTP`,
:class:`~pcapkit.protocols.link.vlan.VLAN` and
:class:`~pcapkit.protocols.link.l2tp.L2TP` are the precedent. No ``_Family`` suffix is
added (:pr:`2446`).

**A protocol class takes its module's name**, whatever its canonical name and
``id()``. The family base takes the family's name and a member its module's versioned
name: :mod:`~pcapkit.protocols.internet.igmpv1` holds
:class:`~pcapkit.protocols.internet.igmpv1.IGMPv1`, though its ``id()`` is ``('IGMP',)``
(:ref:`above <protocol-family-canonical-names>`). **A module holds one protocol
class.** :mod:`~pcapkit.protocols.protocol` is exempt: its
:class:`~pcapkit.protocols.protocol.ProtocolBase` and
:class:`~pcapkit.protocols.protocol.Protocol` are framework bases rather than
dissectors. Both ruled on :issue:`2529`.

The name match ignores case and underscores: :mod:`~pcapkit.protocols.link.c_tag` holds
:class:`~pcapkit.protocols.link.c_tag.C_Tag` and :mod:`~pcapkit.protocols.link.linux_sll1`
holds :class:`~pcapkit.protocols.link.linux_sll1.LinuxSLL1`. **The** ``schema/`` **and**
``data/`` **modules follow the same layout**: the top-level class takes the module's
name, and sub-structure classes such as
:class:`~pcapkit.protocols.schema.internet.igmpv3.Query` share its module. Ruled on
:issue:`2529`, where the classes that do not match yet are pending:
:class:`httpv1.HTTP <pcapkit.protocols.application.httpv1.HTTP>`,
:class:`httpv2.HTTP <pcapkit.protocols.application.httpv2.HTTP>`,
:class:`arp.InARP <pcapkit.protocols.link.arp.InARP>`,
:class:`tls.SSLv3 <pcapkit.protocols.application.tls.SSLv3>` and
:class:`null.NoPayload <pcapkit.protocols.misc.null.NoPayload>`.
