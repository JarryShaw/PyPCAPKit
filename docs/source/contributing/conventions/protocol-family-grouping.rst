.. _protocol-family-grouping:

Protocol Family Grouping
------------------------

A protocol family is a base class named after the family plus its member classes.
What each class returns from :meth:`~pcapkit.protocols.protocol.Protocol.id` is what
the selectors on :class:`~pcapkit.protocols.protocol.Protocol` match against. The
rulings were set on :pr:`2441`, :pr:`2443`, :pr:`2446` and :issue:`2462`.

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
* **The base's own name, then the members.**
  :meth:`VLAN.id() <pcapkit.protocols.link.vlan.VLAN.id>` is
  ``('VLAN', 'C_Tag', 'S_Tag')``,
  :meth:`L2TP.id() <pcapkit.protocols.link.l2tp.L2TP.id>` is ``('L2TP', 'L2TPv2')``
  and :meth:`HTTP.id() <pcapkit.protocols.application.http.HTTP.id>` is
  ``('HTTP', 'HTTPv1', 'HTTPv2')``.

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
       :class:`~pcapkit.protocols.internet.esp.ESP` ``('ESP',)``
   * - Family-inclusive
     - the member's label plus the family name
     - :class:`~pcapkit.protocols.link.c_tag.C_Tag` ``('C_Tag', 'VLAN')``,
       :class:`~pcapkit.protocols.link.s_tag.S_Tag` ``('S_Tag', 'VLAN')``;
       :class:`HTTPv1 <pcapkit.protocols.application.httpv1.HTTP>`
       ``('HTTP', 'HTTPv1')`` and
       :class:`HTTPv2 <pcapkit.protocols.application.httpv2.HTTP>`
       ``('HTTP', 'HTTPv2')``;
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
:class:`~pcapkit.protocols.application.rarp.DRARP` ``('DRARP',)`` inherits the
``__index__`` of RARP.

A family-inclusive member is selected by any sibling's registry key (a key of
``pcapkit.protocols.__proto__``), because each expands to the shared family name
(:ref:`below <protocol-family-selectors>`). A narrow member is selected by its own name
and by the key of each family whose ``id()`` lists it: ``AH`` and ``ESP`` by ``IPsec``
and by ``IPv6_Ext``.

.. _protocol-family-canonical-names:

Canonical Names
~~~~~~~~~~~~~~~

**A versioned protocol's display name includes its version.** This is the stated
preference on :pr:`2444`, not a settled rule.
:class:`~pcapkit.protocols.link.l2tpv2.L2TPv2`'s ``name`` is
``Layer 2 Tunnelling Protocol version 2``. The HTTP/1.1 and HTTP/2 classes define no
``name`` of their own, so they report ``Hypertext Transfer Protocol``, which carries
no version.

**ICMPv4 is the case where the RFC's own name carries no version.** The owner's
reply on :pr:`2446` proposes that ``ICMPv4`` keeps its versioned class and module name,
that its ``id()`` should probably drop the version for the RFC canonical name, and
that its ``name`` carries no "version 4", following RFC 792. It is a proposal, not a
ruling.

.. _protocol-family-selectors:

Selector Matching
~~~~~~~~~~~~~~~~~

**A family name selects every version, and each version name selects its own.**
:pr:`2443`. On an IPv4 frame, ``'IP' in`` is ``True`` and ``'IPv6' in`` is ``False``.
On an IPv6 frame, ``'IP' in`` is ``True`` and ``'IPv4' in`` is ``False``.

What a selector on a frame or a layer reaches is defined by
:meth:`~pcapkit.protocols.protocol.Protocol.expand_comp`,
:meth:`~pcapkit.protocols.protocol.Protocol.__contains__`,
:meth:`~pcapkit.protocols.protocol.Protocol.__getitem__` and ``Protocol.__eq__``.
Selectors are case-insensitive: ``'ipv4' in`` an IPv4 frame is ``True``.

* **String** ``==`` compares against the class and its own ``id()`` only; the selector
  is not expanded. On a parsed IPv4 layer, ``ipv4 == 'IPv4'`` is ``True`` and
  ``ipv4 == 'IP'`` is ``False``. On a parsed C-Tag layer, ``== 'VLAN'`` is ``True``,
  since ``VLAN`` is in its ``id()``, and ``== 'S_Tag'`` is ``False``, though
  ``'S_Tag' in`` the layer is ``True``.
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
added (:pr:`2446`). A member may take a versioned class name, as
:ref:`above <protocol-family-canonical-names>` describes.
