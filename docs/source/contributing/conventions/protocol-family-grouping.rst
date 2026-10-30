.. _protocol-family-grouping:

Protocol Family Grouping
------------------------

A protocol family is a base class named after the family plus its member classes.
What the base and each member return from
:meth:`~pcapkit.protocols.protocol.Protocol.id` decides what every selector matches,
so the tuples are settled here rather than re-derived per family. Set on
:issue:`2441`, :issue:`2446` and :issue:`2462`.

The ``id()`` Criterion
~~~~~~~~~~~~~~~~~~~~~~

**A family base lists its direct concrete subclasses, and nothing else.** An abstract
intermediate is left out, and so is everything beneath it, since that intermediate
carries its own tuple. :issue:`2441`.

* :meth:`IP.id() <pcapkit.protocols.internet.ip.IP.id>` is ``('IPv4', 'IPv6')``.
  :class:`~pcapkit.protocols.internet.ah.AH` and
  :class:`~pcapkit.protocols.internet.esp.ESP` are not in it: they belong to the
  separate abstract :class:`~pcapkit.protocols.internet.ipsec.IPsec`.
* :meth:`IPsec.id() <pcapkit.protocols.internet.ipsec.IPsec.id>` is
  ``('AH', 'ESP')``.

Abstract Family Names
~~~~~~~~~~~~~~~~~~~~~

**A family name composes its members even when the base also parses.**
:class:`~pcapkit.protocols.internet.ipv6_ext.IPv6_Ext` is concrete -- it is the
fallback :class:`~pcapkit.protocols.internet.ipv6.IPv6` substitutes when a dedicated
extension-header parser fails -- but its name is the family's, so its ``id()`` is to
list its direct concrete members, and each member narrows its own ``id()`` to itself.
:issue:`2462`.

The rejected alternative gave the base only its own name, because it also parses
``Shim6``, which has no member class and which every member's name would then select.
That case ends once ``Shim6`` gets its own parser, so the ruling does not wait for it.

One consequence is accepted: once composed, an
:class:`~pcapkit.protocols.internet.ipv6_ext.IPv6_Ext` standing in for a header whose
own parser failed matches every member's name.

Grouping by Name and History
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Members share a base because they share a name and a lineage, not a wire format.**
SSL is the case that settled it: its family covers every SSL version, TLS (a rebrand
of SSL) and DTLS, although the SSL versions are not wire-compatible with each other.
The same reading puts HTTP/1 and HTTP/2 under
:class:`~pcapkit.protocols.application.http.HTTP`, IPv4 and IPv6 under
:class:`~pcapkit.protocols.internet.ip.IP`, and AH and ESP under
:class:`~pcapkit.protocols.internet.ipsec.IPsec`. :issue:`2441`.

Shared parsing code is an implementation detail and does not decide the grouping.
Nor does a family base need dispatcher logic: :class:`~pcapkit.protocols.internet.ip.IP`
and :class:`~pcapkit.protocols.internet.ipsec.IPsec` have none, and each member is
bound directly. :class:`~pcapkit.protocols.application.http.HTTP` dispatches
because it has to guess a version its wire format does not state, not because it is
a family base.

Member Shapes
~~~~~~~~~~~~~

Three shapes are in use. Pick by how far a sibling's selector should reach.

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
     - :class:`~pcapkit.protocols.link.c_tag.C_Tag` ``('C_Tag', 'VLAN')`` and
       :class:`~pcapkit.protocols.link.s_tag.S_Tag`;
       :class:`HTTPv1 <pcapkit.protocols.application.httpv1.HTTP>`
       ``('HTTP', 'HTTPv1')`` and
       :class:`HTTPv2 <pcapkit.protocols.application.httpv2.HTTP>`;
       :class:`~pcapkit.protocols.link.l2tpv2.L2TPv2` ``('L2TP', 'L2TPv2')``
   * - One parser, dynamic alias
     - fixed, whichever protocol was read
     - :class:`~pcapkit.protocols.link.arp.ARP` ``('ARP',)`` parses ARP, InARP,
       RARP and DRARP and reports which through
       :attr:`~pcapkit.protocols.protocol.Protocol.alias`;
       :class:`~pcapkit.protocols.link.arp.InARP` ``('InARP',)`` is a thin
       subclass that exists for explicit construction

A family-inclusive member is selected by any sibling's registry key, because both
expand to the shared family name (see :ref:`below <protocol-family-selectors>`). A
narrow member is selected only by its own name and its family's key.

.. _protocol-family-canonical-names:

Canonical Names
~~~~~~~~~~~~~~~

**A class name may carry a version that the protocol's own name does not.** Where
the defining RFC names the protocol without a version, a versioned class and module
name are fine for telling the members apart in code, but ``id()`` returns the RFC's
canonical name and :attr:`~pcapkit.protocols.protocol.Protocol.name` follows the
RFC's title, with no version string added. :issue:`2446`.

.. _protocol-family-selectors:

Selector Matching
~~~~~~~~~~~~~~~~~

What a selector reaches is defined by
:meth:`~pcapkit.protocols.protocol.Protocol.expand_comp`,
:meth:`~pcapkit.protocols.protocol.Protocol.__contains__`,
:meth:`~pcapkit.protocols.protocol.Protocol.__getitem__` and ``Protocol.__eq__``.
All comparisons are case-insensitive.

* **String** ``==`` compares against the class and its own ``id()`` only; the
  selector is not expanded. On a parsed IPv4 layer, ``ipv4 == 'IPv4'`` is ``True``
  and ``ipv4 == 'IP'`` is ``False``.
* ``in`` **and** ``[]`` expand the selector first. A registry key becomes its class
  plus that class's ``id()``, as does a class object, and a layer matches when any
  of those appears among its own class and ``id()``. So ``'IP' in frame`` is
  ``True`` for an IPv4 frame, and ``'HTTPv2' in frame`` is ``True`` for an HTTP/1.1
  frame, since both sides carry ``'HTTP'``.
* A string that is **not** a registry key is matched by name alone against each
  layer's ``id()``. An alias such as ``'HTTP/1.1'`` matches nothing.

So adding a name to an ``id()`` tuple widens every ``in`` and ``[]`` selector that
can reach it; check the reach before choosing a shape.

No Invented Suffixes
~~~~~~~~~~~~~~~~~~~~

**The family base takes the family's own name.**
:class:`~pcapkit.protocols.internet.ip.IP`,
:class:`~pcapkit.protocols.internet.ipsec.IPsec`,
:class:`~pcapkit.protocols.application.http.HTTP`,
:class:`~pcapkit.protocols.link.vlan.VLAN` and
:class:`~pcapkit.protocols.link.l2tp.L2TP` are the precedent. No ``_Family`` base
exists, and none is to be minted. Where a member already holds the family name, the
member takes its versioned class name instead, as :ref:`above
<protocol-family-canonical-names>`. :issue:`2446`.
