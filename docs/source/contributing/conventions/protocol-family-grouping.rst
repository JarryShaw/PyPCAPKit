.. _protocol-family-grouping:

Protocol Family Grouping
------------------------

A protocol family is a base class named after the family plus its member classes.
What the base and each member return from
:meth:`~pcapkit.protocols.protocol.Protocol.id` is what the selectors on
:class:`~pcapkit.protocols.protocol.Protocol` match against, so the tuples are
settled here rather than re-derived per family. Set on :pr:`2441`, :pr:`2443`,
:pr:`2446` and :issue:`2462`.

The ``id()`` Criterion
~~~~~~~~~~~~~~~~~~~~~~

**A family base lists its direct concrete subclasses.** An abstract intermediate is
left out, and so is everything beneath it, since that intermediate carries its own
tuple. :pr:`2441`.

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

**An abstract family name composes its members.**
:class:`~pcapkit.protocols.internet.ipv6_ext.IPv6_Ext` carries the family's name, so
its ``id()`` is to list its direct concrete members, and each member narrows its own
``id()`` to itself. :issue:`2462`.

Grouping by Name
~~~~~~~~~~~~~~~~

**Members share a base because they share a name, not a wire format.** HTTP/1 and
HTTP/2 share :class:`~pcapkit.protocols.application.http.HTTP`, IPv4 and IPv6 share
:class:`~pcapkit.protocols.internet.ip.IP`, and AH and ESP share
:class:`~pcapkit.protocols.internet.ipsec.IPsec`. A family base needs no dispatcher
logic: :class:`~pcapkit.protocols.internet.ip.IP` and
:class:`~pcapkit.protocols.internet.ipsec.IPsec` have none, and each member is bound
directly. :pr:`2441`.

.. _protocol-family-shapes:

Member Shapes
~~~~~~~~~~~~~

Pick a member's shape by how far a sibling's selector should reach.

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
     - :class:`~pcapkit.protocols.link.arp.ARP` ``('ARP',)`` reads the operation
       code and reports ARP, InARP, RARP or DRARP through
       :attr:`~pcapkit.protocols.protocol.Protocol.alias`;
       :class:`~pcapkit.protocols.link.arp.InARP` ``('InARP',)`` is a thin
       subclass that exists for explicit construction.
       :class:`~pcapkit.protocols.application.rarp.RARP` ``('RARP', 'DRARP')`` and
       :class:`~pcapkit.protocols.application.rarp.DRARP` ``('DRARP',)`` are
       separate classes, bound to EtherType ``0x8035``
       (:attr:`~pcapkit.const.reg.ethertype.EtherType.Reverse_Address_Resolution_Protocol`)

A family-inclusive member is selected by any sibling's registry key, because both
expand to the shared family name (see :ref:`below <protocol-family-selectors>`). A
narrow member is selected only by its own name and its family's key.

.. _protocol-family-canonical-names:

Canonical Names
~~~~~~~~~~~~~~~

**A class name may carry a version that the protocol's own name does not.** Where
the defining RFC names the protocol without a version, a versioned class and module
name may tell the members apart in code; ``id()`` is then expected to drop the
version for the RFC's canonical name, and
:attr:`~pcapkit.protocols.protocol.Protocol.name` to follow the RFC's title with no
version string. :pr:`2446`.

.. _protocol-family-selectors:

Selector Matching
~~~~~~~~~~~~~~~~~

**A family name selects every version, and each version name selects its own.**
:pr:`2443`. The narrow-to-self shape gives exactly that: ``'IP' in frame`` is
``True`` for an IPv4 frame and an IPv6 frame alike, and ``'IPv6' in frame`` is
``False`` for an IPv4 frame. Under the family-inclusive shape a version name also
selects its siblings, as the second bullet below shows for HTTP.

What a selector on a frame or a layer reaches is defined by
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
  layer's class and ``id()``, so an alias such as ``'HTTP/1.1'`` selects no layer:
  ``'HTTP/1.1' in frame`` is ``False``.

:class:`~pcapkit.corekit.protochain.ProtoChain` matches more widely: its
:meth:`~pcapkit.corekit.protochain.ProtoChain.index`,
:meth:`~pcapkit.corekit.protochain.ProtoChain.count` and ``in`` also compare each
layer's alias, so ``'HTTP/1.1' in frame.protochain`` is ``True``.

So adding a name to an ``id()`` tuple widens every ``in`` and ``[]`` selector that
can reach it; check the reach before choosing a shape.

No Invented Suffixes
~~~~~~~~~~~~~~~~~~~~

**The family base takes the family's own name.**
:class:`~pcapkit.protocols.internet.ip.IP`,
:class:`~pcapkit.protocols.internet.ipsec.IPsec`,
:class:`~pcapkit.protocols.application.http.HTTP`,
:class:`~pcapkit.protocols.link.vlan.VLAN` and
:class:`~pcapkit.protocols.link.l2tp.L2TP` are the precedent. No ``_Family`` base is
to be minted. A member that shares the family's protocol name may take a versioned
class name, as :ref:`above <protocol-family-canonical-names>`. :pr:`2446`.
