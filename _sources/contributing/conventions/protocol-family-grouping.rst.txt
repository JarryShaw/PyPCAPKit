.. _protocol-family-grouping:

Protocol Family Grouping
------------------------

A protocol family is a base class named after the family plus its member classes.
What each class returns from :meth:`~pcapkit.protocols.protocol.Protocol.id` is what
the selectors on :class:`~pcapkit.protocols.protocol.Protocol` match against. Each
ruling below names the thread it was set on.

The ``id()`` Criterion
~~~~~~~~~~~~~~~~~~~~~~

**A family base lists its direct concrete subclasses.** An abstract intermediate is
left out, and so is everything beneath it. Ruled in review of :pr:`2441`; no issue
holds the ruling.

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
:class:`~pcapkit.protocols.internet.ip.IP`, AH and ESP share
:class:`~pcapkit.protocols.internet.ipsec.IPsec`, and SSLv2 and SSLv3 share
:class:`~pcapkit.protocols.application.ssl.SSL` (:ref:`below <protocol-family-ssl>`).
Ruled in review of :pr:`2441`; no issue holds the ruling.

.. _protocol-family-ssl:

The SSL Family
~~~~~~~~~~~~~~

**SSLv2 and SSLv3 share a base by name, though only SSLv3 shares TLS's record
layer.** The owner asked on :pr:`2441` for this grouping to be recorded here; no issue
holds the ruling. By the ``id()`` criterion,
:meth:`SSL.id() <pcapkit.protocols.application.ssl.SSL.id>` is
``('SSLv2', 'TLS', 'DTLS')``, without SSLv3, which subclasses TLS.

**One** :class:`~pcapkit.protocols.application.tls.TLS` **class reads SSLv3 through
TLS 1.3**, in the ARP shape (:ref:`protocol-family-shapes`): ``id()`` stays
``('TLS',)`` and ``alias`` names the version read. Only record version ``0x0300`` is
branded SSLv3, in ``name`` as well as ``alias``; every later version is TLS.
:class:`~pcapkit.protocols.application.sslv3.SSLv3` ``('SSLv3',)`` narrows ``id()`` and
nothing else, as :class:`~pcapkit.protocols.link.inarp.InARP` does under ARP, and nothing
dispatches to it: an SSLv3 record on TCP port 443 parses as TLS with alias ``SSLv3``.
:class:`~pcapkit.protocols.application.dtls.DTLS` ``('DTLS',)`` reads DTLS 1.0, 1.2 and
1.3 the same way.

TCP port 443 binds TLS and UDP port 5684 binds DTLS.
:class:`~pcapkit.protocols.application.sslv2.SSLv2` ``('SSLv2',)`` is bound to no port:
on 443, TLS offers SSLv2 a segment whose first record it rejects, and a record SSLv2
takes stays a TLS layer with alias ``SSLv2``. So ``'SSL' in`` selects both TLS and
DTLS layers, while ``'SSLv3' in`` and ``'SSLv2' in`` select no layer port 443 parsed;
only ``frame.protochain`` matches those two, by alias.

.. _protocol-family-dispatch:

Dispatching Bases
~~~~~~~~~~~~~~~~~

**A registry binds a family's base only where its code cannot tell the members apart,
and there the base picks the member.** IP protocol number 2 is IGMP's in every version,
and the TCP and UDP ports bound to HTTP are the family's, so
:class:`~pcapkit.protocols.internet.igmp.IGMP`'s ``_dispatch`` and
:meth:`~pcapkit.protocols.application.http.HTTP._dispatch_version` read the octets to
choose. Every registry that reaches IPv4, IPv6, AH, ESP, TLS or DTLS has a code for
that member alone, so no registry binds :class:`~pcapkit.protocols.internet.ip.IP`,
:class:`~pcapkit.protocols.internet.ipsec.IPsec` or
:class:`~pcapkit.protocols.application.ssl.SSL`, and none of the three defines
``read()``: none needs a dispatcher there. Ruled for IGMP on :pr:`2444` and for SSL on
:pr:`2441`; no issue holds either ruling. The asymmetry is deliberate, and it concerns
the registry only; parsing or building through a base directly is the rule below.

**A versioned family's base dispatches on both paths** (:issue:`2524`). Parsing
octets through it, constructing it from fields and its ``from_data`` give a member,
never an instance of the base, and a subclass of the base is constructed as itself.

**The member is the one the** ``version`` **keyword names, or else the one the octets
or the data model carry, and never one a field picks.** ``version`` names the member
on either path, unchecked against the octets it is given; where their format carries
a version, the member's own parser refuses another's. Without it, octets give the
member the version they carry, where the format has one, and ``from_data`` reads the
data model's class or its ``version``, as the table below gives. No field picks a
member, not even a field only one member takes, and no member is a default: fields
without ``version`` raise :exc:`~pcapkit.utilities.exceptions.ProtocolError`, and a
field the member does not take fails that member's own keyword check. Ruled on
:issue:`2574`. A class built directly takes ``version`` as well, which must then be
its own version: a member's, or, for a subclass outside the members, the one an IGMP
class states in its ``version``, which a subclass of the other bases does not have.
While parsing, the keyword is handed on unread, since an IP layer passes its own
version under that name to the layer it carries.

.. list-table::
   :header-rows: 1
   :widths: 13 15 42 30

   * - Base
     - ``version``
     - Octets without ``version``
     - ``from_data``
   * - :class:`~pcapkit.protocols.application.http.HTTP`
     - ``1``, ``2``
     - :meth:`~pcapkit.protocols.application.http.HTTP._dispatch_version`: the
       connection preface, a start line or a frame header
     - the data model; a :obj:`dict` is refused
   * - :class:`~pcapkit.protocols.internet.igmp.IGMP`
     - ``1``, ``2``, ``3``
     - :meth:`~pcapkit.protocols.internet.igmp.IGMP._dispatch`: type, max response
       time and length, placed by
       :meth:`~pcapkit.protocols.internet.igmp.IGMP._classify`
     - ``version``, which each IGMP data model carries though no octet does,
       ruled on :issue:`2574`
   * - :class:`~pcapkit.protocols.internet.ip.IP`
     - ``4``, ``6``
     - the Version nibble
     - ``version``
   * - :class:`~pcapkit.protocols.internet.icmp.ICMP`
     - ``4``, ``6``
     - refused, below
     - the data model; a :obj:`dict` is refused
   * - :class:`~pcapkit.protocols.link.l2tp.L2TP`
     - ``2``
     - the version nibble
     - ``version``
   * - :class:`~pcapkit.protocols.link.linux_sll.LinuxSLL`
     - ``1``, ``2``
     - refused, below
     - the data model; a :obj:`dict` is refused

HTTP octets carry their version, but the HTTP data models have no top-level
``version`` field, only HTTP/1's ``receipt.version`` string, so
:meth:`HTTP.from_data <pcapkit.protocols.application.http.HTTP.from_data>` reads the
data model's class. It refuses a :obj:`dict` even though the ``receipt`` and ``sid``
keys would tell the members apart, since no key picks a member (:issue:`2628`).

**Octets that carry no version are refused through the base without** ``version``
(:issue:`2574`). An ICMP message and a Linux cooked-capture header have no version
field: the enclosing layer names it, by IP protocol number 1 or 58 and by link type
113 or 276, and those registries bind the members. So ``ICMP(...)`` and
``LinuxSLL(...)`` on octets raise :exc:`~pcapkit.utilities.exceptions.ProtocolError`
rather than guess, as does their ``from_data`` on a :obj:`dict`, whose keys pick no
member. A version a family has no member for, such as L2TP's ``1`` (L2F) and ``3``,
raises the same way.

**Octets neither version takes**, a frameless HTTP/2 connection preface among them,
are :class:`~pcapkit.protocols.misc.raw.Raw` with no ``error`` on the transport path,
and a direct ``HTTP(...)`` on them raises
:exc:`~pcapkit.utilities.exceptions.ProtocolError` (:issue:`2524`). Octets the
dispatcher gives :class:`~pcapkit.protocols.application.httpv2.HTTPv2` that its parser
then refuses, such as a preface and three octets, are
:class:`~pcapkit.protocols.misc.raw.Raw` with the parser's ``error``.

.. _protocol-family-refusals:

Handled Refusals
~~~~~~~~~~~~~~~~

**A refusal a next-layer fallback handles is quiet**, for every protocol and not only
a family's members (:issue:`2588`). The fallback is
:func:`~pcapkit.corekit.decorators.beholder`. It decorates
:meth:`Protocol._import_next_layer <pcapkit.protocols.protocol.Protocol._import_next_layer>`
and the overrides that parse a next layer themselves.
:meth:`Application._import_next_layer
<pcapkit.protocols.application.application.Application._import_next_layer>` and
:meth:`TLS._import_next_layer <pcapkit.protocols.application.tls.TLS._import_next_layer>`
are not decorated: they delegate to decorated methods, the base's or TLS's
``_import_next_record``. The decorated call runs inside a
:class:`~pcapkit.utilities.exceptions.CaughtByCaller` block naming
:exc:`~pcapkit.utilities.exceptions.ProtocolError`. A refused layer, the HTTP/2 case
above or a GRE header of a nonzero version, is then recorded on the ``error`` of the
:class:`~pcapkit.protocols.misc.raw.Raw` that replaces it, and nowhere else: nothing
reaches the ``pcapkit`` logger at any level, and neither :func:`sys.excepthook` nor
:func:`threading.excepthook` is replaced. A refusal the parser handles is the control
flow :class:`~pcapkit.utilities.exceptions.BaseError`'s quiet mode exists for, and
installing a hook from an error the library caught itself is a process-wide side
effect.

A parse whose refusal a fallback absorbs without
:func:`~pcapkit.corekit.decorators.beholder` follows the same rule through an explicit
``CaughtByCaller(ProtocolError)`` around it, as
:meth:`DTLS.analyze_handshake <pcapkit.protocols.application.dtls.DTLS.analyze_handshake>`
keeps a body that does not decode raw -- an application of :issue:`2588`'s rule rather
than a ruling of its own.

**The block spans the whole call to the next layer**, not the refusal alone. Every
:exc:`~pcapkit.utilities.exceptions.ProtocolError` built while that call is on the
stack is quiet, at any depth, unless an inner
:class:`~pcapkit.utilities.exceptions.CaughtByCaller` says otherwise:

* one a parser below catches itself, such as the ``supported_versions`` peek of
  :meth:`SSL._tls_negotiates <pcapkit.protocols.application.ssl.SSL._tls_negotiates>`
  or TLS's SSLv2 trial, which is then recorded nowhere;
* one reporting library state rather than the octets, such as a
  :class:`~pcapkit.corekit.module.ModuleDescriptor` entry whose class its module has
  since lost -- by a later removal, or by a write to ``__proto__`` directly, since
  :func:`~pcapkit.foundation.registry.protocols.transport.register_tcp` refuses such an entry --
  which ends as the ``Raw`` layer's ``error``;
* one raised by an inner fallback's recovery, since the block of the fallback around
  it is still active.

What stays loud:

* **Building the refusing layer directly.** ``GRE(...)`` or ``IPv4(...)`` on the same
  octets raises an error that logs at :data:`logging.CRITICAL` and, outside development
  mode, installs the hooks.
* **Any other error class.** An error the fallback absorbs is as loud as it was
  constructed, and :func:`~pcapkit.corekit.decorators.beholder` logs it at
  :data:`logging.WARNING` as well. Inside a payload
  :meth:`Protocol._make_payload <pcapkit.protocols.protocol.Protocol._make_payload>`
  rebuilds, it is quiet, as the owner ruled on :issue:`2711`: the layer the payload
  is rebuilt for parses the same octets again and reports it there, once.
* **A refusal built under an inner** ``CaughtByCaller()``. A block naming no class,
  such as the one :meth:`~pcapkit.corekit.enum.EnumRegistry.register` enters, makes
  errors loud again inside the fallback's.
* **The outermost fallback's recovery.** Reading the payload and building the ``Raw``
  run after the block has ended, so under the outermost
  :func:`~pcapkit.corekit.decorators.beholder` of a parse an error raised there reaches
  the caller loud. Each block restores the one around it on exit, so none outlives
  that parse.

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
       :class:`HTTPv1 <pcapkit.protocols.application.httpv1.HTTPv1>` ``('HTTP/1',)``
       and :class:`HTTPv2 <pcapkit.protocols.application.httpv2.HTTPv2>`
       ``('HTTP/2',)``; :class:`~pcapkit.protocols.application.sslv2.SSLv2`
       ``('SSLv2',)``
   * - Family-inclusive
     - the member's label plus the family name
     - :class:`~pcapkit.protocols.link.c_tag.C_Tag` ``('C_Tag', 'VLAN')``,
       :class:`~pcapkit.protocols.link.s_tag.S_Tag` ``('S_Tag', 'VLAN')``;
       :class:`~pcapkit.protocols.link.l2tpv2.L2TPv2` ``('L2TP', 'L2TPv2')``
   * - One parser, dynamic alias
     - fixed, whichever protocol was read
     - :class:`~pcapkit.protocols.link.arp.ARP` ``('ARP',)`` reads the operation
       code and reports ARP, RARP, DRARP or InARP through
       :attr:`~pcapkit.protocols.protocol.Protocol.alias`;
       :class:`~pcapkit.protocols.application.tls.TLS` ``('TLS',)`` reports SSLv3 or a
       TLS version, and :class:`~pcapkit.protocols.application.dtls.DTLS`
       ``('DTLS',)`` a DTLS version (:ref:`protocol-family-ssl`)

Nothing dispatches to :class:`~pcapkit.protocols.link.inarp.InARP` ``('InARP',)``:
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
and by the key of each family whose ``id()`` lists it: ``HTTPv1`` and ``HTTPv2`` by
``HTTP``, and ``AH`` and ``ESP`` by ``IPsec`` and by ``IPv6_Ext`` where IPv4 carries
them. Under IPv6 they are no layer of their own but entries of
:attr:`IPv6.extension_headers <pcapkit.protocols.internet.ipv6.IPv6.extension_headers>`,
so on an ``Ethernet:IPv6:AH`` frame ``'AH' in``, ``'IPsec' in`` and ``'IPv6_Ext' in``
are all ``False``; only ``frame.protochain`` matches them.

Chained Records
~~~~~~~~~~~~~~~

**TLS and SSLv2 records sharing a TCP segment, and DTLS records sharing a UDP datagram,
are chained layers, not a list on one layer** (:issue:`2517`, :issue:`2567`,
:issue:`2535`): each record dissected after the first is the previous record's payload,
so a TLS or DTLS record's dynamic alias names its own version -- a ``ServerHello`` then a
``ChangeCipherSpec`` read ``TCP:TLS 1.3:TLS 1.2``, and a DTLS 1.2 record then a DTLS 1.3
unified-header record read ``UDP:DTLS 1.2:DTLS 1.3`` -- and an SSLv2 ``CLIENT-HELLO``
then a ``CLIENT-MASTER-KEY`` read ``TCP:SSLv2:SSLv2``.

**HTTP/2 frames chain the same way** (:issue:`2536`): a ``SETTINGS`` frame then a
``WINDOW_UPDATE`` read ``TCP:HTTP/2:HTTP/2``. A later whole frame that fails to decode
is :class:`~pcapkit.protocols.misc.raw.Raw` with the rest of the segment and the
parser's ``error``, a frame the segment ends inside stays
:class:`~pcapkit.protocols.misc.raw.Raw` with none, and ``protocol=``, ``layer=`` and
:data:`~pcapkit.utilities.config.FRAME_LAYER_LIMIT` stop the chain, as for TLS.

.. _protocol-family-canonical-names:

Canonical Names
~~~~~~~~~~~~~~~

**A versioned protocol's display name includes its version.** This is the preference
stated in review of :pr:`2444`, not a settled rule; no issue holds it.
:class:`~pcapkit.protocols.link.l2tpv2.L2TPv2`'s ``name`` is
``Layer 2 Tunnelling Protocol version 2``. The HTTP/1.1 and HTTP/2 classes define no
``name`` of their own, so they report ``Hypertext Transfer Protocol``, which carries
no version.

**ICMPv4 is the case where the RFC's own name carries no version.** Ruled in review
of :pr:`2446` (:issue:`2436`): ``ICMPv4`` keeps its versioned class and module name,
but its ``id()`` drops the version for the RFC canonical name (:rfc:`792` names it
plain ``ICMP``), and its ``name`` carries no "version 4". ``ICMPv6`` keeps its own
version, since :rfc:`4443` names it with one.

**IGMPv1 follows the same shape, by the same reasoning**, ruled in review of
:pr:`2506`; no issue holds the ruling.
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
``HTTP/2``, so :meth:`HTTPv2.id() <pcapkit.protocols.application.httpv2.HTTPv2.id>` is
``('HTTP/2',)``. :rfc:`9112` names ``HTTP/1.1``, but the HTTP/1 class also reads
messages declaring 1.0 or 0.9, so
:meth:`HTTPv1.id() <pcapkit.protocols.application.httpv1.HTTPv1.id>` is the major
version, ``('HTTP/1',)``, and ``alias`` carries the exact one. No member's name
is the family's, so :meth:`HTTP.id() <pcapkit.protocols.application.http.HTTP.id>`
lists the members alone, ``('HTTP/1', 'HTTP/2')``, the shape of
:meth:`IP.id() <pcapkit.protocols.internet.ip.IP.id>`.

.. _protocol-family-selectors:

Selector Matching
~~~~~~~~~~~~~~~~~

**A family name selects every version, and each version name selects its own.**
Ruled in review of :pr:`2443` (:issue:`2438`). On an IPv4 frame, ``'IP' in`` is
``True`` and ``'IPv6' in`` is ``False``. On an IPv6 frame, ``'IP' in`` is ``True``
and ``'IPv4' in`` is ``False``.

HTTP follows it too (:issue:`2524`). On an HTTP/1.1 frame, ``'HTTP' in`` and
``'HTTP/1' in`` are ``True`` and ``'HTTP/2' in`` is ``False``, since the layer is
:class:`~pcapkit.protocols.application.httpv1.HTTPv1`; an HTTP/2 frame is the reverse.

What a selector on a frame or a layer reaches is defined by
:meth:`~pcapkit.protocols.protocol.Protocol.expand_comp`,
:meth:`~pcapkit.protocols.protocol.Protocol.__contains__`,
:meth:`~pcapkit.protocols.protocol.Protocol.__getitem__` and ``Protocol.__eq__``.
Selectors are case-insensitive: ``'ipv4' in`` an IPv4 frame is ``True``.

* **String** ``==`` compares against the class and its own ``id()`` only; the selector
  is not expanded. On a parsed IPv4 layer, ``ipv4 == 'IPv4'`` is ``True`` and
  ``ipv4 == 'IP'`` is ``False``. On a parsed C-Tag layer, ``== 'VLAN'`` is ``True``,
  since ``VLAN`` is in its ``id()``, and ``== 'S_Tag'`` is ``False``, though
  ``'S_Tag' in`` the layer is ``True``. On a parsed HTTP/1.1 layer, ``== 'HTTP/1'`` is
  ``True`` and ``== 'HTTP'`` is ``False``, since no member's ``id()`` carries
  ``HTTP``, though ``'HTTP' in`` the layer is ``True``.
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
added, as ruled in review of :pr:`2446` (:issue:`2436`).

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
:issue:`2529`.
