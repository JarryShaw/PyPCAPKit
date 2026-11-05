.. _protocol-member-order:

Protocol Member Order
---------------------

The order of members inside a protocol class body. Settled by the owner on
:issue:`2490`, so a new dissector and a refactor land in the same layout.

Each group sits under its section comment, spelled as the repo spells it:
``# Properties.``, ``# Methods.``, ``# Data models.`` and ``# Utilities.``

The Order
~~~~~~~~~

#. **Properties.** Every ``@property`` member.
#. **Methods.** Public methods: mostly ``id()``, ``read()``, ``make()`` and
   ``register_xxx()``.
#. **Data models.** Every dunder name: ``__index__``, ``__length_hint__``,
   ``__init__``, ``__new__``, ``__post_init__`` and any other.
#. **Utilities.** Everything else, mostly private methods, in the subgroups below.
   Every private helper, including ``_check_*``, sits here, after ``_make_data()``.

   a. **Data.** ``_make_data()`` comes first.
   b. **Helpers.** The helpers that ``read()`` or ``make()`` call, one helper at a
      time, in the order ``read()`` or ``make()`` first uses them. "Uses" means a
      direct reference in the body of ``read()`` or ``make()``. Helpers reached only
      through ``getattr``, or through the registry maps (``__proto__``,
      ``__option__``, ``__parameter__`` and similar), do not count. They are ordered
      by the enum value order of the corresponding code, or by the registry's order
      where there is no enum. A registry fallback that ``read()`` or ``make()``
      names directly, such as ``_read_msg_unknown()`` in
      :class:`~pcapkit.protocols.internet.mh.protocol.MH`, does not count either: it is a
      specific reader, ruled on :issue:`2490`. Each helper's
      ``_read_`` and ``_make_`` methods stay together, with the reader first:
      ``_read_addr_resolve()`` then ``_make_addr_resolve()``.
   c. **Specific readers and makers.** The option, type and parameter methods,
      all ``_read_*()`` before all ``_make_*()``. Each set opens with the registry's
      default, its fallback for a code with no entry of its own, as
      ``_read_opt_unassigned()`` opens the readers of
      :class:`~pcapkit.protocols.internet.ipv4.protocol.IPv4`; the rest follow the enum value
      of the code or type each handles, not alphabetical order. Ruled on
      :issue:`2490`. A class with several registries puts every registry's readers
      before any registry's makers, as :class:`~pcapkit.protocols.internet.mh.protocol.MH`
      and :class:`~pcapkit.protocols.misc.pcapng.protocol.PCAPNG` do, ruled on
      :issue:`2772`.
   d. **Other helpers.** Every helper that ``read()``, ``make()`` and the registries
      do not reach goes last, including one that only another helper calls, such as
      ``_decode_text()`` in :class:`~pcapkit.protocols.application.httpv1.protocol.HTTPv1`.
      Ruled on :issue:`2490`.

**Registry maps.** The registry maps themselves (``__proto__``, ``__option__``,
``__parameter__`` and similar) are ordered by their enum values, by key value where
an :class:`int` key has no enum, and alphabetically where the key is a string, as the
namespaces of
:attr:`Option.__enum__ <pcapkit.protocols.misc.pcapng.schema.Option.__enum__>` are.
:attr:`PCAPNG.__option__ <pcapkit.protocols.misc.pcapng.protocol.PCAPNG.__option__>`,
keyed by an option's namespace and value, is ordered by namespace, in the order
:class:`~pcapkit.const.pcapng.option_type.OptionType` declares them, then by value.
Ruled on :issue:`2772`.
:attr:`ProtocolBase.__registry__ <pcapkit.protocols.protocol.ProtocolBase.__registry__>`
groups its built-in entries by layer under the comments ``# Link Layer``,
``# Internet Layer``, ``# Transport Layer``, ``# Application Layer`` and
``# Miscellaneous``, in that order, the last holding what belongs to no layer, and
is alphabetical within each group, ruled on :issue:`2773`.

**The guard.** :file:`tests/project/test_protocol_member_order_2490_unit.py` holds
every protocol class to the groups, ``_make_data()`` first, each ``_read_xxx()``
before its ``_make_xxx()``, subgroups b, c and d, and the order of the registry
maps, layer groups included, with a table of known exceptions (:issue:`2490`). It
values a key that is an enum member, an :class:`int`, a string or a PCAP-NG option
key, and orders a string-keyed map within each group its comment lines open; a map
with a key of another shape it leaves in its own order, which rule c then follows.

Example
~~~~~~~

The utilities of :class:`~pcapkit.protocols.link.arp.protocol.ARP`, reduced to its member
names. ``read()`` resolves a hardware address before a protocol address, so the
hardware pair comes first:

.. code-block:: python

   class ARP(Link[Data_ARP, Schema_ARP]):

       # Utilities.
       def _make_data(cls, data):                    # a. data first
           ...

       def _read_addr_resolve(self, addr, htype):    # b. first helper: reader ...
           ...

       def _make_addr_resolve(self, addr, htype):    # ... then its maker
           ...

       def _read_proto_resolve(self, addr, ptype):   # b. next helper: reader ...
           ...

       def _make_proto_resolve(self, addr, ptype):   # ... then its maker
           ...

The Reference
~~~~~~~~~~~~~

:class:`~pcapkit.protocols.link.arp.protocol.ARP` is the reference for the utilities
order. Its utilities are ``_make_data()`` and the helpers that ``read()`` and
``make()`` name, and nothing else, and there is more than one helper, so the
first-use order of subgroup b shows as well as each reader preceding its maker.
Chosen on :issue:`2614`.
