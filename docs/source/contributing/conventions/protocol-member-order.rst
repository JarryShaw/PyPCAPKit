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
#. **Utilities.** Everything else, mostly private methods, in the subgroups below. Every private helper, including ``_check_*``, sits here, never before ``_make_data()``.

   a. **Data.** ``_make_data()`` comes first in the group, before everything else.
   b. **Helpers.** The helpers that ``read()`` or ``make()`` call, one helper at a
      time, in the order ``read()`` or ``make()`` first uses them. "Uses" means a
      direct reference in the body of ``read()`` or ``make()``. Helpers reached only
      through ``getattr``, or through the registry maps (``__proto__``,
      ``__option__``, ``__parameter__`` and similar), do not count. They are ordered
      by the enum value order of the corresponding code, or by the registry's order
      where there is no enum. A registry fallback that ``read()`` or ``make()``
      names directly, such as ``_read_msg_unknown()`` in
      :class:`~pcapkit.protocols.internet.mh.MH`, does not count either: it is a
      specific reader, ruled on :issue:`2490`. Each helper's
      ``_read_`` and ``_make_`` methods stay together, with the reader first:
      ``_read_mac_addr()`` then ``_make_mac_addr()``.
   c. **Specific readers and makers.** The option, type and parameter methods,
      all ``_read_*()`` before all ``_make_*()``. Each set opens with the registry's
      default, its fallback for a code with no entry of its own, as
      ``_read_opt_unassigned()`` opens the readers of
      :class:`~pcapkit.protocols.internet.ipv4.IPv4`; the rest follow the enum value
      of the code or type each handles, not alphabetical order. Ruled on
      :issue:`2490`.
   d. **Other helpers.** Every helper that ``read()``, ``make()`` and the registries
      do not reach goes last, including one that only another helper calls, such as
      ``_decode_text()`` in :class:`~pcapkit.protocols.application.httpv1.HTTP`.
      Ruled on :issue:`2490`.

**Registry maps.** The registry maps themselves (``__proto__``, ``__option__``,
``__parameter__`` and similar) are ordered by their enum values, or alphabetically
by key where there is no enum.

**The guard.** :file:`tests/project/test_protocol_member_order_2490_unit.py` holds
every protocol class to the groups, ``_make_data()`` first, each ``_read_xxx()``
before its ``_make_xxx()``, and subgroup b, with a table of known exceptions
(:issue:`2490`).

Example
~~~~~~~

The utilities of :class:`~pcapkit.protocols.link.ethernet.Ethernet`, reduced to
its member names:

.. code-block:: python

   class Ethernet(Link[Data_Ethernet, Schema_Ethernet]):

       # Utilities.
       def _make_data(cls, data, ...):      # a. data first
           ...

       def _read_mac_addr(self, ...):       # b. helper: reader ...
           ...

       def _make_mac_addr(self, ...):       # ... then its maker
           ...

The Reference
~~~~~~~~~~~~~

:class:`~pcapkit.protocols.link.ethernet.Ethernet` is the reference for the
utilities order.
