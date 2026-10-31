.. _protocol-member-order:

Protocol Member Order
---------------------

The order of members inside a protocol class body. Settled by the owner as a
ruling, so a new dissector and a refactor land in the same layout.

Each group sits under its section comment, spelled as the repo spells it:
``# Properties.``, ``# Methods.``, ``# Data models.`` and ``# Utilities.``

The Order
~~~~~~~~~

#. **Properties.** Every ``@property`` member.
#. **Methods.** Public methods: mostly ``id()``, ``read()``, ``make()`` and
   ``register_xxx()``.
#. **Data models.** Every dunder name: ``__index__``, ``__length_hint__``,
   ``__init__``, ``__new__``, ``__post_init__`` and any other.
#. **Utilities.** Everything else, mostly private methods, in three subgroups:

   a. **Data.** ``_make_data()`` comes first in the group, before everything else.
   b. **Helpers.** The helpers that ``read()`` or ``make()`` call, one helper at a
      time. Each helper's ``_read_`` and ``_make_`` methods stay together, with the
      reader first: ``_read_mac_addr()`` then ``_make_mac_addr()``.
   c. **Specific readers and makers.** The option, type and parameter methods,
      all ``_read_*()`` before all ``_make_*()``. Each set is ordered by the enum
      value of the code or type it handles, not alphabetically by name.

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
