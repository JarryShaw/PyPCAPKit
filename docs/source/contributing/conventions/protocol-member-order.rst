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
#. **Utilities.** Everything else, mostly private methods. All ``_read_*()`` methods
   come first, in order, then all ``_make_*()`` methods, in order. The two are not
   interleaved pair by pair.

Example
~~~~~~~

.. code-block:: python

   class Foo(Protocol[Data_Foo, Schema_Foo]):

       # Methods.
       def read(self, length, *, ...):
           ...

       def make(self, ...):
           ...

       # Utilities.
       def _read_foo_field(self, ...):
           ...

       def _read_foo_option(self, ...):
           ...

       def _make_foo_field(self, ...):
           ...

       def _make_foo_option(self, ...):
           ...

The Reference
~~~~~~~~~~~~~

:class:`~pcapkit.protocols.internet.ipv4.IPv4`,
:class:`~pcapkit.protocols.transport.tcp.TCP`,
:class:`~pcapkit.protocols.transport.udp.UDP` and
:class:`~pcapkit.protocols.link.arp.ARP` follow this order. When a
new class is unclear, match them.
