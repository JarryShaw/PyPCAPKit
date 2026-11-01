LinuxSLL - Linux "Cooked" Capture Encapsulation Family
======================================================

.. module:: pcapkit.protocols.link.linux_sll

:mod:`pcapkit.protocols.link.linux_sll` contains
:class:`~pcapkit.protocols.link.linux_sll.LinuxSLL` only, the base class of the
Linux "cooked" capture encapsulation family:

.. list-table::
   :header-rows: 1

   * - ``LinkType``
     - Class
   * - ``LINUX_SLL`` (113)
     - :class:`~pcapkit.protocols.link.linux_sll1.LinuxSLL1`
   * - ``LINUX_SLL2`` (276)
     - :class:`~pcapkit.protocols.link.linux_sll2.LinuxSLL2`

The versions differ in field order and width, so each parses its own header.
The base holds what they share: the next-layer dispatch, and link-layer address
validation. It has no registry index, so its ``__index__`` raises.

.. autoclass:: pcapkit.protocols.link.linux_sll.LinuxSLL
   :no-members:
   :show-inheritance:

   .. automethod:: id
   .. automethod:: register
   .. automethod:: __index__
   .. automethod:: _import_next_layer

   .. autoattribute:: __proto__
      :no-value:
   .. autoattribute:: __proto_key__
      :no-value:

Auxiliary Functions
-------------------

.. autofunction:: pcapkit.protocols.link.linux_sll._resolve_next_layer_proto
.. autofunction:: pcapkit.protocols.link.linux_sll._validate_link_addr

Auxiliary Constants
-------------------

.. autodata:: pcapkit.protocols.link.linux_sll._ETHERTYPE_FIELD
   :no-value:

Hardware Types
--------------

The ``arphrd_type`` keys of ``LinuxSLL.__proto__`` are named by
:class:`~pcapkit.const.linux.arphrd.ARPHRD`.

.. _linux-sll-labels:

Selecting a Version
-------------------

The family name selects either version, and each version's own name selects that
version only, as :class:`~pcapkit.protocols.internet.ipv4.IPv4` and
:class:`~pcapkit.protocols.internet.ipv6.IPv6` do under
:class:`~pcapkit.protocols.internet.ip.IP`. ``'LinuxSLL'`` is in both versions;
``'LinuxSLL1' in`` a v2 layer is :data:`False`. String ``==`` does not expand a
key, so ``v1 == 'LinuxSLL'`` is :data:`False` while ``'LinuxSLL' in v1`` is :data:`True`.
