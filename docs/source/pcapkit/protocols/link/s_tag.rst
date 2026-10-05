S_Tag - 802.1ad Service VLAN Tag Type
=====================================

.. module:: pcapkit.protocols.link.s_tag

:mod:`pcapkit.protocols.link.s_tag` contains
:class:`~pcapkit.protocols.link.s_tag.S_Tag` only, which implements extractor for
the 802.1ad Service VLAN Tag Type (S-Tag) [*]_, EtherType ``0x88A8``.

Its structure, and all of its parsing and construction, come from
:class:`~pcapkit.protocols.link.vlan.VLAN`; this class adds only the tag's own
identity -- :attr:`~pcapkit.protocols.link.s_tag.S_Tag.name`,
:attr:`~pcapkit.protocols.link.s_tag.S_Tag.alias`,
:attr:`~pcapkit.protocols.link.s_tag.S_Tag.info_name` -- and its registry index.

It has a module of its own, apart from
:class:`~pcapkit.protocols.link.c_tag.C_Tag`, because the two are reached through
*different* registry indices, ``0x88A8`` against ``0x8100``; see
:mod:`pcapkit.protocols.link.vlan` for the rule.

.. note::

   802.1ad is part of IEEE 802.1Q-2011. The ``802.1ad`` name is kept because it
   is what the provider-bridging tag is universally called.

.. autoclass:: pcapkit.protocols.link.s_tag.S_Tag
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: alias
   .. autoproperty:: info_name

   .. automethod:: id

   .. automethod:: __index__

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/IEEE_802.1ad
