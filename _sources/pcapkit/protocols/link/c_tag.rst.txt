C_Tag - 802.1Q Customer VLAN Tag Type
=====================================

.. module:: pcapkit.protocols.link.c_tag

:mod:`pcapkit.protocols.link.c_tag` contains
:class:`~pcapkit.protocols.link.c_tag.C_Tag` only, which implements extractor for
the 802.1Q Customer VLAN Tag Type (C-Tag, formerly the Q-Tag) [*]_, EtherType
``0x8100``.

Its structure, and all of its parsing and construction, come from
:class:`~pcapkit.protocols.link.vlan.VLAN`; this class adds only the tag's own
identity -- :attr:`~pcapkit.protocols.link.c_tag.C_Tag.name`,
:attr:`~pcapkit.protocols.link.c_tag.C_Tag.alias`,
:attr:`~pcapkit.protocols.link.c_tag.C_Tag.info_name` -- and its registry index.

It lives in a module of its own rather than beside
:class:`~pcapkit.protocols.link.s_tag.S_Tag` because the two are reached through
*different* registry indices, ``0x8100`` against ``0x88A8``, which is the
project's rule for when protocols share a module. Contrast
:class:`~pcapkit.protocols.link.arp.InARP`, which shares
:mod:`~pcapkit.protocols.link.arp` with :class:`~pcapkit.protocols.link.arp.ARP`
precisely because it inherits its index.

.. autoclass:: pcapkit.protocols.link.c_tag.C_Tag
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: alias
   .. autoproperty:: info_name

   .. automethod:: id

   .. automethod:: __index__

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/IEEE_802.1Q
