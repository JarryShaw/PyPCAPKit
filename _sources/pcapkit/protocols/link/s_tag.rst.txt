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

It lives in a module of its own rather than beside
:class:`~pcapkit.protocols.link.c_tag.C_Tag` because the two are reached through
*different* registry indices, ``0x88A8`` against ``0x8100``, which is the
project's rule for when protocols share a module.

.. note::

   802.1ad was incorporated into IEEE 802.1Q-2011, so the service tag is
   specified by 802.1Q today. The ``802.1ad`` name is kept because it is what the
   provider-bridging tag is universally called.

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
