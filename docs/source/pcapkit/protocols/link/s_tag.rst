S_Tag - 802.1ad Service VLAN Tag Type
=====================================

.. module:: pcapkit.protocols.link.s_tag

:mod:`pcapkit.protocols.link.s_tag` contains
:class:`~pcapkit.protocols.link.s_tag.S_Tag` only, which implements the extractor for
the 802.1ad Service VLAN Tag Type (S-Tag) [*]_, EtherType ``0x88A8``.

Its structure, and all of its parsing and construction, come from
:class:`~pcapkit.protocols.link.vlan.VLAN`; this class adds only the tag's own
identity -- :attr:`~pcapkit.protocols.link.s_tag.S_Tag.name`,
:attr:`~pcapkit.protocols.link.s_tag.S_Tag.alias`,
:attr:`~pcapkit.protocols.link.s_tag.S_Tag.info_name`,
:meth:`~pcapkit.protocols.link.s_tag.S_Tag.id` -- and its registry index.

It has a module of its own, apart from
:class:`~pcapkit.protocols.link.c_tag.C_Tag`, since a module holds one protocol
class, named after it, with only the framework bases in
:mod:`pcapkit.protocols.protocol` exempt (:issue:`2529`). The two tags are
reached through different registry indices, ``0x88A8`` against ``0x8100``.

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
