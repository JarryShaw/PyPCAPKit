# -*- coding: utf-8 -*-
"""C_Tag - 802.1Q Customer VLAN Tag Type
==========================================

.. module:: pcapkit.protocols.link.c_tag

:mod:`pcapkit.protocols.link.c_tag` contains
:class:`~pcapkit.protocols.link.c_tag.C_Tag` only, which implements extractor for
the 802.1Q Customer VLAN Tag Type (C-Tag, formerly the Q-Tag) [*]_, EtherType
``0x8100``. Its structure, and all of its parsing and construction, come from
:class:`~pcapkit.protocols.link.vlan.VLAN`; this class adds only the tag's own
identity and its registry index.

It lives in a module of its own rather than beside
:class:`~pcapkit.protocols.link.s_tag.S_Tag` because the two are reached through
*different* registry indices -- ``0x8100`` against ``0x88A8`` -- which is the
project's rule for when protocols share a module. Contrast
:class:`~pcapkit.protocols.link.arp.InARP`, which shares
:mod:`~pcapkit.protocols.link.arp` with :class:`~pcapkit.protocols.link.arp.ARP`
precisely because it inherits its index.

.. [*] https://en.wikipedia.org/wiki/IEEE_802.1Q

"""
from typing import TYPE_CHECKING

from pcapkit.const.reg.ethertype import EtherType as Enum_EtherType
from pcapkit.protocols.data.link.vlan import VLAN as Data_VLAN
from pcapkit.protocols.link.vlan import VLAN
from pcapkit.protocols.schema.link.vlan import VLAN as Schema_VLAN

if TYPE_CHECKING:
    from typing_extensions import Literal

__all__ = ['C_Tag']


# NOTE: ``schema`` and ``data`` are restated here even though :class:`VLAN`
# already declares them. They are not inherited:
# :meth:`ProtocolBase.__init_subclass__ <pcapkit.protocols.protocol.ProtocolBase.__init_subclass__>`
# resolves an omitted schema by looking the *subclass name* up in
# :mod:`pcapkit.protocols.schema`, and assigns unconditionally -- so leaving them
# off would silently bind ``Schema_Raw``/``Data_Raw`` rather than falling back to
# the base class's pair. c.f. :class:`~pcapkit.protocols.link.rarp.RARP`, which
# restates them for the same reason.
class C_Tag(VLAN, schema=Schema_VLAN, data=Data_VLAN):
    """This class implements 802.1Q Customer VLAN Tag Type."""

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["802.1Q Customer VLAN Tag Type"]':
        """Name of current protocol."""
        return '802.1Q Customer VLAN Tag Type'

    @property
    def alias(self) -> 'Literal["802.1Q"]':
        """Acronym of corresponding protocol."""
        return '802.1Q'

    #: NOTE: This is what keeps a stacked service tag and customer tag apart in
    #: the parsed info dict, so it is spelled out rather than left to the
    #: class-name default -- a rename must not silently move the output key.
    @property
    def info_name(self) -> 'Literal["c_tag"]':
        """Key name of the :attr:`info` dict."""
        return 'c_tag'

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["C_Tag"], Literal["VLAN"]]':  # type: ignore[override]
        """Index ID of the protocol.

        Returns:
            Index ID of the protocol. ``VLAN`` is retained alongside the class's
            own name so that selecting the protocol by that name -- as
            ``pcapkit.extract(..., protocol='VLAN')`` did when this class *was*
            ``VLAN`` -- keeps matching.

        """
        return ('C_Tag', 'VLAN')

    ##########################################################################
    # Data models.
    ##########################################################################

    @classmethod
    def __index__(cls) -> 'Enum_EtherType':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            Numeral registry index of the protocol in `IANA`_.

        .. _IANA: https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml

        """
        return Enum_EtherType.Customer_VLAN_Tag_Type  # type: ignore[return-value]
