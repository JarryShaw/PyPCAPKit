# -*- coding: utf-8 -*-
"""C_Tag - 802.1Q Customer VLAN Tag Type
===========================================

.. module:: pcapkit.protocols.link.c_tag.protocol

:mod:`pcapkit.protocols.link.c_tag.protocol` contains
:class:`~pcapkit.protocols.link.c_tag.protocol.C_Tag` only, which implements the extractor for
the 802.1Q Customer VLAN Tag Type (C-Tag, formerly the Q-Tag) [*]_, EtherType
``0x8100``. Its structure, and all of its parsing and construction, come from
:class:`~pcapkit.protocols.link.vlan.protocol.VLAN`; this class adds only the tag's own
identity and its registry index.

It has a package of its own, apart from
:class:`~pcapkit.protocols.link.s_tag.protocol.S_Tag`, since a package holds one protocol
class, named after it (:issue:`2529`).

.. [*] https://en.wikipedia.org/wiki/IEEE_802.1Q

"""
from typing import TYPE_CHECKING

from pcapkit.const.reg.ethertype import EtherType as Enum_EtherType
from pcapkit.protocols.link.vlan.data import VLAN as Data_VLAN
from pcapkit.protocols.link.vlan.protocol import VLAN
from pcapkit.protocols.link.vlan.schema import VLAN as Schema_VLAN

if TYPE_CHECKING:
    from typing_extensions import Literal

__all__ = ['C_Tag']


# NOTE: ``schema`` and ``data`` are restated: with no such modules in this package,
# ProtocolBase.__init_subclass__ would bind Raw's. RARP does the same.
class C_Tag(VLAN, schema=Schema_VLAN, data=Data_VLAN):
    """This class implements 802.1Q Customer VLAN Tag Type.

    .. versionadded:: 1.5.0

       Takes over the customer tag from :class:`~pcapkit.protocols.link.vlan.protocol.VLAN`.

    """

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
        """Key name of the :attr:`~pcapkit.protocols.protocol.Protocol.info` dict."""
        return 'c_tag'

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["C_Tag"], Literal["VLAN"]]':  # type: ignore[override]
        """Index ID of the protocol.

        Returns:
            Index ID of the protocol. ``VLAN`` is retained alongside the class's
            own name so that selecting VLAN tags by that name, e.g.
            ``pcapkit.extract(..., protocol='VLAN')``, matches the customer
            tag; :class:`~pcapkit.protocols.link.s_tag.protocol.S_Tag` carries the same
            alias.

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
