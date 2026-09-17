# -*- coding: utf-8 -*-
"""S_Tag - 802.1ad Service VLAN Tag Type
=========================================

.. module:: pcapkit.protocols.link.s_tag

:mod:`pcapkit.protocols.link.s_tag` contains
:class:`~pcapkit.protocols.link.s_tag.S_Tag` only, which implements extractor for
the 802.1ad Service VLAN Tag Type (S-Tag) [*]_, EtherType ``0x88A8``. Its
structure, and all of its parsing and construction, come from
:class:`~pcapkit.protocols.link.vlan.VLAN`; this class adds only the tag's own
identity and its registry index.

It lives in a module of its own rather than beside
:class:`~pcapkit.protocols.link.c_tag.C_Tag` because the two are reached through
*different* registry indices -- ``0x88A8`` against ``0x8100`` -- which is the
project's rule for when protocols share a module.

.. [*] https://en.wikipedia.org/wiki/IEEE_802.1ad

"""
from typing import TYPE_CHECKING

from pcapkit.const.reg.ethertype import EtherType as Enum_EtherType
from pcapkit.protocols.data.link.vlan import VLAN as Data_VLAN
from pcapkit.protocols.link.vlan import VLAN
from pcapkit.protocols.schema.link.vlan import VLAN as Schema_VLAN

if TYPE_CHECKING:
    from typing_extensions import Literal

__all__ = ['S_Tag']


# NOTE: ``schema`` and ``data`` are restated here for the reason given in
# :mod:`pcapkit.protocols.link.c_tag` -- they are resolved by subclass *name*,
# not inherited, so omitting them would silently bind the Raw pair.
class S_Tag(VLAN, schema=Schema_VLAN, data=Data_VLAN):
    """This class implements 802.1ad Service VLAN Tag Type.

    Note:
        802.1ad was incorporated into IEEE 802.1Q-2011, so the service tag is
        specified by 802.1Q today. The ``802.1ad`` name is kept because it is
        what the provider-bridging tag is universally called, and because it is
        the only thing distinguishing this class from
        :class:`~pcapkit.protocols.link.c_tag.C_Tag` by name.

    """

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["802.1ad Service VLAN Tag Type"]':
        """Name of current protocol."""
        return '802.1ad Service VLAN Tag Type'

    @property
    def alias(self) -> 'Literal["802.1ad"]':
        """Acronym of corresponding protocol."""
        return '802.1ad'

    #: NOTE: c.f. :attr:`C_Tag.info_name <pcapkit.protocols.link.c_tag.C_Tag.info_name>`
    #: -- spelled out deliberately, since it is what keeps a stacked service tag
    #: and customer tag apart in the parsed info dict.
    @property
    def info_name(self) -> 'Literal["s_tag"]':
        """Key name of the :attr:`info` dict."""
        return 's_tag'

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["S_Tag"], Literal["VLAN"]]':  # type: ignore[override]
        """Index ID of the protocol.

        Returns:
            Index ID of the protocol. ``VLAN`` is retained alongside the class's
            own name so that selecting VLAN tags by that name matches the
            service tag as well as the customer tag.

        """
        return ('S_Tag', 'VLAN')

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
        return Enum_EtherType.IEEE_Std_802_1Q_Service_VLAN_tag_identifier  # type: ignore[return-value]
