# -*- coding: utf-8 -*-
"""IGMPv2 - Internet Group Management Protocol version 2
=============================================================

.. module:: pcapkit.protocols.internet.igmpv2

:mod:`pcapkit.protocols.internet.igmpv2` contains
:class:`~pcapkit.protocols.internet.igmpv2.IGMP`, which implements an
extractor for Internet Group Management Protocol version 2
(IGMPv2) [:rfc:`2236`]. It refuses a message of any other version; a
Membership Query with a zero ``max_resp_time`` is IGMPv1, not IGMPv2.

.. versionadded:: 1.6.0

"""
from typing import TYPE_CHECKING

from pcapkit.protocols.data.internet.igmp import IGMP as Data_IGMP
from pcapkit.protocols.internet.igmp import IGMP as IGMPBase
from pcapkit.protocols.schema.internet.igmp import IGMP as Schema_IGMP

if TYPE_CHECKING:
    from typing import Literal

__all__ = ['IGMP']


class IGMP(IGMPBase[Data_IGMP, Schema_IGMP],
           schema=Schema_IGMP, data=Data_IGMP):
    """This class implements Internet Group Management Protocol version 2."""

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def version(self) -> 'Literal[2]':
        """IGMP version this class reads: ``2``."""
        return 2

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["IGMP"], Literal["IGMPv2"]]':  # type: ignore[override]
        """Index ID of the protocol.

        Returns:
            Index ID of the protocol, the family name and the version.

        """
        return ('IGMP', 'IGMPv2')
