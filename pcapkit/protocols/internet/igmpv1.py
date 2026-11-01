# -*- coding: utf-8 -*-
"""IGMPv1 - Internet Group Management Protocol version 1
=============================================================

.. module:: pcapkit.protocols.internet.igmpv1

:mod:`pcapkit.protocols.internet.igmpv1` contains
:class:`~pcapkit.protocols.internet.igmpv1.IGMPv1`, which implements an
extractor for Internet Group Management Protocol version 1
(IGMPv1) [:rfc:`1112`]. It refuses a message of any other version, and a
Membership Query with a non-zero ``max_resp_time`` is IGMPv2, not IGMPv1.

.. versionadded:: 1.6.0

"""
from typing import TYPE_CHECKING

from pcapkit.protocols.data.internet.igmp import IGMP as Data_IGMP
from pcapkit.protocols.internet.igmp import IGMP as IGMPBase
from pcapkit.protocols.schema.internet.igmp import IGMP as Schema_IGMP

if TYPE_CHECKING:
    from typing import Literal

__all__ = ['IGMPv1']


class IGMPv1(IGMPBase[Data_IGMP, Schema_IGMP],
             schema=Schema_IGMP, data=Data_IGMP):
    """This class implements Internet Group Management Protocol version 1."""

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def version(self) -> 'Literal[1]':
        """IGMP version this class reads: ``1``."""
        return 1

    @property
    def alias(self) -> 'Literal["IGMP"]':
        """Acronym of corresponding protocol."""
        return 'IGMP'

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["IGMP"]]':  # type: ignore[override]
        """Index ID of the protocol.

        :rfc:`1112` names the protocol ``IGMP``, without a version.

        String ``==`` compares against ``(cls, *id())``, so ``== 'IGMPv1'`` is
        :data:`False`, while ``'IGMPv1' in`` matches by class.

        Returns:
            Index ID of the protocol.

        """
        return ('IGMP',)
