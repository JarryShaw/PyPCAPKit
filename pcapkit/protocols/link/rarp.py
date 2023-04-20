# -*- coding: utf-8 -*-
"""RARP/DRARP - (Dynamic) Reverse Address Resolution Protocol
================================================================

.. module:: pcapkit.protocols.link.rarp

:mod:`pcapkit.protocols.link.rarp` contains
:class:`~pcapkit.protocols.link.rarp.RARP` only,
which implements extractor for (Dynamic) Reverse
Address Resolution Protocol (RARP/DRARP) [*]_,
whose structure is described as below:

====== ========= ========================= =========================
Octets      Bits        Name                    Description
====== ========= ========================= =========================
  0           0   ``rarp.htype``            Hardware Type
  2          16   ``rarp.ptype``            Protocol Type
  4          32   ``rarp.hlen``             Hardware Address Length
  5          40   ``rarp.plen``             Protocol Address Length
  6          48   ``rarp.oper``             Operation
  8          64   ``rarp.sha``              Sender Hardware Address
  14        112   ``rarp.spa``              Sender Protocol Address
  18        144   ``rarp.tha``              Target Hardware Address
  24        192   ``rarp.tpa``              Target Protocol Address
====== ========= ========================= =========================

.. [*] http://en.wikipedia.org/wiki/Address_Resolution_Protocol

"""
from typing import TYPE_CHECKING

from pcapkit.const.reg.ethertype import EtherType as Enum_EtherType
from pcapkit.protocols.data.link.arp import ARP as Data_ARP
from pcapkit.protocols.link.arp import ARP
from pcapkit.protocols.schema.link.arp import ARP as Schema_ARP

if TYPE_CHECKING:
    from typing_extensions import Literal

__all__ = ['RARP', 'DRARP']


class RARP(ARP, schema=Schema_ARP, data=Data_ARP):  # pylint: disable=abstract-method
    """This class implements Reverse Address Resolution Protocol."""

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["RARP"], Literal["DRARP"]]':  # type: ignore[override]
        """Index ID of the protocol."""
        return ('RARP', 'DRARP')

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
        return Enum_EtherType.Reverse_Address_Resolution_Protocol  # type: ignore[return-value]


class DRARP(RARP):
    """This class implements Dynamic Reverse Address Resolution Protocol."""

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["DRARP"]]':  # type: ignore[override]
        """Index ID of the protocol."""
        return ('DRARP',)
