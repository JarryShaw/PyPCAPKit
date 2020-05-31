# -*- coding: utf-8 -*-
"""(dynamic) reverse address resolution protocol

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
from pcapkit.const.reg.ethertype import EtherType
from pcapkit.protocols.link.arp import ARP

__all__ = ['RARP']


class RARP(ARP):  # pylint: disable=abstract-method
    """This class implements Reverse Address Resolution Protocol."""

    #: Acronym of corresponding protocol.
    _acnm = 'RARP'
    #: Name of corresponding protocol.
    _name = 'Reverse Address Resolution Protocol'

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls):  # pylint: disable=invalid-index-returned
        """Index ID of the protocol.

        Returns:
            Tuple[Literal['RARP'], Literal['DRARP']]: Index ID of the protocol.

        See Also:
            :meth:`pcapkit.protocols.protocol.Protocol.__getitem__`

        """
        return ('RARP', 'DRARP')

    ##########################################################################
    # Data models.
    ##########################################################################

    @classmethod
    def __index__(cls):  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            pcapkit.const.reg.ethertype.EtherType: Numeral registry index of the
            protocol in `IANA`_.

        .. _IANA: https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml

        """
        return EtherType(0x8035)
