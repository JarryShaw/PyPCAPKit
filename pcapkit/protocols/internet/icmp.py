# -*- coding: utf-8 -*-
"""ICMP - Internet Control Message Protocol
===============================================

.. module:: pcapkit.protocols.internet.icmp

:mod:`pcapkit.protocols.internet.icmp` contains
:class:`~pcapkit.protocols.internet.icmp.ICMP` only,
which is a base class for Internet Control Message
Protocol (ICMP) protocol family [*]_, e.g.
:class:`~pcapkit.protocols.internet.icmpv4.ICMPv4` and
:class:`~pcapkit.protocols.internet.icmpv6.ICMPv6`.

.. [*] https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol

"""
from typing import TYPE_CHECKING, Generic

from pcapkit.protocols.internet.internet import Internet
from pcapkit.protocols.protocol import _PT, _ST

if TYPE_CHECKING:
    from typing_extensions import Literal

__all__ = ['ICMP']


class ICMP(Internet[_PT, _ST], Generic[_PT, _ST]):  # pylint: disable=abstract-method
    """Abstract base class for ICMP protocol family.

    - Internet Control Message Protocol (:class:`~pcapkit.protocols.internet.icmpv4.ICMPv4`) [:rfc:`792`]
    - Internet Control Message Protocol for IPv6 (:class:`~pcapkit.protocols.internet.icmpv6.ICMPv6`) [:rfc:`4443`]

    """

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["ICMP"], Literal["ICMPv6"]]':
        """Index ID of the protocol.

        Returns:
            Index ID of the protocol.

        """
        return ('ICMP', 'ICMPv6')
