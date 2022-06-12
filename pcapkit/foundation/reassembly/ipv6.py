# -*- coding: utf-8 -*-
"""IPv6 Datagram Reassembly
==============================

:mod:`pcapkit.foundation.reassembly.ipv6` contains
:class:`~pcapkit.foundation.reassembly.ipv6.IPv6_Reassembly`
only, which reconstructs fragmented IPv6 packets back to
origin. Please refer to :doc:`ip` for more information.

"""
from typing import TYPE_CHECKING

from pcapkit.foundation.reassembly.ip import IP_Reassembly
from pcapkit.protocols.internet.ipv6 import IPv6

if TYPE_CHECKING:
    from ipaddress import IPv6Address
    from typing import Type

    from typing_extensions import Literal

__all__ = ['IPv6_Reassembly']


class IPv6_Reassembly(IP_Reassembly['IPv6Address']):
    """Reassembly for IPv6 payload.

    Example:
        >>> from pcapkit.reassembly import IPv6_Reassembly
        # Initialise instance:
        >>> ipv6_reassembly = IPv6_Reassembly()
        # Call reassembly:
        >>> ipv6_reassembly(packet_dict)
        # Fetch result:
        >>> result = ipv6_reassembly.datagram

    """
    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Internet Protocol version 6"]':
        """Protocol of current packet."""
        return 'Internet Protocol version 6'

    @property
    def protocol(self) -> 'Type[IPv6]':
        """Protocol of current reassembly object."""
        return IPv6
