# -*- coding: utf-8 -*-
"""IPv4 Datagram Reassembly
==============================

:mod:`pcapkit.foundation.reassembly.ipv4` contains
:class:`~pcapkit.foundation.reassembly.ipv4.IPv4_Reassembly`
only, which reconstructs fragmented IPv4 packets back to
origin. Please refer to :doc:`ip` for more information.

"""
from typing import TYPE_CHECKING

from pcapkit.foundation.reassembly.ip import IP_Reassembly
from pcapkit.protocols.internet.ipv4 import IPv4

if TYPE_CHECKING:
    from ipaddress import IPv4Address
    from typing import Type

    from typing_extensions import Literal

__all__ = ['IPv4_Reassembly']


class IPv4_Reassembly(IP_Reassembly['IPv4Address']):
    """Reassembly for IPv4 payload.

    Example:
        >>> from pcapkit.reassembly import IPv4_Reassembly
        # Initialise instance:
        >>> ipv4_reassembly = IPv4_Reassembly()
        # Call reassembly:
        >>> ipv4_reassembly(packet_dict)
        # Fetch result:
        >>> result = ipv4_reassembly.datagram

    """
    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Internet Protocol version 4"]':
        """Protocol of current packet."""
        return 'Internet Protocol version 4'

    @property
    def protocol(self) -> 'Type[IPv4]':
        """Protocol of current reassembly object."""
        return IPv4
