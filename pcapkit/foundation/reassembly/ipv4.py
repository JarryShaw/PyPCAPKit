# -*- coding: utf-8 -*-
"""IPv4 Datagram Reassembly
==============================

.. module:: pcapkit.foundation.reassembly.ipv4

:mod:`pcapkit.foundation.reassembly.ipv4` contains
:class:`~pcapkit.foundation.reassembly.ipv4.IPv4`
only, which reconstructs fragmented IPv4 packets back to
origin. Please refer to :doc:`ip` for more information.

"""
from typing import TYPE_CHECKING

from pcapkit.foundation.reassembly.ip import IP
from pcapkit.protocols.internet.ipv4 import IPv4 as IPv4_Protocol

if TYPE_CHECKING:
    from ipaddress import IPv4Address
    from typing import Type

    from typing_extensions import Literal

__all__ = ['IPv4']


class IPv4(IP['IPv4Address']):
    """Reassembly for IPv4 payload.

    Args:
        strict: if return all datagrams (including those not
            implemented) when submit
        *args: Arbitrary positional arguments.
        **kwargs: Arbitrary keyword arguments.

    Example:
        >>> from pcapkit.reassembly import IPv4
        # Initialise instance:
        >>> ipv4_reassembly = IPv4()
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
    def protocol(self) -> 'Type[IPv4_Protocol]':
        """Protocol of current reassembly object."""
        return IPv4_Protocol
