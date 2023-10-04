# -*- coding: utf-8 -*-
"""IPv6 Datagram Reassembly
==============================

.. module:: pcapkit.foundation.reassembly.ipv6

:mod:`pcapkit.foundation.reassembly.ipv6` contains
:class:`~pcapkit.foundation.reassembly.ipv6.IPv6`
only, which reconstructs fragmented IPv6 packets back to
origin. Please refer to :doc:`ip` for more information.

"""
from typing import TYPE_CHECKING

from pcapkit.foundation.reassembly.ip import IP
from pcapkit.protocols.internet.ipv6 import IPv6 as IPv6_Protocol

if TYPE_CHECKING:
    from ipaddress import IPv6Address

__all__ = ['IPv6']


class IPv6(IP['IPv6Address']):
    """Reassembly for IPv6 payload.

    Args:
        strict: if return all datagrams (including those not
            implemented) when submit
        *args: Arbitrary positional arguments.
        **kwargs: Arbitrary keyword arguments.

    Example:
        >>> from pcapkit.reassembly import IPv6
        # Initialise instance:
        >>> ipv6_reassembly = IPv6()
        # Call reassembly:
        >>> ipv6_reassembly(packet_dict)
        # Fetch result:
        >>> result = ipv6_reassembly.datagram

    """

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Protocol name of current reassembly object.
    __protocol_name__ = 'IPv6'
    #: Protocol of current reassembly object.
    __protocol_type__ = IPv6_Protocol
