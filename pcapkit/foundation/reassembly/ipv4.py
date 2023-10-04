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
    # Defaults.
    ##########################################################################

    #: Protocol name of current reassembly object.
    __protocol_name__ = 'IPv4'
    #: Protocol of current reassembly object.
    __protocol_type__ = IPv4_Protocol
