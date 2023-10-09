# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""Fragmented Packets Reassembly
===================================

.. module:: pcapkit.foundation.reassembly

:mod:`pcapkit.foundation.reassembly` bases on algorithms described
in :rfc:`791` and :rfc:`815`, implements datagram reassembly
of IP and TCP packets.

"""
# Base Class for Reassembly
from pcapkit.foundation.reassembly.reassembly import Reassembly
from pcapkit.foundation.reassembly.ip import IP as IP_Reassembly

# Reassembly for IP
from pcapkit.foundation.reassembly.ipv4 import IPv4 as IPv4_Reassembly
from pcapkit.foundation.reassembly.ipv6 import IPv6 as IPv6_Reassembly

# Reassembly for TCP
from pcapkit.foundation.reassembly.tcp import TCP as TCP_Reassembly

__all__ = [
    'IPv4_Reassembly', 'IPv6_Reassembly',   # IP Reassembly
    'TCP_Reassembly',                       # TCP Reassembly
]

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import Info, info_final

if TYPE_CHECKING:
    from typing import Optional


@info_final
class ReassemblyManager(Info):
    """Reassembly Manager."""

    #: IPv4 reassembly.
    ipv4: 'IPv4_Reassembly'
    #: IPv6 reassembly.
    ipv6: 'IPv6_Reassembly'
    #: TCP reassembly.
    tcp: 'TCP_Reassembly'

    if TYPE_CHECKING:
        def __init__(self, ipv4: 'Optional[IPv4_Reassembly]', ipv6: 'Optional[IPv6_Reassembly]', tcp: 'Optional[TCP_Reassembly]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long
