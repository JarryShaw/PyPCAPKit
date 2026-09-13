# -*- coding: utf-8 -*-
"""data models for reassembly"""

# IP reassembly
from pcapkit.foundation.reassembly.data.ip import Buffer as IP_Buffer
from pcapkit.foundation.reassembly.data.ip import BufferID as IP_BufferID
from pcapkit.foundation.reassembly.data.ip import Datagram as IP_Datagram
from pcapkit.foundation.reassembly.data.ip import DatagramID as IP_DatagramID
from pcapkit.foundation.reassembly.data.ip import Packet as IP_Packet

# TCP reassembly
from pcapkit.foundation.reassembly.data.tcp import Buffer as TCP_Buffer
from pcapkit.foundation.reassembly.data.tcp import BufferID as TCP_BufferID
from pcapkit.foundation.reassembly.data.tcp import Datagram as TCP_Datagram
from pcapkit.foundation.reassembly.data.tcp import DatagramID as TCP_DatagramID
from pcapkit.foundation.reassembly.data.tcp import Fragment as TCP_Fragment
from pcapkit.foundation.reassembly.data.tcp import HoleDiscriptor as TCP_HoleDiscriptor
from pcapkit.foundation.reassembly.data.tcp import Packet as TCP_Packet

__all__ = [
    'IP_Packet', 'IP_DatagramID', 'IP_Datagram', 'IP_Buffer',
    'IP_BufferID',

    'TCP_Packet', 'TCP_DatagramID', 'TCP_Datagram', 'TCP_Buffer',
    'TCP_Fragment', 'TCP_HoleDiscriptor', 'TCP_BufferID',
]

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import Info, info_final

if TYPE_CHECKING:
    from typing import Optional


@info_final
class ReassemblyData(Info):
    """Data storage for reassembly."""

    #: IPv4 reassembled data.
    ipv4: 'tuple[IP_Datagram, ...]'
    #: IPv6 reassembled data.
    ipv6: 'tuple[IP_Datagram, ...]'
    #: TCP reassembled data.
    tcp: 'tuple[TCP_Datagram, ...]'

    if TYPE_CHECKING:
        def __init__(self, ipv4: 'Optional[tuple[IP_Datagram, ...]]', ipv6: 'Optional[tuple[IP_Datagram, ...]]', tcp: 'Optional[tuple[TCP_Datagram, ...]]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long
