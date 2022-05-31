# -*- coding: utf-8 -*-
"""IPv6 fragments reassembly

:mod:`pcapkit.foundation.reassembly.ipv6` contains
:class:`~pcapkit.foundation.reassembly.ipv6.IPv6_Reassembly`
only, which reconstructs fragmented IPv6 packets back to
origin.

Glossary
--------

ipv6.packet
    Data structure for **IPv6 datagram reassembly**
    (:meth:`~pcapkit.foundation.reassembly.reassembly.Reassembly.reassembly`)
    is as following:

    .. code-block:: python

       packet_dict = dict(
         bufid = tuple(
             ipv6.src,                   # source IP address
             ipv6.dst,                   # destination IP address
             ipv6.label,                 # label
             ipv6_frag.next,             # next header field in IPv6 Fragment Header
         ),
         num = frame.number,             # original packet range number
         fo = ipv6_frag.offset,          # fragment offset
         ihl = ipv6.hdr_len,             # header length, only headers before IPv6-Frag
         mf = ipv6_frag.mf,              # more fragment flag
         tl = ipv6.len,                  # total length, header includes
         header = ipv6.header,           # raw bytes type header before IPv6-Frag
         payload = ipv6.payload,         # raw bytearray type payload after IPv6-Frag
       )

ipv6.datagram
    Data structure for **reassembled IPv6 datagram** (element from
    :attr:`~pcapkit.foundation.reassembly.reassembly.Reassembly.datagram` *tuple*)
    is as following:

    .. code-block:: python

       (tuple) datagram
        |--> (Info) data
        |     |--> 'completed' : (bool) True --> implemented
        |     |--> 'id' : (Info) original packet identifier
        |     |            |--> 'src' --> (IPv6Address) ipv6.src
        |     |            |--> 'dst' --> (IPv6Address) ipv6.dst
        |     |            |--> 'id' --> (int) ipv6.label
        |     |            |--> 'proto' --> (EtherType) ipv6_frag.next
        |     |--> 'index' : (tuple) packet numbers
        |     |               |--> (int) original packet range number
        |     |--> 'payload' : (bytes) reassembled IPv4 packet
        |     |--> 'packet' : (Protocol) parsed reassembled payload
        |--> (Info) data
        |     |--> 'completed' : (bool) False --> not implemented
        |     |--> 'id' : (Info) original packet identifier
        |     |            |--> 'src' --> (IPv6Address) ipv6.src
        |     |            |--> 'dst' --> (IPv6Address) ipv6.dst
        |     |            |--> 'id' --> (int) ipv6.id
        |     |            |--> 'proto' --> (EtherType) ipv6_frag.next
        |     |--> 'index' : (tuple) packet numbers
        |     |               |--> (int) original packet range number
        |     |--> 'header' : (bytes) IPv4 header
        |     |--> 'payload' : (tuple) partially reassembled IPv4 payload
        |     |                 |--> (bytes) IPv4 payload fragment
        |     |                 |--> ...
        |     |--> 'packet' : (None)
        |--> (Info) data ...

ipv6.buffer
    Data structure for internal buffering when performing reassembly algorithms
    (:attr:`~pcapkit.foundation.reassembly.reassembly.Reassembly._buffer`) is as following:

    .. code-block:: python

       (dict) buffer --> memory buffer for reassembly
        |--> (tuple) BUFID : (dict)
        |     |--> ipv6.src       |
        |     |--> ipc6.dst       |
        |     |--> ipv6.label     |
        |     |--> ipv6_frag.next |
        |                         |--> 'TDL' : (int) total data length
        |                         |--> RCVBT : (bytearray) fragment received bit table
        |                         |             |--> (bytes) b'\\x00' -> not received
        |                         |             |--> (bytes) b'\\x01' -> received
        |                         |             |--> (bytes) ...
        |                         |--> 'index' : (list) list of reassembled packets
        |                         |               |--> (int) packet range number
        |                         |--> 'header' : (bytes) header buffer
        |                         |--> 'datagram' : (bytearray) data buffer, holes set to b'\\x00'
        |--> (tuple) BUFID ...

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
