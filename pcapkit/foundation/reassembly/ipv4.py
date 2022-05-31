# -*- coding: utf-8 -*-
"""IPv4 fragments reassembly

:mod:`pcapkit.foundation.reassembly.ipv4` contains
:class:`~pcapkit.foundation.reassembly.ipv4.IPv4_Reassembly`
only, which reconstructs fragmented IPv4 packets back to
origin.

Glossary
--------

ipv4.packet
    Data structure for **IPv4 datagram reassembly**
    (:meth:`~pcapkit.foundation.reassembly.reassembly.Reassembly.reassembly`)
    is as following:

    .. code-block:: python

       packet_dict = dict(
         bufid = tuple(
             ipv4.src,                   # source IP address
             ipv4.dst,                   # destination IP address
             ipv4.id,                    # identification
             ipv4.proto,                 # payload protocol type
         ),
         num = frame.number,             # original packet range number
         fo = ipv4.frag_offset,          # fragment offset
         ihl = ipv4.hdr_len,             # internet header length
         mf = ipv4.flags.mf,             # more fragment flag
         tl = ipv4.len,                  # total length, header includes
         header = ipv4.header,           # raw bytes type header
         payload = ipv4.payload,         # raw bytearray type payload
       )

ipv4.datagram
    Data structure for **reassembled IPv4 datagram** (element from
    :attr:`~pcapkit.foundation.reassembly.reassembly.Reassembly.datagram` *tuple*)
    is as following:

    .. code-block:: python

       (tuple) datagram
        |--> (Info) data
        |     |--> 'completed' : (bool) True --> implemented
        |     |--> 'id' : (Info) original packet identifier
        |     |            |--> 'src' --> (IPv4Address) ipv4.src
        |     |            |--> 'dst' --> (IPv4Address) ipv4.dst
        |     |            |--> 'id' --> (int) ipv4.id
        |     |            |--> 'proto' --> (EtherType) ipv4.proto
        |     |--> 'index' : (tuple) packet numbers
        |     |               |--> (int) original packet range number
        |     |--> 'header' : (bytes) IPv4 header
        |     |--> 'payload' : (bytes) reassembled IPv4 payload
        |     |--> 'packet' : (Protocol) parsed reassembled payload
        |--> (Info) data
        |     |--> 'completed' : (bool) False --> not implemented
        |     |--> 'id' : (Info) original packet identifier
        |     |            |--> 'src' --> (IPv4Address) ipv4.src
        |     |            |--> 'dst' --> (IPv4Address) ipv4.dst
        |     |            |--> 'id' --> (int) ipv4.id
        |     |            |--> 'proto' --> (EtherType) ipv4.proto
        |     |--> 'index' : (tuple) packet numbers
        |     |               |--> (int) original packet range number
        |     |--> 'header' : (bytes) IPv4 header
        |     |--> 'payload' : (tuple) partially reassembled IPv4 payload
        |     |                 |--> (bytes) IPv4 payload fragment
        |     |                 |--> ...
        |     |--> 'packet' : (None)
        |--> (Info) data ...

ipv4.buffer
    Data structure for internal buffering when performing reassembly algorithms
    (:attr:`~pcapkit.foundation.reassembly.reassembly.Reassembly._buffer`) is as following:

    .. code-block:: python

       (dict) buffer --> memory buffer for reassembly
        |--> (tuple) BUFID : (dict)
        |     |--> ipv4.src       |
        |     |--> ipv4.dst       |
        |     |--> ipv4.id        |
        |     |--> ipv4.proto     |
        |                         |--> 'TDL' : (int) total data length
        |                         |--> 'RCVBT' : (bytearray) fragment received bit table
        |                         |               |--> (bytes) b'\\x00' -> not received
        |                         |               |--> (bytes) b'\\x01' -> received
        |                         |               |--> (bytes) ...
        |                         |--> 'index' : (list) list of reassembled packets
        |                         |               |--> (int) packet range number
        |                         |--> 'header' : (bytes) header buffer
        |                         |--> 'datagram' : (bytearray) data buffer, holes set to b'\\x00'
        |--> (tuple) BUFID ...

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
