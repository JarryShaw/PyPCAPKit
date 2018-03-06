#!/usr/bin/python3
# -*- coding: utf-8 -*-


# Reassembly IPv6 Fragments
# Reconstruct IPv6 packets back to origin


from jspcap.reassembly.ip import IP_Reassembly


__all__ = ['IPv6_Reassembly']


class IPv6_Reassembly(IP_Reassembly):
    """Reassembly for IPv6 payload.

    Usage:
        >>> from reassembly import IPv6_Reassembly
        # Initialise instance:
        >>> ipv6_reassembly = IPv6_Reassembly()
        # Call reassembly:
        >>> ipv6_reassembly(packet_dict)
        # Fetch result:
        >>> result = ipv6_reassembly.datagram

    Terminology:
     - packet_dict = dict(
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
            header = ipv6.header,           # raw bytearray type header before IPv6-Frag
            payload = ipv6.payload,         # raw bytearray type payload after IPv6-Frag
       )
     - (tuple) datagram
            |--> (dict) data
            |       |--> 'NotImplemented' : (bool) True --> implemented
            |       |--> 'index' : (tuple) packet numbers
            |       |                |--> (int) original packet range number
            |       |--> 'packet' : (bytes/None) reassembled IPv6 packet
            |--> (dict) data
            |       |--> 'NotImplemented' : (bool) False --> not implemented
            |       |--> 'index' : (tuple) packet numbers
            |       |                |--> (int) original packet range number
            |       |--> 'header' : (bytes/None) IPv4 header
            |       |--> 'payload' : (tuple/None) partially reassembled IPv6 payload
            |                        |--> (bytes/None) IPv4 payload fragment
            |--> (dict) data ...
     - (dict) buffer --> memory buffer for reassembly
            |--> (tuple) BUFID : (dict)
            |       |--> ipv6.src       |
            |       |--> ipc6.dst       |
            |       |--> ipv6.label     |
            |       |--> ipv6_frag.next |
            |                           |--> 'TDL' : (int) total data length
            |                           |--> RCVBT : (bytearray) fragment received bit table
            |                           |               |--> (bytes) b\x00' not received
            |                           |               |--> (bytes) b\x01' received
            |                           |               |--> (bytes) ...
            |                           |--> 'index' : (list) list of reassembled packets
            |                           |               |--> (int) packet range number
            |                           |--> 'header' : (bytearray) header buffer
            |                           |--> 'datagram' : (bytearray) data buffer,
            |                                               holes set to b'\x00'
            |--> (tuple) BUFID ...

    """
    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        return 'Internet Protocol version 6'
