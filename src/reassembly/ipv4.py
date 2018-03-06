#!/usr/bin/python3
# -*- coding: utf-8 -*-


# Reassembly IPv4 Fragments
# Reconstruct IPv4 packets back to origin


from jspcap.reassembly.ip import IP_Reassembly


__all__ = ['IPv4_Reassembly']


class IPv4_Reassembly(IP_Reassembly):
    """Reassembly for IPv4 payload.

    Usage:
        >>> from reassembly import IPv4_Reassembly
        # Initialise instance:
        >>> ipv4_reassembly = IPv4_Reassembly()
        # Call reassembly:
        >>> ipv4_reassembly(packet_dict)
        # Fetch result:
        >>> result = ipv4_reassembly.datagram

    Terminology:
     - packet_dict = dict(
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
            header = ipv4.header,           # raw bytearray type header
            payload = ipv4.payload,         # raw bytearray type payload
       )
     - (tuple) datagram
            |--> (dict) data
            |       |--> 'NotImplemented' : (bool) True --> implemented
            |       |--> 'index' : (tuple) packet numbers
            |       |                |--> (int) original packet range number
            |       |--> 'packet' : (bytes/None) reassembled IPv4 packet
            |--> (dict) data
            |       |--> 'NotImplemented' : (bool) False --> not implemented
            |       |--> 'index' : (tuple) packet numbers
            |       |                |--> (int) original packet range number
            |       |--> 'header' : (bytes/None) IPv4 header
            |       |--> 'payload' : (tuple/None) partially reassembled IPv4 payload
            |                        |--> (bytes/None) IPv4 payload fragment
            |--> (dict) data ...
     - (dict) buffer --> memory buffer for reassembly
            |--> (tuple) BUFID : (dict)
            |       |--> ipv4.src    |
            |       |--> ipc4.dst    |
            |       |--> ipv4.id     |
            |       |--> ipv4.proto  |
            |                        |--> 'TDL' : (int) total data length
            |                        |--> RCVBT : (bytearray) fragment received bit table
            |                        |               |--> (bytes) b\x00' not received
            |                        |               |--> (bytes) b\x01' received
            |                        |               |--> (bytes) ...
            |                        |--> 'index' : (list) list of reassembled packets
            |                        |               |--> (int) packet range number
            |                        |--> 'header' : (bytearray) header buffer
            |                        |--> 'datagram' : (bytearray) data buffer, holes set to b'\x00'
            |--> (tuple) BUFID ...

    """
    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        return 'Internet Protocol version 4'
