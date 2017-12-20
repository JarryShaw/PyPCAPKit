#!/usr/bin/python3
# -*- coding: utf-8 -*-


# Reassembly IPv6 Fragments
# Reconstruct IPv6 packets back to origin


from .ip import IP_Reassembly


class IPv6_Reassembly(IP_Reassembly):
    """Reassembly for IPv6 payload.

    Terminology:
     - info : list, contains IPv6 fragments
        |--> fragment : Info, utitlity for reassembly
        |       |--> bufid : tuple, unique seesion descriptor
        |       |       |--> ipv6.src : source IP address
        |       |       |--> ipv6.dst : destination IP address
        |       |       |--> ipv6.proto : payload protocol type
        |       |       |--> ipv6.label : identification
        |       |--> ipv6 : Info, extracted IPv6 infomation
        |       |--> raw : bytearray, raw IPv6 payload
        |       |--> header : bytearray, raw IPv6 header
        |--> fragment ...
        |--> ...
     - buffer : dict, memory buffer for reassembly
        |--> buf : dict, buffer by BUFID
        |       |       |--> bufid : tuple, buffer id introduced above
        |       |               |--> ipv6.src : source IP address
        |       |               |--> ipv6.dst : destination IP address
        |       |               |--> ipv6.proto : payload protocol type
        |       |               |--> ipv6.label : identification
        |       |--> TDL : int, total data length
        |       |--> RCVBT : bytearray, fragment received bit table
        |       |       |--> bit : bytes, if this 8-octet unit received
        |       |       |       |--> "\x00" : bytes, not received
        |       |       |       |--> "\x01" : bytes, received
        |       |       |--> bit ...
        |       |       |--> ...
        |       |--> data : bytearray, data buffer (65535 in length)
        |       |--> header : bytearray, header buffer
        |--> buf ...
        |--> ...
     - datagram : tuple, contains reassembly results
        |--> data : Info, reassembled application layer datagram
        |       |--> NotImplemented : bool, if this datagram is implemented
        |               |--> Implemented
        |               |       |--> packet : bytes, original packet
        |               |--> Not Implemented
        |                       |--> header : bytes, partially reassembled data
        |                       |--> payload : tuple, datagram fragments
        |                               |--> fragment : bytes, partially reassembled datagram
        |                               |--> fragment ...
        |                               |--> ...
        |--> data ...
        |--> ...

    """

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        return 'Internet Protocol version 6'

    ##########################################################################
    # Methods.
    ##########################################################################

    def extraction(self):
        pass

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _ip_reassembly(self, buf):
        FO = buf.ipv6.frag.offset   # Fragment Offset
        IHL = buf.ipv6.hdr_len      # Internet Header Length
        MF = buf.ipv6.frag.mf       # More Fragments flag
        TL = buf.ipv6.len + 40      # Total Length
        BUFID = buf.bufid           # Buffer Identifier
