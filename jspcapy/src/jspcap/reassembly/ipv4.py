#!/usr/bin/python3
# -*- coding: utf-8 -*-


# Reassembly IPv4 Fragments
# Reconstruct IPv4 packets back to origin


from .ip import IP_Reassembly


class IPv4_Reassembly(IP_Reassembly):
    """Reassembly for IPv4 payload.

    Terminology:
     - info : list, contains IPv4 fragments
        |--> fragment : Info, utitlity for reassembly
        |       |--> bufid : tuple, unique seesion descriptor
        |       |       |--> ipv4.src : source IP address
        |       |       |--> ipv4.dst : destination IP address
        |       |       |--> ipv4.proto : payload protocol type
        |       |       |--> ipv4.id : identification
        |       |--> ipv4 : Info, extracted IPv4 infomation
        |       |--> raw : bytearray, raw IPv4 payload
        |       |--> header : bytearray, raw IPv4 header
        |--> fragment ...
        |--> ...
     - buffer : dict, memory buffer for reassembly
        |--> buf : dict, buffer by BUFID
        |       |       |--> bufid : tuple, buffer id introduced above
        |       |               |--> ipv4.src : source IP address
        |       |               |--> ipv4.dst : destination IP address
        |       |               |--> ipv4.proto : payload protocol type
        |       |               |--> ipv4.id : identification
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
        return 'Internet Protocol version 4'

    ##########################################################################
    # Methods.
    ##########################################################################

    def extraction(self):
        pass

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _ip_reassembly(self, buf):
        FO = buf.ipv4.frag_offset   # Fragment Offset
        IHL = buf.ipv4.hdr_len      # Internet Header Length
        MF = buf.ipv4.flags.mf      # More Fragments flag
        TL = buf.ipv4.len           # Total Length
        BUFID = buf.bufid           # Buffer Identifier

        return FO, IHL, MF, TL, BUFID
