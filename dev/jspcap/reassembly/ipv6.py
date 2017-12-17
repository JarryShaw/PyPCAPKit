#!/usr/bin/python3
# -*- coding: utf-8 -*-


# Reassembly IPv6 Fragments
# Reconstruct IPv6 packets back to origin


from .ip import IP_Reassembler


class IPv6_Reassembly(IP_Reassembler):

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
