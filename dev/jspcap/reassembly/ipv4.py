#!/usr/bin/python3
# -*- coding: utf-8 -*-


# Reassembly IPv4 Fragments
# Reconstruct IPv4 packets back to origin


from .ip import IP_Reassembler


class IPv4_Reassembly(IP_Reassembler):

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
