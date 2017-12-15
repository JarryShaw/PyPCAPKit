#!/usr/bin/python3
# -*- coding: utf-8 -*-


# Reverse Address Resolution Protocol
# Analyser for ARP/RARP/DRARP/IARP header


from .arp import ARP


class RARP(ARP):

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        return 'Reverse Address Resolution Protocol'
