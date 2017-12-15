#!/usr/bin/python3
# -*- coding: utf-8 -*-


# Reverse Address Resolution Protocol
# Analyser for RARP/DRARP header


from .arp import ARP


class RARP(ARP):

    _name = 'Reverse Address Resolution Protocol'
