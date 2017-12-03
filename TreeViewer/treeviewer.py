#!/usr/bin/python3
# -*- coding: utf-8 -*-


# PCAP Tree Viewer Header
# Program Interface Implementation


try:
    from graphic import Display
    display = Display()
except ImportError:
    from console import Display
    display = Display()
