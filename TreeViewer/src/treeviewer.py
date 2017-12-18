#!/usr/bin/python3
# -*- coding: utf-8 -*-


import sys


# PCAP Tree Viewer Header
# Program Interface Implementation


if sys.version_info[0] < 3:
    sys.exit()

try:
    from graphic import Display
    display = Display()
except ImportError:
    from console import Display
    display = Display()
