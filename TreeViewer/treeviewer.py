#!/usr/bin/python3
# -*- coding: utf-8 -*-


# PCAP Tree Viewer Header
# Program Interface Implementation


try:
    from graphic import Display
except ImportError:
    from console import Display
finally:
    display = Display()
