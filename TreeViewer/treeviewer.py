#!/usr/bin/python3
# -*- coding: utf-8 -*-


# PCAP Tree Viewer Header
# Program Interface Implementation


try:
    # from graphic import Display
    raise ImportError
except ImportError:
    from console import Display
finally:
    display = Display()
