#!/usr/bin/python3
# -*- coding: utf-8 -*-


import sys


# PCAP Tree Viewer Header
# Program Interface Implementation


if sys.version_info[0] < 3:
    sys.exit()

try:
    from ui import Graphic as Display
except ImportError:
    from ui import Console as Display
finally:
    display = Display()
