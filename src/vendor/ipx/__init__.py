# -*- coding: utf-8 -*-
# pylint: disable=unused-import, wrong-import-position
"""IPX vendor crawler for constant enumerations."""

###############################################################################
import sys
path = sys.path.pop(0)
###############################################################################

from pcapkit.vendor.ipx.packet import Packet as IPX_Packet
from pcapkit.vendor.ipx.socket import Socket as IPX_Socket

###############################################################################
sys.path.insert(0, path)
###############################################################################

__all__ = ['IPX_Packet', 'IPX_Socket']
