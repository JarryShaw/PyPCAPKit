# -*- coding: utf-8 -*-
"""DCCP Packet Types
====================

.. module:: pcapkit.vendor.dccp.packet_type

This module contains the vendor crawler for **DCCP Packet Types**,
which is automatically generating :class:`pcapkit.const.dccp.packet_type.PacketType`.

"""

import sys

from pcapkit.vendor.default import Vendor

__all__ = ['PacketType']


class PacketType(Vendor):
    """DCCP Packet Types"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 15'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/dccp-parameters/dccp-parameters-1.csv'


if __name__ == '__main__':
    sys.exit(PacketType())  # type: ignore[arg-type]
