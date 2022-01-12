# -*- coding: utf-8 -*-
"""data modules for root protocol"""
from pcapkit.corekit.infoclass import Info


class Packet(Info):
    """Header and payload data."""

    #: packet header
    header: 'bytes'
    #: packet payload
    payload: 'bytes'
