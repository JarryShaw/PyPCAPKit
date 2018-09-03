# -*- coding: utf-8 -*-
"""

"""
from pcapkit.ipsuite.protocol import Protocol


class Packet(Protocol):
    """Concatenated packet.

    Properties:
        * name -- str, name of corresponding protocol
        * info -- Info, info dict of current instance
        * data -- bytes, binary packet data if current instance
        * alias -- str, acronym of corresponding protocol

    Methods:
        * index -- return first index of value from a dict
        * pack -- pack integers to bytes

    Utilities:
        * __make__ -- make packet data

    """
    pass
