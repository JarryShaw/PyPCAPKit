# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""TCP Header Flags
======================

.. module:: pcapkit.const.tcp.flags

This module contains the constant enumeration for **TCP Header Flags**,
which is automatically generated from :class:`pcapkit.vendor.tcp.flags.Flags`.

"""

from aenum import IntFlag

from pcapkit.corekit.enums import EnumRegistry

__all__ = ['Flags']

class Flags(EnumRegistry, IntFlag):
    """[Flags] TCP Header Flags"""

    #: Reserved for future use [:rfc:`9293`]
    Reserved_4 = 1 << 4

    #: Reserved for future use [:rfc:`9293`]
    Reserved_5 = 1 << 5

    #: Reserved for future use [:rfc:`9293`]
    Reserved_6 = 1 << 6

    #: AE (Accurate ECN) [:rfc:`9768`]
    AE = 1 << 7

    #: CWR (Congestion Window Reduced) [:rfc:`3168`]
    CWR = 1 << 8

    #: ECE (ECN-Echo) [:rfc:`3168`]
    ECE = 1 << 9

    #: Urgent Pointer field is significant (URG) [:rfc:`9293`]
    URG = 1 << 10

    #: Acknowledgment field is significant (ACK) [:rfc:`9293`]
    ACK = 1 << 11

    #: Push Function (PSH) [:rfc:`9293`]
    PSH = 1 << 12

    #: Reset the connection (RST) [:rfc:`9293`]
    RST = 1 << 13

    #: Synchronize sequence numbers (SYN) [:rfc:`9293`]
    SYN = 1 << 14

    #: No more data from sender (FIN) [:rfc:`9293`]
    FIN = 1 << 15

    @classmethod
    def _missing_(cls, value: 'int') -> 'Flags':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 0xFFFF):
            raise ValueError(f'{value!r} is not a valid {cls.__name__}')
        return super()._missing_(value)
