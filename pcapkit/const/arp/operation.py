# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Operation Codes [:rfc:`826`][:rfc:`5494`]"""

from aenum import IntEnum, extend_enum

__all__ = ['Operation']


class Operation(IntEnum):
    """[Operation] Operation Codes [:rfc:`826`][:rfc:`5494`]"""

    #: Reserved [:rfc:`5494`]
    Reserved_0 = 0

    #: REQUEST [:rfc:`826`][:rfc:`5227`]
    REQUEST = 1

    #: REPLY [:rfc:`826`][:rfc:`5227`]
    REPLY = 2

    #: request Reverse [:rfc:`903`]
    request_Reverse = 3

    #: reply Reverse [:rfc:`903`]
    reply_Reverse = 4

    #: DRARP-Request [:rfc:`1931`]
    DRARP_Request = 5

    #: DRARP-Reply [:rfc:`1931`]
    DRARP_Reply = 6

    #: DRARP-Error [:rfc:`1931`]
    DRARP_Error = 7

    #: InARP-Request [:rfc:`2390`]
    InARP_Request = 8

    #: InARP-Reply [:rfc:`2390`]
    InARP_Reply = 9

    #: ARP-NAK [:rfc:`1577`]
    ARP_NAK = 10

    #: MARS-Request [Grenville Armitage]
    MARS_Request = 11

    #: MARS-Multi [Grenville Armitage]
    MARS_Multi = 12

    #: MARS-MServ [Grenville Armitage]
    MARS_MServ = 13

    #: MARS-Join [Grenville Armitage]
    MARS_Join = 14

    #: MARS-Leave [Grenville Armitage]
    MARS_Leave = 15

    #: MARS-NAK [Grenville Armitage]
    MARS_NAK = 16

    #: MARS-Unserv [Grenville Armitage]
    MARS_Unserv = 17

    #: MARS-SJoin [Grenville Armitage]
    MARS_SJoin = 18

    #: MARS-SLeave [Grenville Armitage]
    MARS_SLeave = 19

    #: MARS-Grouplist-Request [Grenville Armitage]
    MARS_Grouplist_Request = 20

    #: MARS-Grouplist-Reply [Grenville Armitage]
    MARS_Grouplist_Reply = 21

    #: MARS-Redirect-Map [Grenville Armitage]
    MARS_Redirect_Map = 22

    #: MAPOS-UNARP [Mitsuru Maruyama][:rfc:`2176`]
    MAPOS_UNARP = 23

    #: OP_EXP1 [:rfc:`5494`]
    OP_EXP1 = 24

    #: OP_EXP2 [:rfc:`5494`]
    OP_EXP2 = 25

    #: Reserved [:rfc:`5494`]
    Reserved_65535 = 65535

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return Operation(key)
        if key not in Operation._member_map_:  # pylint: disable=no-member
            extend_enum(Operation, key, default)
        return Operation[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 26 <= value <= 65534:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        return super()._missing_(value)
