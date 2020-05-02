# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Operation Codes [:rfc:`826`][:rfc:`5494`]"""

from aenum import IntEnum, extend_enum

__all__ = ['Operation']


class Operation(IntEnum):
    """[Operation] Operation Codes [:rfc:`826`][:rfc:`5494`]"""

    _ignore_ = 'Operation _'
    Operation = vars()

    #: [:rfc:`5494`]
    Operation['Reserved_0'] = 0

    #: [:rfc:`826`][:rfc:`5227`]
    Operation['REQUEST'] = 1

    #: [:rfc:`826`][:rfc:`5227`]
    Operation['REPLY'] = 2

    #: [:rfc:`903`]
    Operation['Request_Reverse'] = 3

    #: [:rfc:`903`]
    Operation['Reply_Reverse'] = 4

    #: [:rfc:`1931`]
    Operation['DRARP_Request'] = 5

    #: [:rfc:`1931`]
    Operation['DRARP_Reply'] = 6

    #: [:rfc:`1931`]
    Operation['DRARP_Error'] = 7

    #: [:rfc:`2390`]
    Operation['InARP_Request'] = 8

    #: [:rfc:`2390`]
    Operation['InARP_Reply'] = 9

    #: [:rfc:`1577`]
    Operation['ARP_NAK'] = 10

    #: [Grenville Armitage]
    Operation['MARS_Request'] = 11

    #: [Grenville Armitage]
    Operation['MARS_Multi'] = 12

    #: [Grenville Armitage]
    Operation['MARS_MServ'] = 13

    #: [Grenville Armitage]
    Operation['MARS_Join'] = 14

    #: [Grenville Armitage]
    Operation['MARS_Leave'] = 15

    #: [Grenville Armitage]
    Operation['MARS_NAK'] = 16

    #: [Grenville Armitage]
    Operation['MARS_Unserv'] = 17

    #: [Grenville Armitage]
    Operation['MARS_SJoin'] = 18

    #: [Grenville Armitage]
    Operation['MARS_SLeave'] = 19

    #: [Grenville Armitage]
    Operation['MARS_Grouplist_Request'] = 20

    #: [Grenville Armitage]
    Operation['MARS_Grouplist_Reply'] = 21

    #: [Grenville Armitage]
    Operation['MARS_Redirect_Map'] = 22

    #: [Mitsuru Maruyama][:rfc:`2176`]
    Operation['MAPOS_UNARP'] = 23

    #: [:rfc:`5494`]
    Operation['OP_EXP1'] = 24

    #: [:rfc:`5494`]
    Operation['OP_EXP2'] = 25

    #: [:rfc:`5494`]
    Operation['Reserved_65535'] = 65535

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
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        return super()._missing_(value)
