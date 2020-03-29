# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""TCP Option Kind Numbers"""

from aenum import IntEnum, extend_enum

__all__ = ['Option']


class Option(IntEnum):
    """[Option] TCP Option Kind Numbers"""

    _ignore_ = 'Option _'
    Option = vars()

    #: [:rfc:`793`]
    Option['EOOL'] = 0

    #: [:rfc:`793`]
    Option['NOP'] = 1

    #: [:rfc:`793`]
    Option['MSS'] = 2

    #: [:rfc:`7323`]
    Option['WS'] = 3

    #: [:rfc:`2018`]
    Option['SACKPMT'] = 4

    #: [:rfc:`2018`]
    Option['SACK'] = 5

    #: [:rfc:`1072`][:rfc:`6247`]
    Option['ECHO'] = 6

    #: [:rfc:`1072`][:rfc:`6247`]
    Option['ECHORE'] = 7

    #: [:rfc:`7323`]
    Option['TS'] = 8

    #: [:rfc:`1693`][:rfc:`6247`]
    Option['POC'] = 9

    #: [:rfc:`1693`][:rfc:`6247`]
    Option['POCSP'] = 10

    #: [:rfc:`1644`][:rfc:`6247`]
    Option['CC'] = 11

    #: [:rfc:`1644`][:rfc:`6247`]
    Option['CCNEW'] = 12

    #: [:rfc:`1644`][:rfc:`6247`]
    Option['CCECHO'] = 13

    #: [:rfc:`1146`][:rfc:`6247`]
    Option['CHKREQ'] = 14

    #: [:rfc:`1146`][:rfc:`6247`]
    Option['CHKSUM'] = 15

    #: [Stev Knowles]
    Option['Skeeter'] = 16

    #: [Stev Knowles]
    Option['Bubba'] = 17

    #: [Subbu Subramaniam][Monroe Bridges]
    Option['Trailer Checksum Option'] = 18

    #: [:rfc:`2385`]
    Option['SIG'] = 19

    #: [Keith Scott]
    Option['SCPS Capabilities'] = 20

    #: [Keith Scott]
    Option['Selective Negative Acknowledgements'] = 21

    #: [Keith Scott]
    Option['Record Boundaries'] = 22

    #: [Keith Scott]
    Option['Corruption experienced'] = 23

    #: [Vladimir Sukonnik]
    Option['SNAP'] = 24

    Option['Unassigned'] = 25

    #: [Steve Bellovin]
    Option['TCP Compression Filter'] = 26

    #: [:rfc:`4782`]
    Option['QS'] = 27

    #: [:rfc:`5482`]
    Option['TIMEOUT'] = 28

    #: [:rfc:`5925`]
    Option['AO'] = 29

    #: [RFC-ietf-mptcp-rfc6824bis-18]
    Option['MP'] = 30

    Option['Reserved [31]'] = 31

    Option['Reserved [32]'] = 32

    Option['Reserved [33]'] = 33

    #: [:rfc:`7413`]
    Option['FASTOPEN'] = 34

    #: [:rfc:`8547`]
    Option['Encryption Negotiation'] = 69

    Option['Reserved [70]'] = 70

    Option['Reserved [76]'] = 76

    Option['Reserved [77]'] = 77

    Option['Reserved [78]'] = 78

    #: [:rfc:`4727`]
    Option['RFC3692-style Experiment 1'] = 253

    #: [:rfc:`4727`]
    Option['RFC3692-style Experiment 2'] = 254

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return Option(key)
        if key not in Option._member_map_:  # pylint: disable=no-member
            extend_enum(Option, key, default)
        return Option[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 35 <= value <= 68:
            extend_enum(cls, 'Reserved [%d]' % value, value)
            return cls(value)
        if 71 <= value <= 75:
            extend_enum(cls, 'Reserved [%d]' % value, value)
            return cls(value)
        if 79 <= value <= 252:
            extend_enum(cls, 'Reserved [%d]' % value, value)
            return cls(value)
        return super()._missing_(value)
