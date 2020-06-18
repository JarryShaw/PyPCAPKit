# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""TCP Option Kind Numbers"""

from aenum import IntEnum, extend_enum

__all__ = ['Option']


class Option(IntEnum):
    """[Option] TCP Option Kind Numbers"""

    #: End of Option List [:rfc:`793`]
    EOOL = 0

    #: No-Operation [:rfc:`793`]
    NOP = 1

    #: Maximum Segment Size [:rfc:`793`]
    MSS = 2

    #: Window Scale [:rfc:`7323`]
    WS = 3

    #: SACK Permitted [:rfc:`2018`]
    SACKPMT = 4

    #: SACK [:rfc:`2018`]
    SACK = 5

    #: Echo (obsoleted by option 8) [:rfc:`1072`][:rfc:`6247`]
    ECHO = 6

    #: Echo Reply (obsoleted by option 8) [:rfc:`1072`][:rfc:`6247`]
    ECHORE = 7

    #: Timestamps [:rfc:`7323`]
    TS = 8

    #: Partial Order Connection Permitted (obsolete) [:rfc:`1693`][:rfc:`6247`]
    POC = 9

    #: Partial Order Service Profile (obsolete) [:rfc:`1693`][:rfc:`6247`]
    POCSP = 10

    #: CC (obsolete) [:rfc:`1644`][:rfc:`6247`]
    CC = 11

    #: CC.NEW (obsolete) [:rfc:`1644`][:rfc:`6247`]
    CCNEW = 12

    #: CC.ECHO (obsolete) [:rfc:`1644`][:rfc:`6247`]
    CCECHO = 13

    #: TCP Alternate Checksum Request (obsolete) [:rfc:`1146`][:rfc:`6247`]
    CHKREQ = 14

    #: TCP Alternate Checksum Data (obsolete) [:rfc:`1146`][:rfc:`6247`]
    CHKSUM = 15

    #: Skeeter [Stev Knowles]
    Skeeter = 16

    #: Bubba [Stev Knowles]
    Bubba = 17

    #: Trailer Checksum Option [Subbu Subramaniam][Monroe Bridges]
    Trailer_Checksum_Option = 18

    #: MD5 Signature Option (obsoleted by option 29) [:rfc:`2385`]
    SIG = 19

    #: SCPS Capabilities [Keith Scott]
    SCPS_Capabilities = 20

    #: Selective Negative Acknowledgements [Keith Scott]
    Selective_Negative_Acknowledgements = 21

    #: Record Boundaries [Keith Scott]
    Record_Boundaries = 22

    #: Corruption experienced [Keith Scott]
    Corruption_experienced = 23

    #: SNAP [Vladimir Sukonnik]
    SNAP = 24

    #: Unassigned (released 2000-12-18)
    Unassigned = 25

    #: TCP Compression Filter [Steve Bellovin]
    TCP_Compression_Filter = 26

    #: Quick-Start Response [:rfc:`4782`]
    QS = 27

    #: User Timeout Option (also, other known unauthorized use) [***][1]
    #: [:rfc:`5482`]
    TIMEOUT = 28

    #: TCP Authentication Option (TCP-AO) [:rfc:`5925`]
    AO = 29

    #: Multipath TCP (MPTCP) [:rfc:`8684`]
    MP = 30

    #: Reserved (known unauthorized use without proper IANA assignment) [**]
    Reserved_31 = 31

    #: Reserved (known unauthorized use without proper IANA assignment) [**]
    Reserved_32 = 32

    #: Reserved (known unauthorized use without proper IANA assignment) [**]
    Reserved_33 = 33

    #: TCP Fast Open Cookie [:rfc:`7413`]
    FASTOPEN = 34

    #: Encryption Negotiation (TCP-ENO) [:rfc:`8547`]
    Encryption_Negotiation = 69

    #: Reserved (known unauthorized use without proper IANA assignment) [**]
    Reserved_70 = 70

    #: Reserved (known unauthorized use without proper IANA assignment) [**]
    Reserved_76 = 76

    #: Reserved (known unauthorized use without proper IANA assignment) [**]
    Reserved_77 = 77

    #: Reserved (known unauthorized use without proper IANA assignment) [**]
    Reserved_78 = 78

    #: RFC3692-style Experiment 1 (also improperly used for shipping
    #: products) [*] [:rfc:`4727`]
    RFC3692_style_Experiment_1 = 253

    #: RFC3692-style Experiment 2 (also improperly used for shipping
    #: products) [*] [:rfc:`4727`]
    RFC3692_style_Experiment_2 = 254

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
            #: Reserved
            extend_enum(cls, 'Reserved_%d' % value, value)
            return cls(value)
        if 71 <= value <= 75:
            #: Reserved
            extend_enum(cls, 'Reserved_%d' % value, value)
            return cls(value)
        if 79 <= value <= 252:
            #: Reserved
            extend_enum(cls, 'Reserved_%d' % value, value)
            return cls(value)
        return super()._missing_(value)
