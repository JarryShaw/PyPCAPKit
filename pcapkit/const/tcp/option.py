# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""TCP Option Kind Numbers
=============================

.. module:: pcapkit.const.tcp.option

This module contains the constant enumeration for **TCP Option Kind Numbers**,
which is automatically generated from :class:`pcapkit.vendor.tcp.option.Option`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['Option']


class Option(IntEnum):
    """[Option] TCP Option Kind Numbers"""

    #: End of Option List [:rfc:`9293`]
    End_of_Option_List = 0

    #: No-Operation [:rfc:`9293`]
    No_Operation = 1

    #: Maximum Segment Size [:rfc:`9293`]
    Maximum_Segment_Size = 2

    #: Window Scale [:rfc:`7323`]
    Window_Scale = 3

    #: SACK Permitted [:rfc:`2018`]
    SACK_Permitted = 4

    #: SACK [:rfc:`2018`]
    SACK = 5

    #: Echo (obsoleted by option 8) [:rfc:`1072`][:rfc:`6247`]
    Echo = 6

    #: Echo Reply (obsoleted by option 8) [:rfc:`1072`][:rfc:`6247`]
    Echo_Reply = 7

    #: Timestamps [:rfc:`7323`]
    Timestamps = 8

    #: Partial Order Connection Permitted (obsolete) [:rfc:`1693`][:rfc:`6247`]
    Partial_Order_Connection_Permitted = 9

    #: Partial Order Service Profile (obsolete) [:rfc:`1693`][:rfc:`6247`]
    Partial_Order_Service_Profile = 10

    #: CC (obsolete) [:rfc:`1644`][:rfc:`6247`]
    CC = 11

    #: CC.NEW (obsolete) [:rfc:`1644`][:rfc:`6247`]
    CC_NEW = 12

    #: CC.ECHO (obsolete) [:rfc:`1644`][:rfc:`6247`]
    CC_ECHO = 13

    #: TCP Alternate Checksum Request (obsolete) [:rfc:`1146`][:rfc:`6247`]
    TCP_Alternate_Checksum_Request = 14

    #: TCP Alternate Checksum Data (obsolete) [:rfc:`1146`][:rfc:`6247`]
    TCP_Alternate_Checksum_Data = 15

    #: Skeeter [Stev Knowles]
    Skeeter = 16

    #: Bubba [Stev Knowles]
    Bubba = 17

    #: Trailer Checksum Option [Subbu Subramaniam][Monroe Bridges]
    Trailer_Checksum_Option = 18

    #: MD5 Signature Option (obsoleted by option 29) [:rfc:`2385`]
    MD5_Signature_Option = 19

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
    Unassigned_25 = 25

    #: TCP Compression Filter [Steve Bellovin]
    TCP_Compression_Filter = 26

    #: Quick-Start Response [:rfc:`4782`]
    Quick_Start_Response = 27

    #: User Timeout Option (also, other known unauthorized use)  [:rfc:`5482`]
    User_Timeout_Option = 28

    #: TCP Authentication Option (TCP-AO) [:rfc:`5925`]
    TCP_Authentication_Option = 29

    #: Multipath TCP (MPTCP) [:rfc:`8684`]
    Multipath_TCP = 30

    #: Reserved (known unauthorized use without proper IANA assignment)
    Reserved_31 = 31

    #: Reserved (known unauthorized use without proper IANA assignment)
    Reserved_32 = 32

    #: Reserved (known unauthorized use without proper IANA assignment)
    Reserved_33 = 33

    #: TCP Fast Open Cookie [:rfc:`7413`]
    TCP_Fast_Open_Cookie = 34

    #: Encryption Negotiation (TCP-ENO) [:rfc:`8547`]
    Encryption_Negotiation = 69

    #: Reserved (known unauthorized use without proper IANA assignment)
    Reserved_70 = 70

    #: Reserved (known unauthorized use without proper IANA assignment)
    Reserved_76 = 76

    #: Reserved (known unauthorized use without proper IANA assignment)
    Reserved_77 = 77

    #: Reserved (known unauthorized use without proper IANA assignment)
    Reserved_78 = 78

    #: Accurate ECN Order 0 (AccECN0) (TEMPORARY - registered 2022-08-03, extension
    #: registered 2024-07-11, expires 2025-08-03) [draft-ietf-tcpm-accurate-ecn-20]
    Accurate_ECN_Order_0 = 172

    #: Reserved
    Reserved_173 = 173

    #: Accurate ECN Order 1 (AccECN1) (TEMPORARY - registered 2022-08-03, extension
    #: registered 2024-07-11, expires 2025-08-03) [draft-ietf-tcpm-accurate-ecn-20]
    Accurate_ECN_Order_1 = 174

    #: RFC3692-style Experiment 1 (also improperly used for shipping
    #: products)  [:rfc:`4727`]
    RFC3692_style_Experiment_1 = 253

    #: RFC3692-style Experiment 2 (also improperly used for shipping
    #: products)  [:rfc:`4727`]
    RFC3692_style_Experiment_2 = 254

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'Option':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return Option(key)
        if key not in Option._member_map_:  # pylint: disable=no-member
            return extend_enum(Option, key, default)
        return Option[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'Option':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 35 <= value <= 68:
            #: Reserved
            return extend_enum(cls, 'Reserved_%d' % value, value)
        if 71 <= value <= 75:
            #: Reserved
            return extend_enum(cls, 'Reserved_%d' % value, value)
        if 79 <= value <= 171:
            #: Reserved
            return extend_enum(cls, 'Reserved_%d' % value, value)
        if 175 <= value <= 252:
            #: Reserved
            return extend_enum(cls, 'Reserved_%d' % value, value)
        return super()._missing_(value)
