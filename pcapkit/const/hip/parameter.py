# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""HIP Parameter Types
=========================

.. module:: pcapkit.const.hip.parameter

This module contains the constant enumeration for **HIP Parameter Types**,
which is automatically generated from :class:`pcapkit.vendor.hip.parameter.Parameter`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['Parameter']


class Parameter(IntEnum):
    """[Parameter] HIP Parameter Types"""

    #: ESP_INFO [:rfc:`7402`] (Length: 12)
    ESP_INFO = 65

    #: R1_Counter (v1 only) [:rfc:`5201`] (Length: 12)
    R1_Counter = 128

    #: R1_COUNTER [:rfc:`7401`] (Length: 12)
    R1_COUNTER = 129

    #: LOCATOR_SET [:rfc:`8046`]
    LOCATOR_SET = 193

    #: PUZZLE [:rfc:`7401`] (Length: 12)
    PUZZLE = 257

    #: SOLUTION [:rfc:`7401`] (Length: 20)
    SOLUTION = 321

    #: SEQ [:rfc:`7401`] (Length: 4)
    SEQ = 385

    #: ACK [:rfc:`7401`]
    ACK = 449

    #: DH_GROUP_LIST [:rfc:`7401`]
    DH_GROUP_LIST = 511

    #: Unassigned
    Unassigned_512 = 512

    #: DIFFIE_HELLMAN [:rfc:`7401`]
    DIFFIE_HELLMAN = 513

    #: HIP_TRANSFORM (v1 only) [:rfc:`5201`]
    HIP_TRANSFORM = 577

    #: Unassigned
    Unassigned_578 = 578

    #: HIP_CIPHER [:rfc:`7401`]
    HIP_CIPHER = 579

    #: NAT_TRAVERSAL_MODE [:rfc:`5770`]
    NAT_TRAVERSAL_MODE = 608

    #: Unassigned
    Unassigned_609 = 609

    #: TRANSACTION_PACING [:rfc:`5770`] (Length: 4)
    TRANSACTION_PACING = 610

    #: ENCRYPTED [:rfc:`7401`]
    ENCRYPTED = 641

    #: HOST_ID [:rfc:`7401`]
    HOST_ID = 705

    #: HIT_SUITE_LIST [:rfc:`7401`]
    HIT_SUITE_LIST = 715

    #: CERT [:rfc:`7401`][:rfc:`8002`]
    CERT = 768

    #: NOTIFICATION [:rfc:`7401`]
    NOTIFICATION = 832

    #: ECHO_REQUEST_SIGNED [:rfc:`7401`]
    ECHO_REQUEST_SIGNED = 897

    #: REG_INFO [:rfc:`8003`]
    REG_INFO = 930

    #: Unassigned
    Unassigned_931 = 931

    #: REG_REQUEST [:rfc:`8003`]
    REG_REQUEST = 932

    #: Unassigned
    Unassigned_933 = 933

    #: REG_RESPONSE [:rfc:`8003`]
    REG_RESPONSE = 934

    #: Unassigned
    Unassigned_935 = 935

    #: REG_FAILED [:rfc:`8003`]
    REG_FAILED = 936

    #: REG_FROM [:rfc:`5770`] (Length: 20)
    REG_FROM = 950

    #: ECHO_RESPONSE_SIGNED [:rfc:`7401`]
    ECHO_RESPONSE_SIGNED = 961

    #: TRANSPORT_FORMAT_LIST [:rfc:`7401`]
    TRANSPORT_FORMAT_LIST = 2049

    #: ESP_TRANSFORM [:rfc:`7402`]
    ESP_TRANSFORM = 4095

    #: SEQ_DATA [:rfc:`6078`] (Length: 4)
    SEQ_DATA = 4481

    #: ACK_DATA [:rfc:`6078`]
    ACK_DATA = 4545

    #: PAYLOAD_MIC [:rfc:`6078`]
    PAYLOAD_MIC = 4577

    #: TRANSACTION_ID [:rfc:`6078`]
    TRANSACTION_ID = 4580

    #: OVERLAY_ID [:rfc:`6079`]
    OVERLAY_ID = 4592

    #: ROUTE_DST [:rfc:`6028`]
    ROUTE_DST = 4601

    #: RELAYED_ADDRESS [:rfc:`9028`] (Length: 20)
    RELAYED_ADDRESS = 4650

    #: MAPPED_ADDRESS [:rfc:`9028`] (Length: 20)
    MAPPED_ADDRESS = 4660

    #: PEER_PERMISSION [:rfc:`9028`] (Length: 48)
    PEER_PERMISSION = 4680

    #: CANDIDATE_PRIORITY [:rfc:`9028`] (Length: 4)
    CANDIDATE_PRIORITY = 4700

    #: NOMINATE [:rfc:`9028`] (Length: 4)
    NOMINATE = 4710

    #: HIP_TRANSPORT_MODE [:rfc:`6261`]
    HIP_TRANSPORT_MODE = 7680

    #: HIP_MAC [:rfc:`7401`]
    HIP_MAC = 61505

    #: HIP_MAC_2 [:rfc:`7401`]
    HIP_MAC_2 = 61569

    #: HIP_SIGNATURE_2 [:rfc:`7401`]
    HIP_SIGNATURE_2 = 61633

    #: HIP_SIGNATURE [:rfc:`7401`]
    HIP_SIGNATURE = 61697

    #: ECHO_REQUEST_UNSIGNED [:rfc:`7401`]
    ECHO_REQUEST_UNSIGNED = 63661

    #: ECHO_RESPONSE_UNSIGNED [:rfc:`7401`]
    ECHO_RESPONSE_UNSIGNED = 63425

    #: RELAY_FROM [:rfc:`5770`] (Length: 20)
    RELAY_FROM = 63998

    #: RELAY_TO [:rfc:`5770`] (Length: 20)
    RELAY_TO = 64002

    #: OVERLAY_TTL [:rfc:`6079`] (Length: 4)
    OVERLAY_TTL = 64011

    #: ROUTE_VIA [:rfc:`6028`]
    ROUTE_VIA = 64017

    #: FROM [:rfc:`8004`] (Length: 16)
    FROM = 65498

    #: Unassigned
    Unassigned_65499 = 65499

    #: RVS_HMAC [:rfc:`8004`]
    RVS_HMAC = 65500

    #: Unassigned
    Unassigned_65501 = 65501

    #: VIA_RVS [:rfc:`8004`]
    VIA_RVS = 65502

    #: RELAY_HMAC [:rfc:`5770`]
    RELAY_HMAC = 65520

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'Parameter':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return Parameter(key)
        if key not in Parameter._member_map_:  # pylint: disable=no-member
            return extend_enum(Parameter, key, default)
        return Parameter[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'Parameter':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 0 <= value <= 64:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 66 <= value <= 127:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 130 <= value <= 192:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 194 <= value <= 256:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 258 <= value <= 320:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 322 <= value <= 384:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 386 <= value <= 448:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 450 <= value <= 510:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 514 <= value <= 576:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 580 <= value <= 607:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 611 <= value <= 640:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 642 <= value <= 704:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 706 <= value <= 714:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 716 <= value <= 767:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 769 <= value <= 831:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 833 <= value <= 896:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 898 <= value <= 929:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 937 <= value <= 949:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 951 <= value <= 960:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 962 <= value <= 2048:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 2050 <= value <= 4094:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 4096 <= value <= 4480:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 4482 <= value <= 4544:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 4546 <= value <= 4576:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 4578 <= value <= 4579:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 4581 <= value <= 4591:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 4593 <= value <= 4600:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 4602 <= value <= 4649:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 4651 <= value <= 4659:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 4661 <= value <= 4679:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 4681 <= value <= 4699:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 4701 <= value <= 4709:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 4711 <= value <= 7679:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 7681 <= value <= 32767:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 32768 <= value <= 49151:
            #: Reserved [:rfc:`7401`]
            return extend_enum(cls, 'Reserved_%d' % value, value)
        if 49152 <= value <= 61504:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 61506 <= value <= 61568:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 61570 <= value <= 61632:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 61634 <= value <= 61696:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 61698 <= value <= 63660:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 63662 <= value <= 63424:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 63426 <= value <= 63997:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 63999 <= value <= 64001:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 64003 <= value <= 64010:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 64012 <= value <= 64016:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 64018 <= value <= 65497:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 65503 <= value <= 65519:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 65521 <= value <= 65535:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        return super()._missing_(value)
