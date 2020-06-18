# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""HIP Parameter Types"""

from aenum import IntEnum, extend_enum

__all__ = ['Parameter']


class Parameter(IntEnum):
    """[Parameter] HIP Parameter Types"""

    #: ESP_INFO [:rfc:`7402`] 12
    ESP_INFO = 65

    #: R1_Counter [:rfc:`5201`] 12 (v1 only)
    R1_Counter = 128

    #: R1_COUNTER [:rfc:`7401`] 12
    R1_COUNTER = 129

    #: LOCATOR_SET [:rfc:`8046`]
    LOCATOR_SET = 193

    #: PUZZLE [:rfc:`7401`] 12
    PUZZLE = 257

    #: SOLUTION [:rfc:`7401`] 20
    SOLUTION = 321

    #: SEQ [:rfc:`7401`] 4
    SEQ = 385

    #: ACK [:rfc:`7401`]
    ACK = 449

    #: DH_GROUP_LIST [:rfc:`7401`]
    DH_GROUP_LIST = 511

    #: Unassigned
    Unassigned_512 = 512

    #: DIFFIE_HELLMAN [:rfc:`7401`]
    DIFFIE_HELLMAN = 513

    #: HIP_TRANSFORM [:rfc:`5201`] (v1 only)
    HIP_TRANSFORM = 577

    #: Unassigned
    Unassigned_578 = 578

    #: HIP_CIPHER [:rfc:`7401`]
    HIP_CIPHER = 579

    #: NAT_TRAVERSAL_MODE [:rfc:`5770`]
    NAT_TRAVERSAL_MODE = 608

    #: Unassigned
    Unassigned_609 = 609

    #: TRANSACTION_PACING [:rfc:`5770`] 4
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

    #: REG_FROM [:rfc:`5770`] 20
    REG_FROM = 950

    #: ECHO_RESPONSE_SIGNED [:rfc:`7401`]
    ECHO_RESPONSE_SIGNED = 961

    #: TRANSPORT_FORMAT_LIST [:rfc:`7401`]
    TRANSPORT_FORMAT_LIST = 2049

    #: ESP_TRANSFORM [:rfc:`7402`]
    ESP_TRANSFORM = 4095

    #: SEQ_DATA [:rfc:`6078`] 4
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

    #: RELAY_FROM [:rfc:`5770`] 20
    RELAY_FROM = 63998

    #: RELAY_TO [:rfc:`5770`] 20
    RELAY_TO = 64002

    #: OVERLAY_TTL [:rfc:`6079`] 4
    OVERLAY_TTL = 64011

    #: ROUTE_VIA [:rfc:`6028`]
    ROUTE_VIA = 64017

    #: FROM [:rfc:`8004`] 16
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
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return Parameter(key)
        if key not in Parameter._member_map_:  # pylint: disable=no-member
            extend_enum(Parameter, key, default)
        return Parameter[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 0 <= value <= 64:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 66 <= value <= 127:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 130 <= value <= 192:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 194 <= value <= 256:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 258 <= value <= 320:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 322 <= value <= 384:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 386 <= value <= 448:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 450 <= value <= 510:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 514 <= value <= 576:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 580 <= value <= 607:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 611 <= value <= 640:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 642 <= value <= 704:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 706 <= value <= 714:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 716 <= value <= 767:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 769 <= value <= 831:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 833 <= value <= 896:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 898 <= value <= 929:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 937 <= value <= 949:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 951 <= value <= 960:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 962 <= value <= 2048:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 2050 <= value <= 4094:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 4096 <= value <= 4480:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 4482 <= value <= 4544:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 4546 <= value <= 4576:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 4578 <= value <= 4579:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 4581 <= value <= 4591:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 4593 <= value <= 4600:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 4602 <= value <= 7679:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 7681 <= value <= 32767:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 32768 <= value <= 49151:
            #: Reserved [:rfc:`7401`]
            extend_enum(cls, 'Reserved_%d' % value, value)
            return cls(value)
        if 49152 <= value <= 61504:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 61506 <= value <= 61568:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 61570 <= value <= 61632:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 61634 <= value <= 61696:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 61698 <= value <= 63660:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 63662 <= value <= 63424:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 63426 <= value <= 63997:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 63999 <= value <= 64001:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 64003 <= value <= 64010:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 64012 <= value <= 64016:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 64018 <= value <= 65497:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 65503 <= value <= 65519:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 65521 <= value <= 65535:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        return super()._missing_(value)
