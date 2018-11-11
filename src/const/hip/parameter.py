# -*- coding: utf-8 -*-

from aenum import IntEnum, extend_enum


class Parameter(IntEnum):
    """Enumeration class for Parameter."""
    _ignore_ = 'Parameter _'
    Parameter = vars()

    # HIP Parameter Types
    Parameter['ESP_INFO'] = 65                                                  # [RFC 7402] 12
    Parameter['R1_Counter'] = 128                                               # [RFC 5201] 12 (v1 only)
    Parameter['R1_COUNTER'] = 129                                               # [RFC 7401] 12
    Parameter['LOCATOR_SET'] = 193                                              # [RFC 8046]
    Parameter['PUZZLE'] = 257                                                   # [RFC 7401] 12
    Parameter['SOLUTION'] = 321                                                 # [RFC 7401] 20
    Parameter['SEQ'] = 385                                                      # [RFC 7401] 4
    Parameter['ACK'] = 449                                                      # [RFC 7401]
    Parameter['DH_GROUP_LIST'] = 511                                            # [RFC 7401]
    Parameter['Unassigned [512]'] = 512
    Parameter['DIFFIE_HELLMAN'] = 513                                           # [RFC 7401]
    Parameter['HIP_TRANSFORM'] = 577                                            # [RFC 5201] (v1 only)
    Parameter['Unassigned [578]'] = 578
    Parameter['HIP_CIPHER'] = 579                                               # [RFC 7401]
    Parameter['NAT_TRAVERSAL_MODE'] = 608                                       # [RFC 5770]
    Parameter['Unassigned [609]'] = 609
    Parameter['TRANSACTION_PACING'] = 610                                       # [RFC 5770] 4
    Parameter['ENCRYPTED'] = 641                                                # [RFC 7401]
    Parameter['HOST_ID'] = 705                                                  # [RFC 7401]
    Parameter['HIT_SUITE_LIST'] = 715                                           # [RFC 7401]
    Parameter['CERT'] = 768                                                     # [RFC 7401][RFC 8002]
    Parameter['NOTIFICATION'] = 832                                             # [RFC 7401]
    Parameter['ECHO_REQUEST_SIGNED'] = 897                                      # [RFC 7401]
    Parameter['REG_INFO'] = 930                                                 # [RFC 8003]
    Parameter['Unassigned [931]'] = 931
    Parameter['REG_REQUEST'] = 932                                              # [RFC 8003]
    Parameter['Unassigned [933]'] = 933
    Parameter['REG_RESPONSE'] = 934                                             # [RFC 8003]
    Parameter['Unassigned [935]'] = 935
    Parameter['REG_FAILED'] = 936                                               # [RFC 8003]
    Parameter['REG_FROM'] = 950                                                 # [RFC 5770] 20
    Parameter['ECHO_RESPONSE_SIGNED'] = 961                                     # [RFC 7401]
    Parameter['TRANSPORT_FORMAT_LIST'] = 2049                                   # [RFC 7401]
    Parameter['ESP_TRANSFORM'] = 4095                                           # [RFC 7402]
    Parameter['SEQ_DATA'] = 4481                                                # [RFC 6078] 4
    Parameter['ACK_DATA'] = 4545                                                # [RFC 6078]
    Parameter['PAYLOAD_MIC'] = 4577                                             # [RFC 6078]
    Parameter['TRANSACTION_ID'] = 4580                                          # [RFC 6078]
    Parameter['OVERLAY_ID'] = 4592                                              # [RFC 6079]
    Parameter['ROUTE_DST'] = 4601                                               # [RFC 6028]
    Parameter['HIP_TRANSPORT_MODE'] = 7680                                      # [RFC 6261]
    Parameter['HIP_MAC'] = 61505                                                # [RFC 7401]
    Parameter['HIP_MAC_2'] = 61569                                              # [RFC 7401]
    Parameter['HIP_SIGNATURE_2'] = 61633                                        # [RFC 7401]
    Parameter['HIP_SIGNATURE'] = 61697                                          # [RFC 7401]
    Parameter['ECHO_REQUEST_UNSIGNED'] = 63661                                  # [RFC 7401]
    Parameter['ECHO_RESPONSE_UNSIGNED'] = 63425                                 # [RFC 7401]
    Parameter['RELAY_FROM'] = 63998                                             # [RFC 5770] 20
    Parameter['RELAY_TO'] = 64002                                               # [RFC 5770] 20
    Parameter['OVERLAY_TTL'] = 64011                                            # [RFC 6079] 4
    Parameter['ROUTE_VIA'] = 64017                                              # [RFC 6028]
    Parameter['FROM'] = 65498                                                   # [RFC 8004] 16
    Parameter['Unassigned [65499]'] = 65499
    Parameter['RVS_HMAC'] = 65500                                               # [RFC 8004]
    Parameter['Unassigned [65501]'] = 65501
    Parameter['VIA_RVS'] = 65502                                                # [RFC 8004]
    Parameter['RELAY_HMAC'] = 65520                                             # [RFC 5770]

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return Parameter(key)
        if key not in Parameter._member_map_:
            extend_enum(Parameter, key, default)
        return Parameter[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 0 <= value <= 64:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 66 <= value <= 127:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 130 <= value <= 192:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 194 <= value <= 256:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 258 <= value <= 320:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 322 <= value <= 384:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 386 <= value <= 448:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 450 <= value <= 510:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 514 <= value <= 576:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 580 <= value <= 607:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 611 <= value <= 640:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 642 <= value <= 704:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 706 <= value <= 714:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 716 <= value <= 767:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 769 <= value <= 831:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 833 <= value <= 896:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 898 <= value <= 929:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 937 <= value <= 949:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 951 <= value <= 960:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 962 <= value <= 2048:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 2050 <= value <= 4094:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 4096 <= value <= 4480:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 4482 <= value <= 4544:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 4546 <= value <= 4576:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 4578 <= value <= 4579:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 4581 <= value <= 4591:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 4593 <= value <= 4600:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 4602 <= value <= 7679:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 7681 <= value <= 32767:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 32768 <= value <= 49151:
        # [RFC 7401]
            extend_enum(cls, 'Reserved [%d]' % value, value)
            return cls(value)
        if 49152 <= value <= 61504:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 61506 <= value <= 61568:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 61570 <= value <= 61632:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 61634 <= value <= 61696:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 61698 <= value <= 63660:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 63662 <= value <= 63424:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 63426 <= value <= 63997:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 63999 <= value <= 64001:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 64003 <= value <= 64010:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 64012 <= value <= 64016:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 64018 <= value <= 65497:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 65503 <= value <= 65519:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 65521 <= value <= 65535:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        super()._missing_(value)
