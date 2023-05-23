# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Status Codes
==================

.. module:: pcapkit.const.mh.status_code

This module contains the constant enumeration for **Status Codes**,
which is automatically generated from :class:`pcapkit.vendor.mh.status_code.StatusCode`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['StatusCode']


class StatusCode(IntEnum):
    """[StatusCode] Status Codes"""

    #: Binding Update accepted/Proxy Binding Update accepted
    #: [:rfc:`6275`][:rfc:`5213`]
    Binding_Update_accepted_Proxy_Binding_Update_accepted = 0

    #: Accepted but prefix discovery necessary [:rfc:`6275`]
    Accepted_but_prefix_discovery_necessary = 1

    #: GRE_KEY_OPTION_NOT_REQUIRED [:rfc:`5845`]
    GRE_KEY_OPTION_NOT_REQUIRED = 2

    #: GRE_TUNNELING_BUT_TLV_HEADER_NOT_SUPPORTED [:rfc:`5845`]
    GRE_TUNNELING_BUT_TLV_HEADER_NOT_SUPPORTED = 3

    #: MCOA NOTCOMPLETE [:rfc:`5648`]
    MCOA_NOTCOMPLETE = 4

    #: MCOA RETURNHOME WO/NDP [:rfc:`5648`]
    MCOA_RETURNHOME_WO_NDP = 5

    #: PBU_ACCEPTED_TB_IGNORED_SETTINGSMISMATCH [:rfc:`6058`]
    PBU_ACCEPTED_TB_IGNORED_SETTINGSMISMATCH = 6

    #: Reason unspecified [:rfc:`6275`]
    Reason_unspecified = 128

    #: Administratively prohibited [:rfc:`6275`]
    Administratively_prohibited = 129

    #: Insufficient resources [:rfc:`6275`]
    Insufficient_resources = 130

    #: Home registration not supported [:rfc:`6275`]
    Home_registration_not_supported = 131

    #: Not home subnet [:rfc:`6275`]
    Not_home_subnet = 132

    #: Not home agent for this mobile node [:rfc:`6275`]
    Not_home_agent_for_this_mobile_node = 133

    #: Duplicate Address Detection failed [:rfc:`6275`]
    Duplicate_Address_Detection_failed = 134

    #: Sequence number out of window [:rfc:`6275`]
    Sequence_number_out_of_window = 135

    #: Expired home nonce index [:rfc:`6275`]
    Expired_home_nonce_index = 136

    #: Expired care-of nonce index [:rfc:`6275`]
    Expired_care_of_nonce_index = 137

    #: Expired nonces [:rfc:`6275`]
    Expired_nonces = 138

    #: Registration type change disallowed [:rfc:`6275`]
    Registration_type_change_disallowed = 139

    #: Mobile Router Operation not permitted [:rfc:`3963`]
    Mobile_Router_Operation_not_permitted = 140

    #: Invalid Prefix [:rfc:`3963`]
    Invalid_Prefix = 141

    #: Not Authorized for Prefix [:rfc:`3963`]
    Not_Authorized_for_Prefix = 142

    #: Forwarding Setup failed [:rfc:`3963`]
    Forwarding_Setup_failed = 143

    #: MIPV6-ID-MISMATCH [:rfc:`4285`]
    MIPV6_ID_MISMATCH = 144

    #: MIPV6-MESG-ID-REQD [:rfc:`4285`]
    MIPV6_MESG_ID_REQD = 145

    #: MIPV6-AUTH-FAIL [:rfc:`4285`]
    MIPV6_AUTH_FAIL = 146

    #: Permanent home keygen token unavailable [:rfc:`4866`]
    Permanent_home_keygen_token_unavailable = 147

    #: CGA and signature verification failed [:rfc:`4866`]
    CGA_and_signature_verification_failed = 148

    #: Permanent home keygen token exists [:rfc:`4866`]
    Permanent_home_keygen_token_exists = 149

    #: Non-null home nonce index expected [:rfc:`4866`]
    Non_null_home_nonce_index_expected = 150

    #: SERVICE_AUTHORIZATION_FAILED [:rfc:`5149`]
    SERVICE_AUTHORIZATION_FAILED = 151

    #: PROXY_REG_NOT_ENABLED [:rfc:`5213`]
    PROXY_REG_NOT_ENABLED = 152

    #: NOT_LMA_FOR_THIS_MOBILE_NODE [:rfc:`5213`]
    NOT_LMA_FOR_THIS_MOBILE_NODE = 153

    #: MAG_NOT_AUTHORIZED_FOR_PROXY_REG [:rfc:`5213`]
    MAG_NOT_AUTHORIZED_FOR_PROXY_REG = 154

    #: NOT_AUTHORIZED_FOR_HOME_NETWORK_PREFIX [:rfc:`5213`]
    NOT_AUTHORIZED_FOR_HOME_NETWORK_PREFIX = 155

    #: TIMESTAMP_MISMATCH [:rfc:`5213`]
    TIMESTAMP_MISMATCH = 156

    #: TIMESTAMP_LOWER_THAN_PREV_ACCEPTED [:rfc:`5213`]
    TIMESTAMP_LOWER_THAN_PREV_ACCEPTED = 157

    #: MISSING_HOME_NETWORK_PREFIX_OPTION [:rfc:`5213`]
    MISSING_HOME_NETWORK_PREFIX_OPTION = 158

    #: BCE_PBU_PREFIX_SET_DO_NOT_MATCH [:rfc:`5213`]
    BCE_PBU_PREFIX_SET_DO_NOT_MATCH = 159

    #: MISSING_MN_IDENTIFIER_OPTION [:rfc:`5213`]
    MISSING_MN_IDENTIFIER_OPTION = 160

    #: MISSING_HANDOFF_INDICATOR_OPTION [:rfc:`5213`]
    MISSING_HANDOFF_INDICATOR_OPTION = 161

    #: MISSING_ACCESS_TECH_TYPE_OPTION [:rfc:`5213`]
    MISSING_ACCESS_TECH_TYPE_OPTION = 162

    #: GRE_KEY_OPTION_REQUIRED [:rfc:`5845`]
    GRE_KEY_OPTION_REQUIRED = 163

    #: MCOA MALFORMED [:rfc:`5648`]
    MCOA_MALFORMED = 164

    #: MCOA NON-MCOA BINDING EXISTS [:rfc:`5648`]
    MCOA_NON_MCOA_BINDING_EXISTS = 165

    #: MCOA PROHIBITED [:rfc:`5648`]
    MCOA_PROHIBITED = 166

    #: MCOA UNKNOWN COA [:rfc:`5648`]
    MCOA_UNKNOWN_COA = 167

    #: MCOA BULK REGISTRATION PROHIBITED [:rfc:`5648`]
    MCOA_BULK_REGISTRATION_PROHIBITED = 168

    #: MCOA SIMULTANEOUS HOME AND FOREIGN PROHIBITED [:rfc:`5648`]
    MCOA_SIMULTANEOUS_HOME_AND_FOREIGN_PROHIBITED = 169

    #: NOT_AUTHORIZED_FOR_IPV4_MOBILITY_SERVICE [:rfc:`5844`]
    NOT_AUTHORIZED_FOR_IPV4_MOBILITY_SERVICE = 170

    #: NOT_AUTHORIZED_FOR_IPV4_HOME_ADDRESS [:rfc:`5844`]
    NOT_AUTHORIZED_FOR_IPV4_HOME_ADDRESS = 171

    #: NOT_AUTHORIZED_FOR_IPV6_MOBILITY_SERVICE [:rfc:`5844`]
    NOT_AUTHORIZED_FOR_IPV6_MOBILITY_SERVICE = 172

    #: MULTIPLE_IPV4_HOME_ADDRESS_ASSIGNMENT_NOT_SUPPORTED [:rfc:`5844`]
    MULTIPLE_IPV4_HOME_ADDRESS_ASSIGNMENT_NOT_SUPPORTED = 173

    #: Invalid Care-of Address [:rfc:`6275`]
    Invalid_Care_of_Address = 174

    #: INVALID_MOBILE_NODE_GROUP_IDENTIFIER [:rfc:`6602`]
    INVALID_MOBILE_NODE_GROUP_IDENTIFIER = 175

    #: REINIT_SA_WITH_HAC [:rfc:`6618`]
    REINIT_SA_WITH_HAC = 176

    #: NOT_AUTHORIZED_FOR_DELEGATED_MNP [:rfc:`7148`]
    NOT_AUTHORIZED_FOR_DELEGATED_MNP = 177

    #: REQUESTED_DMNP_IN_USE [:rfc:`7148`]
    REQUESTED_DMNP_IN_USE = 178

    #: CANNOT_MEET_QOS_SERVICE_REQUEST [:rfc:`7222`]
    CANNOT_MEET_QOS_SERVICE_REQUEST = 179

    #: CANNOT_SUPPORT_MULTIPATH_BINDING [:rfc:`8278`]
    CANNOT_SUPPORT_MULTIPATH_BINDING = 180

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'StatusCode':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return StatusCode(key)
        if key not in StatusCode._member_map_:  # pylint: disable=no-member
            return extend_enum(StatusCode, key, default)
        return StatusCode[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'StatusCode':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 7 <= value <= 127:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        #: Unspecified in the IANA registry
        return extend_enum(cls, 'Unassigned_%d' % value, value)
