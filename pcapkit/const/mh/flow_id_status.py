# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Flow Identification Mobility Option Status Codes
======================================================

.. module:: pcapkit.const.mh.flow_id_status

This module contains the constant enumeration for **Flow Identification Mobility Option Status Codes**,
which is automatically generated from :class:`pcapkit.vendor.mh.flow_id_status.FlowIDStatus`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['FlowIDStatus']


class FlowIDStatus(IntEnum):
    """[FlowIDStatus] Flow Identification Mobility Option Status Codes"""

    #: Flow binding successful [:rfc:`6089`]
    Flow_binding_successful = 0

    #: Administratively prohibited [:rfc:`6089`]
    Administratively_prohibited = 128

    #: Flow binding rejected, reason unspecified [:rfc:`6089`]
    Flow_binding_rejected_reason_unspecified = 129

    #: Flow identification mobility option malformed [:rfc:`6089`]
    Flow_identification_mobility_option_malformed = 130

    #: BID not found [:rfc:`6089`]
    BID_not_found = 131

    #: FID not found [:rfc:`6089`]
    FID_not_found = 132

    #: Traffic selector format not supported [:rfc:`6089`]
    Traffic_selector_format_not_supported = 133

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'FlowIDStatus':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return FlowIDStatus(key)
        if key not in FlowIDStatus._member_map_:  # pylint: disable=no-member
            return extend_enum(FlowIDStatus, key, default)
        return FlowIDStatus[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'FlowIDStatus':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 1 <= value <= 127:
            #: Unassigned; available for success codes
            return extend_enum(cls, 'Unassigned_available_for_success_codes_%d' % value, value)
        if 134 <= value <= 250:
            #: Unassigned; available for reject codes
            return extend_enum(cls, 'Unassigned_available_for_reject_codes_%d' % value, value)
        if 251 <= value <= 255:
            #: Reserved for Experimental Use [:rfc:`6089`]
            return extend_enum(cls, 'Reserved_for_Experimental_Use_%d' % value, value)
        return super()._missing_(value)
