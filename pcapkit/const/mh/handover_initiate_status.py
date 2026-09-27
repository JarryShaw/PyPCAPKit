# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Handover Initiate Status Codes
====================================

.. module:: pcapkit.const.mh.handover_initiate_status

This module contains the constant enumeration for **Handover Initiate Status Codes**,
which is automatically generated from :class:`pcapkit.vendor.mh.handover_initiate_status.HandoverInitiateStatus`.

"""

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry

__all__ = ['HandoverInitiateStatus']


class HandoverInitiateStatus(EnumRegistry, IntEnum):
    """[HandoverInitiateStatus] Handover Initiate Status Codes"""

    #: FBU with the PCoA as source IP address [:rfc:`5568`]
    FBU_with_the_PCoA_as_source_IP_address = 0

    #: FBU whose source IP address is not PCoA [:rfc:`5568`]
    FBU_whose_source_IP_address_is_not_PCoA = 1

    #: Indicate the completion of forwarding [:rfc:`5949`]
    Indicate_the_completion_of_forwarding = 2

    #: All available context transferred [:rfc:`5949`]
    All_available_context_transferred = 3

    @classmethod
    def _missing_(cls, value: 'int') -> 'HandoverInitiateStatus':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 4 <= value <= 255:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        return super()._missing_(value)
