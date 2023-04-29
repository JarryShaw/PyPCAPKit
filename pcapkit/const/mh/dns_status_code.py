# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Status Codes (DNS Update Mobility Option)
===============================================

.. module:: pcapkit.const.mh.dns_status_code

This module contains the constant enumeration for **Status Codes (DNS Update Mobility Option)**,
which is automatically generated from :class:`pcapkit.vendor.mh.dns_status_code.DNSStatusCode`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['DNSStatusCode']


class DNSStatusCode(IntEnum):
    """[DNSStatusCode] Status Codes (DNS Update Mobility Option)"""

    #: DNS update performed [:rfc:`5026`]
    DNS_update_performed = 0

    #: Reason unspecified [:rfc:`5026`]
    Reason_unspecified = 128

    #: Administratively prohibited [:rfc:`5026`]
    Administratively_prohibited = 129

    #: DNS Update Failed [:rfc:`5026`]
    DNS_Update_Failed = 130

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'DNSStatusCode':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return DNSStatusCode(key)
        if key not in DNSStatusCode._member_map_:  # pylint: disable=no-member
            return extend_enum(DNSStatusCode, key, default)
        return DNSStatusCode[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'DNSStatusCode':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 1 <= value <= 127:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 131 <= value <= 255:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        return super()._missing_(value)
