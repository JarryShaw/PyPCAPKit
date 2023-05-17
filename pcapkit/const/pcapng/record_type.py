# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Record Types
==================

.. module:: pcapkit.const.pcapng.record_type

This module contains the constant enumeration for **Record Types**,
which is automatically generated from :class:`pcapkit.vendor.pcapng.record_type.RecordType`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['RecordType']


class RecordType(IntEnum):
    """[RecordType] Record Types"""

    #: nrb_record_end
    nrb_record_end = 0x0000

    #: nrb_record_ipv4
    nrb_record_ipv4 = 0x0001

    #: nrb_record_ipv6
    nrb_record_ipv6 = 0x0002

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'RecordType':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return RecordType(key)
        if key not in RecordType._member_map_:  # pylint: disable=no-member
            return extend_enum(RecordType, key, default)
        return RecordType[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'RecordType':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 0xFFFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned_0x%04x' % value, value)
        return cls(value)
