# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Mobile Node Group Identifier Type Registry
================================================

.. module:: pcapkit.const.mh.mn_group_id

This module contains the constant enumeration for **Mobile Node Group Identifier Type Registry**,
which is automatically generated from :class:`pcapkit.vendor.mh.mn_group_id.MNGroupID`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['MNGroupID']


class MNGroupID(IntEnum):
    """[MNGroupID] Mobile Node Group Identifier Type Registry"""

    #: Reserved [:rfc:`6602`]
    Reserved_0 = 0

    #: Bulk Binding Update Group [:rfc:`6602`]
    Bulk_Binding_Update_Group = 1

    #: Reserved [:rfc:`6602`]
    Reserved_255 = 255

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'MNGroupID':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return MNGroupID(key)
        if key not in MNGroupID._member_map_:  # pylint: disable=no-member
            return extend_enum(MNGroupID, key, default)
        return MNGroupID[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'MNGroupID':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 2 <= value <= 254:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        return super()._missing_(value)
