# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Access Network Information (ANI) Sub-Option Type Values
=============================================================

.. module:: pcapkit.const.mh.ani_suboption

This module contains the constant enumeration for **Access Network Information (ANI) Sub-Option Type Values**,
which is automatically generated from :class:`pcapkit.vendor.mh.ani_suboption.ANISuboption`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['ANISuboption']


class ANISuboption(IntEnum):
    """[ANISuboption] Access Network Information (ANI) Sub-Option Type Values"""

    #: Reserved [:rfc:`6757`]
    Reserved_0 = 0

    #: Network-Identifier sub-option [:rfc:`6757`]
    Network_Identifier = 1

    #: Geo-Location sub-option [:rfc:`6757`]
    Geo_Location = 2

    #: Operator-Identifier sub-option [:rfc:`6757`]
    Operator_Identifier = 3

    #: Civic-Location sub-option [:rfc:`7563`]
    Civic_Location = 4

    #: MAG-Group-Identifier sub-option [:rfc:`7563`]
    MAG_Group_Identifier = 5

    #: ANI Update-Timer sub-option [:rfc:`7563`]
    ANI_Update_Timer = 6

    #: Reserved [:rfc:`6757`]
    Reserved_255 = 255

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'ANISuboption':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return ANISuboption(key)
        if key not in ANISuboption._member_map_:  # pylint: disable=no-member
            return extend_enum(ANISuboption, key, default)
        return ANISuboption[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'ANISuboption':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 7 <= value <= 254:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        return super()._missing_(value)
