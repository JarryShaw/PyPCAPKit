# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""LMA-Controlled MAG Parameters Sub-Option Type Values
==========================================================

.. module:: pcapkit.const.mh.lma_mag_suboption

This module contains the constant enumeration for **LMA-Controlled MAG Parameters Sub-Option Type Values**,
which is automatically generated from :class:`pcapkit.vendor.mh.lma_mag_suboption.LMAControlledMAGSuboption`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['LMAControlledMAGSuboption']


class LMAControlledMAGSuboption(IntEnum):
    """[LMAControlledMAGSuboption] LMA-Controlled MAG Parameters Sub-Option Type Values"""

    #: Reserved [:rfc:`8127`]
    Reserved_0 = 0

    #: Binding Re-registration Control Sub-Option [:rfc:`8127`]
    Binding_Re_registration_Control = 1

    #: Heartbeat Control Sub-Option [:rfc:`8127`]
    Heartbeat_Control = 2

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'LMAControlledMAGSuboption':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return LMAControlledMAGSuboption(key)
        if key not in LMAControlledMAGSuboption._member_map_:  # pylint: disable=no-member
            return extend_enum(LMAControlledMAGSuboption, key, default)
        return LMAControlledMAGSuboption[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'LMAControlledMAGSuboption':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 3 <= value <= 255:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        return super()._missing_(value)
