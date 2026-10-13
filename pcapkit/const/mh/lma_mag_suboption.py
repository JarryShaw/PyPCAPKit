# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""LMA-Controlled MAG Parameters Sub-Option Type Values
==========================================================

.. module:: pcapkit.const.mh.lma_mag_suboption

This module contains the constant enumeration for **LMA-Controlled MAG Parameters Sub-Option Type Values**,
which is automatically generated from :class:`pcapkit.vendor.mh.lma_mag_suboption.LMAControlledMAGSuboption`.

"""

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry

__all__ = ['LMAControlledMAGSuboption']


class LMAControlledMAGSuboption(EnumRegistry, IntEnum):
    """[LMAControlledMAGSuboption] LMA-Controlled MAG Parameters Sub-Option Type Values"""

    #: Reserved [:rfc:`8127`]
    Reserved_0 = 0

    #: Binding Re-registration Control Sub-Option [:rfc:`8127`]
    Binding_Re_registration_Control = 1

    #: Heartbeat Control Sub-Option [:rfc:`8127`]
    Heartbeat_Control = 2

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
            return cls._unregistered_member(value, 'Unassigned')
        return super()._missing_(value)
