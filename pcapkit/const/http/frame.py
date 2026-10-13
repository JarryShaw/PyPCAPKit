# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""HTTP/2 Frame Type
=======================

.. module:: pcapkit.const.http.frame

This module contains the constant enumeration for **HTTP/2 Frame Type**,
which is automatically generated from :class:`pcapkit.vendor.http.frame.Frame`.

"""

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry

__all__ = ['Frame']


class Frame(EnumRegistry, IntEnum):
    """[Frame] HTTP/2 Frame Type"""

    #: ``DATA`` [RFC 9113, Section 6.1]
    DATA = 0x00

    #: ``HEADERS`` [RFC 9113, Section 6.2]
    HEADERS = 0x01

    #: ``PRIORITY`` [RFC 9113, Section 6.3]
    PRIORITY = 0x02

    #: ``RST_STREAM`` [RFC 9113, Section 6.4]
    RST_STREAM = 0x03

    #: ``SETTINGS`` [RFC 9113, Section 6.5]
    SETTINGS = 0x04

    #: ``PUSH_PROMISE`` [RFC 9113, Section 6.6]
    PUSH_PROMISE = 0x05

    #: ``PING`` [RFC 9113, Section 6.7]
    PING = 0x06

    #: ``GOAWAY`` [RFC 9113, Section 6.8]
    GOAWAY = 0x07

    #: ``WINDOW_UPDATE`` [RFC 9113, Section 6.9]
    WINDOW_UPDATE = 0x08

    #: ``CONTINUATION`` [RFC 9113, Section 6.10]
    CONTINUATION = 0x09

    #: ``ALTSVC`` [RFC 7838, Section 4]
    ALTSVC = 0x0A

    #: ``Unassigned``
    Unassigned_0x0B = 0x0B

    #: ``ORIGIN`` [RFC 8336]
    ORIGIN = 0x0C

    #: ``PRIORITY_UPDATE`` [RFC 9218]
    PRIORITY_UPDATE = 0x10

    @classmethod
    def _missing_(cls, value: 'int') -> 'Frame':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0x00 <= value <= 0xFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 0x0D <= value <= 0x0F:
            #: ``Unassigned``
            return cls._unregistered_member(value, 'Unassigned')
        if 0x11 <= value <= 0xFF:
            #: ``Unassigned``
            return cls._unregistered_member(value, 'Unassigned')
        return super()._missing_(value)
