# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""IPv6 Extension Header Types
=================================

.. module:: pcapkit.const.ipv6.extension_header

This module contains the constant enumeration for **IPv6 Extension Header Types**,
which is automatically generated from :class:`pcapkit.vendor.ipv6.extension_header.ExtensionHeader`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['ExtensionHeader']


class ExtensionHeader(EnumRegistry, IntEnum):
    """[ExtensionHeader] IPv6 Extension Header Types"""

    #: HOPOPT, IPv6 Hop-by-Hop Option [:rfc:`8200`]
    HOPOPT = 0

    #: IPv6-Route, Routing Header for IPv6 [:rfc:`8200`][:rfc:`5095`]
    IPv6_Route = 43

    #: IPv6-Frag, Fragment Header for IPv6 [:rfc:`8200`]
    IPv6_Frag = 44

    #: ESP, Encapsulating Security Payload [:rfc:`4303`]
    ESP = 50

    #: AH, Authentication Header [:rfc:`4302`]
    AH = 51

    #: IPv6-Opts, Destination Options for IPv6 [:rfc:`8200`]
    IPv6_Opts = 60

    #: Mobility Header [:rfc:`6275`]
    Mobility_Header = 135

    #: HIP, Host Identity Protocol [:rfc:`7401`]
    HIP = 139

    #: Shim6, Shim6 Protocol [:rfc:`5533`]
    Shim6 = 140

    #: Use for experimentation and testing [:rfc:`3692`][:rfc:`4727`]
    Use_for_experimentation_and_testing_253 = 253

    #: Use for experimentation and testing [:rfc:`3692`][:rfc:`4727`]
    Use_for_experimentation_and_testing_254 = 254

    @classmethod
    def _validate_value(cls, value: 'Any') -> 'None':
        """Reject ``value`` unless it fits the 8-bit Next Header field.

        Overrides :meth:`~pcapkit.corekit.enum.EnumLookup._validate_value` so
        that :meth:`~pcapkit.corekit.enum.EnumRegistry.register` refuses a
        value no extension header can carry, as
        :meth:`~pcapkit.corekit.enum.EnumLookup.get` does, in the same words
        (:issue:`1816`). There is no ``_missing_`` here to take a range from
        -- the constructor refuses every value no member carries -- so the
        range is that of the Next Header field an extension header type is
        sent in (:rfc:`8200#section-3`), and an unassigned type within it may
        still be minted.

        Args:
            value: Value about to be looked up or minted.

        Raises:
            EnumValueError: If ``value`` is not an :class:`int` in
                ``0``-``255``. A :exc:`ValueError`, so an ``except
                ValueError`` caller is unaffected.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise EnumValueError('%r is not a valid %s' % (value, cls.__name__))
