# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Destination Options and Hop-by-Hop Options
================================================

.. module:: pcapkit.const.ipv6.option

This module contains the constant enumeration for **Destination Options and Hop-by-Hop Options**,
which is automatically generated from :class:`pcapkit.vendor.ipv6.option.Option`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['Option']


class Option(IntEnum):
    """[Option] Destination Options and Hop-by-Hop Options"""

    #: Pad1 [:rfc:`2460`]
    Pad1 = 0x00

    #: PadN [:rfc:`2460`]
    PadN = 0x01

    #: Jumbo Payload [:rfc:`2675`]
    Jumbo_Payload = 0xC2

    #: RPL Option [:rfc:`9008`]
    RPL_Option_0x23 = 0x23

    #: RPL Option (DEPRECATED) [:rfc:`6553`][:rfc:`9008`]
    RPL_Option_0x63 = 0x63

    #: Tunnel Encapsulation Limit [:rfc:`2473`]
    Tunnel_Encapsulation_Limit = 0x04

    #: Router Alert (DEPRECATED for New Protocols) [:rfc:`2711`][:rfc:`9805`]
    Router_Alert = 0x05

    #: Quick-Start [:rfc:`4782`][RFC Errata 2034]
    Quick_Start = 0x26

    #: CALIPSO [:rfc:`5570`]
    CALIPSO = 0x07

    #: SMF_DPD [:rfc:`6621`]
    SMF_DPD = 0x08

    #: Home Address [:rfc:`6275`]
    Home_Address = 0xC9

    #: Endpoint Identification (DEPRECATED) [CHARLES LYNN]
    Endpoint_Identification = 0x8A

    #: ILNP Nonce [:rfc:`6744`]
    ILNP_Nonce = 0x8B

    #: Line-Identification Option [:rfc:`6788`]
    Line_Identification_Option = 0x8C

    #: Deprecated [:rfc:`7731`]
    Deprecated = 0x4D

    #: MPL Option [:rfc:`7731`]
    MPL_Option = 0x6D

    #: IP_DFF [:rfc:`6971`]
    IP_DFF = 0xEE

    #: Performance and Diagnostic Metrics (PDM) [:rfc:`8250`]
    PDM = 0x0F

    #: Minimum Path MTU Hop-by-Hop Option [:rfc:`9268`]
    Minimum_Path_MTU_Hop_by_Hop_Option = 0x30

    #: IOAM Destination Option and IOAM Hop-by-Hop Option [:rfc:`9486`]
    IOAM_Destination_Option_and_IOAM_Hop_by_Hop_Option_0x11 = 0x11

    #: IOAM Destination Option and IOAM Hop-by-Hop Option [:rfc:`9486`]
    IOAM_Destination_Option_and_IOAM_Hop_by_Hop_Option_0x31 = 0x31

    #: AltMark [:rfc:`9343`]
    AltMark = 0x12

    #: RFC3692-style Experiment [:rfc:`4727`]
    RFC3692_style_Experiment_0x1E = 0x1E

    #: RFC3692-style Experiment [:rfc:`4727`]
    RFC3692_style_Experiment_0x3E = 0x3E

    #: RFC3692-style Experiment [:rfc:`4727`]
    RFC3692_style_Experiment_0x5E = 0x5E

    #: RFC3692-style Experiment [:rfc:`4727`]
    RFC3692_style_Experiment_0x7E = 0x7E

    #: RFC3692-style Experiment [:rfc:`4727`]
    RFC3692_style_Experiment_0x9E = 0x9E

    #: RFC3692-style Experiment [:rfc:`4727`]
    RFC3692_style_Experiment_0xBE = 0xBE

    #: RFC3692-style Experiment [:rfc:`4727`]
    RFC3692_style_Experiment_0xDE = 0xDE

    #: RFC3692-style Experiment [:rfc:`4727`]
    RFC3692_style_Experiment_0xFE = 0xFE

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'Option':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found. The placeholder ``-1`` stands
                for *no default*, in which case an unresolvable key propagates
                the lookup error instead of falling back.

        :meta private:
        """
        if isinstance(key, int):
            try:
                return Option(key)
            except ValueError:
                if default == -1:
                    raise
                return Option(default)
        try:
            return Option[key]  # type: ignore[misc]
        except KeyError:
            if default == -1:
                raise
            return Option(default)

    @classmethod
    def register(cls, value: 'int', name: 'str') -> 'Option':
        """Explicitly register a new member.

        Unlike :meth:`get` and :meth:`_missing_`, which resolve a key or a
        value without minting anything new, this is the caller-named entry
        point that still grows the registry, via :func:`aenum.extend_enum`.

        Args:
            value: Value of the new member.
            name: Name of the new member.

        Returns:
            The newly registered member.

        """
        return extend_enum(cls, name, value)

    @classmethod
    def _unregistered_member(cls, value: 'int', name: 'str') -> 'Option':
        """Build a member absent from this registry's own lookup tables.

        Used by :meth:`_missing_` for a bounded-but-unassigned value it
        resolves without anyone asking for a name, so that such a lookup no
        longer grows the registry -- contrast :meth:`register`, the explicit
        path that still does.

        Args:
            value: The member's value.
            name: The member's name.

        Returns:
            The unregistered member.

        """
        obj = int.__new__(cls, value)
        obj._name_ = name  # pylint: disable=protected-access
        obj._value_ = value  # pylint: disable=protected-access
        return obj

    @classmethod
    def _missing_(cls, value: 'int') -> 'Option':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0x00 <= value <= 0xFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return extend_enum(cls, 'Unassigned_0x%s' % hex(value)[2:].upper().zfill(2), value)
