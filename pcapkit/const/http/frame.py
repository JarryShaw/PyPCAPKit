# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""HTTP/2 Frame Type
=======================

.. module:: pcapkit.const.http.frame

This module contains the constant enumeration for **HTTP/2 Frame Type**,
which is automatically generated from :class:`pcapkit.vendor.http.frame.Frame`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['Frame']


class Frame(IntEnum):
    """[Frame] HTTP/2 Frame Type"""

    #: ``DATA`` [:rfc:`9113#section-6.1`]
    DATA = 0x00

    #: ``HEADERS`` [:rfc:`9113#section-6.2`]
    HEADERS = 0x01

    #: ``PRIORITY`` [:rfc:`9113#section-6.3`]
    PRIORITY = 0x02

    #: ``RST_STREAM`` [:rfc:`9113#section-6.4`]
    RST_STREAM = 0x03

    #: ``SETTINGS`` [:rfc:`9113#section-6.5`]
    SETTINGS = 0x04

    #: ``PUSH_PROMISE`` [:rfc:`9113#section-6.6`]
    PUSH_PROMISE = 0x05

    #: ``PING`` [:rfc:`9113#section-6.7`]
    PING = 0x06

    #: ``GOAWAY`` [:rfc:`9113#section-6.8`]
    GOAWAY = 0x07

    #: ``WINDOW_UPDATE`` [:rfc:`9113#section-6.9`]
    WINDOW_UPDATE = 0x08

    #: ``CONTINUATION`` [:rfc:`9113#section-6.10`]
    CONTINUATION = 0x09

    #: ``ALTSVC`` [:rfc:`7838#section-4`]
    ALTSVC = 0x0A

    #: ``Unassigned``
    Unassigned_0x0B = 0x0B

    #: ``ORIGIN`` [:rfc:`8336`]
    ORIGIN = 0x0C

    #: ``PRIORITY_UPDATE`` [:rfc:`9218`]
    PRIORITY_UPDATE = 0x10

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'Frame':
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
                return Frame(key)
            except ValueError:
                if default == -1:
                    raise
                return Frame(default)
        try:
            return Frame[key]  # type: ignore[misc]
        except KeyError:
            if default == -1:
                raise
            return Frame(default)

    @classmethod
    def register(cls, value: 'int', name: 'str') -> 'Frame':
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
    def _unregistered_member(cls, value: 'int', name: 'str') -> 'Frame':
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
    def _missing_(cls, value: 'int') -> 'Frame':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0x00 <= value <= 0xFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 0x0D <= value <= 0x0F:
            #: ``Unassigned``
            return extend_enum(cls, 'Unassigned_0x%s' % hex(value)[2:].upper().zfill(2), value)
        if 0x11 <= value <= 0xFF:
            #: ``Unassigned``
            return extend_enum(cls, 'Unassigned_0x%s' % hex(value)[2:].upper().zfill(2), value)
        return super()._missing_(value)
