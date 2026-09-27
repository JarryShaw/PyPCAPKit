# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""HTTP/2 Settings
=====================

.. module:: pcapkit.const.http.setting

This module contains the constant enumeration for **HTTP/2 Settings**,
which is automatically generated from :class:`pcapkit.vendor.http.setting.Setting`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['Setting']


class Setting(IntEnum):
    """[Setting] HTTP/2 Settings"""

    #: ``Reserved`` [:rfc:`9113`]
    Reserved_0x0000 = 0x0000

    #: ``HEADER_TABLE_SIZE`` [:rfc:`9113#section-6.5.2`] (Initial Value: 4096)
    HEADER_TABLE_SIZE = 0x0001

    #: ``ENABLE_PUSH`` [:rfc:`9113#section-6.5.2`] (Initial Value: 1)
    ENABLE_PUSH = 0x0002

    #: ``MAX_CONCURRENT_STREAMS`` [:rfc:`9113#section-6.5.2`] (Initial Value:
    #: infinite)
    MAX_CONCURRENT_STREAMS = 0x0003

    #: ``INITIAL_WINDOW_SIZE`` [:rfc:`9113#section-6.5.2`] (Initial Value: 65535)
    INITIAL_WINDOW_SIZE = 0x0004

    #: ``MAX_FRAME_SIZE`` [:rfc:`9113#section-6.5.2`] (Initial Value: 16384)
    MAX_FRAME_SIZE = 0x0005

    #: ``MAX_HEADER_LIST_SIZE`` [:rfc:`9113#section-6.5.2`] (Initial Value:
    #: infinite)
    MAX_HEADER_LIST_SIZE = 0x0006

    #: ``Unassigned``
    Unassigned_0x0007 = 0x0007

    #: ``SETTINGS_ENABLE_CONNECT_PROTOCOL`` [:rfc:`8441`] (Initial Value: 0)
    SETTINGS_ENABLE_CONNECT_PROTOCOL = 0x0008

    #: ``SETTINGS_NO_RFC7540_PRIORITIES`` [:rfc:`9218`] (Initial Value: 0)
    SETTINGS_NO_RFC7540_PRIORITIES = 0x0009

    #: ``TLS_RENEG_PERMITTED`` [MS-HTTP2E][Gabriel Montenegro] (Initial Value:
    #: 0x00)
    TLS_RENEG_PERMITTED = 0x0010

    #: ``SETTINGS_ENABLE_METADATA`` [draft-beky-httpbis-metadata-02] (Initial
    #: Value: 0)
    SETTINGS_ENABLE_METADATA = 0x4D44

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'Setting':
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
                return Setting(key)
            except ValueError:
                if default == -1:
                    raise
                return Setting(default)
        try:
            return Setting[key]  # type: ignore[misc]
        except KeyError:
            if default == -1:
                raise
            return Setting(default)

    @classmethod
    def register(cls, value: 'int', name: 'str') -> 'Setting':
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
    def _unregistered_member(cls, value: 'int', name: 'str') -> 'Setting':
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
    def _missing_(cls, value: 'int') -> 'Setting':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0x0000 <= value <= 0xFFFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 0x000A <= value <= 0x000F:
            #: ``Unassigned``
            return extend_enum(cls, 'Unassigned_0x%s' % hex(value)[2:].upper().zfill(4), value)
        if 0x0011 <= value <= 0x4D43:
            #: ``Unassigned``
            return extend_enum(cls, 'Unassigned_0x%s' % hex(value)[2:].upper().zfill(4), value)
        if 0x4D45 <= value <= 0xFFFF:
            #: ``Unassigned``
            return extend_enum(cls, 'Unassigned_0x%s' % hex(value)[2:].upper().zfill(4), value)
        return super()._missing_(value)
