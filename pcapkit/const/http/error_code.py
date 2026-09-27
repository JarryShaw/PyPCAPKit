# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""HTTP/2 Error Code
=======================

.. module:: pcapkit.const.http.error_code

This module contains the constant enumeration for **HTTP/2 Error Code**,
which is automatically generated from :class:`pcapkit.vendor.http.error_code.ErrorCode`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['ErrorCode']


class ErrorCode(IntEnum):
    """[ErrorCode] HTTP/2 Error Code"""

    #: NO_ERROR, Graceful shutdown [:rfc:`9113#section-7`]
    NO_ERROR = 0x00000000

    #: PROTOCOL_ERROR, Protocol error detected [:rfc:`9113#section-7`]
    PROTOCOL_ERROR = 0x00000001

    #: INTERNAL_ERROR, Implementation fault [:rfc:`9113#section-7`]
    INTERNAL_ERROR = 0x00000002

    #: FLOW_CONTROL_ERROR, Flow-control limits exceeded [:rfc:`9113#section-7`]
    FLOW_CONTROL_ERROR = 0x00000003

    #: SETTINGS_TIMEOUT, Settings not acknowledged [:rfc:`9113#section-7`]
    SETTINGS_TIMEOUT = 0x00000004

    #: STREAM_CLOSED, Frame received for closed stream [:rfc:`9113#section-7`]
    STREAM_CLOSED = 0x00000005

    #: FRAME_SIZE_ERROR, Frame size incorrect [:rfc:`9113#section-7`]
    FRAME_SIZE_ERROR = 0x00000006

    #: REFUSED_STREAM, Stream not processed [:rfc:`9113#section-7`]
    REFUSED_STREAM = 0x00000007

    #: CANCEL, Stream cancelled [:rfc:`9113#section-7`]
    CANCEL = 0x00000008

    #: COMPRESSION_ERROR, Compression state not updated [:rfc:`9113#section-7`]
    COMPRESSION_ERROR = 0x00000009

    #: CONNECT_ERROR, TCP connection error for CONNECT method
    #: [:rfc:`9113#section-7`]
    CONNECT_ERROR = 0x0000000A

    #: ENHANCE_YOUR_CALM, Processing capacity exceeded [:rfc:`9113#section-7`]
    ENHANCE_YOUR_CALM = 0x0000000B

    #: INADEQUATE_SECURITY, Negotiated TLS parameters not acceptable
    #: [:rfc:`9113#section-7`]
    INADEQUATE_SECURITY = 0x0000000C

    #: HTTP_1_1_REQUIRED, Use HTTP/1.1 for the request [:rfc:`9113#section-7`]
    HTTP_1_1_REQUIRED = 0x0000000D

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'ErrorCode':
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
                return ErrorCode(key)
            except ValueError:
                if default == -1:
                    raise
                return ErrorCode(default)
        try:
            return ErrorCode[key]  # type: ignore[misc]
        except KeyError:
            if default == -1:
                raise
            return ErrorCode(default)

    @classmethod
    def register(cls, value: 'int', name: 'str') -> 'ErrorCode':
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
    def _unregistered_member(cls, value: 'int', name: 'str') -> 'ErrorCode':
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
    def _missing_(cls, value: 'int') -> 'ErrorCode':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0x00000000 <= value <= 0xFFFFFFFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 0x0000000E <= value <= 0xFFFFFFFF:
            #: Unassigned
            temp = hex(value)[2:].upper().zfill(8)
            return extend_enum(cls, 'Unassigned_0x%s' % (temp[:4]+'_'+temp[4:]), value)
        return super()._missing_(value)
