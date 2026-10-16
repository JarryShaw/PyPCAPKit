# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""HTTP/2 Error Code
=======================

.. module:: pcapkit.const.http.error_code

This module contains the constant enumeration for **HTTP/2 Error Code**,
which is automatically generated from :class:`pcapkit.vendor.http.error_code.ErrorCode`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['ErrorCode']


class ErrorCode(EnumRegistry, IntEnum):
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

    @classmethod
    def _validate_value(cls, value: 'Any') -> 'None':
        """Reject ``value`` unless it passes the range check :meth:`_missing_` makes.

        Overrides :meth:`~pcapkit.corekit.enum.EnumLookup._validate_value`
        with that check and the message it raises, so
        :meth:`~pcapkit.corekit.enum.EnumRegistry.register` refuses exactly the
        values :meth:`~pcapkit.corekit.enum.EnumLookup.get` refuses, in the
        same words (:issue:`1816`).

        Args:
            value: Value about to be looked up or minted.

        Raises:
            EnumValueError: If ``value`` fails that check. A
                :exc:`ValueError`, so an ``except ValueError`` caller is
                unaffected.

        """
        if not (isinstance(value, int) and 0x00000000 <= value <= 0xFFFFFFFF):
            raise EnumValueError('%r is not a valid %s' % (value, cls.__name__))

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
            return cls._unregistered_member(value, 'Unassigned')
        return super()._missing_(value)
