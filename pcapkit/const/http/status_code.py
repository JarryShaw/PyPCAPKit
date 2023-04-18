# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""HTTP Status Code
======================

.. module:: pcapkit.const.http.status_code

This module contains the constant enumeration for **HTTP Status Code**,
which is automatically generated from :class:`pcapkit.vendor.http.status_code.StatusCode`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum, extend_enum

if TYPE_CHECKING:
    from typing import Type

__all__ = ['StatusCode']


class StatusCode(IntEnum):
    """[StatusCode] HTTP Status Code"""

    def __new__(cls, value: 'int', message: 'str' = '') -> 'Type[StatusCode]':
        obj = int.__new__(cls, value)
        obj._value_ = value

        #: Status message.
        obj.message = message

        return obj

    #: Continue [:rfc:`9110#section-15.2.1`]
    CONTINUE = 100, 'Continue'

    #: Switching Protocols [:rfc:`9110#section-15.2.2`]
    SWITCHING_PROTOCOLS = 101, 'Switching Protocols'

    #: Processing [:rfc:`2518`]
    PROCESSING = 102, 'Processing'

    #: Early Hints [:rfc:`8297`]
    EARLY_HINTS = 103, 'Early Hints'

    #: OK [:rfc:`9110#section-15.3.1`]
    OK = 200, 'OK'

    #: Created [:rfc:`9110#section-15.3.2`]
    CREATED = 201, 'Created'

    #: Accepted [:rfc:`9110#section-15.3.3`]
    ACCEPTED = 202, 'Accepted'

    #: Non-Authoritative Information [:rfc:`9110#section-15.3.4`]
    NON_AUTHORITATIVE_INFORMATION = 203, 'Non-Authoritative Information'

    #: No Content [:rfc:`9110#section-15.3.5`]
    NO_CONTENT = 204, 'No Content'

    #: Reset Content [:rfc:`9110#section-15.3.6`]
    RESET_CONTENT = 205, 'Reset Content'

    #: Partial Content [:rfc:`9110#section-15.3.7`]
    PARTIAL_CONTENT = 206, 'Partial Content'

    #: Multi-Status [:rfc:`4918`]
    MULTI_STATUS = 207, 'Multi-Status'

    #: Already Reported [:rfc:`5842`]
    ALREADY_REPORTED = 208, 'Already Reported'

    #: IM Used [:rfc:`3229`]
    IM_USED = 226, 'IM Used'

    #: Multiple Choices [:rfc:`9110#section-15.4.1`]
    MULTIPLE_CHOICES = 300, 'Multiple Choices'

    #: Moved Permanently [:rfc:`9110#section-15.4.2`]
    MOVED_PERMANENTLY = 301, 'Moved Permanently'

    #: Found [:rfc:`9110#section-15.4.3`]
    FOUND = 302, 'Found'

    #: See Other [:rfc:`9110#section-15.4.4`]
    SEE_OTHER = 303, 'See Other'

    #: Not Modified [:rfc:`9110#section-15.4.5`]
    NOT_MODIFIED = 304, 'Not Modified'

    #: Use Proxy [:rfc:`9110#section-15.4.6`]
    USE_PROXY = 305, 'Use Proxy'

    #: (Unused) [:rfc:`9110#section-15.4.7`]
    STATUSCODE_306 = 306, '(Unused)'

    #: Temporary Redirect [:rfc:`9110#section-15.4.8`]
    TEMPORARY_REDIRECT = 307, 'Temporary Redirect'

    #: Permanent Redirect [:rfc:`9110#section-15.4.9`]
    PERMANENT_REDIRECT = 308, 'Permanent Redirect'

    #: Bad Request [:rfc:`9110#section-15.5.1`]
    BAD_REQUEST = 400, 'Bad Request'

    #: Unauthorized [:rfc:`9110#section-15.5.2`]
    UNAUTHORIZED = 401, 'Unauthorized'

    #: Payment Required [:rfc:`9110#section-15.5.3`]
    PAYMENT_REQUIRED = 402, 'Payment Required'

    #: Forbidden [:rfc:`9110#section-15.5.4`]
    FORBIDDEN = 403, 'Forbidden'

    #: Not Found [:rfc:`9110#section-15.5.5`]
    NOT_FOUND = 404, 'Not Found'

    #: Method Not Allowed [:rfc:`9110#section-15.5.6`]
    METHOD_NOT_ALLOWED = 405, 'Method Not Allowed'

    #: Not Acceptable [:rfc:`9110#section-15.5.7`]
    NOT_ACCEPTABLE = 406, 'Not Acceptable'

    #: Proxy Authentication Required [:rfc:`9110#section-15.5.8`]
    PROXY_AUTHENTICATION_REQUIRED = 407, 'Proxy Authentication Required'

    #: Request Timeout [:rfc:`9110#section-15.5.9`]
    REQUEST_TIMEOUT = 408, 'Request Timeout'

    #: Conflict [:rfc:`9110#section-15.5.10`]
    CONFLICT = 409, 'Conflict'

    #: Gone [:rfc:`9110#section-15.5.11`]
    GONE = 410, 'Gone'

    #: Length Required [:rfc:`9110#section-15.5.12`]
    LENGTH_REQUIRED = 411, 'Length Required'

    #: Precondition Failed [:rfc:`9110#section-15.5.13`]
    PRECONDITION_FAILED = 412, 'Precondition Failed'

    #: Content Too Large [:rfc:`9110#section-15.5.14`]
    CONTENT_TOO_LARGE = 413, 'Content Too Large'

    #: URI Too Long [:rfc:`9110#section-15.5.15`]
    URI_TOO_LONG = 414, 'URI Too Long'

    #: Unsupported Media Type [:rfc:`9110#section-15.5.16`]
    UNSUPPORTED_MEDIA_TYPE = 415, 'Unsupported Media Type'

    #: Range Not Satisfiable [:rfc:`9110#section-15.5.17`]
    RANGE_NOT_SATISFIABLE = 416, 'Range Not Satisfiable'

    #: Expectation Failed [:rfc:`9110#section-15.5.18`]
    EXPECTATION_FAILED = 417, 'Expectation Failed'

    #: (Unused) [:rfc:`9110#section-15.5.19`]
    STATUSCODE_418 = 418, '(Unused)'

    #: Misdirected Request [:rfc:`9110#section-15.5.20`]
    MISDIRECTED_REQUEST = 421, 'Misdirected Request'

    #: Unprocessable Content [:rfc:`9110#section-15.5.21`]
    UNPROCESSABLE_CONTENT = 422, 'Unprocessable Content'

    #: Locked [:rfc:`4918`]
    LOCKED = 423, 'Locked'

    #: Failed Dependency [:rfc:`4918`]
    FAILED_DEPENDENCY = 424, 'Failed Dependency'

    #: Too Early [:rfc:`8470`]
    TOO_EARLY = 425, 'Too Early'

    #: Upgrade Required [:rfc:`9110#section-15.5.22`]
    UPGRADE_REQUIRED = 426, 'Upgrade Required'

    #: Unassigned
    UNASSIGNED_427 = 427, 'Unassigned'

    #: Precondition Required [:rfc:`6585`]
    PRECONDITION_REQUIRED = 428, 'Precondition Required'

    #: Too Many Requests [:rfc:`6585`]
    TOO_MANY_REQUESTS = 429, 'Too Many Requests'

    #: Unassigned
    UNASSIGNED_430 = 430, 'Unassigned'

    #: Request Header Fields Too Large [:rfc:`6585`]
    REQUEST_HEADER_FIELDS_TOO_LARGE = 431, 'Request Header Fields Too Large'

    #: Unavailable For Legal Reasons [:rfc:`7725`]
    UNAVAILABLE_FOR_LEGAL_REASONS = 451, 'Unavailable For Legal Reasons'

    #: Internal Server Error [:rfc:`9110#section-15.6.1`]
    INTERNAL_SERVER_ERROR = 500, 'Internal Server Error'

    #: Not Implemented [:rfc:`9110#section-15.6.2`]
    NOT_IMPLEMENTED = 501, 'Not Implemented'

    #: Bad Gateway [:rfc:`9110#section-15.6.3`]
    BAD_GATEWAY = 502, 'Bad Gateway'

    #: Service Unavailable [:rfc:`9110#section-15.6.4`]
    SERVICE_UNAVAILABLE = 503, 'Service Unavailable'

    #: Gateway Timeout [:rfc:`9110#section-15.6.5`]
    GATEWAY_TIMEOUT = 504, 'Gateway Timeout'

    #: HTTP Version Not Supported [:rfc:`9110#section-15.6.6`]
    HTTP_VERSION_NOT_SUPPORTED = 505, 'HTTP Version Not Supported'

    #: Variant Also Negotiates [:rfc:`2295`]
    VARIANT_ALSO_NEGOTIATES = 506, 'Variant Also Negotiates'

    #: Insufficient Storage [:rfc:`4918`]
    INSUFFICIENT_STORAGE = 507, 'Insufficient Storage'

    #: Loop Detected [:rfc:`5842`]
    LOOP_DETECTED = 508, 'Loop Detected'

    #: Unassigned
    UNASSIGNED_509 = 509, 'Unassigned'

    #: Not Extended (OBSOLETED) [:rfc:`2774`][status-change-http-experiments-to-
    #: historic]
    NOT_EXTENDED = 510, 'Not Extended (OBSOLETED)'

    #: Network Authentication Required [:rfc:`6585`]
    NETWORK_AUTHENTICATION_REQUIRED = 511, 'Network Authentication Required'

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'StatusCode':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return StatusCode(key)
        if key not in StatusCode._member_map_:  # pylint: disable=no-member
            extend_enum(StatusCode, key, default)
        return StatusCode[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'StatusCode':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 100 <= value <= 599):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 104 <= value <= 199:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 209 <= value <= 225:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 227 <= value <= 299:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 309 <= value <= 399:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 419 <= value <= 420:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 432 <= value <= 450:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 452 <= value <= 499:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 512 <= value <= 599:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        return super()._missing_(value)
