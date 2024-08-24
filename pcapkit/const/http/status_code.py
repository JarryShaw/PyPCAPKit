# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
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

    if TYPE_CHECKING:
        #: Status message.
        message: 'str'

    def __new__(cls, value: 'int', message: 'str' = '(Unknown)') -> 'Type[StatusCode]':
        obj = int.__new__(cls, value)
        obj._value_ = value

        obj.message = message

        return obj

    def __repr__(self) -> 'str':
        return "<%s [%s]>" % (self.__class__.__name__, self._value_)

    def __str__(self) -> 'str':
        return "[%s] %s" % (self._value_, self.message)

    #: Continue [:rfc:`9110#section-15.2.1`]
    CODE_100 = 100, 'Continue'

    #: Switching Protocols [:rfc:`9110#section-15.2.2`]
    CODE_101 = 101, 'Switching Protocols'

    #: Processing [:rfc:`2518`]
    CODE_102 = 102, 'Processing'

    #: Early Hints [:rfc:`8297`]
    CODE_103 = 103, 'Early Hints'

    #: OK [:rfc:`9110#section-15.3.1`]
    CODE_200 = 200, 'OK'

    #: Created [:rfc:`9110#section-15.3.2`]
    CODE_201 = 201, 'Created'

    #: Accepted [:rfc:`9110#section-15.3.3`]
    CODE_202 = 202, 'Accepted'

    #: Non-Authoritative Information [:rfc:`9110#section-15.3.4`]
    CODE_203 = 203, 'Non-Authoritative Information'

    #: No Content [:rfc:`9110#section-15.3.5`]
    CODE_204 = 204, 'No Content'

    #: Reset Content [:rfc:`9110#section-15.3.6`]
    CODE_205 = 205, 'Reset Content'

    #: Partial Content [:rfc:`9110#section-15.3.7`]
    CODE_206 = 206, 'Partial Content'

    #: Multi-Status [:rfc:`4918`]
    CODE_207 = 207, 'Multi-Status'

    #: Already Reported [:rfc:`5842`]
    CODE_208 = 208, 'Already Reported'

    #: IM Used [:rfc:`3229`]
    CODE_226 = 226, 'IM Used'

    #: Multiple Choices [:rfc:`9110#section-15.4.1`]
    CODE_300 = 300, 'Multiple Choices'

    #: Moved Permanently [:rfc:`9110#section-15.4.2`]
    CODE_301 = 301, 'Moved Permanently'

    #: Found [:rfc:`9110#section-15.4.3`]
    CODE_302 = 302, 'Found'

    #: See Other [:rfc:`9110#section-15.4.4`]
    CODE_303 = 303, 'See Other'

    #: Not Modified [:rfc:`9110#section-15.4.5`]
    CODE_304 = 304, 'Not Modified'

    #: Use Proxy [:rfc:`9110#section-15.4.6`]
    CODE_305 = 305, 'Use Proxy'

    #: (Unused) [:rfc:`9110#section-15.4.7`]
    CODE_306 = 306, '(Unused)'

    #: Temporary Redirect [:rfc:`9110#section-15.4.8`]
    CODE_307 = 307, 'Temporary Redirect'

    #: Permanent Redirect [:rfc:`9110#section-15.4.9`]
    CODE_308 = 308, 'Permanent Redirect'

    #: Bad Request [:rfc:`9110#section-15.5.1`]
    CODE_400 = 400, 'Bad Request'

    #: Unauthorized [:rfc:`9110#section-15.5.2`]
    CODE_401 = 401, 'Unauthorized'

    #: Payment Required [:rfc:`9110#section-15.5.3`]
    CODE_402 = 402, 'Payment Required'

    #: Forbidden [:rfc:`9110#section-15.5.4`]
    CODE_403 = 403, 'Forbidden'

    #: Not Found [:rfc:`9110#section-15.5.5`]
    CODE_404 = 404, 'Not Found'

    #: Method Not Allowed [:rfc:`9110#section-15.5.6`]
    CODE_405 = 405, 'Method Not Allowed'

    #: Not Acceptable [:rfc:`9110#section-15.5.7`]
    CODE_406 = 406, 'Not Acceptable'

    #: Proxy Authentication Required [:rfc:`9110#section-15.5.8`]
    CODE_407 = 407, 'Proxy Authentication Required'

    #: Request Timeout [:rfc:`9110#section-15.5.9`]
    CODE_408 = 408, 'Request Timeout'

    #: Conflict [:rfc:`9110#section-15.5.10`]
    CODE_409 = 409, 'Conflict'

    #: Gone [:rfc:`9110#section-15.5.11`]
    CODE_410 = 410, 'Gone'

    #: Length Required [:rfc:`9110#section-15.5.12`]
    CODE_411 = 411, 'Length Required'

    #: Precondition Failed [:rfc:`9110#section-15.5.13`]
    CODE_412 = 412, 'Precondition Failed'

    #: Content Too Large [:rfc:`9110#section-15.5.14`]
    CODE_413 = 413, 'Content Too Large'

    #: URI Too Long [:rfc:`9110#section-15.5.15`]
    CODE_414 = 414, 'URI Too Long'

    #: Unsupported Media Type [:rfc:`9110#section-15.5.16`]
    CODE_415 = 415, 'Unsupported Media Type'

    #: Range Not Satisfiable [:rfc:`9110#section-15.5.17`]
    CODE_416 = 416, 'Range Not Satisfiable'

    #: Expectation Failed [:rfc:`9110#section-15.5.18`]
    CODE_417 = 417, 'Expectation Failed'

    #: (Unused) [:rfc:`9110#section-15.5.19`]
    CODE_418 = 418, '(Unused)'

    #: Misdirected Request [:rfc:`9110#section-15.5.20`]
    CODE_421 = 421, 'Misdirected Request'

    #: Unprocessable Content [:rfc:`9110#section-15.5.21`]
    CODE_422 = 422, 'Unprocessable Content'

    #: Locked [:rfc:`4918`]
    CODE_423 = 423, 'Locked'

    #: Failed Dependency [:rfc:`4918`]
    CODE_424 = 424, 'Failed Dependency'

    #: Too Early [:rfc:`8470`]
    CODE_425 = 425, 'Too Early'

    #: Upgrade Required [:rfc:`9110#section-15.5.22`]
    CODE_426 = 426, 'Upgrade Required'

    #: Unassigned
    CODE_427 = 427, 'Unassigned'

    #: Precondition Required [:rfc:`6585`]
    CODE_428 = 428, 'Precondition Required'

    #: Too Many Requests [:rfc:`6585`]
    CODE_429 = 429, 'Too Many Requests'

    #: Unassigned
    CODE_430 = 430, 'Unassigned'

    #: Request Header Fields Too Large [:rfc:`6585`]
    CODE_431 = 431, 'Request Header Fields Too Large'

    #: Unavailable For Legal Reasons [:rfc:`7725`]
    CODE_451 = 451, 'Unavailable For Legal Reasons'

    #: Internal Server Error [:rfc:`9110#section-15.6.1`]
    CODE_500 = 500, 'Internal Server Error'

    #: Not Implemented [:rfc:`9110#section-15.6.2`]
    CODE_501 = 501, 'Not Implemented'

    #: Bad Gateway [:rfc:`9110#section-15.6.3`]
    CODE_502 = 502, 'Bad Gateway'

    #: Service Unavailable [:rfc:`9110#section-15.6.4`]
    CODE_503 = 503, 'Service Unavailable'

    #: Gateway Timeout [:rfc:`9110#section-15.6.5`]
    CODE_504 = 504, 'Gateway Timeout'

    #: HTTP Version Not Supported [:rfc:`9110#section-15.6.6`]
    CODE_505 = 505, 'HTTP Version Not Supported'

    #: Variant Also Negotiates [:rfc:`2295`]
    CODE_506 = 506, 'Variant Also Negotiates'

    #: Insufficient Storage [:rfc:`4918`]
    CODE_507 = 507, 'Insufficient Storage'

    #: Loop Detected [:rfc:`5842`]
    CODE_508 = 508, 'Loop Detected'

    #: Unassigned
    CODE_509 = 509, 'Unassigned'

    #: Not Extended (OBSOLETED) [:rfc:`2774`][Status change of HTTP experiments to
    #: Historic]
    CODE_510 = 510, 'Not Extended'

    #: Network Authentication Required [:rfc:`6585`]
    CODE_511 = 511, 'Network Authentication Required'

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
            return extend_enum(cls, 'CODE_%d' % value, value, 'Unassigned')
        if 209 <= value <= 225:
            #: Unassigned
            return extend_enum(cls, 'CODE_%d' % value, value, 'Unassigned')
        if 227 <= value <= 299:
            #: Unassigned
            return extend_enum(cls, 'CODE_%d' % value, value, 'Unassigned')
        if 309 <= value <= 399:
            #: Unassigned
            return extend_enum(cls, 'CODE_%d' % value, value, 'Unassigned')
        if 419 <= value <= 420:
            #: Unassigned
            return extend_enum(cls, 'CODE_%d' % value, value, 'Unassigned')
        if 432 <= value <= 450:
            #: Unassigned
            return extend_enum(cls, 'CODE_%d' % value, value, 'Unassigned')
        if 452 <= value <= 499:
            #: Unassigned
            return extend_enum(cls, 'CODE_%d' % value, value, 'Unassigned')
        if 512 <= value <= 599:
            #: Unassigned
            return extend_enum(cls, 'CODE_%d' % value, value, 'Unassigned')
        return super()._missing_(value)
