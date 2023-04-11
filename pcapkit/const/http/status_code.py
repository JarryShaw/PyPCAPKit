# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""HTTP Status Code
======================

This module contains the constant enumeration for **HTTP Status Code**,
which is automatically generated from :class:`pcapkit.vendor.http.status_code.StatusCode`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['StatusCode']


class StatusCode(IntEnum):
    """[StatusCode] HTTP Status Code"""

    #: Continue [:rfc:`9110#section-15.2.1`]
    Continue = 100

    #: Switching Protocols [:rfc:`9110#section-15.2.2`]
    Switching_Protocols = 101

    #: Processing [:rfc:`2518`]
    Processing = 102

    #: Early Hints [:rfc:`8297`]
    Early_Hints = 103

    #: OK [:rfc:`9110#section-15.3.1`]
    OK = 200

    #: Created [:rfc:`9110#section-15.3.2`]
    Created = 201

    #: Accepted [:rfc:`9110#section-15.3.3`]
    Accepted = 202

    #: Non-Authoritative Information [:rfc:`9110#section-15.3.4`]
    Non_Authoritative_Information = 203

    #: No Content [:rfc:`9110#section-15.3.5`]
    No_Content = 204

    #: Reset Content [:rfc:`9110#section-15.3.6`]
    Reset_Content = 205

    #: Partial Content [:rfc:`9110#section-15.3.7`]
    Partial_Content = 206

    #: Multi-Status [:rfc:`4918`]
    Multi_Status = 207

    #: Already Reported [:rfc:`5842`]
    Already_Reported = 208

    #: IM Used [:rfc:`3229`]
    IM_Used = 226

    #: Multiple Choices [:rfc:`9110#section-15.4.1`]
    Multiple_Choices = 300

    #: Moved Permanently [:rfc:`9110#section-15.4.2`]
    Moved_Permanently = 301

    #: Found [:rfc:`9110#section-15.4.3`]
    Found = 302

    #: See Other [:rfc:`9110#section-15.4.4`]
    See_Other = 303

    #: Not Modified [:rfc:`9110#section-15.4.5`]
    Not_Modified = 304

    #: Use Proxy [:rfc:`9110#section-15.4.6`]
    Use_Proxy = 305

    #: (Unused) [:rfc:`9110#section-15.4.7`]
    StatusCode_306 = 306

    #: Temporary Redirect [:rfc:`9110#section-15.4.8`]
    Temporary_Redirect = 307

    #: Permanent Redirect [:rfc:`9110#section-15.4.9`]
    Permanent_Redirect = 308

    #: Bad Request [:rfc:`9110#section-15.5.1`]
    Bad_Request = 400

    #: Unauthorized [:rfc:`9110#section-15.5.2`]
    Unauthorized = 401

    #: Payment Required [:rfc:`9110#section-15.5.3`]
    Payment_Required = 402

    #: Forbidden [:rfc:`9110#section-15.5.4`]
    Forbidden = 403

    #: Not Found [:rfc:`9110#section-15.5.5`]
    Not_Found = 404

    #: Method Not Allowed [:rfc:`9110#section-15.5.6`]
    Method_Not_Allowed = 405

    #: Not Acceptable [:rfc:`9110#section-15.5.7`]
    Not_Acceptable = 406

    #: Proxy Authentication Required [:rfc:`9110#section-15.5.8`]
    Proxy_Authentication_Required = 407

    #: Request Timeout [:rfc:`9110#section-15.5.9`]
    Request_Timeout = 408

    #: Conflict [:rfc:`9110#section-15.5.10`]
    Conflict = 409

    #: Gone [:rfc:`9110#section-15.5.11`]
    Gone = 410

    #: Length Required [:rfc:`9110#section-15.5.12`]
    Length_Required = 411

    #: Precondition Failed [:rfc:`9110#section-15.5.13`]
    Precondition_Failed = 412

    #: Content Too Large [:rfc:`9110#section-15.5.14`]
    Content_Too_Large = 413

    #: URI Too Long [:rfc:`9110#section-15.5.15`]
    URI_Too_Long = 414

    #: Unsupported Media Type [:rfc:`9110#section-15.5.16`]
    Unsupported_Media_Type = 415

    #: Range Not Satisfiable [:rfc:`9110#section-15.5.17`]
    Range_Not_Satisfiable = 416

    #: Expectation Failed [:rfc:`9110#section-15.5.18`]
    Expectation_Failed = 417

    #: (Unused) [:rfc:`9110#section-15.5.19`]
    StatusCode_418 = 418

    #: Misdirected Request [:rfc:`9110#section-15.5.20`]
    Misdirected_Request = 421

    #: Unprocessable Content [:rfc:`9110#section-15.5.21`]
    Unprocessable_Content = 422

    #: Locked [:rfc:`4918`]
    Locked = 423

    #: Failed Dependency [:rfc:`4918`]
    Failed_Dependency = 424

    #: Too Early [:rfc:`8470`]
    Too_Early = 425

    #: Upgrade Required [:rfc:`9110#section-15.5.22`]
    Upgrade_Required = 426

    #: Unassigned
    Unassigned_427 = 427

    #: Precondition Required [:rfc:`6585`]
    Precondition_Required = 428

    #: Too Many Requests [:rfc:`6585`]
    Too_Many_Requests = 429

    #: Unassigned
    Unassigned_430 = 430

    #: Request Header Fields Too Large [:rfc:`6585`]
    Request_Header_Fields_Too_Large = 431

    #: Unavailable For Legal Reasons [:rfc:`7725`]
    Unavailable_For_Legal_Reasons = 451

    #: Internal Server Error [:rfc:`9110#section-15.6.1`]
    Internal_Server_Error = 500

    #: Not Implemented [:rfc:`9110#section-15.6.2`]
    Not_Implemented = 501

    #: Bad Gateway [:rfc:`9110#section-15.6.3`]
    Bad_Gateway = 502

    #: Service Unavailable [:rfc:`9110#section-15.6.4`]
    Service_Unavailable = 503

    #: Gateway Timeout [:rfc:`9110#section-15.6.5`]
    Gateway_Timeout = 504

    #: HTTP Version Not Supported [:rfc:`9110#section-15.6.6`]
    HTTP_Version_Not_Supported = 505

    #: Variant Also Negotiates [:rfc:`2295`]
    Variant_Also_Negotiates = 506

    #: Insufficient Storage [:rfc:`4918`]
    Insufficient_Storage = 507

    #: Loop Detected [:rfc:`5842`]
    Loop_Detected = 508

    #: Unassigned
    Unassigned_509 = 509

    #: Not Extended (OBSOLETED) [:rfc:`2774`][status-change-http-experiments-to-
    #: historic]
    Not_Extended = 510

    #: Network Authentication Required [:rfc:`6585`]
    Network_Authentication_Required = 511

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'StatusCode':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

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
