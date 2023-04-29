# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""HTTP Method
=================

.. module:: pcapkit.const.http.method

This module contains the constant enumeration for **HTTP Method**,
which is automatically generated from :class:`pcapkit.vendor.http.method.Method`.

"""

from typing import TYPE_CHECKING

from aenum import StrEnum, extend_enum

if TYPE_CHECKING:
    from typing import Optional, Type

__all__ = ['Method']

class Method(StrEnum):
    """[Method] HTTP Method"""

    if TYPE_CHECKING:
        #: Safe method.
        safe: 'bool'
        #: Idempotent method.
        idempotent: 'bool'

    def __new__(cls, value: 'str', safe: 'bool' = False,
                idempotent: 'bool' = False) -> 'Type[Method]':
        obj = str.__new__(cls)
        obj._value_ = value

        obj.safe = safe
        obj.idempotent = idempotent

        return obj

    def __repr__(self) -> 'str':
        return "<%s.%s>" % (self.__class__.__name__, self._value_)

    #: ACL [:rfc:`3744#section-8.1`]
    ACL = 'ACL', False, True

    #: BASELINE-CONTROL [:rfc:`3253#section-12.6`]
    BASELINE_CONTROL = 'BASELINE-CONTROL', False, True

    #: BIND [:rfc:`5842#section-4`]
    BIND = 'BIND', False, True

    #: CHECKIN [:rfc:`3253#section-4.4,-section-9.4`]
    CHECKIN = 'CHECKIN', False, True

    #: CHECKOUT [:rfc:`3253#section-4.3,-section-8.8`]
    CHECKOUT = 'CHECKOUT', False, True

    #: CONNECT [:rfc:`9110#section-9.3.6`]
    CONNECT = 'CONNECT', False, False

    #: COPY [:rfc:`4918#section-9.8`]
    COPY = 'COPY', False, True

    #: DELETE [:rfc:`9110#section-9.3.5`]
    DELETE = 'DELETE', False, True

    #: GET [:rfc:`9110#section-9.3.1`]
    GET = 'GET', True, True

    #: HEAD [:rfc:`9110#section-9.3.2`]
    HEAD = 'HEAD', True, True

    #: LABEL [:rfc:`3253#section-8.2`]
    LABEL = 'LABEL', False, True

    #: LINK [:rfc:`2068#section-19.6.1.2`]
    LINK = 'LINK', False, True

    #: LOCK [:rfc:`4918#section-9.10`]
    LOCK = 'LOCK', False, False

    #: MERGE [:rfc:`3253#section-11.2`]
    MERGE = 'MERGE', False, True

    #: MKACTIVITY [:rfc:`3253#section-13.5`]
    MKACTIVITY = 'MKACTIVITY', False, True

    #: MKCALENDAR [:rfc:`4791#section-5.3.1`][:rfc:`8144#section-2.3`]
    MKCALENDAR = 'MKCALENDAR', False, True

    #: MKCOL
    #: [:rfc:`4918#section-9.3`][:rfc:`5689#section-3`][:rfc:`8144#section-2.3`]
    MKCOL = 'MKCOL', False, True

    #: MKREDIRECTREF [:rfc:`4437#section-6`]
    MKREDIRECTREF = 'MKREDIRECTREF', False, True

    #: MKWORKSPACE [:rfc:`3253#section-6.3`]
    MKWORKSPACE = 'MKWORKSPACE', False, True

    #: MOVE [:rfc:`4918#section-9.9`]
    MOVE = 'MOVE', False, True

    #: OPTIONS [:rfc:`9110#section-9.3.7`]
    OPTIONS = 'OPTIONS', True, True

    #: ORDERPATCH [:rfc:`3648#section-7`]
    ORDERPATCH = 'ORDERPATCH', False, True

    #: PATCH [:rfc:`5789#section-2`]
    PATCH = 'PATCH', False, False

    #: POST [:rfc:`9110#section-9.3.3`]
    POST = 'POST', False, False

    #: PRI [:rfc:`9113#section-3.4`]
    PRI = 'PRI', True, True

    #: PROPFIND [:rfc:`4918#section-9.1`][:rfc:`8144#section-2.1`]
    PROPFIND = 'PROPFIND', True, True

    #: PROPPATCH [:rfc:`4918#section-9.2`][:rfc:`8144#section-2.2`]
    PROPPATCH = 'PROPPATCH', False, True

    #: PUT [:rfc:`9110#section-9.3.4`]
    PUT = 'PUT', False, True

    #: REBIND [:rfc:`5842#section-6`]
    REBIND = 'REBIND', False, True

    #: REPORT [:rfc:`3253#section-3.6`][:rfc:`8144#section-2.1`]
    REPORT = 'REPORT', True, True

    #: SEARCH [:rfc:`5323#section-2`]
    SEARCH = 'SEARCH', True, True

    #: TRACE [:rfc:`9110#section-9.3.8`]
    TRACE = 'TRACE', True, True

    #: UNBIND [:rfc:`5842#section-5`]
    UNBIND = 'UNBIND', False, True

    #: UNCHECKOUT [:rfc:`3253#section-4.5`]
    UNCHECKOUT = 'UNCHECKOUT', False, True

    #: UNLINK [:rfc:`2068#section-19.6.1.3`]
    UNLINK = 'UNLINK', False, True

    #: UNLOCK [:rfc:`4918#section-9.11`]
    UNLOCK = 'UNLOCK', False, True

    #: UPDATE [:rfc:`3253#section-7.1`]
    UPDATE = 'UPDATE', False, True

    #: UPDATEREDIRECTREF [:rfc:`4437#section-7`]
    UPDATEREDIRECTREF = 'UPDATEREDIRECTREF', False, True

    #: VERSION-CONTROL [:rfc:`3253#section-3.5`]
    VERSION_CONTROL = 'VERSION-CONTROL', False, True

    @staticmethod
    def get(key: 'str', default: 'Optional[str]' = None) -> 'Method':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if key not in Method._member_map_:  # pylint: disable=no-member
            return extend_enum(Method, key.upper(), default if default is not None else key)
        return Method[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'str') -> 'Method':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        return extend_enum(cls, value.upper(), value)
