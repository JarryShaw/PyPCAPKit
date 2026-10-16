# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""HTTP Method
=================

.. module:: pcapkit.const.http.method

This module contains the constant enumeration for **HTTP Method**,
which is automatically generated from :class:`pcapkit.vendor.http.method.Method`.

"""

from typing import TYPE_CHECKING

from aenum import StrEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any, Optional, Type

__all__ = ['Method']

class Method(EnumRegistry, StrEnum):
    """[Method] HTTP Method

    .. versionchanged:: 1.5.0

       Neither ``_missing_`` nor ``get()`` mints a member, per the owner's
       ruling on GitHub issue :issue:`860`: only IANA-registered values are
       legitimate members, and a new one is created through :meth:`register`,
       which can supply :attr:`safe` and :attr:`idempotent` where a bare wire
       method verb carries neither. ``get()`` matches ``key`` case-sensitively,
       as :rfc:`9110` makes the method token (:issue:`896`), and checks it
       against member values as well as names (:issue:`908`). A member's
       :class:`str` payload is its value, so ``Method.GET == 'GET'``
       (:issue:`870`).

    """

    if TYPE_CHECKING:
        #: Safe method.
        safe: 'bool'
        #: Idempotent method.
        idempotent: 'bool'

    def __new__(cls, value: 'str', safe: 'bool' = False,
                idempotent: 'bool' = False) -> 'Type[Method]':
        obj = str.__new__(cls, value)
        obj._value_ = value

        obj.safe = safe
        obj.idempotent = idempotent

        return obj

    def __repr__(self) -> 'str':
        return f'<{self.__class__.__name__}.{self._value_}>'

    #: ACL [:rfc:`3744#section-8.1`]
    ACL = 'ACL', False, True

    #: BASELINE-CONTROL [:rfc:`3253#section-12.6`]
    BASELINE_CONTROL = 'BASELINE-CONTROL', False, True

    #: BIND [:rfc:`5842#section-4`]
    BIND = 'BIND', False, True

    #: CHECKIN [:rfc:`3253#section-9.4`]
    CHECKIN = 'CHECKIN', False, True

    #: CHECKOUT [:rfc:`3253#section-8.8`]
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

    #: QUERY [:rfc:`10008#section-2`]
    QUERY = 'QUERY', True, True

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

    @classmethod
    def _unregistered_member(cls, value: 'str', name: 'str') -> 'Method':
        """Build a member absent from this registry's own lookup tables.

        Leaves :attr:`safe` and :attr:`idempotent` at the same defaults
        :meth:`__new__` itself would, rather than missing entirely --
        :meth:`~pcapkit.corekit.enum.EnumRegistry._unregistered_member`
        bypasses :meth:`__new__` (it calls :class:`str`'s directly), so
        those attributes would otherwise be absent. There is no more
        specific value to reconstruct them from -- a bare wire method verb
        carries neither, which is exactly the owner's reasoning for why
        ``get()``/``_missing_`` must not mint one: :meth:`register` is the
        path that can actually supply them.

        Args:
            value: Value to get enum item -- the convention here, shared with
                :class:`~pcapkit.const.ftp.command.FEATCode` and
                :class:`~pcapkit.const.ftp.command.Command`, is the caller's
                own casing, unchanged: an unregistered member's *value* is
                exactly what was observed on the wire, matching how a
                *registered* member's own value is exactly what was
                declared, never reformatted. Only :attr:`name` -- the
                identifier, not the value -- is canonicalised.

                A *registered* member carries its value the same way:
                :meth:`__new__` passes ``value`` to ``str.__new__``, as
                :class:`~pcapkit.const.ftp.command.Command`'s own
                ``__new__`` does (:issue:`870`), so both kinds of member
                carry their own value as real :class:`str` content
                (``str(Method.GET) == 'GET'`` and
                ``str(Method('frob')) == 'frob'``).
            name: Bare label for the unregistered member -- here, the
                canonical upper-case form of ``value``, matching the name
                every *registered* member of this class is looked up by,
                since :issue:`860`'s open-vocabulary registries have no manufactured
                placeholder label to fall back to.

        """
        obj = super()._unregistered_member(value, name)
        obj.safe = False
        obj.idempotent = False
        return obj

    @classmethod
    def get(cls, key: 'str', default: 'Optional[str]' = None) -> 'Method':
        """Backport support for original codes.

        Delegates to :meth:`~pcapkit.corekit.enum.EnumLookup.get` for the
        lookup itself, so ``key`` is checked against member values as well
        as names (GitHub issue :issue:`908`). That is what resolves the two
        IANA methods whose member *name* differs from their *value* --
        ``BASELINE_CONTROL`` / ``'BASELINE-CONTROL'`` and
        ``VERSION_CONTROL`` / ``'VERSION-CONTROL'``, a hyphen being unusable
        in a Python identifier -- which :meth:`_missing_` (and so the
        constructor) also finds by value.

        It is a :class:`classmethod`, as the base is, because a
        zero-argument ``super()`` needs a first argument to bind
        (:issue:`908`). ``Method.get('X')`` binds the same as it would on a
        :class:`staticmethod`.

        ``default`` does not follow the base's ``NO_DEFAULT`` sentinel and
        value-only fallback: the base's ``default`` must name a
        *registered* value (resolved through ``_value2member_map_``), while
        this override's ``default`` supplies the *value* of the
        unregistered member it builds on a miss.

        .. versionchanged:: 1.5.0

           A non-:class:`str` ``key`` raises :exc:`ValueError`
           (:issue:`908`). ``get(42)`` and ``get(None)`` raised
           :exc:`AttributeError` from ``key.upper()``, and ``get(b'GET')``
           raised :exc:`TypeError`.

        Args:
            key: Key to get enum item. Looked up case-**sensitively**,
                per :rfc:`9110#section-9.1` -- the method token is
                case-sensitive, unlike
                :meth:`~pcapkit.const.ftp.command.Command.get`'s equivalent override, which stays
                case-insensitive because :rfc:`959#section-5` says FTP
                command codes are not. Checked against both member names
                and values, via the base's own precedence -- name before
                value -- so a value-only match such as
                ``'BASELINE-CONTROL'`` resolves too (:issue:`908`).
            default: Value for the unregistered member built when ``key``
                matches neither a name nor a value. ``None``, the
                default, uses ``key`` itself.

        Raises:
            ValueError: If ``key`` is not a :class:`str`. This reaches the
                caller from the base's non-``str`` branch, where
                :meth:`_validate_value` refuses it before ``cls(key)`` could
                reach ``_missing_``, and is **not** caught by
                the ``except KeyError`` fallback below -- only a failed
                *name* lookup is. Raising is the intended behaviour for
                ``get(b'GET')`` as well: a member whose name and
                value were both the :class:`bytes` object is not a thing
                this registry should hand back.

        :meta private:
        """
        try:
            return super().get(key)
        except KeyError:
            # NOTE: the value is ``default`` if the caller supplied one, or
            # else ``key`` exactly as given -- never its upper-cased form --
            # so an unregistered member's value is the caller's own casing,
            # the same convention :meth:`_unregistered_member` documents and
            # :class:`~pcapkit.const.ftp.command.FEATCode` already followed.
            # The name is always the canonical upper-case form, matching
            # :meth:`_missing_` and every registered member's own name. Two
            # calls naming the same method in different case, e.g.
            # ``get('frob')`` and ``get('FROB')``, therefore build results
            # that are *not* equal -- each is exactly what its own caller
            # passed, per GitHub issue #860's conversion away from minting.
            return cls._unregistered_member(default if default is not None else key, key.upper())

    @classmethod
    def _validate_value(cls, value: 'Any') -> 'None':
        """Reject ``value`` unless it is a :class:`str`, as :meth:`_missing_` does.

        Overrides :meth:`~pcapkit.corekit.enum.EnumLookup._validate_value`
        with the check :meth:`_missing_` makes, and the message it raises, so
        :meth:`~pcapkit.corekit.enum.EnumRegistry.register` refuses exactly the
        values :meth:`get` refuses, in the same words (:issue:`1816`). Any
        :class:`str` passes, since :meth:`get` and :meth:`_missing_` resolve
        every one.

        Args:
            value: Value about to be looked up or minted.

        Raises:
            EnumValueError: If ``value`` is not a :class:`str`. A
                :exc:`ValueError`, so an ``except ValueError`` caller is
                unaffected.

        """
        if not isinstance(value, str):
            raise EnumValueError(f'{value!r} is not a valid {cls.__name__}')

    @classmethod
    def _missing_(cls, value: 'str') -> 'Method':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item. Matched case-insensitively against
                the canonical upper-case member names -- deliberately unlike
                :meth:`get`, which is case-**sensitive** per
                :rfc:`9110#section-9.1`. The split was ruled deliberate on
                GitHub issue :issue:`896`; GitHub issue :issue:`908` is the pointer between
                the two, so the two rationales are not left contradicting each
                other with nothing tying them together.

        """
        if not isinstance(value, str):
            raise ValueError(f'{value!r} is not a valid {cls.__name__}')
        name = value.upper()
        if name in cls._member_map_:
            return cls._member_map_[name]  # type: ignore[return-value]
        return cls._unregistered_member(value, name)
