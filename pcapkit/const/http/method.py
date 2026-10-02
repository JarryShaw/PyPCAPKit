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

if TYPE_CHECKING:
    from typing import Optional, Type

__all__ = ['Method']

class Method(EnumRegistry, StrEnum):
    """[Method] HTTP Method

    .. note::

       Neither ``_missing_`` nor ``get()`` mints any more. The owner ruled on
       GitHub issue #860 that ``get`` should not mint: only IANA-registered
       values are legitimate members, a new one is properly created through
       :meth:`register`, and ``get`` is not given enough information to create
       one. Concretely true here -- a bare wire method verb carries no
       :attr:`safe`/:attr:`idempotent`, so minting one used to register a
       permanent member with both hollowed out to their defaults;
       :meth:`register` is the path that can actually supply them.

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
        those two attributes would otherwise be absent. There is no more
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

                A *registered* member of this class used to carry something
                different here: GitHub issue #870 found that
                :meth:`__new__` called ``str.__new__(cls)`` with no
                argument at all, so every one of the 40 declared members'
                own :class:`str` payload was permanently empty regardless
                of ``value`` (``str(Method.GET) == ''``, and
                ``Method.GET == 'GET'`` was :obj:`False`) -- true on
                ``main`` at ``60b85e3a4`` as well as when this docstring
                was first written. #870 fixed :meth:`__new__` to
                ``str.__new__(cls, value)``, mirroring
                :class:`~pcapkit.const.ftp.command.Command`'s own
                ``__new__``, so a registered member's payload now agrees
                with an *unregistered* member built through this method:
                both carry their own value as real :class:`str` content
                (``str(Method('frob')) == 'frob'``).
            name: Bare label for the unregistered member -- here, the
                canonical upper-case form of ``value``, matching the name
                every *registered* member of this class is looked up by,
                since #860's open-vocabulary registries have no manufactured
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
        lookup itself, per GitHub issue #908: the previous override checked
        only ``_member_map_`` (names), never ``_value2member_map_``
        (values), so the two IANA methods whose member *name* differs from
        their *value* -- ``BASELINE_CONTROL`` / ``'BASELINE-CONTROL'`` and
        ``VERSION_CONTROL`` / ``'VERSION-CONTROL'``, a hyphen being unusable
        in a Python identifier -- failed to resolve through ``get`` even
        though :meth:`_missing_` (and so the constructor) already found
        them via that same value-side lookup.

        The base is a :class:`classmethod`
        (:meth:`~pcapkit.corekit.enum.EnumLookup.get`), and a zero-argument
        ``super()`` needs a first argument to bind, so this override had to
        move from :class:`staticmethod` to :class:`classmethod` to delegate
        at all -- see GitHub issue #908's own correction of the fix it
        originally proposed. Callers are unaffected by the switch itself:
        ``Method.get('X')`` binds identically either way.

        ``default`` keeps its existing meaning here rather than adopting
        the base's ``NO_DEFAULT`` sentinel and its value-only fallback --
        widening it would be caller-visible, since the base's ``default``
        must already name a *registered* value (resolved through
        ``_value2member_map_``), while this override's ``default`` instead
        supplies the *value* of a freshly minted unregistered member.
        Nothing in this tree calls ``get`` with a non-``None`` ``default``
        to notice today, but widening the signature is a separate change
        from this defect and stays out of scope.

        Args:
            key: Key to get enum item. Looked up case-**sensitively**,
                per :rfc:`9110#section-9.1` -- the method token is
                case-sensitive, unlike :meth:`~pcapkit.const.ftp.command.
                Command.get`'s equivalent override, which stays
                case-insensitive because :rfc:`959#section-5` says FTP
                command codes are not. Checked against both member names
                and values, via the base's own precedence -- name before
                value -- so a value-only match such as
                ``'BASELINE-CONTROL'`` now resolves too, closing GitHub
                issue #908.
            default: Value for the unregistered member built when ``key``
                matches neither a name nor a value. ``None``, the
                default, uses ``key`` itself -- unchanged from before
                GitHub issue #908.

        Raises:
            ValueError: If ``key`` is not a :class:`str`. This reaches the
                caller from the base's non-``str`` branch, which calls
                ``cls(key)`` and so ``_missing_``, and is **not** caught by
                the ``except KeyError`` fallback below -- only a failed
                *name* lookup is. The non-``str`` surface therefore moved
                with GitHub issue #908: ``get(42)`` and ``get(None)`` used
                to raise :exc:`AttributeError` from ``key.upper()``, and
                ``get(b'GET')`` used to *return* a member whose name and
                value were both the :class:`bytes` object. Raising is the
                intended behaviour -- a ``bytes``-valued ``Method`` is not a
                thing this registry should hand back -- but it is a change,
                so it is stated rather than left to be discovered.

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
    def _missing_(cls, value: 'str') -> 'Method':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item. Matched case-insensitively against
                the canonical upper-case member names -- deliberately unlike
                :meth:`get`, which is case-**sensitive** per
                :rfc:`9110#section-9.1`. The split was ruled deliberate on
                GitHub issue #896; GitHub issue #908 is the pointer between
                the two, so a reader of this one file is not left with two
                contradictory rationales and nothing tying them together.

        """
        if not isinstance(value, str):
            raise ValueError(f'{value!r} is not a valid {cls.__name__}')
        name = value.upper()
        if name in cls._member_map_:
            return cls._member_map_[name]  # type: ignore[return-value]
        return cls._unregistered_member(value, name)
