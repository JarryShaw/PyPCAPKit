# -*- coding: utf-8 -*-
"""Constant Enumeration Base
==============================

.. module:: pcapkit.corekit.enums

:mod:`pcapkit.corekit.enums` contains :class:`~pcapkit.corekit.enums.EnumRegistry`
only, the base class every constant enumeration under :mod:`pcapkit.const` is to
inherit the registry protocol from.

The maintainer's ruling on GitHub issue #842, verbatim: *"to finalise the
abstraction idea, get/get_all/register/register_alias should always exist on the
const enums - so they're to be moved to the base class. And AppType's sub-base
class will do its necessary overrides and dispatching logic; AppType subclasses
will have their necessary overrides again pertaining their different contracts."*

That is a three-tier hierarchy, of which this module is **tier one**:

1. :class:`EnumRegistry` -- the four methods, in the form that suits a registry
   mapping one key to one member. Every generated enumeration under
   :mod:`pcapkit.const` inherits them from here.
2. ``AppType``'s sub-base -- overrides all four to route through its
   ``_dispatch``, because a port lookup needs a transport protocol to be
   answerable at all. Not in this module, and not yet written: today's
   :class:`pcapkit.const.reg.apptype.apptype.AppType` carries that logic
   directly and stays as it is until tier two lands.
3. The ``AppType`` transport subclasses -- ``TCP``, ``UDP``, ``SCTP``, ``DCCP``
   -- override again for their own contracts.

Before this, the four methods lived as generated *text*: written out longhand in
:data:`pcapkit.vendor.default.LINE` and copied verbatim into each of the eleven
crawlers that replace that template wholesale, none of which carried
``register``, ``register_alias`` or ``get_all`` at all. Adding one method meant
editing every bespoke template by hand, which is the cost #775 asks to remove.

The contracts are the maintainer's, verbatim: *"get is a shortcut for ``[]``
operation and returns the canonical enum. get_all returns all matching enums.
register mints new enum to the class at runtime with specified names - so we
don't have to guess blindly. register_alias(es) adds additional alias(es) to a
given enum's mapping."*

"""
from typing import TYPE_CHECKING

from aenum import extend_enum

if TYPE_CHECKING:
    from typing import Any

    from typing_extensions import Self

__all__ = ['EnumRegistry']

#: The ``default`` argument value that means *no default*, i.e. let an
#: unresolvable key propagate its lookup error rather than falling back.
#:
#: ``-1`` rather than a sentinel object because that is what the 121 generated
#: registries already document and what their callers already pass, so the
#: migration onto this base class is not also a signature change. It is a safe
#: sentinel for both member types in play: no registry generated from an
#: upstream assignment carries a negative code, and ``-1`` is not a
#: :class:`str`, so a :class:`~aenum.StrEnum` registry can never mistake it for
#: one of its own values either.
NO_DEFAULT = -1


class EnumRegistry:
    """Registry protocol shared by every constant enumeration under
    :mod:`pcapkit.const`.

    This is a plain mix-in rather than an :class:`~aenum.Enum` subclass, because
    an enumeration that already has members cannot be subclassed. Mixed in
    *before* the member type -- ``class Foo(EnumRegistry, IntFlag)`` -- it
    contributes methods only, so :mod:`aenum` still resolves the member data type
    from the enumeration base: ``int`` for :class:`~aenum.IntEnum` and
    :class:`~aenum.IntFlag`, ``str`` for :class:`~aenum.StrEnum`. That is what
    lets one base serve all three, where a generated template fragment would
    have needed a separate rendering per member type.

    The methods deliberately touch only ``_member_map_``, ``_member_names_`` and
    ``_value2member_map_``, which both :mod:`enum` and :mod:`aenum` maintain, so
    nothing here depends on :mod:`aenum` internals beyond
    :func:`~aenum.extend_enum` itself.

    """

    if TYPE_CHECKING:
        #: The enumeration machinery's own lookup tables and member data type,
        #: declared here because they are contributed by the :class:`~aenum.Enum`
        #: base this mix-in is combined with rather than by the mix-in itself.
        _member_map_: 'dict[str, Self]'
        _member_names_: 'list[str]'
        _value2member_map_: 'dict[Any, Self]'
        # NOTE: deliberately ``Any`` rather than ``type``. Annotating the member
        # data type precisely makes ``cls._member_type_.__new__(cls, value)``
        # resolve to ``type.__new__``, which mypy then reads as building a
        # *class* rather than an instance -- five errors for a call that is
        # correct. Which concrete type it is depends on the Enum base each
        # subclass picks, so there is nothing more precise to say here anyway.
        _member_type_: 'Any'

    @classmethod
    def get(cls, key: 'Any', default: 'Any' = NO_DEFAULT) -> 'Self':
        """Resolve ``key`` to the canonical member.

        A shortcut for the ``[]`` operation, per the ruling on #842: given a
        name it is ``cls[key]``, and given a value it is ``cls(key)``. Either
        way the answer is the *canonical* member -- subscripting an alias
        returns the member the alias points at, not a separate object -- so
        two names for one assignment resolve to one enum.

        It never mints. Registering a member is :meth:`register`'s job and
        nobody else's, which is the ruling #775 exists to carry out: *"so that
        we dont create registered enums out of unrecognised/unregistered
        values, unless user/caller explicitly created them"*. A value inside a
        registry's declared-but-unassigned range still resolves, through that
        registry's own ``_missing_`` and :meth:`_unregistered_member`, to a
        member that is deliberately absent from the lookup tables.

        Args:
            key: Name or value to look up.
            default: Value to fall back to when ``key`` does not resolve.
                :data:`NO_DEFAULT` stands for *no default*, in which case the
                lookup error propagates instead.

        Returns:
            The canonical member for ``key``, or for ``default``.

        Raises:
            ValueError: If a value does not resolve and there is no usable
                default.
            KeyError: If a name does not resolve and there is no usable
                default.

        """
        if isinstance(key, str):
            try:
                return cls._member_map_[key]
            except KeyError:
                if default == NO_DEFAULT:
                    raise
                return cls(default)  # type: ignore[call-arg]
        try:
            return cls(key)  # type: ignore[call-arg]
        except ValueError:
            if default == NO_DEFAULT:
                raise
            return cls(default)  # type: ignore[call-arg]

    @classmethod
    def get_all(cls, key: 'Any') -> 'tuple[Self, ...]':
        """Every member matching ``key``, canonical first.

        For a registry that maps one key to one member -- which is every
        registry inheriting this base unmodified -- that tuple holds exactly one
        entry, since an alias registered by :meth:`register_alias` is a second
        *name* for the canonical member rather than a second member. The method
        still exists here, per the ruling that all four *"should always exist on
        the const enums"*, and it is where a registry with genuinely several
        matches puts them: ``AppType`` overrides it to return every service IANA
        assigns to a port.

        Args:
            key: Name or value to look up.

        Returns:
            The canonical member, followed by any further distinct member
            carrying the same value.

        Raises:
            ValueError: As :meth:`get` with no default, for a value.
            KeyError: As :meth:`get` with no default, for a name.

        """
        canonical = cls.get(key)
        return (canonical, *(
            member for member in cls._member_map_.values() if member is not canonical
            and member.value == canonical.value  # type: ignore[attr-defined]
        ))

    @classmethod
    def register(cls, value: 'Any', name: 'str') -> 'Self':
        """Mint a new member on this registry at runtime, under ``name``.

        The caller-named path, and the only one that grows the registry:
        *"register mints new enum to the class at runtime with specified names -
        so we don't have to guess blindly"*. Contrast :meth:`get` and
        ``_missing_``, which resolve without naming anything.

        Refuses a ``value`` that already has a member. Without this guard,
        :func:`~aenum.extend_enum` does not mint anything for an already-taken
        value -- :mod:`aenum` treats that as a request to *alias* the existing
        member under the caller's ``name`` instead, silently: the call returns
        the *existing* member, ``name`` becomes reachable in ``__members__``
        pointing at it, and ``_member_names_`` does not grow. That is
        :meth:`register_alias`'s own effect, reached through the wrong method
        and with nothing raised to say so -- exactly the "guess blindly" this
        method exists to rule out. Membership is tested against
        ``_value2member_map_`` rather than by calling ``cls(value)``, for the
        same reason :meth:`register_alias` tests it that way: a
        declared-but-unassigned value resolves through ``_missing_`` to an
        :meth:`_unregistered_member` absent from that table, so a successful
        call proves nothing about whether a member already exists.

        Args:
            value: Value of the new member.
            name: Name of the new member. Required rather than derived, which
                is the whole point -- a generated name is a guess.

        Returns:
            The newly registered member.

        Raises:
            ValueError: If ``value`` already has a member -- use
                :meth:`register_alias` to add a further name for it instead.
            ValueError: If ``name`` is already taken. :mod:`aenum` reports that
                as :exc:`TypeError`; it is translated so that the ways one call
                can fail are one exception type.

        """
        if value in cls._value2member_map_:
            existing = cls._value2member_map_[value]
            raise ValueError(f'{value!r} is already registered on {cls.__name__} as '
                             f'{existing.name!r}; use {cls.__name__}.register_alias() '
                             f'to add a further name for it')
        return cls._extend(value, name)

    @classmethod
    def _extend(cls, value: 'Any', name: 'str') -> 'Self':
        """The raw :func:`~aenum.extend_enum` call, shared by :meth:`register`
        and :meth:`register_alias`.

        Neither public method calls the other: :meth:`register` now refuses an
        already-registered ``value`` before it would ever reach here, and
        :meth:`register_alias` depends on the opposite of that -- it verifies
        ``value`` *is* already registered and then relies on exactly the
        mint-or-alias behaviour this wraps to add ``name`` as a further name
        for the existing member rather than a new one. Routing both through
        this shared, ungated call is what keeps that behaviour available to
        :meth:`register_alias` while :meth:`register` still rejects it.

        Args:
            value: Value of the member, new or existing.
            name: Name to add.

        Returns:
            The member now reachable under ``name``, new or existing.

        Raises:
            ValueError: If ``name`` is already taken. :mod:`aenum` reports that
                as :exc:`TypeError`; it is translated so that the ways one call
                can fail are one exception type.

        """
        try:
            return extend_enum(cls, name, value)
        except TypeError as error:
            raise ValueError(str(error)) from error

    @classmethod
    def register_alias(cls, value: 'Any', name: 'str') -> 'Self':
        """Add ``name`` as a further name for the member already at ``value``.

        Per the ruling, an alias *"adds additional alias(es) to a given enum's
        mapping"* -- so it needs an enum to be given, and this refuses a value
        no member carries rather than falling through to :meth:`register`.
        Asked whether that should hold generally, the maintainer's answer was
        *"actually i think it should always be for an existing member"*, and on
        what an alias means away from ``AppType``: *"For non-AppType registries,
        'Alias' is custom/caller-opt-in names, which are not recorded in IANA
        registrars"*. Minting under the name of an aliasing call would
        manufacture exactly the unrecorded member #775 removes.

        Membership is tested against ``_value2member_map_`` rather than by
        calling ``cls(value)``: a declared-but-unassigned value resolves through
        ``_missing_`` to an :meth:`_unregistered_member` that is deliberately
        absent from that table, so a successful call proves nothing about
        whether a member exists.

        An alias adds a *name*, not a member: ``__members__`` grows by one while
        ``_member_names_``, iteration and ``_value2member_map_`` are untouched.
        Calls :meth:`_extend` directly rather than :meth:`register`, which
        would now refuse this call outright -- :meth:`register` and
        :meth:`register_alias` test ``value``'s membership for opposite
        outcomes, so neither can be the other's implementation any more.

        Args:
            value: Value of the existing member to alias.
            name: Alias to add for it.

        Returns:
            The existing member, now reachable under ``name`` as well.

        Raises:
            ValueError: If no member carries ``value``, or if ``name`` is
                already taken.

        """
        if value not in cls._value2member_map_:
            raise ValueError(f'{value!r} is not a registered {cls.__name__}; '
                             f'use {cls.__name__}.register() to mint one')
        return cls._extend(value, name)

    @classmethod
    def register_aliases(cls, value: 'Any', *names: 'str') -> 'tuple[Self, ...]':
        """Add several aliases for the member at ``value``, left to right.

        Args:
            value: Value of the existing member to alias.
            *names: Aliases to add for it.

        Returns:
            One entry per name in ``names``, each the aliased member.

        Raises:
            ValueError: As :meth:`register_alias`. Names before the failing one
                stay registered -- :func:`~aenum.extend_enum` has no transaction
                to roll back, and undoing it by hand would mean reaching further
                into enumeration internals than anything else here does.

        """
        return tuple(cls.register_alias(value, name) for name in names)

    @classmethod
    def _unregistered_member(cls, value: 'Any', name: 'str') -> 'Self':
        """Build a member absent from this registry's own lookup tables.

        Used by a registry's ``_missing_`` for a declared-but-unassigned value
        it resolves without anyone asking for a name, so that such a lookup no
        longer grows the registry -- contrast :meth:`register`, the explicit
        path that still does.

        The member is constructed through ``cls._member_type_``, which
        :mod:`aenum` sets from the enumeration base, so this serves ``int``- and
        ``str``-valued registries alike without either having to say which it
        is.

        Args:
            value: The member's value.
            name: The member's name.

        Returns:
            The unregistered member.

        """
        obj = cls._member_type_.__new__(cls, value)
        obj._name_ = name  # pylint: disable=protected-access
        obj._value_ = value  # pylint: disable=protected-access
        return obj
