# -*- coding: utf-8 -*-
"""Constant Enumeration Base
==============================

.. module:: pcapkit.corekit.enum

:mod:`pcapkit.corekit.enum` contains :class:`~pcapkit.corekit.enum.EnumRegistry`
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

from pcapkit.utilities.compat import final

if TYPE_CHECKING:
    from typing import Any

    from typing_extensions import Self

__all__ = ['NO_DEFAULT', 'NoDefaultType', 'EnumRegistry']


@final
class NoDefaultType:
    """Type of :data:`NO_DEFAULT`, the omitted-``default`` sentinel for :meth:`EnumRegistry.get`.

    A dedicated class rather than a bare :class:`object`, per the owner's ruling
    on #859: *"use dedicated class rather than bare object. Follow the house
    convention."* A bare :class:`object` compares under ``is`` exactly as
    safely as a dedicated class with no ``__eq__`` of its own does -- identity
    comparison was never the problem an earlier revision's docstring here
    overstated it to be. What a bare :class:`object` actually lacks is a
    readable representation: it prints as ``<object object at 0x...>`` in a
    signature, in :func:`help`, and in a traceback, where ``NoDefaultType()``
    -- via :meth:`__repr__` below -- prints as ``<NO_DEFAULT>``.

    Named ``NoDefaultType`` for the *class* because that half of the house
    convention is settled: both :class:`~pcapkit.corekit.module.NullType` and
    :class:`~pcapkit.corekit.fields.field.NoValueType` use ``<Name>Type``. The
    *instance*'s own name is not similarly settled -- the owner's follow-up
    on #859 is explicit that ``NULL`` (``SCREAMING_CASE``) and ``NoValue``
    (``CapWords``) disagree, and "mainly depends on how we need it." The need
    here is continuity: ``NO_DEFAULT`` is already the name on ``main`` --
    referenced in :meth:`EnumRegistry.get`'s signature, its docstring, and
    both comparison sites -- and this change is to *what the sentinel is*,
    not to *what it is called*, so it keeps that name rather than being
    renamed to match either precedent's instance casing for its own sake.
    ``NULL``'s ``SCREAMING_CASE`` is the closer match regardless, since
    :data:`NO_DEFAULT` was already spelled that way.

    Genuinely a singleton, not merely a class this module happens to
    instantiate once: :meth:`__new__` always hands back the one instance that
    already exists, rather than building a new one. That guards against a
    caller writing ``registry.get(key, default=NoDefaultType())`` -- perhaps
    not realising :data:`NO_DEFAULT` already exists -- and getting back a
    *second*, non-identical sentinel that silently fails ``is NO_DEFAULT``
    inside :meth:`EnumRegistry.get`, so their call is treated as supplying a
    real (if useless) default instead of the *no default* they meant. With the
    guard, :class:`NoDefaultType() <NoDefaultType>` always returns the one
    canonical :data:`NO_DEFAULT`, so that mistake self-corrects.

    Unlike :class:`~pcapkit.corekit.module.NullType`, this does *not* also
    define ``__copy__``, ``__deepcopy__`` or ``__reduce__`` -- but not because
    :func:`copy.deepcopy` or :mod:`pickle` "bypass" :meth:`__new__`; they do
    not, for protocol 2 and above. :meth:`object.__reduce_ex__` at protocol 2
    reduces through :func:`copyreg.__newobj__`, which reconstructs by calling
    ``cls.__new__(cls)`` -- exactly the guarded path above -- so
    ``copy.copy``, ``copy.deepcopy`` and every pickle protocol from 2 on
    already come back as the one canonical instance with no extra code.
    Measured::

        >>> NO_DEFAULT.__reduce_ex__(2)
        (<function __newobj__ at 0x...>, (<class '...NoDefaultType'>,), None, None, None)
        >>> copy.deepcopy(NO_DEFAULT) is NO_DEFAULT
        True

    The one path :meth:`__new__` cannot see is pickle protocol 0 (and 1),
    which reduces through :func:`copyreg._reconstructor` instead, and *that*
    calls :func:`object.__new__` directly::

        >>> NO_DEFAULT.__reduce_ex__(0)
        (<function _reconstructor at 0x...>, (<class '...NoDefaultType'>, <class 'object'>, None))
        >>> pickle.loads(pickle.dumps(NO_DEFAULT, protocol=0)) is NO_DEFAULT
        False

    That gap is exactly what :class:`~pcapkit.corekit.module.NullType`'s own
    :meth:`~pcapkit.corekit.module.NullType.__reduce__` exists to close, because
    :data:`~pcapkit.corekit.module.NULL` is stored as a
    :class:`~pcapkit.corekit.module.ModuleDescriptor` field that a caller's own
    :func:`copy.deepcopy` or :mod:`pickle` call can walk into and reconstruct.
    :data:`NO_DEFAULT` is left unhandled here not because the gap cannot occur
    in principle, but because nothing in this package ever pickles it at
    protocol 0: it is reachable -- from :meth:`EnumRegistry.get`'s own bound
    parameter default (``EnumRegistry.get.__defaults__[0]``, or any
    subclass's, e.g. ``Hardware.get.__func__.__defaults__[0]``) and from
    ``inspect.signature(Hardware.get).parameters['default'].default`` -- but
    neither is a field any object here gets pickled *as*, and both still
    survive :func:`copy.deepcopy` with identity intact regardless, because
    deep-copying either still reduces the sentinel itself through the same,
    guarded protocol-2 path measured above.

    A caveat, not a defect, but a real and *worse* one than the marker it
    replaces: :func:`importlib.reload` on this module does not merely leave
    the class stale, it breaks :meth:`EnumRegistry.get`'s own no-default
    contract for every subclass whose ``get`` was already resolved before the
    reload. Reload re-executes both ``class NoDefaultType:`` and
    ``NO_DEFAULT = NoDefaultType()`` below, so the *module global*
    :meth:`EnumRegistry.get`'s body compares against becomes a fresh, distinct
    object. But each subclass's own ``get`` inherited its **bound parameter
    default** -- ``default: 'Any' = NO_DEFAULT`` -- at function-definition
    time, before the reload, and a bound default is frozen then, not looked
    up again per call. So after the reload, calling ``get`` with ``default``
    *omitted* no longer compares the pre-reload default against ``NO_DEFAULT``
    truthfully: it is comparing the stale pre-reload sentinel against the
    fresh post-reload one, ``is`` reads *False*, and ``get`` falls through to
    attempting ``cls(default)`` on the stale sentinel instead of re-raising
    the original lookup error. Measured::

        >>> Hardware.get('Definitely-Not-A-Member')              # before reload
        KeyError: 'Definitely-Not-A-Member'
        >>> importlib.reload(pcapkit.corekit.enum)
        >>> Hardware.get('Definitely-Not-A-Member')               # after reload
        ValueError: <NO_DEFAULT> is not a valid Hardware

    ``-1`` never had this failure mode: ``-1 == -1`` holds no matter which
    module execution produced either side, since it compares by value, not by
    identity, so a reload could not disturb it. Trading that immunity away is
    the real cost of moving to an identity-compared sentinel, and it is not
    hypothetical to this tree specifically: reload staleness is a *tracked*
    defect class here, not a theoretical one -- see
    :meth:`pcapkit.protocols.protocol.ProtocolBase._lookup_next_layer`'s own
    docstring note citing GitHub issues #425, #428 and #560, and
    :mod:`tests.protocols.test_dispatch_default_resolution_unit`'s own
    ``test_no_stale_class_survives_a_module_reload``, which reloads a module
    deliberately to pin the fix for exactly that class of bug elsewhere. So
    "nothing in this package reloads :mod:`pcapkit.corekit.enum` after
    import" is the only thing standing between this sentinel and that same
    defect class -- true today, but a caveat to keep honest rather than a
    guarantee this class enforces.

    Also unlike both :class:`~pcapkit.corekit.module.NullType` and
    :class:`~pcapkit.corekit.fields.field.NoValueType`, this deliberately does
    *not* define ``__bool__``. Both of those model an *absent* value, so
    reading falsy in a boolean context is the point. :data:`NO_DEFAULT` models
    something different: a marker meaning *no default was supplied*, checked
    exclusively by ``is`` at :meth:`EnumRegistry.get`'s two comparison sites --
    nothing here ever evaluates it for truthiness. Giving it ``__bool__ ->
    False`` for symmetry with the other two would invite exactly the
    conflation this sentinel exists to rule out: code that writes ``if not
    default:`` instead of ``if default is NO_DEFAULT:`` would then read
    :data:`NO_DEFAULT` the same way it reads a caller's genuine falsy default
    -- ``0``, ``''``, ``None`` or ``False`` -- which is the exact collision
    ``-1`` used to cause under ``==`` and the reason #857 exists. Leaving
    ``__bool__`` undefined makes ``NoDefaultType()`` truthy (the default for
    any object defining neither ``__bool__`` nor ``__len__``), which at least
    does not *look* like one of the falsy values it must never be mistaken
    for.

    """

    #: 'NoDefaultType | None': The one instance :meth:`__new__` ever returns,
    #: including for the module-level ``NO_DEFAULT = NoDefaultType()`` below
    #: that creates it in the first place. Kept on the class rather than as a
    #: module global so :meth:`__new__` can read and write it without a
    #: ``global`` statement.
    _instance: 'NoDefaultType | None' = None

    def __new__(cls) -> 'NoDefaultType':
        """Return the one instance of this class there will ever be."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> 'str':
        """Return :obj:`str` representation of the sentinel."""
        return '<NO_DEFAULT>'


#: NoDefaultType: The ``default`` argument value that means *no default*, i.e.
#: let an unresolvable key propagate its lookup error rather than falling
#: back. See :class:`NoDefaultType` for why this is a dedicated class rather
#: than a bare :class:`object`, why it is a guarded singleton, and why it
#: defines neither the copy/pickle hooks nor the ``__bool__`` that its two
#: :mod:`pcapkit.corekit` precedents do.
NO_DEFAULT = NoDefaultType()


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
                if default is NO_DEFAULT:
                    raise
                return cls(default)  # type: ignore[call-arg]
        try:
            return cls(key)  # type: ignore[call-arg]
        except ValueError:
            if default is NO_DEFAULT:
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
