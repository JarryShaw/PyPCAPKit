# -*- coding: utf-8 -*-
"""Constant Enumeration Base
==============================

.. module:: pcapkit.corekit.enum

:mod:`pcapkit.corekit.enum` contains the two bases every enumeration in this
library is meant to inherit from, split by whether the enumeration may *grow*:

* :class:`EnumLookup` -- the bare **lookup** half: :meth:`~EnumLookup.get`,
  :meth:`~EnumLookup.get_all` and the overridable
  :meth:`~EnumLookup._validate_value` guard. Nothing here mutates the
  enumeration, so it is what a *closed* set can inherit without being handed a
  contract it must refuse.
* :class:`EnumRegistry`, a subclass of the above -- adds the **mutating** half:
  :meth:`~EnumRegistry.register`, :meth:`~EnumRegistry.register_alias`,
  :meth:`~EnumRegistry.register_aliases`, :meth:`~EnumRegistry._extend` and
  :meth:`~EnumRegistry._unregistered_member`. Every generated registry under
  :mod:`pcapkit.const` inherits from here.

That split follows the rules laid down in GitHub issue #877: a helper enumeration is
immutable by default, unless RFC or IANA documents its value space as open.
Such closed sets subclass a bare base enumeration in this module, and
:class:`EnumRegistry` subclasses that base for the mutable ones.

Which methods land on which tier was settled in the same thread. The deciding
consideration was that a base carrying ``register`` has no principled reason to
withhold ``register_alias``, so drawing the line between them risked setting a
bad precedent. Following that through,
a base holding both would leave :class:`EnumRegistry` with only
``register_aliases``, ``_extend`` and ``_unregistered_member`` -- too thin to
justify a second class, collapsing the two tiers into one. So all five mutating
methods stay put, and what the base carries instead is the other requirement
from that thread: some range-validation logic that inheriting classes can hook
into, which is :meth:`EnumLookup._validate_value`. Legality is
every enumeration's concern; mutation is only the open registries'.

Supporting measurement, taken on this tree at the time of the split: **0** of the
26 non-registry enumerations define ``register``, ``register_alias``,
``register_aliases`` or ``_unregistered_member``, and there are **0**
:class:`EnumRegistry` subclasses outside :mod:`pcapkit.const`. The mutating half
therefore had no users to serve among the classes being re-parented.

.. note::

   Re-parenting every non-registry enumeration onto :class:`EnumLookup` was
   **phase 2** of GitHub issue #877, and it is now **complete**: introducing
   the base above was deliberately behaviour-preserving on its own, so that it
   could land while other work was still in flight on the files the re-parent
   touches, and the phase itself landed in two pull requests for exactly that
   reason -- the first for the 17 enumerations that were free to move at
   once, and the second, `#930
   <https://github.com/JarryShaw/PyPCAPKit/issues/930>`__, for the
   remaining seven once the files holding them freed up.

The registry tier's own shape is the earlier design settled in GitHub issue #842:
``get``, ``get_all``, ``register`` and ``register_alias`` are to exist on every
const registry, so the abstraction is finished by moving them to the base class.
The closed sets split off by #877 are outside that contract.
``AppType``'s sub-base class carries the overrides and dispatching logic it
needs, and ``AppType``'s subclasses override again where their contracts
differ.

That is a three-tier hierarchy, of which this module is **tier one**:

1. :class:`EnumRegistry` -- the four methods, in the form that suits a registry
   mapping one key to one member. Every generated registry under
   :mod:`pcapkit.const` inherits them from here.
2. ``AppType``'s sub-base -- overrides all four to route through its
   ``_dispatch``, because a port lookup needs a transport protocol to be
   answerable at all. Landed as of GitHub issue #860: not in this module, but
   in :class:`pcapkit.const.reg.apptype.apptype.AppType` itself, which now
   mixes in :class:`EnumRegistry` directly and overrides ``get``, ``get_all``,
   ``register`` and ``register_alias`` with that dispatch, plus
   ``_unregistered_member`` for its own three extra attributes (``svc``,
   ``port``, ``proto``) that the generic one below does not know to set.
3. The ``AppType`` transport subclasses -- ``TCP``, ``UDP``, ``SCTP``, ``DCCP``
   -- turned out to need no override of their own at all: ``_dispatch``
   already returns ``cls`` unchanged the moment ``cls.__registry__`` is not
   :obj:`None`, which is true for exactly these four, so tier 2's methods
   already answer correctly on each of them without a further layer.

Before this, the four methods lived as generated *text*: written out longhand in
:data:`pcapkit.vendor.default.LINE` and copied verbatim into each of the eleven
crawlers that replace that template wholesale, none of which carried
``register``, ``register_alias`` or ``get_all`` at all. Adding one method meant
editing every bespoke template by hand, which is the cost #775 asks to remove.

The contracts are those set out on GitHub issue #842: ``get`` is a shortcut for
the ``[]`` operation and returns the canonical enumeration member; ``get_all``
returns every matching member; ``register`` mints a new member on the class at
runtime under the name the caller specifies, so nothing has to be guessed;
``register_alias`` (and ``register_aliases``) adds further alias names to a
given member's mapping.

"""
from typing import TYPE_CHECKING

from aenum import extend_enum

from pcapkit.corekit.sentinels import NO_DEFAULT, NoDefaultType  # pylint: disable=unused-import
from pcapkit.utilities.exceptions import BaseError, EnumKeyError, EnumValueError

if TYPE_CHECKING:
    from typing import Any

    from typing_extensions import Self

__all__ = ['NO_DEFAULT', 'EnumLookup', 'EnumRegistry']


class EnumLookup:
    """Bare lookup protocol, shared by open registries and closed sets alike.

    Carries :meth:`get`, :meth:`get_all` and the :meth:`_validate_value` guard --
    everything an enumeration needs in order to be *read* by name or by value,
    and nothing that could grow it. :class:`EnumRegistry` adds the mutating half
    on top; a closed enumeration inherits this one directly and so is never
    handed a ``register`` it would have to refuse.

    This is a plain mix-in rather than an :class:`~aenum.Enum` subclass, because
    an enumeration that already has members cannot be subclassed. Mixed in
    *before* the member type -- ``class Foo(EnumRegistry, IntFlag)``, or
    ``class Bar(EnumLookup, IntEnum)`` -- it contributes methods only, so
    :mod:`aenum` still resolves the member data type from the enumeration base:
    ``int`` for :class:`~aenum.IntEnum` and :class:`~aenum.IntFlag`, ``str`` for
    :class:`~aenum.StrEnum`. That is what lets one base serve all three, where a
    generated template fragment would have needed a separate rendering per
    member type.

    Because both tiers are plain classes, inserting this one *above*
    :class:`EnumRegistry` leaves the member data type exactly where it was:
    ``class Foo(EnumRegistry, IntFlag)`` resolves as ``Foo -> EnumRegistry ->
    EnumLookup -> IntFlag -> int -> ...``, so ``_member_type_`` still comes from
    the enumeration base and not from anything in this module. Had this tier
    subclassed :class:`~aenum.Enum` in order to "be an enum", it would have
    become the member type itself and broken all three shapes at once.

    The methods deliberately touch only ``_member_map_``, ``_member_names_`` and
    ``_value2member_map_``, which both :mod:`enum` and :mod:`aenum` maintain, so
    nothing on this tier depends on :mod:`aenum` internals at all -- the one
    :func:`~aenum.extend_enum` call in this module belongs to
    :class:`EnumRegistry`, which is the tier that mutates.

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
    def _validate_value(cls, value: 'Any') -> 'None':
        """Hook: reject ``value`` if this enumeration's contract does not allow it.

        GitHub issue #877 requires some range-validation logic for the inheriting
        classes to hook into. This is that hook, and it is what the bare tier carries
        **instead** of ``register``: what values are *legal* is something every enumeration
        has an opinion on, whereas who may *add* one is only an open registry's
        concern.

        The base implementation accepts everything, because a base cannot know
        any subclass's range. Overriding it is how a subclass states one -- the
        shape ``_missing_`` spells by hand across the generated registries
        today::

            @classmethod
            def _validate_value(cls, value: 'Any') -> 'None':
                if not (isinstance(value, int) and 0 <= value <= 0xFF):
                    raise EnumValueError(f'{value!r} is not a valid {cls.__name__}')

        An override **raises or returns**; it must never *normalise*. The return
        type is :obj:`None` deliberately rather than the validated value, so that
        this hook cannot become a converter: a subclass that returned a changed
        value here would silently alter what a lookup resolves to, which is
        exactly the case-folding the ruling on GitHub issue #877 rules out:
        an enumeration keeps the original spellings its registrars use.
        Case handling belongs in a deliberate ``get`` override with
        an RFC behind it, not in a validation hook.

        Raise from :mod:`pcapkit.utilities.exceptions`, per the same issue's
        ruling that in-library code raises in-library exceptions --
        :exc:`~pcapkit.utilities.exceptions.EnumValueError` is the fitting one
        and is already what the closed enumerations in
        :mod:`pcapkit.protocols.internet.mh` raise. Note what that buys on the
        :meth:`get` path: :exc:`~pcapkit.utilities.exceptions.EnumValueError`
        subclasses :exc:`ValueError`, so a rejection here is caught by
        :meth:`get`'s own ``except ValueError`` and falls back to ``default``
        just as any other unresolvable value does. An override raising something
        outside that hierarchy would instead propagate past ``default``, which is
        a real difference in behaviour rather than a stylistic preference. With
        no usable ``default``, a rejection from this hook reaches the caller
        exactly as the override raised it -- :meth:`get` re-raises an in-library
        ``ValueError`` unchanged rather than re-wrapping it, so the override's own
        message and the single log record it already emitted are what the caller
        sees.

        Called from exactly two places, and the omissions are deliberate:

        * :meth:`get`, immediately before ``cls(key)`` -- the one point at which
          a lookup can reach a subclass's ``_missing_`` and mint. The ``str``-key
          path does **not** call it, because that path never calls ``cls(key)``:
          it resolves against the already-populated lookup tables only, where
          every value present is legal by construction, so there is nothing left
          to validate.
        * :meth:`EnumRegistry.register`, before minting -- the one point at which
          a caller can introduce a value no member carries yet.

        :meth:`EnumRegistry.register_alias` does not call it, and does not need
        to: it refuses any ``value`` that is not already registered, so the value
        it aliases has necessarily passed validation already.
        :meth:`EnumRegistry._unregistered_member` does not call it either,
        because its callers are the subclasses' own ``_missing_`` bodies, which
        already range-check before delegating here -- validating again would
        double the check without being able to disagree with it.

        Deliberately carries no ``Raises:`` clause, because this implementation
        raises nothing at all -- an override is what raises, and documenting an
        exception here that this body cannot produce is exactly the phantom
        :class:`tests.test_docstring_contract.DocstringRaisesTests` rejects.
        An override adds its own clause naming what *it* rejects.

        Args:
            value: Candidate value to check.

        Returns:
            Nothing. A value this enumeration allows is reported by returning
            normally; a value it does not is reported by raising.

        """

    @classmethod
    def get(cls, key: 'Any', default: 'Any' = NO_DEFAULT) -> 'Self':
        """Resolve ``key`` to the canonical member.

        A shortcut for the ``[]`` operation, per the ruling on #842: given a
        name it is ``cls[key]``, and given a value it is ``cls(key)``. Either
        way the answer is the *canonical* member -- subscripting an alias
        returns the member the alias points at, not a separate object -- so
        two names for one assignment resolve to one enum.

        It never mints while resolving ``default``; ``key`` may still mint
        through a ``_missing_`` that GitHub issue #775's ruling deliberately
        kept minting, on one registry (``CGAType``) -- the ruling's final
        round converted the other two it originally held out,
        ``EtherType`` and ``Socket``, so they no longer mint on any path
        either. Registering a member any other way is :meth:`register`'s
        job and nobody else's, which is the ruling #775 exists to carry
        out: an unrecognised or unregistered value does not become a registered
        member unless a user or caller explicitly creates one. A value inside a
        registry's declared-but-unassigned range still resolves, through that
        registry's own ``_missing_`` and :meth:`_unregistered_member`, to a member
        that is deliberately absent from the lookup tables -- true outside the one registry
        named above, where such a value instead lands in *both* tables,
        exactly as :meth:`register` would leave it -- for a non-``str`` key;
        the ``str`` case is qualified below. Both describe ``key`` resolution
        only. ``default`` never reaches ``_missing_`` on either branch: a
        declared-but-unassigned ``default`` does not resolve to an
        unregistered member the way such a ``key`` does -- it simply does
        not resolve, and the lookup error ``key`` itself would have raised
        propagates instead.

        For a ``str`` key, a name match wins over a value match -- the two are
        checked in that order, so a string that happens to be both a member's
        name and a *different* member's value resolves to the name's member,
        matching what already happened for a name that resolves today. The
        value side of that check is a plain ``_value2member_map_`` lookup, not
        ``cls(key)``: on a registry whose own ``_missing_`` mints for an
        unrecognised value, routing a failed *name* lookup through the
        constructor would let a mere ``get()`` call mint a permanent member
        where it previously just raised. Defensive rather than observed: of
        the 127 classes that reach this method -- 125 until GitHub issue #880's
        own PR added ``pcapkit/const/ngap/procedure_code.py`` and
        ``pcapkit/const/ngap/protocol_ie.py``, remeasured while auditing
        GitHub issue #903 -- the ``str``-valued ones
        (:class:`~pcapkit.const.ftp.command.Command`, :class:`~pcapkit.const.
        ftp.command.FEATCode`, :class:`~pcapkit.const.http.method.Method`,
        :class:`~pcapkit.const.pcapng.option_type.OptionType`,
        :class:`~pcapkit.const.reg.apptype.apptype.AppType` and its four
        transport subclasses :class:`~pcapkit.const.reg.apptype.tcp.TCP`,
        :class:`~pcapkit.const.reg.apptype.udp.UDP`,
        :class:`~pcapkit.const.reg.apptype.sctp.SCTP` and
        :class:`~pcapkit.const.reg.apptype.dccp.DCCP` -- completing that set as
        of GitHub issue #860's own PR 2 -- and, newest of them,
        :class:`~pcapkit.const.pcapng.tls_key_label.TLSKeyLabel`, which GitHub
        issue #877's own thread reclassified from a hand-written helper to a
        generated registry once RFC 9850 §4.2 turned its member list into a
        live IANA registry) no longer mint
        on any path, so no live witness exists in this tree today. The one
        registry that still mints directly via :func:`~aenum.extend_enum`,
        :class:`~pcapkit.const.mh.cga_type.CGAType`, is
        :class:`int`-valued, so a ``str`` name could not reach its mint
        branch even if this restriction did not exist; it is not an
        exception to it, just not reachable by it. GitHub issue #775's final
        round converted the other two that used to share this footnote,
        :class:`~pcapkit.const.ipx.socket.Socket` and
        :class:`~pcapkit.const.reg.ethertype.EtherType`, so ``CGAType`` is
        now the only one left. This is about a future
        ``str``-valued registry (or a present one whose ``_missing_``
        someday changes) reaching this base with a minting ``_missing_`` of
        its own, which the restriction below is written to stay correct
        for regardless. Restricting
        the value side of ``key`` to an already-registered value keeps *that
        side* non-minting on every ``str``-valued registry, not only the ones
        without a minting ``_missing_``. Since #864, that is no longer merely
        a claim about the value side alone: ``default`` resolves through the
        same kind of ``_value2member_map_`` lookup rather than
        ``cls(default)``, so for a ``str`` key every path through this
        method -- name, value and ``default`` alike -- is non-minting.

        That restriction has a cost the paragraph above glosses over: a
        *declared-but-unassigned* value -- the case resolved there through
        ``_missing_`` and :meth:`_unregistered_member` without either lookup
        table growing -- is for that exact reason invisible to the
        ``_value2member_map_`` check above. Such a value resolves through
        ``cls(value)`` but not through ``get(value)`` when ``value`` is a
        ``str``; the non-``str`` path below has no such gap, since it always
        calls ``cls(key)`` and so always reaches ``_missing_``. Closing that
        gap here would mean calling ``cls(key)`` for a ``str`` value too,
        which reopens the exact minting hazard the paragraph above exists to
        avoid -- so the asymmetry is deliberate, not an oversight.

        The non-``str`` path calls :meth:`_validate_value` immediately before
        ``cls(key)``, which is the only point at which this method can reach a
        subclass's ``_missing_``, so a subclass that declares a range gets it
        checked before the constructor rather than after. The base hook accepts
        everything, so this changes nothing for a subclass that does not override
        it. A rejection raised as
        :exc:`~pcapkit.utilities.exceptions.EnumValueError` -- or any other
        :exc:`ValueError` subclass -- is caught by the same ``except`` that
        catches an ordinary failed construction, and so falls back to ``default``
        on the same terms; the ``str`` path does not call the hook, for the reason
        given on :meth:`_validate_value` itself.

        Both failure paths raise from :mod:`pcapkit.utilities.exceptions`
        rather than a builtin, per the ruling recorded on GitHub issue #923:
        in-library code raises from ``pcapkit.utilities.exceptions`` rather
        than a builtin, and whether ``ValueError`` or ``KeyError`` applies
        follows what stdlib's ``Enum`` raises in the same circumstance. The *shape*
        is unchanged by that ruling and deliberately so -- a name miss
        stays :exc:`KeyError`-derived and a value miss :exc:`ValueError`-derived,
        matching ``E['nosuch']`` and ``E(999)`` on a stdlib
        :class:`~enum.Enum`, and matching the 119 of this tree's 127 concrete
        subclasses that already answered a name miss that way. Only the
        provenance changed, so every ``except KeyError`` and ``except
        ValueError`` around a call to this method keeps catching.

        Two details of that conversion are worth stating, since neither is
        visible from the exception type alone:

        * **The name miss is raised quietly** --
          :exc:`~pcapkit.utilities.exceptions.EnumKeyError` with ``quiet=True``,
          so nothing is logged and :data:`sys.tracebacklimit` is left alone.
          That is not a cosmetic choice: this method's name miss is in-library
          control flow at six call sites, and at
          :meth:`~pcapkit.const.http.method.Method.get` it is part of a
          *successful* call -- that override catches it in order to mint. A loud
          error there would put a :data:`logging.CRITICAL` record on every such
          call and set :data:`sys.tracebacklimit` to ``0`` process-wide, which
          is exactly the GitHub issue #362 defect
          :class:`~pcapkit.utilities.exceptions.BaseError` documents ``quiet``
          for. The value miss takes no such fallback anywhere in this tree, so
          it stays loud.
        * **An in-library rejection propagates unchanged.** A ``ValueError``
          that is already a :exc:`~pcapkit.utilities.exceptions.BaseError` --
          typically :exc:`~pcapkit.utilities.exceptions.EnumValueError` from a
          subclass's :meth:`_validate_value` -- is re-raised as it stands rather
          than wrapped, so the subclass's own message survives and the error is
          logged once instead of twice. Only :mod:`aenum`'s and :mod:`enum`'s
          own "no member carries this value" is converted. This is the same
          discrimination :meth:`EnumField.post_process
          <pcapkit.corekit.fields.numbers.EnumField.post_process>` already
          makes for the same reason.

        Args:
            key: Name or value to look up.
            default: An already-registered value to fall back to when
                ``key`` does not resolve. Resolved through a plain
                ``_value2member_map_`` lookup, never through
                ``cls(default)``, so it cannot mint -- see #864.
                :data:`NO_DEFAULT` stands for *no default*; that and a
                ``default`` naming no registered member both fall through to
                the same lookup error ``key`` itself would have raised.

        Returns:
            The canonical member for ``key``, or for ``default``.

        Raises:
            EnumValueError: If a value does not resolve and there is no usable
                default. Also what a subclass's :meth:`_validate_value`
                rejection reaches the caller as, since that hook is documented
                to raise this very class and it is passed through rather than
                re-wrapped. A :exc:`ValueError`, so an
                ``except ValueError`` caller is unaffected.
            EnumKeyError: If a name does not resolve and there is no usable
                default. A :exc:`KeyError`, so an ``except KeyError`` caller is
                unaffected.

        """
        if isinstance(key, str):
            try:
                return cls._member_map_[key]
            except KeyError:
                if key in cls._value2member_map_:
                    return cls._value2member_map_[key]
                if default is NO_DEFAULT or default not in cls._value2member_map_:
                    raise EnumKeyError(f'{key!r} is not a valid {cls.__name__}',
                                       quiet=True) from None
                return cls._value2member_map_[default]
        try:
            cls._validate_value(key)
            return cls(key)  # type: ignore[call-arg]
        except ValueError as error:
            if default is NO_DEFAULT or default not in cls._value2member_map_:
                if isinstance(error, BaseError):
                    raise
                raise EnumValueError(str(error)) from error
            return cls._value2member_map_[default]

    @classmethod
    def get_all(cls, key: 'Any') -> 'tuple[Self, ...]':
        """Every member matching ``key``, canonical first.

        For a registry that maps one key to one member -- which is every
        registry inheriting this base unmodified -- that tuple holds exactly one
        entry, since an alias registered by :meth:`register_alias` is a second
        *name* for the canonical member rather than a second member. The method
        still exists here, because all four methods are to exist on every const
        registry (GitHub issue #842), and it is where a registry with genuinely
        several matches puts them: ``AppType`` overrides it to return every service IANA
        assigns to a port.

        Args:
            key: Name or value to look up.

        Returns:
            The canonical member, followed by any further distinct member
            carrying the same value.

        Raises:
            EnumValueError: As :meth:`get` with no default, for a value.
            EnumKeyError: As :meth:`get` with no default, for a name.

        """
        canonical = cls.get(key)
        return (canonical, *(
            member for member in cls._member_map_.values() if member is not canonical
            and member.value == canonical.value  # type: ignore[attr-defined]
        ))


class EnumRegistry(EnumLookup):
    """Registry protocol shared by every constant enumeration under
    :mod:`pcapkit.const`.

    :class:`EnumLookup` above carries the read half -- :meth:`~EnumLookup.get`,
    :meth:`~EnumLookup.get_all` and :meth:`~EnumLookup._validate_value`, all
    inherited here unchanged. What this tier adds is the half that makes a
    registry *open*: :meth:`register`, :meth:`register_alias`,
    :meth:`register_aliases`, :meth:`_extend` and :meth:`_unregistered_member`.

    An enumeration inherits from *here* when it may grow at runtime, and from
    :class:`EnumLookup` directly when it may not. The owner's ruling on GitHub
    issue #877 is what draws that line: an enumeration is immutable unless
    RFC or IANA says otherwise.

    Mixed in ahead of the enum base exactly as before -- ``class
    Foo(EnumRegistry, IntFlag)`` -- and gaining :class:`EnumLookup` as a parent
    does not disturb that: both tiers are plain classes, so ``_member_type_``
    still resolves past them to the enumeration base.

    """

    @classmethod
    def register(cls, value: 'Any', name: 'str') -> 'Self':
        """Mint a new member on this registry at runtime, under ``name``.

        The caller-named path, and the only one that grows the registry:
        it mints a new member on the class at runtime under the ``name`` the
        caller specifies, so nothing has to be guessed (GitHub issue #842).
        Contrast :meth:`get` and ``_missing_``, which resolve without naming anything.

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

        Routes through :meth:`~EnumLookup._validate_value` before minting, so a
        subclass that declares a range gets it enforced on the caller-named path
        too and not only on the lookup one. The duplicate check runs *first*: a
        ``value`` that already has a member is legal by construction, so the
        actionable "use ``register_alias()`` instead" message is the better answer
        for it than a range complaint would be, and validation is left to guard
        only the genuinely new value that is about to be minted.

        Args:
            value: Value of the new member.
            name: Name of the new member. Required rather than derived, which
                is the whole point -- a generated name is a guess.

        Returns:
            The newly registered member.

        Raises:
            ValueError: If ``value`` already has a member -- use
                :meth:`register_alias` to add a further name for it instead.
            EnumValueError: If a subclass's
                :meth:`~EnumLookup._validate_value` rejects ``value``. The base
                implementation of that hook accepts everything, so this cannot
                arise on a registry that does not override it.
            ValueError: If ``name`` is already taken. :mod:`aenum` reports that
                as :exc:`TypeError`; it is translated so that the ways one call
                can fail are one exception type.

        """
        if value in cls._value2member_map_:
            existing = cls._value2member_map_[value]
            raise ValueError(f'{value!r} is already registered on {cls.__name__} as '
                             f'{existing.name!r}; use {cls.__name__}.register_alias() '
                             f'to add a further name for it')
        cls._validate_value(value)
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

        Per GitHub issue #842, an alias adds a further name to a given member's
        mapping -- so it needs an existing member to attach to, and this refuses a
        value no member carries rather than falling through to :meth:`register`.
        #842 settled on an alias always attaching to an existing member, leaving
        open only whether ``AppType`` or a concrete enumeration might need to
        alias a value no member carries. ``AppType``'s override does not: it
        requires the port to already carry a member of that very registry. What an
        alias means also differs away from ``AppType``: on every other registry it
        is a custom name the caller opts into, not one recorded by the IANA
        registrars. Minting under the name of an aliasing call would manufacture
        exactly the unrecorded member #775 removes.

        Membership is tested against ``_value2member_map_`` rather than by
        calling ``cls(value)``: a declared-but-unassigned value resolves through
        ``_missing_`` to an :meth:`_unregistered_member` that is deliberately
        absent from that table, so a successful call proves nothing about
        whether a member exists.

        On this base, an alias adds a *name*, not a member: ``__members__`` grows
        by one while ``_member_names_``, iteration and ``_value2member_map_`` are
        untouched. Calls :meth:`_extend` directly rather than :meth:`register`, which
        would now refuse this call outright -- :meth:`register` and
        :meth:`register_alias` test ``value``'s membership for opposite
        outcomes, so neither can be the other's implementation any more.
        ``AppType``'s override differs: it mints a real member through
        :func:`~aenum.extend_enum`, so its iteration grows too.

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
