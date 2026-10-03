# -*- coding: utf-8 -*-
"""Sentinel Objects
=====================

.. module:: pcapkit.corekit.sentinels

:mod:`pcapkit.corekit.sentinels` is the single, shared home for every
module-level singleton sentinel this package defines for itself -- a value
whose only job is to be recognised by identity (``value is SENTINEL``), so
that it can never be confused with a value a caller might legitimately pass.
See the "Naming a Sentinel" section of
:file:`docs/source/contributing/conventions/sentinel-convention.rst` for the
house rule the four below follow.

Before this module existed, each of the four lived beside the one class that
used it: :class:`NullType` in :mod:`pcapkit.corekit.module`,
:class:`NoValueType` in :mod:`pcapkit.corekit.fields.field`,
:class:`NoDefaultType` in :mod:`pcapkit.corekit.enum` and
:class:`AbsentType` in :mod:`pcapkit.protocols.protocol`. The owner's ruling
on GitHub issue :issue:`911`, choosing one shared module over one module per
sentinel, moves the four *definitions* here; each original module keeps a three-line
re-export so that no existing ``from <module> import <name>`` breaks,
including the ``if TYPE_CHECKING:``-only imports of the *types* that
:mod:`pcapkit.foundation.registry.foundation`,
:mod:`pcapkit.foundation.registry.protocols` and
:mod:`pcapkit.corekit.fields.ipaddress`, :mod:`~pcapkit.corekit.fields.misc`,
:mod:`~pcapkit.corekit.fields.numbers` and :mod:`~pcapkit.corekit.fields.strings`
already carry.

``NO_VALUE`` and ``ABSENT`` differ in how far the ruling reaches. ``NO_VALUE``
is documented as the value of
:attr:`FieldBase.default <pcapkit.corekit.fields.field.FieldBase.default>`,
so it is a published contract and the re-export at
:mod:`pcapkit.corekit.fields.field` is load-bearing for callers outside this
package. ``ABSENT`` is private to :mod:`pcapkit.protocols.protocol` --
nothing outside that module ever imports it, from here or from there -- so
its re-export exists only so that module's own code keeps reading
``ABSENT`` rather than a fully-qualified name; see :class:`AbsentType`'s
own docstring below for why it stays private after the move. GitHub issue
:issue:`937` later dropped the leading underscore both used to carry
(``_Absent``, ``_AbsentType``) in favour of SCREAMING_SNAKE/CamelCase like
their two siblings; the privacy this paragraph describes did not move with the
name -- see :class:`AbsentType`'s docstring for what carries it now.

"""
from typing import TYPE_CHECKING

from pcapkit.utilities.compat import final

__all__ = ['NULL', 'NO_VALUE', 'NO_DEFAULT']

if TYPE_CHECKING:
    from typing import Any, Callable

    from typing_extensions import Literal


@final
class NullType:
    """Type of :data:`NULL`, the omitted-``class_``/``module`` sentinel.

    A distinct class rather than a plain :class:`str` -- which is what the
    registry helpers in :mod:`pcapkit.foundation.registry.protocols` and
    :mod:`pcapkit.foundation.registry.foundation` used to define,
    independently of each other -- so that ``is`` comparisons against it mean
    what they say: no :class:`str` a caller passes, including one that
    happens to spell ``'(null)'`` itself, can compare equal to this sentinel
    by identity. See GitHub issue :issue:`833`.

    Genuinely a singleton, not merely a class this module happens to
    instantiate once: :meth:`__new__` always hands back the one instance
    that already exists, rather than building a new one, so no caller --
    direct, or :mod:`copy`/:mod:`pickle` reconstructing an instance behind
    the scenes -- can end up holding a second object that fails an ``is
    NULL`` check downstream. :meth:`ModuleDescriptor.klass
    <pcapkit.corekit.module.ModuleDescriptor.klass>` makes exactly that
    check, and a stricter guard that raises on a second call would be truer
    to "singleton" in the abstract, but it would also mean the module's own
    ``NULL = NullType()`` below is the only call that is ever allowed to
    succeed -- fragile for no real benefit, since nothing here needs
    *rejecting* a second construction, only preventing it from producing a
    distinct object.

    That still leaves :func:`copy.deepcopy`, :func:`copy.copy` and
    :mod:`pickle` unhandled: none of them constructs a new instance by
    calling ``NullType()`` themselves, so the guard above never runs for
    them. Each is therefore given its own override below, rather than left
    to fall back to the default behaviour for a plain object:

    * :func:`copy.copy` and :func:`copy.deepcopy` check for
      :meth:`__copy__`/:meth:`__deepcopy__` before ever falling back to
      reduction, so :meth:`__deepcopy__` in particular has to be defined --
      its absence is the actual defect this class used to have: deepcopying
      a :class:`~pcapkit.corekit.module.ModuleDescriptor` recursed into this
      sentinel, reduced it, and rebuilt a second, non-identical
      :class:`NullType` that then read as an ordinary attribute name to
      :func:`getattr`, downgrading a clean
      :exc:`~pcapkit.utilities.exceptions.ProtocolError` into a bare
      :exc:`TypeError` (``attribute name must be string, not 'NullType'``).
    * :mod:`pickle` protocols 2 and up reconstruct through
      ``cls.__new__(cls)``, which the guarded :meth:`__new__` already keeps
      to one instance -- but protocols 0 and 1 reconstruct through
      :func:`copyreg._reconstructor`, which calls :func:`object.__new__`
      *directly*, bypassing :meth:`__new__` entirely. :meth:`__reduce__` is
      defined so that every protocol, not only the ones that happen to go
      through this class's own :meth:`__new__`, is routed through the same
      module-level getter instead of through reconstruction at all.

    A caveat rather than a defect: :func:`importlib.reload` on this module
    re-executes ``NULL = NullType()`` below, producing a *second* singleton
    that the reloaded code compares against correctly but that every module
    which already imported the pre-reload :data:`NULL` still holds -- so a
    comparison spanning the reload sees two "singletons" that are not each
    other. :meth:`ModuleDescriptor.klass
    <pcapkit.corekit.module.ModuleDescriptor.klass>` faces exactly this class
    of problem for the *class* it resolves, which is why it re-reads
    :data:`sys.modules` on every call rather than memoising; nothing
    equivalent is possible here, because unlike a resolved class there is no
    live registry this sentinel could be re-read from. The pre-:issue:`833`
    ``str`` sentinel had the same fragility for the same reason -- it is a
    property of sharing one module-level binding across a reload, not
    something this class's singleton guarantees claim to solve -- and nothing
    in this package reloads :mod:`pcapkit.corekit.sentinels` after import.

    A second caveat, specific to this class now living apart from its one
    caller-visible re-export: reloading :mod:`pcapkit.corekit.module`
    itself -- rather than this module -- no longer has any effect on the
    singleton at all. That module now only re-imports :data:`NULL` and
    :class:`NullType` from here, and re-running an already-satisfied
    ``from ... import`` reads the current binding in :mod:`sys.modules`
    rather than re-executing anything, so it neither mints a new instance
    nor loses the old one. The reload hazard this docstring describes moved
    with the class definition; it did not double.

    """

    #: 'NullType | None': The one instance :meth:`__new__` ever returns,
    #: including for the module-level ``NULL = NullType()`` below that
    #: creates it in the first place. Kept on the class rather than as a
    #: module global so :meth:`__new__` can read and write it without a
    #: ``global`` statement.
    _instance: 'NullType | None' = None

    def __new__(cls) -> 'NullType':
        """Return the one instance of this class there will ever be."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __bool__(self) -> 'Literal[False]':
        """Return :obj:`False`."""
        return False

    def __repr__(self) -> 'str':
        """Return :obj:`str` representation of the sentinel."""
        return '<NULL>'

    def __copy__(self) -> 'NullType':
        """Return ``self`` -- there is, and only ever will be, one of these."""
        return self

    def __deepcopy__(self, memo: 'dict[int, Any]') -> 'NullType':
        """Return ``self``, for the same reason as :meth:`__copy__`.

        Args:
            memo: The :func:`copy.deepcopy` memo table. Unused: returning
                ``self`` needs no entry, since nothing about this object is
                ever copied.

        """
        return self

    def __reduce__(self) -> 'tuple[Callable[[], NullType], tuple[()]]':
        """Reduce to the module-level singleton getter, for every :mod:`pickle` protocol.

        A class that defines :meth:`__reduce__` has it honoured by
        :meth:`object.__reduce_ex__` for every protocol uniformly, rather
        than only for the ones that would otherwise call
        :func:`copyreg._reconstructor` -- so naming :func:`_get_null` here
        sidesteps reconstruction, and therefore :meth:`__new__`, altogether.
        That makes this correct independent of whatever :meth:`__new__` does,
        which is what actually covers protocols 0 and 1; see the class
        docstring.

        """
        return (_get_null, ())


#: NullType: Sentinel for an omitted ``class_`` argument to the ``register_*``
#: helpers in :mod:`pcapkit.foundation.registry.protocols` and
#: :mod:`pcapkit.foundation.registry.foundation`. Housed here, alongside the
#: package's other sentinels, rather than in :mod:`pcapkit.corekit.module`
#: where it used to live -- per the owner's ruling on GitHub issue
#: :issue:`911`, see the module docstring above. :mod:`pcapkit.corekit.module`
#: keeps a re-export so every existing
#: ``from pcapkit.corekit.module import NULL`` keeps working.
NULL = NullType()


def _get_null() -> 'NullType':
    """Return :data:`NULL`, for :meth:`NullType.__reduce__`.

    A module-level function rather than a lambda or a bound method, so every
    :mod:`pickle` protocol -- including 0 and 1, which cannot reference
    anything nested inside a class -- can name it.

    """
    return NULL


@final
class NoValueType:
    """Type of :data:`NO_VALUE`, the default value for :mod:`pcapkit.corekit.fields`.

    Housed here per GitHub issue :issue:`911` rather than in
    :mod:`pcapkit.corekit.fields.field`, where it used to be defined and where
    :attr:`FieldBase.default <pcapkit.corekit.fields.field.FieldBase.default>`
    still documents it as the field-default sentinel.

    """

    def __bool__(self) -> 'Literal[False]':
        """Return :obj:`False`."""
        return False


#: NoValueType: Default value for
#: :attr:`FieldBase.default <pcapkit.corekit.fields.field.FieldBase.default>`.
#: :mod:`pcapkit.corekit.fields.field` keeps a re-export, since that
#: attribute's own documentation is a published contract naming this object.
#: Renamed from ``NoValue`` to ``NO_VALUE`` by GitHub issue :issue:`937`,
#: which normalised all four sentinel *objects* to SCREAMING_SNAKE.
NO_VALUE = NoValueType()


@final
class NoDefaultType:
    """Type of :data:`NO_DEFAULT`, the omitted-``default`` sentinel for
    :meth:`EnumLookup.get <pcapkit.corekit.enum.EnumLookup.get>`.

    A dedicated class rather than a bare :class:`object`, per a ruling given in
    review of the work for :issue:`857`, which asked for a dedicated class that
    follows the house convention. A bare :class:`object` compares under
    ``is`` exactly as safely as a dedicated class with no ``__eq__`` of its
    own does -- identity comparison was never the problem an earlier
    revision's docstring here overstated it to be. What a bare
    :class:`object` actually lacks is a readable representation: it prints
    as ``<object object at 0x...>`` in a signature, in :func:`help`, and in
    a traceback, where ``NoDefaultType()``
    -- via :meth:`__repr__` below -- prints as ``<NO_DEFAULT>``.

    Named ``NoDefaultType`` for the *class* because that half of the house
    convention is settled: both :class:`NullType` and :class:`NoValueType`
    use ``<Name>Type``. At the time, the *instance*'s own name was not
    similarly settled -- a follow-up given in review of the work for
    :issue:`857` was explicit that ``NULL`` (``SCREAMING_CASE``) and
    ``NoValue`` (``CapWords``) disagreed, and that the choice should follow
    what each sentinel is needed for rather than a settled rule. The need here
    was continuity: ``NO_DEFAULT`` was already the name on ``main`` --
    referenced in
    :meth:`EnumLookup.get <pcapkit.corekit.enum.EnumLookup.get>`'s signature,
    its docstring, and both comparison sites -- and that change was to *what
    the sentinel is*, not to *what it is called*, so it kept that name rather
    than being renamed to match either precedent's instance casing for its own
    sake. ``NULL``'s ``SCREAMING_CASE`` was the closer match regardless, since
    :data:`NO_DEFAULT` was already spelled that way -- and GitHub issue
    :issue:`937` later settled the question this paragraph left open:
    ``NoValue`` became :data:`NO_VALUE` and ``_Absent`` became :data:`ABSENT`,
    so every instance name now agrees on SCREAMING_SNAKE.

    Genuinely a singleton, not merely a class this module happens to
    instantiate once: :meth:`__new__` always hands back the one instance that
    already exists, rather than building a new one. That guards against a
    caller writing ``registry.get(key, default=NoDefaultType())`` -- perhaps
    not realising :data:`NO_DEFAULT` already exists -- and getting back a
    *second*, non-identical sentinel that silently fails ``is NO_DEFAULT``
    inside :meth:`EnumLookup.get <pcapkit.corekit.enum.EnumLookup.get>`, so
    their call is treated as supplying a real (if useless) default instead of
    the *no default* they meant. With the guard, :class:`NoDefaultType() <NoDefaultType>`
    always returns the one canonical :data:`NO_DEFAULT`, so that mistake
    self-corrects.

    Unlike :class:`NullType`, this does *not* also define ``__copy__``,
    ``__deepcopy__`` or ``__reduce__`` -- but not because :func:`copy.deepcopy`
    or :mod:`pickle` "bypass" :meth:`__new__`; they do not, for protocol 2 and
    above. :meth:`object.__reduce_ex__` at protocol 2 reduces through
    :func:`copyreg.__newobj__`, which reconstructs by calling
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

    That gap is exactly what :class:`NullType`'s own
    :meth:`~NullType.__reduce__` exists to close, because :data:`NULL` is
    stored as a :class:`~pcapkit.corekit.module.ModuleDescriptor` field that a
    caller's own :func:`copy.deepcopy` or :mod:`pickle` call can walk into and
    reconstruct. :data:`NO_DEFAULT` is left unhandled here not because the gap
    cannot occur in principle, but because nothing in this package ever
    pickles it at protocol 0: it is reachable -- from :meth:`EnumLookup.get
    <pcapkit.corekit.enum.EnumLookup.get>`'s own bound parameter default
    (``EnumLookup.get.__defaults__[0]``, or any subclass's, e.g.
    ``Hardware.get.__func__.__defaults__[0]``) and from
    ``inspect.signature(Hardware.get).parameters['default'].default`` -- but
    neither is a field any object here gets pickled *as*, and both still
    survive :func:`copy.deepcopy` with identity intact regardless, because
    deep-copying either still reduces the sentinel itself through the same,
    guarded protocol-2 path measured above.

    A caveat that turns out to be dormant rather than live, on the current
    tree -- worth stating precisely rather than either repeating the older,
    inaccurate claim or dropping the topic. :func:`importlib.reload` on this
    module re-executes both ``class NoDefaultType:`` and ``NO_DEFAULT =
    NoDefaultType()`` below, producing a fresh, distinct object; any consumer
    that had already captured the pre-reload one -- as a bound parameter
    default, say -- goes on holding the stale one, and a bare
    ``held_default is NO_DEFAULT`` comparison against the post-reload global
    then reads :data:`False` where it once read :data:`True`.
    :meth:`EnumLookup.get <pcapkit.corekit.enum.EnumLookup.get>` looked
    exactly like such a consumer before GitHub issue :issue:`864`: an
    unrecognised, non-``NO_DEFAULT`` value used to fall through to
    ``cls(default)``, so a stale sentinel handed to that call could raise a
    :exc:`ValueError` a caller had no reason to expect from an *omitted*
    argument. :issue:`864` closed a different hole -- ``default`` could mint
    a new member -- by replacing that call with a
    ``default not in cls._value2member_map_`` guard, and the guard happens to
    close this one too: a :class:`NoDefaultType` instance, stale or fresh, is
    never a registered enum value, so the guard's ``not in`` half reads
    :data:`True` for it either way and ``get`` re-raises the original lookup
    error correctly regardless of which :data:`NO_DEFAULT` a caller's stale
    default is stale *against*. Measured on the current tree, guard
    included::

        >>> Hardware.get('Definitely-Not-A-Member')              # before reload
        KeyError: 'Definitely-Not-A-Member'
        >>> importlib.reload(pcapkit.corekit.sentinels)
        >>> Hardware.get('Definitely-Not-A-Member')               # after reload
        KeyError: 'Definitely-Not-A-Member'

    So the docstring this class carried before GitHub issue :issue:`911`'s
    move -- which claimed the second call above raises :exc:`ValueError` --
    was already wrong on ``main`` at ``d31c0aaf6``, independently of the
    move: it described the pre-:issue:`864` ``cls(default)`` call, and
    nobody had re-verified it against the guard :issue:`864` added
    afterwards. Fixed here as a drive-by correction, not a consequence of
    the housing change itself.

    None of that makes the underlying hazard theoretical elsewhere in this
    package: ``-1`` never had this failure mode at all, since ``-1 == -1``
    compares by value rather than identity, and reload staleness is a
    *tracked* defect class here for other constructs -- see
    :meth:`pcapkit.protocols.protocol.ProtocolBase._lookup_next_layer`'s own
    docstring note citing GitHub issues :issue:`425` and :issue:`555`, and
    :mod:`tests.protocols.test_dispatch_default_resolution_unit`'s own
    ``test_no_stale_class_survives_a_module_reload``, which reloads a module
    deliberately to pin the fix for exactly that class of bug elsewhere. A
    *future* comparison site written the vulnerable way -- a bare ``is
    NO_DEFAULT`` with no independent guard behind it, the way :issue:`864`'s
    fix itself was not -- would still reproduce it. "Nothing in this package
    reloads :mod:`pcapkit.corekit.sentinels` after import" remains true
    today, but it is a caveat to keep honest rather than a guarantee this
    class enforces.

    .. note::

       GitHub issue :issue:`911` also changes *which* reload is the one that
       matters, independently of the :issue:`864` finding above.
       :mod:`pcapkit.corekit.enum` no longer defines ``NoDefaultType``
       itself; it only reads :data:`NO_DEFAULT` off this module once, at its
       own import time, into its own module global. Reloading
       :mod:`pcapkit.corekit.enum` alone therefore now just re-runs that
       read, which -- so long as this module has not *also* been reloaded --
       fetches back the identical object and changes nothing. Producing a
       fresh :data:`NO_DEFAULT` at all now takes reloading *this* module,
       where the class statement lives; reloading only
       :mod:`pcapkit.corekit.enum` is not enough on its own, because ``from
       ... import`` binds a copy rather than a live alias, and that module's
       own global stays pointed at whatever it read until something re-runs
       that import.

    Also unlike both :class:`NullType` and :class:`NoValueType`, this
    deliberately does *not* define ``__bool__``. Both of those model an
    *absent* value, so reading falsy in a boolean context is the point.
    :data:`NO_DEFAULT` models something different: a marker meaning *no
    default was supplied*, checked exclusively by ``is`` at
    :meth:`EnumLookup.get <pcapkit.corekit.enum.EnumLookup.get>`'s two
    comparison sites -- nothing here ever evaluates it for truthiness. Giving
    it ``__bool__ -> False`` for symmetry with the other two would invite
    exactly the conflation this sentinel exists to rule out: code that writes
    ``if not default:`` instead of ``if default is NO_DEFAULT:`` would then
    read :data:`NO_DEFAULT` the same way it reads a caller's genuine falsy
    default -- ``0``, ``''``, ``None`` or ``False`` -- which is the exact
    collision ``-1`` used to cause under ``==`` and the reason :issue:`857`
    exists. Leaving ``__bool__`` undefined makes ``NoDefaultType()`` truthy
    (the default for any object defining neither ``__bool__`` nor
    ``__len__``), which at least does not *look* like one of the falsy values
    it must never be mistaken for.

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
#: defines neither the copy/pickle hooks nor the ``__bool__`` that its
#: :mod:`pcapkit.corekit` siblings do. :mod:`pcapkit.corekit.enum` keeps a
#: re-export, since :meth:`EnumLookup.get <pcapkit.corekit.enum.EnumLookup.get>`
#: names this object in its signature and docstring.
NO_DEFAULT = NoDefaultType()


@final
class AbsentType:
    """Type of :data:`ABSENT`, the absent-key sentinel.

    A distinct class rather than a bare :obj:`object` so that the sentinel has a
    name of its own in a traceback or a debugger, and so that a type checker has
    something to name where ``object()`` would give it nothing. It
    follows :class:`NoValueType`, which does the same job for an unset field
    default; this is a sibling of it rather than a reuse, since that one is
    documented as the default value of
    :attr:`FieldBase.default <pcapkit.corekit.fields.field.FieldBase.default>`
    and means "no value was given", not "this key is not here".

    Defined here, alongside the package's other sentinels, per the owner's
    ruling on GitHub issue :issue:`911`. Originally named
    ``_AbsentType``/``_Absent``, with the leading underscore standing in for
    "private" -- GitHub issue :issue:`937` normalised every sentinel *object*
    to SCREAMING_SNAKE and dropped it, so this pair now reads as
    CamelCase/SCREAMING_SNAKE like their two siblings and privacy is no longer
    signalled by the name at all. The owner's ruling on GitHub issue
    :issue:`719` accepted that rename, and held that documenting ``ABSENT`` as
    a private type and class, not for public use, is enough to replace the
    underscore. So this class and :data:`ABSENT` stay exactly as private as
    they were: nothing outside :mod:`pcapkit.protocols.protocol` reads
    :data:`ABSENT`, from here or from there, and neither this module's nor
    that module's :attr:`__all__` names either one. This docstring, and the
    "Naming a Sentinel" section of
    :file:`docs/source/contributing/conventions/sentinel-convention.rst`, are
    what now records that fact in place of the leading underscore.

    """

    def __bool__(self) -> 'Literal[False]':
        """Return :obj:`False`."""
        return False

    def __repr__(self) -> 'str':
        """Return :obj:`str` representation of the sentinel."""
        return '<absent>'


#: AbsentType: Absent-versus-:obj:`None` sentinel for
#: :func:`pcapkit.protocols.protocol._declared_keywords` to read a class's
#: own ``__keywords__`` out of its :attr:`~object.__dict__`, where
#: :obj:`None` is itself a meaningful value -- the opt-out that says the
#: class cannot enumerate its keywords, c.f.
#: :attr:`ProtocolBase.__keywords__
#: <pcapkit.protocols.protocol.ProtocolBase.__keywords__>`. Never leaves
#: :mod:`pcapkit.protocols.protocol`, which keeps a private re-export of it
#: for exactly that one read. Private by convention and documentation only,
#: not by a leading underscore, which GitHub issue :issue:`937` dropped --
#: see :class:`AbsentType`'s own docstring for why.
ABSENT = AbsentType()
