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
house rule the sentinels below follow.

The owner's ruling on GitHub issue :issue:`911` chose one shared module over
one module per sentinel, and this module is the only import path for each
of them: the module of the class that uses each one does not re-export it
(:issue:`1744`), per the ruling recorded on :issue:`1103` that a moved name keeps no
re-export at its old path. :mod:`pcapkit.corekit.module`,
:mod:`pcapkit.corekit.fields.field`, :mod:`pcapkit.corekit.enum` and
:mod:`pcapkit.protocols.protocol` import the object they use from here, but
none lists it in ``__all__`` or documents it, and none binds the type.

Every sentinel type derives from :class:`_Sentinel`, which makes it a true
singleton: calling the type again, :func:`copy.copy`, :func:`copy.deepcopy`
and every :mod:`pickle` protocol give back the one instance (:issue:`1842`).

``ABSENT`` is private to :mod:`pcapkit.protocols.protocol` -- nothing outside
that module ever reads it. It carries no leading underscore;
:class:`AbsentType`'s docstring says what marks it private instead.

.. versionadded:: 1.5.0

   :class:`NoValueType` moves here from :mod:`pcapkit.corekit.fields.field`
   (:issue:`911`), and :data:`NO_VALUE` replaces its ``NoValue`` there
   (:issue:`937`).

"""
import abc
from typing import TYPE_CHECKING, cast

from pcapkit.utilities.compat import final

__all__ = ['NULL', 'NO_VALUE', 'NO_DEFAULT']

if TYPE_CHECKING:
    from typing import Any

    from typing_extensions import Literal, Self


class _Sentinel(abc.ABC):
    """Abstract base of every sentinel type here, carrying the singleton protocol.

    A subclass sets ``_name`` to the name of the module-level variable
    that holds its one instance, and gets the rest from here:

    * :meth:`__new__` hands back the one instance, so calling the type again
      cannot produce a second object that fails an ``is`` check. It returns
      the existing instance rather than raising, so a caller who builds one
      by mistake still gets the sentinel.
    * :meth:`__copy__` and :meth:`__deepcopy__` return ``self``.
    * :meth:`__reduce__` returns ``_name``, so :mod:`pickle` stores the
      instance as a reference to that module-level name and loads it back as
      the same object, at every protocol. Guarding :meth:`__new__` alone
      would not cover protocols 0 and 1, which rebuild through
      :func:`copyreg._reconstructor` and so call :meth:`object.__new__`
      directly.
    * :meth:`__repr__` wraps ``_name`` in angle brackets, as in ``<NULL>``.

    ``__bool__`` is left to each sentinel, since only some of them stand for
    an absent value.

    Private, because every sentinel is defined in this module (:issue:`911`),
    so nothing outside it has a reason to subclass this.

    A pickle written before :issue:`1842` still loads. A pickle of
    :data:`NULL` names ``_get_null``, kept for it, and a pickle of another
    sentinel at protocol 2 or above rebuilds through :meth:`__new__`; both
    load as the sentinel. A pickle of another sentinel at protocol 0 or 1
    rebuilds through :func:`copyreg._reconstructor`, which no hook on the
    class can reach, so it loads as a second instance of the type.

    """

    #: '_Sentinel | None': The one instance of a subclass, once :meth:`__new__`
    #: has made it. Assigned on the subclass, so each sentinel type has its own.
    _instance: '_Sentinel | None' = None

    @property
    @abc.abstractmethod
    def _name(self) -> 'str':
        """Name of the module-level variable that holds the one instance.

        A subclass overrides this with a plain class attribute, which is what
        makes it concrete.

        """

    def __new__(cls) -> 'Self':
        """Return the one instance of this class there will ever be."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cast('Self', cls._instance)

    def __repr__(self) -> 'str':
        """Return :obj:`str` representation of the sentinel."""
        return f'<{self._name}>'

    def __copy__(self) -> 'Self':
        """Return ``self`` -- there is, and only ever will be, one of these."""
        return self

    def __deepcopy__(self, memo: 'dict[int, Any]') -> 'Self':
        """Return ``self``, for the same reason as :meth:`__copy__`.

        Args:
            memo: The :func:`copy.deepcopy` memo table. Unused: returning
                ``self`` needs no entry, since nothing about this object is
                ever copied.

        """
        return self

    def __reduce__(self) -> 'str':
        """Reduce to ``_name``, which :mod:`pickle` stores as a global reference."""
        return self._name


@final
class NullType(_Sentinel):
    """Type of :data:`NULL`, the omitted-``class_``/``module`` sentinel.

    A distinct class rather than a plain :class:`str` such as ``'(null)'``,
    so that ``is`` comparisons against it mean what they say: no
    :class:`str` a caller passes, including one that happens to spell
    ``'(null)'`` itself, can be this sentinel. See GitHub issue :issue:`833`.

    :class:`_Sentinel` keeps it to one instance. :meth:`ModuleDescriptor.klass
    <pcapkit.corekit.module.ModuleDescriptor.klass>` checks ``is NULL``; a
    second instance would slip past it to :func:`getattr` and downgrade a
    clean :exc:`~pcapkit.utilities.exceptions.ProtocolError` into a bare
    :exc:`TypeError` (``attribute name must be string, not 'NullType'``).

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
    live registry this sentinel could be re-read from. It is a property of
    sharing one module-level binding across a reload, not something this
    class's singleton guarantees claim to solve, and nothing in this package
    reloads :mod:`pcapkit.corekit.sentinels` after import. Pickling a
    pre-reload :data:`NULL` raises :exc:`pickle.PicklingError`, since it is
    no longer the object its name refers to.

    Reloading :mod:`pcapkit.corekit.module` instead has no effect on the
    singleton at all. That module only imports :data:`NULL` from here, and
    re-running an already-satisfied ``from ... import`` reads the current
    binding in :mod:`sys.modules` rather than re-executing anything, so it
    neither mints a new instance nor loses the old one.

    """

    _name = 'NULL'

    def __bool__(self) -> 'Literal[False]':
        """Return :obj:`False`."""
        return False


#: NullType: Sentinel for an omitted ``class_`` argument to the ``register_*``
#: helpers in :mod:`pcapkit.foundation.registry.protocols` and
#: :mod:`pcapkit.foundation.registry.foundation`. Housed here with the
#: package's other sentinels, per the module docstring above.
NULL = NullType()


def _get_null() -> 'NullType':
    """Return :data:`NULL`, for a pickle written before :issue:`1842`.

    ``NullType.__reduce__`` used to name this function, so such a pickle
    calls it to load. Nothing here calls it any more; it stays so that those
    pickles keep loading, as :data:`NULL` itself.

    """
    return NULL


@final
class NoValueType(_Sentinel):
    """Type of :data:`NO_VALUE`, the default value for :mod:`pcapkit.corekit.fields`.

    Housed here per GitHub issue :issue:`911`;
    :attr:`FieldBase.default <pcapkit.corekit.fields.field.FieldBase.default>`
    documents it as the field-default sentinel.

    .. versionchanged:: 1.5.0

       A singleton: calling this type, :func:`copy.deepcopy` and :mod:`pickle`
       give back :data:`NO_VALUE` rather than a second instance
       (:issue:`1842`). It reprs as ``<NO_VALUE>`` rather than as an object
       address, which is what a field constructor's signature and a parsed
       schema's repr show for an unset value (:issue:`1841`).

    """

    _name = 'NO_VALUE'

    def __bool__(self) -> 'Literal[False]':
        """Return :obj:`False`."""
        return False


#: NoValueType: Default value for
#: :attr:`FieldBase.default <pcapkit.corekit.fields.field.FieldBase.default>`.
NO_VALUE = NoValueType()


@final
class NoDefaultType(_Sentinel):
    """Type of :data:`NO_DEFAULT`, the omitted-``default`` sentinel for
    :meth:`EnumLookup.get <pcapkit.corekit.enum.EnumLookup.get>`.

    A dedicated class rather than a bare :class:`object`, as review of the
    work for :issue:`857` asked, following the house convention. A bare
    :class:`object` compares under ``is`` exactly as safely as a dedicated
    class with no ``__eq__`` of its own does; what it lacks is a readable
    representation: it prints as ``<object object at 0x...>`` in a signature,
    in :func:`help`, and in a traceback, where ``NoDefaultType()`` -- via the
    ``__repr__`` :class:`_Sentinel` gives it -- prints as ``<NO_DEFAULT>``.
    The names follow the convention every sentinel here shares, settled by
    GitHub issue :issue:`937`: ``<Name>Type`` for the class and
    SCREAMING_SNAKE for the instance.

    :class:`_Sentinel` keeps it to one instance. That guards against a caller
    writing ``registry.get(key, default=NoDefaultType())`` -- perhaps not
    realising :data:`NO_DEFAULT` already exists -- and getting back a
    *second*, non-identical sentinel that silently fails ``is NO_DEFAULT``
    inside :meth:`EnumLookup.get <pcapkit.corekit.enum.EnumLookup.get>`, so
    their call is treated as supplying a real (if useless) default instead of
    the *no default* they meant.

    A reload caveat that is dormant rather than live. :func:`importlib.reload`
    on this module re-executes both ``class NoDefaultType:`` and
    ``NO_DEFAULT = NoDefaultType()`` below, producing a fresh, distinct
    object; any consumer that had already captured the pre-reload one -- as a
    bound parameter default, say -- goes on holding the stale one, and a bare
    ``held_default is NO_DEFAULT`` comparison against the post-reload global
    then reads :data:`False` where it once read :data:`True`.
    :meth:`EnumLookup.get <pcapkit.corekit.enum.EnumLookup.get>` is such a
    consumer but is not affected: its fallback is guarded by
    ``default not in cls._value2member_map_`` (added by GitHub issue
    :issue:`864` to stop ``default`` minting a new member), and a
    :class:`NoDefaultType` instance, stale or fresh, is never a registered
    enum value, so the guard reads :data:`True` for it either way and ``get``
    re-raises the original lookup error regardless of which
    :data:`NO_DEFAULT` a caller's default is stale *against*. Measured::

        >>> Hardware.get('Definitely-Not-A-Member')              # before reload
        EnumKeyError: "'Definitely-Not-A-Member' is not a valid Hardware"
        >>> importlib.reload(pcapkit.corekit.sentinels)
        >>> Hardware.get('Definitely-Not-A-Member')               # after reload
        EnumKeyError: "'Definitely-Not-A-Member' is not a valid Hardware"

    The hazard is not theoretical elsewhere: reload staleness is a *tracked*
    defect class here for other constructs -- see
    :meth:`pcapkit.protocols.protocol.ProtocolBase._lookup_next_layer`'s own
    docstring note on why it declines to memoise a resolved class, and
    :mod:`tests.protocols.test_dispatch_default_resolution_unit`'s own
    ``test_no_stale_class_survives_a_module_reload``, which reloads a module
    deliberately to pin the fix for exactly that class of bug. A *future*
    comparison site written the vulnerable way -- a bare ``is NO_DEFAULT``
    with no independent guard behind it -- would reproduce it. Nothing in
    this package reloads :mod:`pcapkit.corekit.sentinels` after import, but
    that is a caveat to keep honest rather than a guarantee this class
    enforces.

    .. note::

       Reloading :mod:`pcapkit.corekit.enum` alone does not produce a fresh
       :data:`NO_DEFAULT`. That module does not define ``NoDefaultType``; it
       reads :data:`NO_DEFAULT` off this module once, at its own import time,
       into its own module global, and a reload just re-runs that read,
       which -- so long as this module has not *also* been reloaded --
       fetches back the identical object. Producing a fresh one takes
       reloading *this* module, where the class statement lives; and since
       ``from ... import`` binds a copy rather than a live alias,
       :mod:`pcapkit.corekit.enum`'s own global stays pointed at whatever it
       read until something re-runs that import.

    Unlike both :class:`NullType` and :class:`NoValueType`, this
    deliberately does *not* define ``__bool__``. Both of those model an
    *absent* value, so reading falsy in a boolean context is the point.
    :data:`NO_DEFAULT` models something different: a marker meaning *no
    default was supplied*, checked exclusively by ``is`` at
    :meth:`EnumLookup.get <pcapkit.corekit.enum.EnumLookup.get>`'s
    comparison sites -- nothing here ever evaluates it for truthiness. Giving
    it ``__bool__ -> False`` for symmetry with those two would invite
    exactly the conflation this sentinel exists to rule out: code that writes
    ``if not default:`` instead of ``if default is NO_DEFAULT:`` would then
    read :data:`NO_DEFAULT` the same way it reads a caller's genuine falsy
    default -- ``0``, ``''``, ``None`` or ``False`` -- which is the
    collision with a genuine default that :issue:`857` exists to rule out.
    Leaving ``__bool__`` undefined makes ``NoDefaultType()`` truthy
    (the default for any object defining neither ``__bool__`` nor
    ``__len__``), which at least does not *look* like one of the falsy values
    it must never be mistaken for.

    """

    _name = 'NO_DEFAULT'


#: NoDefaultType: The ``default`` argument value that means *no default*, i.e.
#: let an unresolvable key propagate its lookup error rather than falling
#: back. See :class:`NoDefaultType` for why this is a dedicated class rather
#: than a bare :class:`object`, and why it does not define the ``__bool__``
#: that its :mod:`pcapkit.corekit` siblings do.
NO_DEFAULT = NoDefaultType()


@final
class AbsentType(_Sentinel):
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
    ruling on GitHub issue :issue:`911`. **Private**, although the names
    carry no leading underscore: GitHub issue :issue:`937` put every sentinel
    on the CamelCase/SCREAMING_SNAKE convention, and the owner's ruling on
    GitHub issue :issue:`719` held that documenting ``ABSENT`` as a private
    type and class, not for public use, is enough to replace the underscore.
    Nothing outside :mod:`pcapkit.protocols.protocol` reads :data:`ABSENT`,
    from here or from there, and neither this module's nor that module's
    :attr:`__all__` names either one. This docstring, and the "Naming a
    Sentinel" section of
    :file:`docs/source/contributing/conventions/sentinel-convention.rst`, are
    what record that.

    """

    _name = 'ABSENT'

    def __bool__(self) -> 'Literal[False]':
        """Return :obj:`False`."""
        return False

    def __repr__(self) -> 'str':
        """Return :obj:`str` representation of the sentinel.

        ``<absent>``, as it was before :issue:`1842`, rather than the
        ``<ABSENT>`` that :class:`_Sentinel` would give.

        """
        return '<absent>'


#: AbsentType: Absent-versus-:obj:`None` sentinel for
#: :func:`pcapkit.protocols.protocol._declared_keywords` to read a class's
#: own ``__keywords__`` out of its :attr:`~object.__dict__`, where
#: :obj:`None` is itself a meaningful value -- the opt-out that says the
#: class cannot enumerate its keywords, c.f.
#: :attr:`ProtocolBase.__keywords__
#: <pcapkit.protocols.protocol.ProtocolBase.__keywords__>`. Never leaves
#: :mod:`pcapkit.protocols.protocol`, which imports it from here for exactly
#: that one read. Private by documentation rather than by a
#: leading underscore -- see :class:`AbsentType`'s own docstring.
ABSENT = AbsentType()
