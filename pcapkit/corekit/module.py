# -*- coding: utf-8 -*-
"""Module Descriptor
=======================

.. module:: pcapkit.corekit.module

:mod:`pcapkit.corekit.module` contains :obj:`tuple`
like class :class:`~pcapkit.corekit.module.ModuleDescriptor`,
which is originally designed as :obj:`tuple[str, str] <tuple>`.

"""
import collections
import importlib
import sys
from typing import TYPE_CHECKING, Generic, TypeVar, cast

from pcapkit.utilities.compat import final
from pcapkit.utilities.exceptions import ProtocolError

__all__ = ['NULL', 'NullType', 'ModuleDescriptor']

if TYPE_CHECKING:
    from typing import Any, Callable, Type

    from typing_extensions import Literal

_T = TypeVar('_T')


@final
class NullType:
    """Type of :data:`NULL`, the omitted-``class_``/``module`` sentinel.

    A distinct class rather than a plain :class:`str` -- which is what the
    registry helpers in :mod:`pcapkit.foundation.registry.protocols` and
    :mod:`pcapkit.foundation.registry.foundation` used to define,
    independently of each other -- so that ``is`` comparisons against it mean
    what they say: no :class:`str` a caller passes, including one that
    happens to spell ``'(null)'`` itself, can compare equal to this sentinel
    by identity. See GitHub issue #833.

    Genuinely a singleton, not merely a class this module happens to
    instantiate once: :meth:`__new__` always hands back the one instance
    that already exists, rather than building a new one, so no caller --
    direct, or :mod:`copy`/:mod:`pickle` reconstructing an instance behind
    the scenes -- can end up holding a second object that fails an ``is
    NULL`` check downstream. :meth:`ModuleDescriptor.klass` makes exactly
    that check, and a stricter guard that raises on a second call would be
    truer to "singleton" in the abstract, but it would also mean the
    module's own ``NULL = NullType()`` below is the only call that is ever
    allowed to succeed -- fragile for no real benefit, since nothing here
    needs *rejecting* a second construction, only preventing it from
    producing a distinct object.

    That still leaves :func:`copy.deepcopy`, :func:`copy.copy` and
    :mod:`pickle` unhandled: none of them constructs a new instance by
    calling ``NullType()`` themselves, so the guard above never runs for
    them. Each is therefore given its own override below, rather than left
    to fall back to the default behaviour for a plain object:

    * :func:`copy.copy` and :func:`copy.deepcopy` check for
      :meth:`__copy__`/:meth:`__deepcopy__` before ever falling back to
      reduction, so :meth:`__deepcopy__` in particular has to be defined --
      its absence is the actual defect this class used to have: deepcopying
      a :class:`ModuleDescriptor` recursed into this sentinel, reduced it,
      and rebuilt a second, non-identical :class:`NullType` that then read as
      an ordinary attribute name to :func:`getattr`, downgrading a clean
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
    other. :meth:`ModuleDescriptor.klass` faces exactly this class of
    problem for the *class* it resolves, which is why it re-reads
    :data:`sys.modules` on every call rather than memoising; nothing
    equivalent is possible here, because unlike a resolved class there is no
    live registry this sentinel could be re-read from. The pre-#833 ``str``
    sentinel had the same fragility for the same reason -- it is a property
    of sharing one module-level binding across a reload, not something this
    class's singleton guarantees claim to solve -- and nothing in this
    package reloads :mod:`pcapkit.corekit.module` after import.

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
#: :mod:`pcapkit.foundation.registry.foundation`. Defined once, here, rather
#: than once per module: both already import :class:`ModuleDescriptor` from
#: this module, so it is the shared home that needs no new module and creates
#: no import cycle.
NULL = NullType()


def _get_null() -> 'NullType':
    """Return :data:`NULL`, for :meth:`NullType.__reduce__`.

    A module-level function rather than a lambda or a bound method, so every
    :mod:`pickle` protocol -- including 0 and 1, which cannot reference
    anything nested inside a class -- can name it.

    """
    return NULL


class ModuleDescriptor(collections.namedtuple('ModuleDescriptor', ['module', 'name']), Generic[_T]):
    """Module descriptor contains module name and class name, the actual
    class can be imported by ``from module import name``."""

    __slots__ = ()

    #: Module name.
    module: str
    #: Class name, or :data:`NULL` when whatever built this descriptor never
    #: got one -- see :attr:`klass`.
    name: 'str | NullType'

    @property
    def klass(self) -> 'Type[_T]':
        """Import class from module.

        Raises:
            pcapkit.utilities.exceptions.ProtocolError: If :attr:`name` is
                :data:`NULL` -- the caller building this descriptor omitted
                the class name rather than naming one that turned out wrong --
                or if :attr:`module` has no attribute named :attr:`name`.

        Important:
            The module is read from :data:`sys.modules` first, and
            :func:`importlib.import_module` is entered only when it is not
            loaded yet. That matters because this property is on a *per-frame*
            dispatch path: a next layer code nobody registered falls back to a
            :class:`ModuleDescriptor` for
            :class:`~pcapkit.protocols.misc.raw.Raw` which
            :meth:`ProtocolBase._lookup_next_layer
            <pcapkit.protocols.protocol.ProtocolBase._lookup_next_layer>`
            deliberately does not write back, so every unrecognised frame
            resolves the same descriptor again -- 48 of the 52 resolutions an
            extraction of :file:`many_interfaces.pcapng` performs.
            :func:`~importlib.import_module` keeps real per-call work for an
            already-imported module (locks, :class:`~importlib.machinery.ModuleSpec`
            checks, the ``fromlist`` walk), so each repeat cost ~436 ns where
            this property now costs ~117 ns.

            The class is still read off the module with :func:`getattr` on
            every access, and nothing is memoised here. That is the point:
            :data:`sys.modules` *is* the module cache, and it is the only one
            whose invalidation the interpreter maintains --
            :func:`importlib.reload` rebinds the class in place and
            ``sys.modules.pop()`` drops the entry, both of which this sees
            immediately. Holding the resolved class instead would serve the
            pre-reload class forever, and an instance of it fails
            :func:`isinstance` against the live one.

        """
        if self.name is NULL:
            # ``module`` is a ``str`` and the caller never named a class --
            # GitHub issue #832. Reporting that plainly, before ``getattr``
            # ever sees it, is more useful than letting the sentinel reach
            # ``getattr`` and be reported as an absent attribute named
            # ``'(null)'``, which is what happened before #833 gave the
            # sentinel a type no caller-supplied string can collide with.
            raise ProtocolError(f'missing class name for module {self.module!r}: pass an '
                                'explicit class_ argument')

        # ``self.name`` is a ``str`` from here on -- the ``NULL`` case just
        # raised above -- so ``getattr`` below always gets a real name.
        name = cast('str', self.name)

        module = sys.modules.get(self.module)
        if module is not None:
            try:
                return getattr(module, name)
            except AttributeError:
                # ``sys.modules`` also holds modules whose body is still
                # executing -- a circular import, or another thread part way
                # through importing this one. ``import_module`` waits on the
                # per-module import lock, so defer to it rather than reporting
                # the attribute missing; a name that really is absent raises
                # from the ``getattr`` below instead, with the same message.
                pass
        try:
            return getattr(importlib.import_module(self.module), name)
        except AttributeError as error:
            # GitHub issue #832: every ``register_*`` helper that builds a
            # descriptor from a bad class name used to fail with this bare
            # stdlib :exc:`AttributeError` -- a caller cannot catch that as a
            # :mod:`pcapkit` error. Re-raised as :exc:`ProtocolError` naming
            # both the module and the class that turned out missing; the
            # message text itself is unchanged; only the type is not.
            raise ProtocolError(str(error)) from error
