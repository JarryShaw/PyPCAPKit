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

# NOTE: ``_get_null`` is re-exported alongside the two public names for
# backward compatibility, not for use here. Every pickle written before GitHub
# issue #911 moved the definitions names ``pcapkit.corekit.module _get_null``
# in its payload -- that is what :meth:`NullType.__reduce__` emitted -- so
# dropping the name from this module would make those payloads unloadable with
# ``AttributeError: module 'pcapkit.corekit.module' has no attribute
# '_get_null'``. Newly written pickles name the new home; both resolve to the
# same function and yield the same singleton.
from pcapkit.corekit.sentinels import NULL, NullType, _get_null  # pylint: disable=unused-import
from pcapkit.utilities.exceptions import ProtocolError

__all__ = ['NULL', 'ModuleDescriptor']

if TYPE_CHECKING:
    from typing import Type

_T = TypeVar('_T')


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
