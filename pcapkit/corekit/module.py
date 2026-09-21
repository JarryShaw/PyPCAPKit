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
from typing import TYPE_CHECKING, Generic, TypeVar

__all__ = ['ModuleDescriptor']

if TYPE_CHECKING:
    from typing import Type

_T = TypeVar('_T')


class ModuleDescriptor(collections.namedtuple('ModuleDescriptor', ['module', 'name']), Generic[_T]):
    """Module descriptor contains module name and class name, the actual
    class can be imported by ``from module import name``."""

    __slots__ = ()

    #: Module name.
    module: str
    #: Class name.
    name: str

    @property
    def klass(self) -> 'Type[_T]':
        """Import class from module.

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
        module = sys.modules.get(self.module)
        if module is not None:
            try:
                return getattr(module, self.name)
            except AttributeError:
                # ``sys.modules`` also holds modules whose body is still
                # executing -- a circular import, or another thread part way
                # through importing this one. ``import_module`` waits on the
                # per-module import lock, so defer to it rather than reporting
                # the attribute missing; a name that really is absent raises
                # from the ``getattr`` below instead, with the same message.
                pass
        return getattr(importlib.import_module(self.module), self.name)
