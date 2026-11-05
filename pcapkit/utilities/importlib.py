# -*- coding: utf-8 -*-
"""Lazy Imports
==================

.. module:: pcapkit.utilities.importlib

:mod:`pcapkit.utilities.importlib` holds :func:`lazy_exports`, which gives a package
the :pep:`562` ``__getattr__`` and ``__dir__`` that import each name it exports
the first time the name is reached, rather than with the package itself. The
:mod:`pcapkit.const` packages (:issue:`2729`) and the :mod:`pcapkit.protocols`
packages (:issue:`2730`) import their exports that way. It also holds
:data:`import_lock`, under which every such first import, and that of a
:class:`~pcapkit.corekit.module.ModuleDescriptor`, is made.

.. versionadded:: 1.6.0

"""
import importlib
import threading
import types
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any, Callable, Iterable, Mapping, Optional

__all__ = ['lazy_exports', 'import_lock']

# NOTE: no pcapkit module resolves a lazy name or a descriptor on import: imported directly,
# it would wait on this lock holding its own import lock, which the holder may need (#2771).
#: threading.RLock: Held by every first import :func:`lazy_exports`
#: makes, and by :attr:`ModuleDescriptor.klass
#: <pcapkit.corekit.module.ModuleDescriptor.klass>` when its module is not imported
#: yet, so threads make them one at a time; unserialised, they deadlock the import
#: system (:issue:`2771`). Re-entrant, as one first import can nest another.
import_lock = threading.RLock()


def lazy_exports(package: 'str', namespace: 'dict[str, Any]',
                 exports: 'Optional[Mapping[str, tuple[str, str]]]' = None, *,
                 packages: 'Iterable[str]' = ()) -> 'tuple[Callable[[str], Any], Callable[[], list[str]]]':
    """Return the ``__getattr__`` and ``__dir__`` of a package that imports its exports on first use.

    A package binds both at module level, after its ``__all__``, and imports the
    exported names only under :data:`~typing.TYPE_CHECKING`, for the type checkers:

    .. code-block:: python

       if TYPE_CHECKING:
           from pcapkit.const.tcp.option import Option as TCP_Option

       __all__ = ['TCP_Option']

       __getattr__, __dir__ = lazy_exports(__name__, globals(), {
           'TCP_Option': ('option', 'Option'),
       })

    :pep:`562` calls ``__getattr__`` only for a name missing from the package's
    globals. For an exported name it imports the submodule, reads the attribute
    off it and binds it in ``namespace``, so it runs once per name; for the name
    of a submodule an export comes from, it imports that submodule, which the
    import system binds on the package. So ``from package import Name``,
    ``import package.submodule``, attribute access, ``import *`` and the
    :mod:`pickle` of an object defined in a submodule all behave as an eager
    import would, apart from *when* the import happens.

    That import holds :data:`import_lock`, shared by every package using this
    function, so threads reaching names at once resolve them one at a time and
    a resolution may nest another. Unserialised, they deadlock the import
    system (:issue:`2771`): a family member's protocol module imports a module of
    its base's package, taking that module's import lock before waiting on the
    package, while a thread importing the package takes the two the other way.
    A resolved name is bound in ``namespace``, so reaching it again takes no lock.

    ``__dir__`` lists what the eager import would have bound: the names the
    import system sets, ``__all__``, every export, every submodule an export
    comes from, and any other submodule already imported. The package's own
    helpers -- ``TYPE_CHECKING``, this function, the two hooks -- are left out.

    Args:
        package: The package's ``__name__``.
        namespace: The package's ``globals()``, which ``__getattr__`` binds
            each name in once it is imported.
        exports: The names imported on first use, each mapped to the submodule
            it is defined in, relative to ``package``, and its name there.
        packages: Subpackages, relative to ``package``, whose ``__all__`` this
            package re-exports. Each is imported by this call -- one using
            :func:`lazy_exports` itself imports none of its exports -- and every
            name in its ``__all__`` is read off it on first use.

    Returns:
        The package's ``__getattr__`` and ``__dir__``.

    """
    table = dict(exports or {})
    for name in packages:
        module = importlib.import_module(f'{package}.{name}')
        table.update((export, (name, export)) for export in module.__all__)
    submodules = {module for module, _ in table.values()}

    def __getattr__(name: 'str') -> 'Any':
        if name in table:
            with import_lock:
                # NOTE: another thread may have bound it while this one waited.
                if name in namespace:
                    return namespace[name]
                module, attribute = table[name]
                value = getattr(importlib.import_module(f'{package}.{module}'), attribute)
                namespace[name] = value
                return value
        if name in submodules:
            with import_lock:
                return importlib.import_module(f'{package}.{name}')
        raise AttributeError(f'module {package!r} has no attribute {name!r}')

    def __dir__() -> 'list[str]':
        names = {name for name in namespace if name.startswith('__') and name.endswith('__')}
        names -= {'__getattr__', '__dir__'}
        names.update(namespace.get('__all__', ()), table, submodules)
        names.update(name for (name, value) in list(namespace.items())
                     if isinstance(value, types.ModuleType) and value.__name__ == f'{package}.{name}')
        return sorted(names)

    return __getattr__, __dir__
