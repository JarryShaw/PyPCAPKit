# -*- coding: utf-8 -*-
"""Lazy Imports
==================

.. module:: pcapkit.utilities.lazy

:mod:`pcapkit.utilities.lazy` holds :func:`lazy_exports`, which gives a package
the :pep:`562` ``__getattr__`` and ``__dir__`` that import each name it exports
the first time the name is reached, rather than with the package itself. Every
package under :mod:`pcapkit.const` imports its enumerations that way
(:issue:`2729`), the mechanism :mod:`pcapkit.const.reg.apptype` had for its TCP
and UDP registries (:issue:`1538`) made general.

.. versionadded:: 1.6.0

"""
import importlib
import types
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any, Callable, Iterable, Mapping, Optional

__all__ = ['lazy_exports']


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
            module, attribute = table[name]
            value = getattr(importlib.import_module(f'{package}.{module}'), attribute)
            namespace[name] = value
            return value
        if name in submodules:
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
