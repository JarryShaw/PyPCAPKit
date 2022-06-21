# -*- coding: utf-8 -*-

import builtins
import collections.abc
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any, Callable, Optional, Type, Union

__all__ = [
    # exceptions
    'ModuleNotFoundError',

    # classes
    'Collection', 'cached_property',

    # modules
    'pathlib',
]

version = sys.version_info[:2]

if version < (3, 6):
    class ModuleNotFoundError(ImportError):  # pylint: disable=redefined-builtin
        """Module not found."""
else:
    ModuleNotFoundError = builtins.ModuleNotFoundError  # type: ignore[misc,assignment]

if version <= (3, 5):
    def _check_methods(C: 'Type[Any]', *methods: 'str') -> 'bool | Any':
        mro = C.__mro__
        for method in methods:
            for B in mro:
                if method in B.__dict__:
                    if B.__dict__[method] is None:
                        return NotImplemented
                    break
            else:
                return NotImplemented
        return True

    class Collection(collections.abc.Sized, collections.abc.Iterable, collections.abc.Container):  # pylint: disable=abstract-method

        __slots__ = ()

        @classmethod
        def __subclasshook__(cls, C: 'Type[Any]') -> 'bool | Any':
            if cls is Collection:
                return _check_methods(C, "__len__", "__iter__", "__contains__")
            return NotImplemented
else:
    Collection = collections.abc.Collection  # type: ignore[misc,assignment]

if version <= (3, 4):
    import pathlib2 as pathlib  # pylint: disable=import-error
else:
    import pathlib  # type: ignore[no-redef]

# functools.cached_property added in 3.8
if version >= (3, 8):
    from functools import cached_property
else:
    from _thread import RLock  # type: ignore[attr-defined]
    from typing import Generic, TypeVar  # isort: split

    _T = TypeVar("_T")
    _S = TypeVar("_S")

    _NOT_FOUND = object()

    class cached_property(Generic[_T]):  # type: ignore[no-redef]
        def __init__(self, func: 'Callable[[Any], _T]') -> 'None':
            self.func = func  # type: Callable[[Any], _T]
            self.attrname = None  # type: Optional[str]
            self.__doc__ = func.__doc__
            self.lock = RLock()

        def __set_name__(self, owner: 'Type[Any]', name: 'str') -> 'None':
            if self.attrname is None:
                self.attrname = name
            elif name != self.attrname:
                raise TypeError(
                    "Cannot assign the same cached_property to two different names "
                    f"({self.attrname!r} and {name!r})."
                )

        def __get__(self, instance: 'Optional[_S]',
                    owner: 'Optional[Type[Any]]' = None) -> 'Union[cached_property[_T], _T]':
            if instance is None:
                return self  # type: ignore[return-value]
            if self.attrname is None:
                raise TypeError(
                    "Cannot use cached_property instance without calling __set_name__ on it.")
            try:
                cache = instance.__dict__
            except AttributeError:  # not all objects have __dict__ (e.g. class defines slots)
                msg = (
                    f"No '__dict__' attribute on {type(instance).__name__!r} "
                    f"instance to cache {self.attrname!r} property."
                )
                raise TypeError(msg) from None
            val = cache.get(self.attrname, _NOT_FOUND)
            if val is _NOT_FOUND:
                with self.lock:
                    # check if another thread filled cache while we awaited lock
                    val = cache.get(self.attrname, _NOT_FOUND)
                    if val is _NOT_FOUND:
                        val = self.func(instance)
                        try:
                            cache[self.attrname] = val
                        except TypeError:
                            msg = (
                                f"The '__dict__' attribute on {type(instance).__name__!r} instance "
                                f"does not support item assignment for caching {self.attrname!r} property."
                            )
                            raise TypeError(msg) from None
            return val
