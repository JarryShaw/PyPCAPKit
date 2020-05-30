# -*- coding: utf-8 -*-

import builtins
import collections.abc
import sys

__all__ = [
    # exceptions
    'ModuleNotFoundError',

    # classes
    'Collection', 'cached_property',

    # modules
    'pathlib',
]

if sys.version_info[:2] < (3, 6):
    class ModuleNotFoundError(ImportError):  # pylint: disable=redefined-builtin
        """Module not found."""
else:
    ModuleNotFoundError = builtins.ModuleNotFoundError

if sys.version_info[:2] <= (3, 5):
    def _check_methods(C, *methods):
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
        def __subclasshook__(cls, C):
            if cls is Collection:
                return _check_methods(C, "__len__", "__iter__", "__contains__")
            return NotImplemented
else:
    Collection = collections.abc.Collection

if sys.version_info[:2] <= (3, 4):
    import pathlib2 as pathlib  # pylint: disable=import-error
else:
    import pathlib

try:
    from functools import cached_property
except ImportError:
    from _thread import RLock

    _NOT_FOUND = object()

    class cached_property:
        def __init__(self, func):
            self.func = func
            self.attrname = None
            self.__doc__ = func.__doc__
            self.lock = RLock()

        def __set_name__(self, owner, name):
            if self.attrname is None:
                self.attrname = name
            elif name != self.attrname:
                raise TypeError(
                    "Cannot assign the same cached_property to two different names "
                    f"({self.attrname!r} and {name!r})."
                )

        def __get__(self, instance, owner=None):
            if instance is None:
                return self
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
