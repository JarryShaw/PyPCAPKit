# -*- coding: utf-8 -*-

import builtins
import collections.abc
import sys

__all__ = [
    'ModuleNotFoundError',  # exceptions
    'Collection',           # classes
    'pathlib',              # modules
]

if sys.version_info[:2] < (3, 6):
    class ModuleNotFoundError(ImportError):
        pass
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

    class Collection(collections.abc.Sized, collections.abc.Iterable, collections.abc.Container):

        __slots__ = ()

        @classmethod
        def __subclasshook__(cls, C):
            if cls is Collection:
                return _check_methods(C,  "__len__", "__iter__", "__contains__")
            return NotImplemented
else:
    Collection = collections.abc.Collection

if sys.version_info[:2] <= (3, 4):
    import pathlib2 as pathlib
else:
    import pathlib
