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
from typing import TYPE_CHECKING, Generic, TypeVar

__all__ = ['ModuleDescriptor']

if TYPE_CHECKING:
    from typing import Type

T = TypeVar('T')


class ModuleDescriptor(collections.namedtuple('ModuleDescriptor', ['module', 'name']), Generic[T]):
    """Module descriptor contains module name and class name, the actual
    class can be imported by ``from module import name``."""

    __slots__ = ()

    #: Module name.
    module: str
    #: Class name.
    name: str

    @property
    def klass(self) -> 'Type[T]':
        """Import class from module."""
        module = importlib.import_module(self.module)
        return getattr(module, self.name)
