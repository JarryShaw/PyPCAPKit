# -*- coding: utf-8 -*-
"""Abstract Classes
======================

.. module:: pcapkit.utilities.inspect

:mod:`pcapkit.utilities.inspect` holds :func:`isabstract`, which tells an abstract
class from a concrete one without the interpreter's abstract flag, so the answer is
the same on every interpreter, during :meth:`~object.__init_subclass__` and after the
class is made (:issue:`2784`).

.. versionadded:: 1.6.0

"""
import abc
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

__all__ = ['isabstract']


# GraalPy freezes a class's ``__flags__`` at the first read, so setting
# ``__abstractmethods__`` afterwards never raises the abstract flag there (#2784,
# measured on GraalPy 25.4.4). :func:`inspect.isabstract` reads the flag first, so
# called from ``__init_subclass__``, before :class:`abc.ABCMeta` has set
# ``__abstractmethods__``, it leaves an abstract class reported concrete from then
# on. This reads no flag; it derives the answer as :class:`abc.ABCMeta` does.
def isabstract(cls: 'Any') -> 'bool':
    """Whether ``cls`` is an abstract class, without its ``__flags__``.

    A class made by :class:`abc.ABCMeta` is abstract when its own namespace holds
    an abstract method, or when a name one of its bases lists in
    ``__abstractmethods__`` still resolves to an abstract method on it. That is
    how :class:`abc.ABCMeta` computes ``__abstractmethods__``, so the answer
    agrees with it after the class is made, and is already the same while
    :meth:`~object.__init_subclass__` runs, before :class:`abc.ABCMeta` has set
    it. :func:`inspect.isabstract` takes the same route there, but reads the
    interpreter's abstract flag first.

    Args:
        cls: Object to check. Anything other than a class made by
            :class:`abc.ABCMeta` is not abstract.

    Returns:
        Whether ``cls`` is abstract.

    """
    if not isinstance(cls, abc.ABCMeta):
        return False
    if any(getattr(value, '__isabstractmethod__', False) for value in vars(cls).values()):
        return True
    return any(getattr(getattr(cls, name, None), '__isabstractmethod__', False)
               for base in cls.__bases__ for name in getattr(base, '__abstractmethods__', ()))
