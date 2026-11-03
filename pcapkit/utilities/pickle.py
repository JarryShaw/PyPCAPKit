# -*- coding: utf-8 -*-
"""Pickle Reductions
=======================

.. module:: pcapkit.utilities.pickle

:mod:`pcapkit.utilities.pickle` holds the :mod:`pickle` reductions several
:mod:`pcapkit` classes share, so each is written once (:issue:`2714`):

* :class:`ReduceAsProtocol2` reduces under every protocol as protocol 2 does, so a
  :class:`typing.Generic` subclass or a class with ``__slots__`` pickles under
  protocol 0 and 1, on GraalPy as on CPython;
* :class:`ReduceToName` reduces a singleton to the module-level name holding it;
* :class:`ReduceToItems` reduces a multi-valued mapping to a call of its class on
  its item pairs;
* :func:`reduce_to` makes one instance reduce to a call of a given function.

A pickle a class wrote before it took one of these still loads, and one it writes
with it loads where the class still reduces by its own.

"""

import functools
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any, Callable, SupportsIndex, TypeVar

    _T = TypeVar('_T')

__all__ = ['ReduceAsProtocol2', 'ReduceToName', 'ReduceToItems', 'reduce_to']


class ReduceAsProtocol2:
    """Mixin reducing an instance under every :mod:`pickle` protocol as protocol 2 does.

    Below protocol 2, :meth:`object.__reduce_ex__` hands the instance to
    ``copyreg._reduce_ex``, which walks ``type(self).__mro__`` for the first
    base that is not a heap type and, unless that base is :class:`object`, calls it
    on the instance. :class:`~typing.Generic` is a heap type on CPython, so the walk
    passes it. GraalPy builds ``Generic`` as a built-in, so the walk stops there and
    raises ``TypeError: typing.Generic() takes no arguments`` for any generic class
    with no reduction of its own (:issue:`2714`). The same walk refuses a class
    with ``__slots__`` and no ``__getstate__`` of its own on every interpreter.

    Protocol 2's reduction reads the class and the instance state without that
    walk, slots included, and protocol 0 and 1 write it as an ordinary call of
    ``copyreg.__newobj__``, restoring the instance through ``__new__`` as
    protocol 2 does. The next ``__reduce_ex__`` in the MRO builds it, so a base
    with a reduction of its own keeps it, as
    :class:`~pcapkit.corekit.infoclass.OrderedMultiInfo` keeps
    :class:`~pcapkit.corekit.multidict.OrderedMultiDict`'s, and a subclass
    overriding ``__reduce__`` keeps its own.

    It goes before :class:`~typing.Generic` among the bases, as on
    :class:`~pcapkit.corekit.infoclass.Info`,
    :class:`~pcapkit.protocols.schema.schema.Schema`,
    :class:`~pcapkit.foundation.reassembly.reassembly.ReassemblyBase` and
    :class:`~pcapkit.foundation.reassembly.data.data.Deferred`.

    .. versionadded:: 1.6.0

    """

    __slots__ = ()

    def __reduce_ex__(self, protocol: 'SupportsIndex') -> 'str | tuple[Any, ...]':
        """Reduce as protocol 2 does, or as ``protocol`` does if higher.

        Args:
            protocol: Pickle protocol in use.

        Returns:
            The reduction for ``protocol``, or for protocol 2 below it.

        """
        return super().__reduce_ex__(max(int(protocol), 2))


class ReduceToName:
    """Mixin reducing a singleton to the module-level name that holds it.

    :meth:`__reduce__` returns ``_name``, as ``Ellipsis.__reduce__()`` returns
    ``'Ellipsis'``, so :mod:`pickle` stores the instance as a reference to that
    name in the class's module and loads it back as the same object, at every
    protocol. A class using it sets ``_name`` to that name.

    It is shared by every :class:`~pcapkit.corekit.sentinels.Sentinel` and by the
    missing-value marker of :mod:`pcapkit.corekit.multidict`.

    .. versionadded:: 1.6.0

    """

    __slots__ = ()

    def __reduce__(self) -> 'str':
        """Reduce to ``_name``, which :mod:`pickle` stores as a global reference."""
        return self._name  # type: ignore[attr-defined] # pylint: disable=no-member


class ReduceToItems:
    """Mixin reducing a multi-valued mapping to a call of its class on its item pairs.

    :meth:`__reduce_ex__` returns ``(type(self), (pairs,))``, the pairs being
    ``list(self.items(multi=True))``, under every protocol. Rebuilding through the
    class keeps the order of interleaved keys and builds whatever the class keeps
    beside the pairs, and needs no state to be restored afterwards, which an
    immutable class refuses.

    It is shared by :class:`~pcapkit.corekit.multidict.OrderedMultiDict` and
    :class:`~pcapkit.corekit.infoclass.MultiInfo`.

    .. versionadded:: 1.6.0

    """

    __slots__ = ()

    def __reduce_ex__(self, protocol: 'SupportsIndex') -> 'str | tuple[Any, ...]':
        """Reduce to a call of the class on the item pairs, under every protocol.

        Args:
            protocol: Pickle protocol in use, which does not change the reduction.

        Returns:
            ``(type(self), (list(self.items(multi=True)),))``.

        """
        return type(self), (list(self.items(multi=True)),)  # type: ignore[attr-defined] # pylint: disable=no-member


def reduce_to(obj: '_T', rebuild: 'Callable[..., Any]', *args: 'Any') -> '_T':
    """Make ``obj`` reduce to ``rebuild(*args)`` under :mod:`pickle` and :mod:`copy`.

    The reduction goes on the *instance*, as ``obj.__reduce_ex__``, which both
    :mod:`pickle` and :mod:`copy` honour, since each fetches it with
    :func:`getattr` on the object. That suits an object whose type reduces it
    wrongly, as ``Enum.__reduce_ex__`` reduces an unregistered member to the one
    value lookup it is absent from. :func:`functools.partial` rather than a
    closure keeps ``obj`` out of its own reducer, so being reducible does not put
    it in a reference cycle.

    It is shared by :meth:`EnumRegistry._make_reducible
    <pcapkit.corekit.enum.EnumRegistry._make_reducible>` and
    :meth:`EnumField._unregistered_member
    <pcapkit.corekit.fields.numbers.EnumField._unregistered_member>`.

    Args:
        obj: The object to make reducible.
        rebuild: A module-level callable, which every :mod:`pickle` protocol can
            name, rebuilding an equivalent object from ``args``.
        *args: The arguments to ``rebuild``.

    Returns:
        ``obj``, for use as a ``return`` expression.

    .. versionadded:: 1.6.0

    """
    obj.__reduce_ex__ = functools.partial(_reduce_to, rebuild, args)  # type: ignore[method-assign]
    return obj


def _reduce_to(  # pylint: disable=unused-argument
        rebuild: 'Callable[..., Any]', args: 'tuple[Any, ...]',
        protocol: 'int') -> 'tuple[Callable[..., Any], tuple[Any, ...]]':
    """The ``__reduce_ex__`` :func:`reduce_to` installs, bound to its first two arguments.

    Args:
        rebuild: The callable to rebuild through.
        args: Its arguments.
        protocol: Pickle protocol in use, ignored; :mod:`copy` passes 4.

    Returns:
        ``(rebuild, args)``.

    """
    return rebuild, args
