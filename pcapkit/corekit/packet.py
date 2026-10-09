# -*- coding: utf-8 -*-
"""Deferred Packet
===================

.. module:: pcapkit.corekit.packet

:mod:`pcapkit.corekit.packet` contains
:class:`~pcapkit.corekit.packet.DeferredPacket`, the mixin that lets an
:class:`~pcapkit.corekit.infoclass.Info` subclass hold its ``packet`` field as
a placeholder and resolve it on first read. A reassembled datagram's ``packet``
is a second parse of its payload, and a traced flow's is a reassembly of its
stream; most callers want neither, so both are postponed until somebody reads
them.

A subclass keeps a three-part contract, which
:meth:`DeferredPacket.__init_subclass__` checks at class creation:

* It is declared ``class X(DeferredPacket, Info)``, mixin first, so the methods
  here take precedence over :class:`~pcapkit.corekit.infoclass.Info`'s own.
* It lists ``packet`` in its ``__additional__``. That is what makes the field
  lazy at all: :class:`~pcapkit.corekit.infoclass.Info` stores a field named
  there under a mangled key and maps it back on the way out, so ``packet``
  never lands in :attr:`~object.__dict__` under its own name. Reading it
  therefore reaches :meth:`DeferredPacket.__getattr__`, where the placeholder
  can be resolved, while ``dict(x)``, :meth:`DeferredPacket.to_dict` and
  iteration still report the field as ``packet``.
* It names its placeholder class in
  :attr:`~DeferredPacket.__deferred__`. A value of that class is called with no
  arguments to produce the real ``packet``; any other value already is one.

Resolution happens **at most once**: the result replaces the placeholder in
:attr:`~object.__dict__`, so every later read returns that same object and the
placeholder is never called again.

This module imports nothing from :mod:`pcapkit.foundation` or
:mod:`pcapkit.protocols`. Each placeholder class stays with the subsystem that
creates it, and only the subclass knows which one it holds.

"""
from typing import TYPE_CHECKING

from pcapkit.utilities.exceptions import InfoError

if TYPE_CHECKING:
    from typing import Any, Callable, ClassVar, Type

__all__ = ['DeferredPacket']


class DeferredPacket:
    """Resolves a deferred ``packet`` field on first read.

    A mixin for :class:`~pcapkit.corekit.infoclass.Info` subclasses; see
    :mod:`pcapkit.corekit.packet` for the contract a subclass keeps. Reading
    ``packet`` -- as an attribute, as ``x['packet']``, or through
    :meth:`to_dict`, :func:`str` or :func:`repr` -- resolves a placeholder once
    and keeps the result. ``'packet' in x``, :func:`len` and iteration report the
    field by name without resolving it.

    It is shared by
    :class:`pcapkit.foundation.reassembly.data.ip.Datagram`,
    :class:`pcapkit.foundation.reassembly.data.tcp.Datagram` and
    :class:`pcapkit.foundation.traceflow.data.tcp.Index`, which differ only in
    the placeholder class each names in :attr:`__deferred__`
    (:issue:`1516`). It is still importable from where it lived before:
    :mod:`pcapkit.foundation.reassembly.data`,
    :mod:`pcapkit.foundation.reassembly.data.data` and
    :mod:`pcapkit.foundation.traceflow.data.data`.

    """

    if TYPE_CHECKING:
        #: Placeholder class the ``packet`` field may hold, set by each subclass.
        #: A value of this class is resolved by calling it with no arguments;
        #: an instance of any other class, :data:`None` included, is not.
        __deferred__: 'ClassVar[Type[Callable[[], Any]]]'

    # NOTE: the ``super()`` calls below are suppressed for both checkers. They are
    # undefined *on this mixin*, which is what a mixin is -- the base arrives at
    # the point of use, where every subclass is declared
    # ``class X(DeferredPacket, Info)`` and :class:`~pcapkit.corekit.infoclass.Info`
    # supplies all three. Neither mypy nor pylint can see that from here, and
    # pylint calls it an *error* rather than a warning.

    def __init_subclass__(cls, /, *args: 'Any', **kwargs: 'Any') -> 'None':
        """Refuse a subclass that does not keep the contract.

        Either omission would otherwise fail silently, and only on a read.
        Without ``packet`` in ``__additional__`` the field lands in
        :attr:`~object.__dict__` under its own name, :meth:`__getattr__` is never
        reached, and the placeholder itself comes back. Without
        :attr:`__deferred__`, :meth:`__analyse__` raises :exc:`AttributeError`
        from inside :meth:`__getattr__`, which ``getattr(x, 'packet', None)``
        takes for a missing attribute and answers with :data:`None`.

        Args:
            *args: Arbitrary positional arguments.
            **kwargs: Arbitrary keyword arguments in class definition.

        Raises:
            InfoError: If ``cls`` does not list ``packet`` in its
                ``__additional__``, or does not name a class in its
                :attr:`__deferred__`.

        """
        super().__init_subclass__(*args, **kwargs)

        if 'packet' not in getattr(cls, '__additional__', ()):
            raise InfoError(f"{cls.__name__}: 'packet' is not listed in __additional__, "
                            'so reading it would never resolve the placeholder')
        if not isinstance(getattr(cls, '__deferred__', None), type):
            raise InfoError(f"{cls.__name__}: __deferred__ does not name the placeholder class "
                            "that 'packet' may hold")

    def __analyse__(self) -> 'Any':
        """Resolve the ``packet`` field, at most once.

        A placeholder, i.e. an instance of :attr:`__deferred__`, is called with
        no arguments and its result replaces it in :attr:`~object.__dict__`. Any
        other value is returned as it is.

        Returns:
            The resolved ``packet``, which may be :data:`None` when the subclass
            stored that instead of a placeholder.

        """
        key = self.__map__.get('packet', 'packet')
        value = self.__dict__[key]
        if isinstance(value, self.__deferred__):
            value = value()
            self.__dict__[key] = value
        return value

    def __getattr__(self, name: 'str') -> 'Any':
        # NOTE: reached only for names absent from ``__dict__``, which ``packet``
        # always is -- see ``__additional__`` in the module docstring. Everything
        # else has to raise, or a typo would silently answer with the resolved
        # ``packet``.
        if name != 'packet':
            raise AttributeError(f'{type(self).__name__!r} object has no attribute {name!r}')
        return self.__analyse__()

    def __getitem__(self, name: 'str') -> 'Any':
        if name == 'packet':
            return self.__analyse__()
        return super().__getitem__(name)  # type: ignore[misc] # pylint: disable=no-member

    def __contains__(self, name: 'object') -> 'bool':
        # NOTE: ``Mapping.__contains__`` answers by fetching the value, which
        # would resolve the placeholder merely to decide that the field exists.
        # ``packet`` is a declared field, so it is always there.
        return name == 'packet' or super().__contains__(name)  # type: ignore[misc] # pylint: disable=no-member

    def __str__(self) -> 'str':
        self.__analyse__()
        return super().__str__()

    def __repr__(self) -> 'str':
        self.__analyse__()
        return super().__repr__()

    def to_dict(self) -> 'dict[str, Any]':
        """Convert the instance into :obj:`dict`.

        Returns:
            The fields, with ``packet`` resolved if it had not been read yet --
            a :obj:`dict` holding the placeholder would leak an implementation
            detail into what is meant to be plain data.

        """
        self.__analyse__()
        return super().to_dict()  # type: ignore[misc] # pylint: disable=no-member
