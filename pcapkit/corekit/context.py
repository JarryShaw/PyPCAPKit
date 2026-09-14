# -*- coding: utf-8 -*-
"""Parsing Context
=====================

.. module:: pcapkit.corekit.context

:mod:`pcapkit.corekit.context` provides a *protocol keyed* channel for
caller supplied information that a protocol needs in order to parse a
packet, but that is **not** carried on the wire.

Most protocols are self describing -- every length, offset and type that
:mod:`pcapkit` needs to walk a packet is present in the packet itself. A
few are not. :class:`~pcapkit.protocols.internet.esp.ESP` is the
motivating example: :rfc:`4303` deliberately leaves the payload length,
the position of the ``Pad Length`` / ``Next Header`` trailer and the
length of the ``Integrity Check Value`` to be derived from the Security
Association (SA), which is negotiated out of band and is therefore
knowable only to the caller.

Rather than adding protocol specific keyword arguments to
:class:`~pcapkit.foundation.extraction.Extractor`, such information is
passed as a :class:`ContextRegistry` -- a mapping of protocol index ID
(c.f. :meth:`Protocol.id <pcapkit.protocols.protocol.ProtocolBase.id>`)
to a :class:`ProtocolContext` instance. The registry is handed to
:class:`~pcapkit.foundation.extraction.Extractor` once, and is then
propagated down the protocol stack by
:meth:`Protocol._import_next_layer <pcapkit.protocols.protocol.ProtocolBase._import_next_layer>`,
so that a protocol nested arbitrarily deep can reach it through
:meth:`Protocol._get_context <pcapkit.protocols.protocol.ProtocolBase._get_context>`.

Example:
    Decoding an ESP tunnel end to end::

        >>> import pcapkit
        >>> from pcapkit.protocols.internet.esp import (Cipher, ESPContext,
        ...                                            Integrity, SecurityAssociation)
        >>> sa = SecurityAssociation(
        ...     spi=0x4321,
        ...     encryption=Cipher.AES_CBC,
        ...     encryption_key=bytes.fromhex('90d382b410eeba7ad938c46cec1a82bf'),
        ... )
        >>> extraction = pcapkit.extract('esp.pcap', context=ESPContext(sa))

Important:
    A context object frequently holds secrets -- ESP encryption and
    integrity keys, for instance. Contexts are therefore held as plain
    instance attributes on the protocol object and are **never** written
    into the protocol's data model, which is the only thing that reaches
    :meth:`Info.to_dict <pcapkit.corekit.infoclass.Info.to_dict>` and,
    from there, the output dumpers. Implementations of
    :class:`ProtocolContext` are expected to keep secrets out of their
    :meth:`~object.__repr__` as well.

"""
import abc
import collections.abc
from typing import TYPE_CHECKING, TypeVar

from pcapkit.utilities.compat import Mapping
from pcapkit.utilities.exceptions import RegistryError

__all__ = ['ProtocolContext', 'ContextRegistry']

if TYPE_CHECKING:
    from typing import Any, Iterable, Iterator, Optional, Type

    from typing_extensions import Self

_CT = TypeVar('_CT', bound='ProtocolContext')


class ProtocolContext(metaclass=abc.ABCMeta):
    """Abstract base class for caller supplied protocol parsing context.

    A subclass carries whatever out-of-band information the corresponding
    protocol needs, and declares which protocol it applies to through
    :meth:`protocol`.

    Warning:
        Should the context hold secrets, the subclass **must** override
        :meth:`~object.__repr__` so that they are not printed. The default
        implementation below prints the class name and the protocol names
        only, and is safe in that respect.

    """

    @classmethod
    @abc.abstractmethod
    def protocol(cls) -> 'tuple[str, ...]':
        """Index ID of the protocol(s) this context applies to.

        The returned names are matched against
        :meth:`Protocol.id <pcapkit.protocols.protocol.ProtocolBase.id>`,
        and are case insensitive.

        """

    def __repr__(self) -> 'str':
        """Representation of the context, free of any secrets."""
        return f'<{type(self).__name__} protocol={"|".join(self.protocol())}>'


class ContextRegistry(Mapping[str, 'ProtocolContext']):
    """Protocol keyed collection of :class:`ProtocolContext` instances.

    Args:
        *contexts: Context instances, each keyed by its own
            :meth:`ProtocolContext.protocol`.
        **named: Context instances keyed explicitly by protocol index ID.

    """

    def __init__(self, *contexts: 'ProtocolContext', **named: 'ProtocolContext') -> 'None':
        self.__data__ = {}  # type: dict[str, ProtocolContext]

        for context in contexts:
            self.register(context)
        for name, context in named.items():
            self.register(context, name=name)

    ##########################################################################
    # Methods.
    ##########################################################################

    def register(self, context: 'ProtocolContext', *, name: 'Optional[str]' = None) -> 'None':
        """Register ``context`` under one or more protocol index IDs.

        Args:
            context: Context instance to register.
            name: Protocol index ID to register the context under; if not
                given, :meth:`ProtocolContext.protocol` is used, which is
                the usual case.

        Raises:
            RegistryError: If ``context`` is not a :class:`ProtocolContext`,
                or if a context is already registered for the same protocol.

        """
        if not isinstance(context, ProtocolContext):
            raise RegistryError(f'not a protocol context: {context!r}')

        names = (name,) if name is not None else context.protocol()
        for key in names:
            index = key.upper()
            if index in self.__data__:
                raise RegistryError(f'context already registered for protocol: {index}')
            self.__data__[index] = context

    @classmethod
    def make(cls, value: 'Optional[ContextRegistry | ProtocolContext | Mapping[str, ProtocolContext] | Iterable[ProtocolContext]]') -> 'Self':  # pylint: disable=line-too-long
        """Coerce ``value`` into a :class:`ContextRegistry`.

        This is the normalisation used by the public interfaces, so that a
        caller may pass whichever shape is most convenient:

        * :data:`None` -- an empty registry;
        * a :class:`ContextRegistry` -- copied as is;
        * a single :class:`ProtocolContext`;
        * a mapping of protocol index ID to :class:`ProtocolContext`;
        * any iterable of :class:`ProtocolContext`.

        Args:
            value: Value to coerce.

        Returns:
            A new :class:`ContextRegistry`.

        Raises:
            RegistryError: If ``value`` is of an unsupported type.

        """
        self = cls()
        if value is None:
            return self

        if isinstance(value, ContextRegistry):
            self.__data__.update(value.__data__)
            return self

        if isinstance(value, ProtocolContext):
            self.register(value)
            return self

        if isinstance(value, collections.abc.Mapping):
            for name, context in value.items():
                self.register(context, name=name)
            return self

        if isinstance(value, collections.abc.Iterable):
            for context in value:
                self.register(context)
            return self

        raise RegistryError(f'unsupported context: {value!r}')

    def match(self, names: 'Iterable[str]',
              cls: 'Optional[Type[_CT]]' = None) -> 'Optional[_CT]':
        """Find the context registered for any of ``names``.

        Args:
            names: Protocol index IDs to look up, in order of preference.
            cls: If given, the context is only returned when it is an
                instance of ``cls``.

        Returns:
            The first matching context, or :data:`None` if there is none.

        """
        for name in names:
            context = self.__data__.get(name.upper())
            if context is None:
                continue
            if cls is not None and not isinstance(context, cls):
                continue
            return context  # type: ignore[return-value]
        return None

    ##########################################################################
    # Data models.
    ##########################################################################

    def __getitem__(self, key: 'str') -> 'ProtocolContext':
        """Get the context registered for ``key``."""
        return self.__data__[key.upper()]

    def __iter__(self) -> 'Iterator[str]':
        """Iterate over the registered protocol index IDs."""
        return iter(self.__data__)

    def __len__(self) -> 'int':
        """Number of registered contexts."""
        return len(self.__data__)

    def __contains__(self, key: 'Any') -> 'bool':
        """Test whether a context is registered for ``key``."""
        if isinstance(key, str):
            return key.upper() in self.__data__
        return False

    def __bool__(self) -> 'bool':
        """Test whether any context is registered."""
        return bool(self.__data__)

    def __repr__(self) -> 'str':
        """Representation of the registry, free of any secrets."""
        return f'ContextRegistry({", ".join(f"{k}={v!r}" for k, v in self.__data__.items())})'
