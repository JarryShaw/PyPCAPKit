# -*- coding: utf-8 -*-
"""Protocol Chain
====================

.. module:: pcapkit.corekit.protochain

:mod:`pcapkit.corekit.protochain` contains special protocol
collection class :class:`~pcapkit.corekit.protochain.ProtoChain`.

"""
import collections.abc
import copy
from typing import TYPE_CHECKING, overload

from pcapkit.utilities.compat import cached_property
from pcapkit.utilities.exceptions import IndexNotFound

if TYPE_CHECKING:
    from typing import Iterator, Optional, Type

    from typing_extensions import Self

    from pcapkit.protocols.protocol import ProtocolBase as Protocol

__all__ = ['ProtoChain']


class ProtoChain(collections.abc.Sequence):
    """Protocols chain.

    Args:
        proto: New protocol class on the top stack.
        alias: New protocol alias on the top stack.
        basis: Original protocol chain as base stacks.

    """

    #: Internal data storage for protocol chain.
    __data__: 'tuple[tuple[str, Type[Protocol]], ...]'

    ##########################################################################
    # Properties.
    ##########################################################################

    @cached_property
    def protocols(self) -> 'tuple[Type[Protocol], ...]':
        """List of protocols in the chain."""
        return tuple(data[1] for data in self.__data__)

    @cached_property
    def aliases(self) -> 'tuple[str, ...]':
        """Protocol names."""
        return tuple(data[0] for data in self.__data__)

    @property
    def chain(self) -> 'str':
        """Protocol chain string."""
        return self.__str__()

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def from_list(cls, data: 'list[Protocol | Type[Protocol]]') -> 'Self':
        """Create a protocol chain from a list.

        Args:
            data: Protocol chain list.

        """
        from pcapkit.protocols.protocol import \
            ProtocolBase as Protocol  # pylint: disable=import-outside-toplevel

        temp_data = []
        for proto in data:
            if isinstance(proto, Protocol):
                alias = proto.alias
                proto = type(proto)

            temp_data.append((alias, proto))

        obj = cls.__new__(cls)
        obj.__data__ = tuple(temp_data)
        return obj

    def index(self, value: 'str | Protocol | Type[Protocol]',
              start: 'Optional[int]' = None, stop: 'Optional[int]' = None) -> 'int':
        """First index of ``value``.

        Args:
            value: Value to search.
            start: start offset.
            stop: stop offset.

        Raises:
            IndexNotFound: If the value is not present.

        """
        if start is None:
            start = 0
        elif start < 0:
            start = max(len(self) + start, 0)

        if stop is not None and stop < 0:
            stop += len(self)

        # prepare comparison values
        from pcapkit.protocols.protocol import \
            ProtocolBase as Protocol  # pylint: disable=import-outside-toplevel
        comp = Protocol.expand_comp(value)

        pool = self.__data__[start:stop]
        for idx, (alias, proto) in enumerate(pool):
            test_comp = (proto, alias.upper(), *(name.upper() for name in proto.id()))
            for test in comp:
                if test in test_comp:
                    return start + idx
        raise IndexNotFound(f'{value!r} is not in {self.__class__.__name__!r}')

    def count(self, value: 'str | Protocol | Type[Protocol]') -> int:
        """Number of occurrences of ``value``.

        Args:
            value: Value to search.

        """
        # prepare comparison values
        from pcapkit.protocols.protocol import \
            ProtocolBase as Protocol  # pylint: disable=import-outside-toplevel
        comp = Protocol.expand_comp(value)

        cnt = 0
        for alias, proto in self.__data__:
            test_comp = (proto, alias.upper(), *(name.upper() for name in proto.id()))
            for test in comp:
                if test in test_comp:
                    cnt += 1
                    break
        return cnt

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, proto: 'Protocol | Type[Protocol]', alias: 'Optional[str]' = None, *,
                 basis: 'Optional[ProtoChain]' = None):
        """Initialisation.

        Args:
            proto: New protocol class on the top stack.
            alias: New protocol alias on the top stack.
            basis: Original protocol chain as base stacks.

        """
        from pcapkit.protocols.protocol import \
            ProtocolBase as Protocol  # pylint: disable=import-outside-toplevel
        if isinstance(proto, Protocol):
            if alias is None:
                alias = proto.alias
            proto = type(proto)

        if alias is None:
            alias = proto.__name__

        temp_data = [(alias, proto)]
        if basis is not None:
            temp_data.extend(basis)
        self.__data__ = tuple(temp_data)

    def __repr__(self) -> 'str':
        """Returns representation of protocol chain data.

        Example:
            >>> protochain
            ProtoChain(Ethernet, IPv6, Raw)

        """
        return f"ProtoChain({', '.join(map(lambda p: p[1].__name__, self.__data__))})"

    def __str__(self) -> 'str':
        """Returns formatted hex representation of source data stream.

        Example:
            >>> protochain
            ProtoChain(Ethernet, IPv6, Raw)
            >>> print(protochain)
            Ethernet:IPv6:Raw

        """
        return ':'.join(map(lambda p: p[0], self.__data__))

    def __contains__(self, name: 'str | Protocol | Type[Protocol]') -> 'bool':  # type: ignore[override]
        """Returns if ``name`` is in the chain.

        Args:
            name: Name to search.

        Returns:
            Whether ``name`` is in the chain.

        """
        from pcapkit.protocols.protocol import \
            ProtocolBase as Protocol  # pylint: disable=import-outside-toplevel
        comp = Protocol.expand_comp(name)

        for alias, proto in self.__data__:
            test_comp = (proto, alias.upper(), *(name.upper() for name in proto.id()))
            for test in comp:
                if test in test_comp:
                    return True
        return False

    @overload
    def __getitem__(self, index: 'int') -> 'str': ...
    @overload
    def __getitem__(self, index: 'slice') -> 'tuple[str, ...]': ...

    def __getitem__(self, index: 'int | slice') -> 'str | tuple[str, ...]':
        """Subscription (``getitem``) support.

        Args:
            index: Indexing key.

        Returns:
            Protocol alias at such index.

        """
        if isinstance(index, slice):
            return tuple(data[0] for data in self.__data__[index])
        return self.__data__[index][0]

    def __iter__(self) -> 'Iterator[tuple[str, Type[Protocol]]]':
        """Iterator support.

        Returns:
            Iterator of protocol alias and class.

        """
        return iter(self.__data__)

    def __len__(self) -> 'int':
        """Length support.

        Returns:
            Length of protocol chain.

        """
        return len(self.__data__)

    def __add__(self, other: 'ProtoChain') -> 'ProtoChain':
        """Merge protocol chain by appending protocols from ``other``.

        Args:
            other: Protocol chain to be merged.

        Returns:
            Merged protocol chain.

        """
        new = copy.copy(self)
        new.__data__ += other.__data__
        return new
