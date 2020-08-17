# -*- coding: utf-8 -*-
"""protocol chain collection

:mod:`pcapkit.corekit.protochain` contains special protocol
collection class :class:`~pcapkit.corekit.protochain.ProtoChain`.

"""
import collections.abc
import contextlib
import numbers
import re

from pcapkit.corekit.infoclass import Info
from pcapkit.utilities.compat import Collection, cached_property
from pcapkit.utilities.exceptions import IndexNotFound, IntError

###############################################################################
# from pcapkit.protocols.protocol import Protocol
###############################################################################

__all__ = ['ProtoChain']


class _ProtoList(Collection):
    """List of protocol classes for :class:`ProtoChain`."""

    @property
    def data(self):
        """Protocol data.

        :rtype: List[pcapkit.protocols.protocol.Protocol]
        """
        return self.__data__

    def __init__(self, data=None, *, base=None):
        """Initialisation.

        Args:
            data (Optional[pcapkit.protocols.protocol.Protocol]): New protocol class
                on the top stack.

        Keyword Args:
            base (Union[pcapkit.corekit.protochain._ProtoList, List[pcapkit.protocols.protocol.Protocol]]):
                Original protocol class chain as base stacks.

        """
        self.__data__ = list()

        if data is not None:
            self.__data__.append(data)

        if base is not None:
            if isinstance(base, _ProtoList):
                self.__data__.extend(base.data)
            else:
                self.__data__.extend(base)

    def __len__(self):
        """Length of the protocol chain.

        :rtype: int
        """
        return len(self.__data__)

    def __iter__(self):
        """Iterate through the protocol chain.

        :rtype: Iterator[pcapkit.protocols.protocol.Protocol]
        """
        return iter(self.__data__)

    def __contains__(self, x):
        """Returns if ``x`` is in the chain.

        Args:
            x (Union[str, pcapkit.protocols.protocol.Protocol, Type[pcapkit.protocols.protocol, Protocol]]):
                name to search

        Returns:
            bool: if ``x`` is in the chain

        """
        from pcapkit.protocols.protocol import Protocol  # pylint: disable=import-outside-toplevel

        try:
            flag = issubclass(x, Protocol)
        except TypeError:
            flag = issubclass(type(x), Protocol)
        if flag or isinstance(x, Protocol):
            return x in self.__data__

        with contextlib.suppress(Exception):
            for data in self.__data__:
                index = data.id()
                if isinstance(index, tuple):
                    index = r'|'.join(index)
                if re.fullmatch(index, x, re.IGNORECASE):
                    return True
        return False


class _AliasList(collections.abc.Sequence):
    """List of protocol aliases for ProtoChain"""

    @property
    def data(self):
        """Protocol alias data.

        :rtype: List[str]
        """
        return self.__data__

    def __init__(self, data=None, *, base=None):
        """Initialisation.

        Args:
            data (Optional[str]): New protocol alias on top stack.

        Keyword Args:
            base (Union[pcapkit.corekit.protochain._AliasLists, List[str]]):
                Original protocol alias chain as base stacks.

        """
        self.__data__ = list()

        if data is not None:
            self.__data__.append(data)

        if base is not None:
            if isinstance(base, _AliasList):
                self.__data__.extend(base.data)
            else:
                self.__data__.extend(base)

    def __len__(self):
        """Length of the protocol chain.

        :rtype: int
        """
        return len(self.__data__)

    def __iter__(self):
        """Iterate through the protocol chain.

        :rtype: Iterator[str]
        """
        return iter(self.__data__)

    def __getitem__(self, index):
        """Subscription (``getitem``) support.

        Args:
            index (int): Indexing key.

        Returns:
            str: Protocol alias at such index.

        """
        return self.__data__[index]

    def __reversed__(self):
        """Reverse the protocol alias chain.

        :rtype: List[str]
        """
        return reversed(self.__data__)

    def __contains__(self, x):
        """Returns if ``x`` is in the chain.

        Args:
            x (Union[str, pcapkit.protocols.protocol.Protocol, Type[pcapkit.protocols.protocol, Protocol]]):
                name to search

        Returns:
            bool: if ``x`` is in the chain

        """
        from pcapkit.protocols.protocol import Protocol  # pylint: disable=import-outside-toplevel

        try:
            flag = issubclass(x, Protocol)
        except TypeError:
            flag = issubclass(type(x), Protocol)

        if flag or isinstance(x, Protocol):
            x = x.id()
            if isinstance(x, tuple):
                x = r'|'.join(x)

        with contextlib.suppress(Exception):
            for data in self.__data__:
                if re.fullmatch(x, data, re.IGNORECASE):
                    return True
        return False

    def count(self, value):
        """Number of occurrences of ``value``.

        Args:
            value: (Union[str, pcapkit.protocols.protocol.Protocol, Type[pcapkit.protocols.protocol, Protocol]]):
                value to search

        Returns:
            int: Number of occurrences of ``value``.

        """
        from pcapkit.protocols.protocol import Protocol  # pylint: disable=import-outside-toplevel

        try:
            flag = issubclass(value, Protocol)
        except TypeError:
            flag = issubclass(type(value), Protocol)

        if flag or isinstance(value, Protocol):
            value = value.id()
            if isinstance(value, tuple):
                value = r'|'.join(value)

        with contextlib.suppress(Exception):
            return sum(1 for data in self.__data__ if re.fullmatch(value, data, re.IGNORECASE) is not None)
        return 0

    def index(self, value, start=0, stop=None):  # pylint: disable=inconsistent-return-statements
        """First index of ``value``.

        Args:
            value (Union[str, pcapkit.protocols.protocol.Protocol, Type[pcapkit.protocols.protocol, Protocol]]):
                value to search
            start (int): start offset
            stop (int): stop offset

        Returns:
            int: First index of ``value``.

        Raises:
            IntError: If the value is not present.

        """
        if start is not None and start < 0:
            start = max(len(self) + start, 0)
        if stop is not None and stop < 0:
            stop += len(self)

        try:
            if not isinstance(start, numbers.Integral):
                start = self.index(start)
            if not isinstance(stop, numbers.Integral):
                stop = self.index(stop)
        except IndexNotFound:
            raise IntError('slice indices must be integers or have an __index__ method') from None

        from pcapkit.protocols.protocol import Protocol  # pylint: disable=import-outside-toplevel

        try:
            flag = issubclass(value, Protocol)
        except TypeError:
            flag = issubclass(type(value), Protocol)

        if flag or isinstance(value, Protocol):
            value = value.id()
            if isinstance(value, tuple):
                value = r'|'.join(value)

        try:
            for index, data in enumerate(self.__data__[start:stop]):
                if re.fullmatch(value, data, re.IGNORECASE):
                    return index
        except Exception:
            raise IndexNotFound(f'{value!r} is not in {self.__class__.__name__!r}')
        return -1


class ProtoChain(collections.abc.Container):
    """Protocols chain."""

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def proto(self):
        """Protocol classes chain.

        :rtype: pcapkit.corekit.protocol._ProtoList
        """
        return self.__proto__

    @property
    def alias(self):
        """Protocol aliases chain.

        :rtype: pcapkit.corekit.protocol._AliasList
        """
        return self.__alias__

    @cached_property
    def tuple(self):
        """Protocol names.

        :rtype: Tuple[str]
        """
        return tuple(proto.__name__ for proto in self.__proto__.data)

    @property
    def chain(self):
        """Protocol chain string.

        :rtype: str
        """
        return self.__str__()

    ##########################################################################
    # Methods.
    ##########################################################################

    def index(self, value, start=None, stop=None):
        """First index of ``value``.

        Args:
            value (Union[str, pcapkit.protocols.protocol.Protocol, Type[pcapkit.protocols.protocol, Protocol]]):
                value to search
            start (int): start offset
            stop (int): stop offset

        Returns:
            int: First index of ``value``.

        Raises:
            IntError: If the value is not present.

        See Also:
            This method calls :meth:`self.__alias__.index <pcapkit.corekit.protochain._AliasList.index>`
            for the actual processing.

        """
        return self.__alias__.index(value, start, stop)

    def count(self, value):
        """Number of occurrences of ``value``.

        Args:
            value: (Union[str, pcapkit.protocols.protocol.Protocol, Type[pcapkit.protocols.protocol, Protocol]]):
                value to search

        Returns:
            int: Number of occurrences of ``value``.

        See Also:
            This method calls :meth:`self.__alias__.count <pcapkit.corekit.protochain._AliasList.count>`
            for the actual processing.

        """
        return self.__alias__.count(value)

    ##########################################################################
    # Data modules.
    ##########################################################################

    def __init__(self, proto=None, alias=None, *, basis=None):
        """Initialisation.

        Args:
            proto (Optional[pcapkit.protocols.protocol.Protocol]): New protocol class
                on the top stack.
            alias (Optional[str]): New protocol alias on the top stack.

        Keyword Args:
            basis (pcapkit.corekit.protochain.ProtoChain): Original protocol chain as base stacks.

        """
        if alias is None and proto is not None:
            alias = getattr(proto, '__name__', type(proto).__name__)

        if basis is None:
            basis = Info(proto=None, alias=None)

        self.__proto__ = _ProtoList(proto, base=basis.proto)
        self.__alias__ = _AliasList(alias, base=basis.alias)

    def __repr__(self):
        """Returns representation of protocol chain data.

        Example:
            >>> protochain
            ProtoChain(<class 'pcapkit.protocols.link.ethernet.Ethernet'>, ...)

        """
        return f"ProtoChain({', '.join(map(lambda p: p.__name__, self.__proto__.data))})"

    def __str__(self):
        """Returns formatted hex representation of source data stream.

        Example:
            >>> protochain
            ProtoChain(<class 'pcapkit.protocols.link.ethernet.Ethernet'>, ...)
            >>> print(protochain)
            Ethernet:IPv6:Raw

        """
        return ':'.join(self.__alias__.data)

    def __contains__(self, name):
        """Returns if ``name`` is in the chain.

        Args:
            name (Union[str, pcapkit.protocols.protocol.Protocol, Type[pcapkit.protocols.protocol, Protocol]]):
                name to search

        Returns:
            bool: if ``name`` is in the chain

        """
        return (name in self.__proto__) or (name in self.__alias__)

    def __getitem__(self, index):
        """Subscription (``getitem``) support.

        Args:
            index (int): Indexing key.

        Returns:
            str: Protocol alias at such index.

        """
        return self.__alias__[index]
