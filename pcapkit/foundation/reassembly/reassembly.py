# -*- coding: utf-8 -*-
"""Base Class
================

:mod:`pcapkit.foundation.reassembly.reassembly` contains
:class:`~pcapkit.foundation.reassembly.reassembly.Reassembly` only,
which is an abstract base class for all reassembly classes,
bases on algorithms described in :rfc:`791` and :rfc:`815`,
implements datagram reassembly of IP and TCP packets.

"""
import abc
from typing import TYPE_CHECKING, Generic, TypeVar

if TYPE_CHECKING:
    from typing import Any, Optional, Type

    from pcapkit.corekit.infoclass import Info
    from pcapkit.protocols.protocol import Protocol

__all__ = ['Reassembly']

# packet
PT = TypeVar('PT', bound='Info')
# datagram
DT = TypeVar('DT', bound='Info')
# buffer ID
IT = TypeVar('IT', bound='tuple')
# buffer
BT = TypeVar('BT', bound='Info')


class Reassembly(Generic[PT, DT, IT, BT], metaclass=abc.ABCMeta):
    """Base class for reassembly procedure.

    Args:
        strict: if return all datagrams (including those not
            implemented) when submit

    """

    # Internal data storage for cached properties.
    __cached__: 'dict[str, Any]'

    ##########################################################################
    # Properties.
    ##########################################################################

    # protocol name of current reassembly object
    @property
    @abc.abstractmethod
    def name(self) -> 'str':
        """Protocol name of current reassembly object."""

    # total number of reassembled packets
    @property
    def count(self) -> 'int':
        """Total number of reassembled packets."""
        if (cached := self.__cached__.get('count')) is not None:
            return cached

        ret = len(self.datagram)
        self.__cached__['count'] = ret
        return ret

    # reassembled datagram
    @property
    def datagram(self) -> 'tuple[DT, ...]':
        """Reassembled datagram."""
        if self._buffer:
            return self.fetch()
        return tuple(self._dtgram)

    @property
    @abc.abstractmethod
    def protocol(self) -> 'Type[Protocol]':
        """Protocol of current reassembly object."""

    ##########################################################################
    # Methods.
    ##########################################################################

    # reassembly procedure
    @abc.abstractmethod
    def reassembly(self, info: 'PT') -> 'None':
        """Reassembly procedure.

        Arguments:
            info: info dict of packets to be reassembled

        """
        # clear cache
        self.__cached__['count'] = None
        self.__cached__['fetch'] = None

    # submit reassembled payload
    @abc.abstractmethod
    def submit(self, buf: 'BT', **kwargs: 'Any') -> 'list[DT]':
        """Submit reassembled payload.

        Arguments:
            buf: buffer dict of reassembled packets
            **kwargs: arbitrary keyword arguments

        """

    # fetch datagram
    def fetch(self) -> 'tuple[DT, ...]':
        """Fetch datagram.

        Returns:
            Tuple of reassembled datagrams.

        Fetch reassembled datagrams from
        :attr:`~pcapkit.foundation.reassembly.reassembly.Reassembly._dtgram`
        and returns a *tuple* of such datagrams.

        If no cache found, the method will call
        :meth:`~pcapkit.foundation.reassembly.reassembly.Reassembly.submit` to
        *forcedly* obtain newly reassembled payload. Otherwise, the
        already calculated :attr:`~pcapkit.foundation.reassembly.reassembly.Reassembly._dtgram`
        will be returned.

        """
        if (cached := self.__cached__.get('fetch')) is not None:
            return cached

        temp_dtgram = []  # type: list[DT]
        for (bufid, buffer) in self._buffer.items():
            temp_dtgram.extend(
                self.submit(buffer, bufid=bufid)
            )
        temp_dtgram.extend(self._dtgram)
        ret = tuple(temp_dtgram)

        self.__cached__['fetch'] = ret
        return ret

    # return datagram index
    def index(self, pkt_num: 'int') -> 'Optional[int]':
        """Return datagram index.

        Arguments:
            pkt_num: index of packet

        Returns:
            Reassembled datagram index which was from No. ``pkt_num`` packet;
            if not found, returns :obj:`None`.

        """
        for counter, datagram in enumerate(self.datagram):
            if pkt_num in datagram.index:  # type: ignore[attr-defined]
                return counter
        return None

    # run automatically
    def run(self, packets: 'list[PT]') -> 'None':
        """Run automatically.

        Arguments:
            packets: list of packet dicts to be reassembled

        """
        for packet in packets:
            self.reassembly(packet)

    ##########################################################################
    # Data models.
    ##########################################################################

    def __new__(cls, *args: 'Any', **kwargs: 'Any') -> 'Reassembly[PT, DT, IT, BT]':  # pylint: disable=unused-argument
        self = super().__new__(cls)

        # NOTE: Assign this attribute after ``__new__`` to avoid shared memory
        # reference between instances.
        self.__cached__ = {}

        return self

    def __init__(self, *, strict: 'bool' = True) -> 'None':
        """Initialise packet reassembly.

        Args:
            strict: if return all datagrams (including those not
                implemented) when submit

        """
        #: bool: Strict mode flag.
        self._strflg = strict
        #: dict[IT, BT]: Dict buffer field.
        self._buffer = {}  # type: dict[IT, BT]
        #: list[DT]: List reassembled datagram.
        self._dtgram = []  # type: list[DT]

    def __call__(self, packet: 'PT') -> 'None':
        """Call packet reassembly.

        Arguments:
            packet: packet dict to be reassembled
                (detailed format described in corresponding protocol)

        """
        self.reassembly(packet)
