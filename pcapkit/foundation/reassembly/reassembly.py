# -*- coding: utf-8 -*-
"""Base Class
================

.. module:: pcapkit.foundation.reassembly.reassembly

:mod:`pcapkit.foundation.reassembly.reassembly` contains
:class:`~pcapkit.foundation.reassembly.reassembly.Reassembly` only,
which is an abstract base class for all reassembly classes,
bases on algorithms described in :rfc:`791` and :rfc:`815`,
implements datagram reassembly of IP and TCP packets.

"""
import abc
from typing import TYPE_CHECKING, Generic, Type, TypeVar, cast

from pcapkit.protocols import __proto__ as protocol_registry
from pcapkit.protocols.misc.raw import Raw
from pcapkit.utilities.exceptions import UnsupportedCall

if TYPE_CHECKING:
    from typing import Any, Callable, Optional, Type

    from typing_extensions import Self

    from pcapkit.corekit.infoclass import Info
    from pcapkit.protocols.protocol import ProtocolBase as Protocol

    CallbackFn = Callable[[list['_DT']], None]

__all__ = ['Reassembly']

# packet
_PT = TypeVar('_PT', bound='Info')
# datagram
_DT = TypeVar('_DT', bound='Info')
# buffer ID
_IT = TypeVar('_IT', bound='tuple')
# buffer
_BT = TypeVar('_BT', bound='Info')


class ReassemblyMeta(abc.ABCMeta):
    """Meta class to add dynamic support to :class:`Reassembly`.

    This meta class is used to generate necessary attributes for the
    :class:`Reassembly` class. It can be useful to reduce unnecessary
    registry calls and simplify the customisation process.

    """
    if TYPE_CHECKING:
        #: Protocol name of current reassembly object.
        __protocol_name__: 'str'
        #: Protocol of current reassembly object.
        __protocol_type__: 'Type[Protocol]'

    @property
    def name(cls) -> 'str':
        """Protocol name of current reassembly object."""
        if hasattr(cls, '__protocol_name__'):
            return cls.__protocol_name__
        return cls.__name__

    @property
    def protocol(cls) -> 'Type[Protocol]':
        """Protocol of current reassembly object."""
        if hasattr(cls, '__protocol_type__'):
            return cls.__protocol_type__
        return protocol_registry.get(cls.name.upper(), Raw)


class ReassemblyBase(Generic[_PT, _DT, _IT, _BT], metaclass=ReassemblyMeta):
    """Base class for reassembly procedure.

    Args:
        strict: if return all datagrams (including those not
                implemented) when submit
        store: if store reassembled datagram in memory, i.e.,
            :attr:`self._dtgram <_dtgram>` (if not, datagram
            will be discarded after callback)

    Note:
        This class is for internal use only. For customisation, please use
        :class:`TraceFlow` instead.

    """
    if TYPE_CHECKING:
        #: Protocol name of current reassembly object.
        __protocol_name__: 'str'
        #: Protocol of current reassembly object.
        __protocol_type__: 'Type[Protocol]'

        #: List of callback functions upon reassembled datagram.
        __callback_fn__: 'list[CallbackFn]'

    _flag_s: 'bool'
    _flag_d: 'bool'
    _flag_n: 'bool'

    # Internal data storage for cached properties.
    __cached__: 'dict[str, Any]'

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'str':
        """Protocol name of current reassembly object.

        Note:
            This property is not available as a class
            attribute.

        """
        if hasattr(self, '__protocol_name__'):
            return self.__protocol_name__
        return type(self).name  # type: ignore[return-value]

    @property
    def protocol(self) -> 'Type[Protocol]':
        """Protocol of current reassembly object.

        Note:
            This property is not available as a class
            attribute.

        """
        if hasattr(self, '__protocol_type__'):
            return self.__protocol_type__
        return type(self).protocol  # type: ignore[return-value]

    # total number of reassembled packets
    @property
    def count(self) -> 'int':
        """Total number of reassembled packets."""
        if self._flag_n:
            self.__cached__.clear()
            self._flag_n = False

        if (cached := self.__cached__.get('count')) is not None:
            return cached

        ret = len(self.datagram)
        self.__cached__['count'] = ret
        return ret

    # reassembled datagram
    @property
    def datagram(self) -> 'tuple[_DT, ...]':
        """Reassembled datagram.

        Raises:
            UnsupportedCall: If :attr:`self._flag_d <_flag_d>` is
                set to :data:`False`.

        """
        if not self._flag_d:
            raise UnsupportedCall(f'{self.__class__.__name__}(store=False) has no attribute "datagram"')

        if self._buffer:
            return self.fetch()
        return tuple(self._dtgram)

    ##########################################################################
    # Methods.
    ##########################################################################

    # reassembly procedure
    @abc.abstractmethod
    def reassembly(self, info: '_PT') -> 'None':
        """Reassembly procedure.

        Arguments:
            info: info dict of packets to be reassembled

        """
        # clear cache
        self._flag_n = False
        self.__cached__['count'] = None
        self.__cached__['fetch'] = None

    # submit reassembled payload
    @abc.abstractmethod
    def submit(self, buf: '_BT', **kwargs: 'Any') -> 'list[_DT]':
        """Submit reassembled payload.

        Arguments:
            buf: buffer dict of reassembled packets
            **kwargs: arbitrary keyword arguments

        """

    # fetch datagram
    def fetch(self) -> 'tuple[_DT, ...]':
        """Fetch datagram.

        Returns:
            Tuple of reassembled datagrams.

        Fetch reassembled datagrams from
        :attr:`self._dtgram <pcapkit.foundation.reassembly.reassembly.Reassembly._dtgram>`
        and returns a *tuple* of such datagrams.

        If no cache found, the method will call
        :meth:`self.submit <pcapkit.foundation.reassembly.reassembly.Reassembly.submit>`
        to *forcedly* obtain newly reassembled payload. Otherwise, the
        already calculated
        :attr:`self._dtgram <pcapkit.foundation.reassembly.reassembly.Reassembly._dtgram>`
        will be returned.

        """
        if self._flag_n:
            self.__cached__.clear()
            self._flag_n = False

        if (cached := self.__cached__.get('fetch')) is not None:
            return cached

        temp_dtgram = []  # type: list[_DT]
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
    def run(self, packets: 'list[_PT]') -> 'None':
        """Run automatically.

        Arguments:
            packets: list of packet dicts to be reassembled

        """
        for packet in packets:
            self.reassembly(packet)

    # register callback function
    @classmethod
    def register(cls, callback: 'CallbackFn', *, index: 'Optional[int]' = None) -> 'None':
        """Register callback function.

        Arguments:
            callback: callback function, which will be called
                when reassembled datagram is obtained, with the
                list of reassembled datagrams as its only argument
            index: index to be inserted in the callback list,; by
                default, the callback will be appended to the end
                of the list

        """
        if index is not None:
            cls.__callback_fn__.insert(index, callback)
        else:
            cls.__callback_fn__.append(callback)

    ##########################################################################
    # Data models.
    ##########################################################################

    def __new__(cls, *args: 'Any', **kwargs: 'Any') -> 'Self':  # pylint: disable=unused-argument
        self = super().__new__(cls)

        # NOTE: Assign this attribute after ``__new__`` to avoid shared memory
        # reference between instances.
        self.__cached__ = {}

        return self

    def __init__(self, *, strict: 'bool' = True, store: 'bool' = True) -> 'None':
        """Initialise packet reassembly.

        Args:
            strict: if return all datagrams (including those not
                implemented) when submit
            store: if store reassembled datagram in memory, i.e.,
                :attr:`self._dtgram <_dtgram>` (if not, datagram
                will be discarded after callback)

        """
        #: bool: Strict mode flag. If set to :data:`True`, all
        #: data will be returned, including those not completely
        #: reassembled; otherwise, only completely reassembled
        #: data will be returned.
        self._flag_s = strict
        #: bool: Store mode flag. If set to :data:`True`, all
        #: reassembled datagram will be stored in memory, i.e.,
        #: :attr:`self._dtgram <_dtgram>`; otherwise, datagram
        #: will be discarded after callback.
        self._flag_d = store
        #: bool: New datagram flag. If set to :data:`True`, the
        #: :attr:`self._dtgram <_dtgram>` will be repopulated.
        self._flag_n = False

        #: dict[_IT, _BT]: Dict buffer field. This field is used to
        #: store reassembled packets in the form of ``{bufid: buffer}``.
        self._buffer = {}  # type: dict[_IT, _BT]
        #: list[_DT]: List reassembled datagram. This list is used
        #: to store reassembled datagrams.
        self._dtgram = []  # type: list[_DT]

    def __call__(self, packet: '_PT') -> 'None':
        """Call packet reassembly.

        Arguments:
            packet: packet dict to be reassembled
                (detailed format described in corresponding protocol)

        """
        self._flag_n = True
        self.reassembly(packet)

    def __init_subclass__(cls) -> 'None':
        """Initialise subclass.

        This method is to be used for generating necessary attributes
        for the :class:`Reassembly` class. It can be useful to reduce
        unnecessary registry calls and simplify the customisation process.

        """
        cls.__callback_fn__ = []


class Reassembly(ReassemblyBase[_PT, _DT, _IT, _BT], Generic[_PT, _DT, _IT, _BT]):
    """Base flow tracing class.

    Example:

        Use keyword argument ``protocol`` to specify the protocol
        name at class definition:

        .. code-block:: python

           class MyProtocol(Reassembly, protocol='my_protocol'):
               ...

    Arguments:
        strict: if return all datagrams (including those not
                implemented) when submit
        store: if store reassembled datagram in memory, i.e.,
            :attr:`self._dtgram <_dtgram>` (if not, datagram
            will be discarded after callback)

    """

    def __init_subclass__(cls, /, protocol: 'Optional[str]' = None, *args: 'Any', **kwargs: 'Any') -> 'None':
        """Initialise subclass.

        This method is to be used for registering the engine class to
        :class:`~pcapkit.foundation.extraction.Extractor` class.

        Args:
            name: Protocol name, default to class name.
            *args: Arbitrary positional arguments.
            **kwargs: Arbitrary keyword arguments.

        See Also:
            For more details, please refer to
            :meth:`pcapkit.foundation.extraction.Extractor.register_reassembly`.

        """
        if protocol is None:
            protocol = cast('str', cls.name)

        from pcapkit.foundation.extraction import Extractor
        Extractor.register_reassembly(protocol.lower(), cls)

        return super().__init_subclass__()
