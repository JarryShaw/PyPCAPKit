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
import math
from typing import TYPE_CHECKING, Generic, Type, TypeVar, cast

from pcapkit.protocols import __proto__ as protocol_registry
from pcapkit.protocols.misc.raw import Raw
from pcapkit.utilities.exceptions import FieldValueError, UnsupportedCall
from pcapkit.utilities.logging import get_logger

# NB: declared above the ``TYPE_CHECKING`` block, not below it, so that
# ``CallbackFn`` can name ``_DT`` outright. As a quoted forward reference it was
# resolvable only from this module's namespace, and every module that spells
# ``CallbackFn`` in an annotation -- ``pcapkit.foundation.registry.foundation``
# does -- has to evaluate the alias in its own.
# packet
_PT = TypeVar('_PT', bound='Info')
# datagram
_DT = TypeVar('_DT', bound='Info')
# buffer ID
_IT = TypeVar('_IT', bound='tuple')
# buffer
_BT = TypeVar('_BT', bound='Info')

if TYPE_CHECKING:
    from typing import Any, Callable, Optional, Type

    from typing_extensions import Self

    from pcapkit.corekit.infoclass import Info
    from pcapkit.corekit.module import ModuleDescriptor
    from pcapkit.protocols.protocol import ProtocolBase

    CallbackFn = Callable[[list[_DT]], None]

__all__ = ['Reassembly']

#: logging.Logger: Module-level logger, a child of the package-wide
#: :data:`pcapkit.utilities.logging.logger`.
logger = get_logger(__name__)


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
        __protocol_type__: 'Type[ProtocolBase]'

    @property
    def name(cls) -> 'str':
        """Protocol name of current reassembly object."""
        if hasattr(cls, '__protocol_name__'):
            return cls.__protocol_name__
        return cls.__name__

    @property
    def protocol(cls) -> 'Type[ProtocolBase]':
        """Protocol of current reassembly object."""
        if hasattr(cls, '__protocol_type__'):
            return cls.__protocol_type__
        return protocol_registry.get(cls.name.upper(), Raw)

    @property
    def registry(cls) -> 'dict[str, ModuleDescriptor[Reassembly] | Type[Reassembly]]':
        """Mapping of protocol names to reassembly classes.

        Note:
            Unlike :attr:`EnumSchema.registry
            <pcapkit.protocols.schema.schema.EnumSchema.registry>`, this is not
            a per-class mapping: every reassembly registration lands in the
            single :attr:`Extractor.__reassembly__
            <pcapkit.foundation.extraction.Extractor.__reassembly__>` table, so
            reading it through any subclass returns that same object. The
            property exists so ``MyReassembly.registry`` is spelled the same way
            here as it is for schemas.

            Note also that :class:`EnumSchema` carries *two* ``registry``
            properties, one on its metaclass and one on the class body, so it
            answers on an instance as well. This one is on the metaclass only,
            so it is available as a class attribute and **not** on an instance.

        """
        from pcapkit.foundation.extraction import \
            Extractor  # pylint: disable=import-outside-toplevel

        return Extractor.__reassembly__


class ReassemblyBase(Generic[_PT, _DT, _IT, _BT], metaclass=ReassemblyMeta):
    """Base class for reassembly procedure.

    Args:
        strict: if return all datagrams (including those not
                implemented) when submit
        store: if store reassembled datagram in memory, i.e.,
            :attr:`self._dtgram <_dtgram>` (if not, datagram
            will be discarded after callback)
        timeout: reassembly timeout in seconds, measured on the
            *capture's* clock; :data:`None` selects the protocol's
            own :attr:`__timeout__` default

    Note:
        This class is for internal use only. For customisation, please use
        :class:`Reassembly` instead.

    """
    if TYPE_CHECKING:
        #: Protocol name of current reassembly object.
        __protocol_name__: 'str'
        #: Protocol of current reassembly object.
        __protocol_type__: 'Type[ProtocolBase]'

        #: List of callback functions upon reassembled datagram.
        __callback_fn__: 'list[CallbackFn]'

    _flag_s: 'bool'
    _flag_d: 'bool'
    _flag_n: 'bool'
    _timeout: 'float'

    # Internal data storage for cached properties.
    __cached__: 'dict[str, Any]'

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: float: Default reassembly timeout, in seconds, for this protocol --
    #: overridden per protocol, e.g.
    #: :attr:`IPv6.__timeout__ <pcapkit.foundation.reassembly.ipv6.IPv6.__timeout__>`.
    #: :data:`math.inf` means "never expire", which is the base default because
    #: nothing here knows what a protocol's specification asks for.
    __timeout__: 'float' = math.inf

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def timeout(self) -> 'float':
        """Reassembly timeout, in seconds, of the current reassembly object.

        A buffer whose first-arriving fragment is older than this many seconds
        **on the capture's own clock** is abandoned rather than held for the life
        of the object -- see :meth:`expire`. :data:`math.inf` disables expiry.

        """
        return self._timeout

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
    def protocol(self) -> 'Type[ProtocolBase]':
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
            **kwargs: arbitrary keyword arguments; implementations accept
                ``timeout``, set when the buffer is being submitted because
                :meth:`expire` abandoned it rather than because it completed or
                the capture ended

        """

    # abandon timed-out buffers
    def expire(self, timestamp: 'float') -> 'list[_DT]':
        """Abandon every buffer whose reassembly timeout has elapsed.

        Arguments:
            timestamp: Current time on the capture's clock, in seconds since the
                Unix epoch -- i.e. the capture timestamp of the packet just
                handed to :meth:`reassembly`.

        Returns:
            Datagrams of the buffers abandoned, reported with
            :attr:`Completion.TIMEOUT <pcapkit.foundation.reassembly.data.data.Completion.TIMEOUT>`.
            Empty when nothing expired, which is the overwhelmingly common case.

        A buffer expires when more than :attr:`timeout` seconds separate
        ``timestamp`` from the capture timestamp of its **first-arriving**
        fragment, which is the deadline :rfc:`8200#section-4.5` states ("within
        60 seconds of the reception of the first-arriving fragment") and which
        :rfc:`815` suggests implementing by reading "the clock when each first
        fragment arrives". A later fragment therefore does not extend the
        deadline.

        Note:
            The clock only advances when *this* reassembly object is fed, since
            a packet handed to it is the only evidence an offline parser has that
            capture time has moved on. For IPv4 and TCP that is nearly every
            frame of the relevant protocol; for IPv6 it is only the fragments,
            so an IPv6 buffer that stalls and is followed by no further IPv6
            fragment is reported as
            :attr:`Completion.PARTIAL <pcapkit.foundation.reassembly.data.data.Completion.PARTIAL>`
            at the end of the capture. That is the honest answer: the capture
            never shows that the deadline passed. A caller with an outside
            source of time may call this method itself to advance the clock.

        """
        if math.isinf(self._timeout) or not self._buffer:
            return []

        # NOTE: The deadline is compared against the buffer's own origin rather
        # than an elapsed count decremented per packet, so the answer depends
        # only on the timestamps in the capture file and not on how the frames
        # were handed over. That is what keeps a replay deterministic.
        deadline = timestamp - self._timeout
        expired = [
            bufid for (bufid, buffer) in self._buffer.items()
            if cast('Any', buffer).timestamp < deadline
        ]

        ret = []  # type: list[_DT]
        for bufid in expired:
            buffer = self._buffer.pop(bufid)

            # NOTE: :rfc:`8200#section-4.5` and :rfc:`1122#section-3.3.2` both
            # ask for an ICMP Time Exceeded here, gated on the offset-zero
            # fragment having been received. An offline parser sends nothing, so
            # the condition is reported instead: the header buffer is non-empty
            # exactly when that fragment arrived.
            owed_icmp = bool(getattr(buffer, 'header', None) or getattr(buffer, 'hdr', None))
            logger.debug('%s: abandoning buffer %s after %.6fs > %.6fs timeout '
                         '(ICMP Time Exceeded owed: %s)', self.name, bufid,
                         timestamp - cast('Any', buffer).timestamp, self._timeout, owed_icmp)

            ret.extend(self.submit(buffer, bufid=bufid, timeout=True))
        return ret

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

        logger.debug('%s: flushing %d outstanding buffer(s)', self.name, len(self._buffer))

        temp_dtgram = []  # type: list[_DT]
        for (bufid, buffer) in self._buffer.items():
            temp_dtgram.extend(
                self.submit(buffer, bufid=bufid)
            )
        temp_dtgram.extend(self._dtgram)
        ret = tuple(temp_dtgram)

        logger.debug('%s: fetched %d datagram(s)', self.name, len(ret))

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
        logger.debug('%s: reassembling %d packet(s)', self.name, len(packets))
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

    def __init__(self, *, strict: 'bool' = True, store: 'bool' = True,
                 timeout: 'Optional[float]' = None) -> 'None':
        """Initialise packet reassembly.

        Args:
            strict: if return all datagrams (including those not
                implemented) when submit
            store: if store reassembled datagram in memory, i.e.,
                :attr:`self._dtgram <_dtgram>` (if not, datagram
                will be discarded after callback)
            timeout: reassembly timeout in seconds, measured on the capture's
                own clock rather than the host's; :data:`None` selects this
                protocol's :attr:`__timeout__` default, and
                :data:`math.inf` disables expiry entirely

        Raises:
            FieldValueError: If ``timeout`` is negative.

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

        if timeout is None:
            timeout = self.__timeout__
        elif timeout < 0:
            raise FieldValueError(f'{type(self).__name__}: reassembly timeout must not be '
                                  f'negative, got {timeout!r}')
        #: float: Reassembly timeout in seconds, on the capture's clock.
        #: :data:`math.inf` disables expiry.
        self._timeout = float(timeout)

        #: dict[_IT, _BT]: Dict buffer field. This field is used to
        #: store reassembled packets in the form of ``{bufid: buffer}``.
        self._buffer = {}  # type: dict[_IT, _BT]
        #: list[_DT]: List reassembled datagram. This list is used
        #: to store reassembled datagrams.
        self._dtgram = []  # type: list[_DT]

        logger.debug('%s reassembly initialised (strict=%s, store=%s, timeout=%s)',
                     self.name, strict, store, self._timeout)

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
    """Base reassembly class.

    Example:

        Registration is opt-in. Pass keyword argument ``protocol`` at class
        definition to register the reassembly under that protocol name:

        .. code-block:: python

           class MyProtocol(Reassembly, protocol='my_protocol'):
               ...

        Omit it and the subclass is *not* registered, which is how a class
        that is not meant to be selectable by name declines:

        .. code-block:: python

           class MyMixin(Reassembly):  # not registered
               ...

        Such a class can still be registered later, on demand:

        .. code-block:: python

           Extractor.register_reassembly('my_mixin', MyMixin)

    Arguments:
        strict: if return all datagrams (including those not
                implemented) when submit
        store: if store reassembled datagram in memory, i.e.,
            :attr:`self._dtgram <_dtgram>` (if not, datagram
            will be discarded after callback)
        timeout: reassembly timeout in seconds, on the capture's own clock;
            :data:`None` selects the protocol's :attr:`__timeout__` default

    """

    def __init_subclass__(cls, /, protocol: 'Optional[str]' = None, *args: 'Any', **kwargs: 'Any') -> 'None':
        """Initialise subclass.

        This method is to be used for registering the reassembly class to
        :class:`~pcapkit.foundation.extraction.Extractor` class.

        Args:
            protocol: Protocol name to register the subclass under, lowercased.
                :data:`None` (the default) skips registration entirely.
            *args: Arbitrary positional arguments.
            **kwargs: Arbitrary keyword arguments.

        Raises:
            UnsupportedCall: If any unrecognised class keyword is given.

        Registration is **opt-in**: the subclass is registered if and only if
        ``protocol`` is given. This is what lets a subclass decline registration
        rather than having to inherit :class:`ReassemblyBase` to avoid it, and it
        matches :meth:`EnumSchema.__init_subclass__
        <pcapkit.protocols.schema.schema.EnumSchema.__init_subclass__>`, which
        has guarded on its own ``code`` keyword all along.

        Note:
            :attr:`__protocol_name__` is *not* an opt-in. It supplies the
            :attr:`name <pcapkit.foundation.reassembly.reassembly.ReassemblyMeta.name>`
            the reassembly reports, which it does whether or not the class is
            registered; only the keyword decides registration.

        See Also:
            For more details, please refer to
            :meth:`pcapkit.foundation.extraction.Extractor.register_reassembly`.

        """
        # NOTE: the keyword here is ``protocol``, but ``Engine`` spells the same
        # idea ``name`` -- so guessing ``name=`` by analogy is the expected
        # mistake, not a careless one. It used to land in ``**kwargs``, get
        # dropped by the bare ``super().__init_subclass__()`` below, and leave
        # the class registered under its own class name instead: no exception, no
        # warning. See the sibling note in ``Engine.__init_subclass__``.
        if args or kwargs:
            unexpected = ', '.join([*map(repr, args), *sorted(kwargs)])
            raise UnsupportedCall(f'{cls.__name__}: unexpected class keyword(s): {unexpected}')

        if protocol is not None:
            from pcapkit.foundation.extraction import \
                Extractor  # pylint: disable=import-outside-toplevel

            Extractor.register_reassembly(protocol.lower(), cls)

        return super().__init_subclass__()
