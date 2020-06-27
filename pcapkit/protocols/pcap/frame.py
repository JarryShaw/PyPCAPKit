# -*- coding: utf-8 -*-
"""frame header

:mod:`pcapkit.protocols.pcap.frame` contains
:class:`~pcapkit.protocols.pcap.frame.Frame` only,
which implements extractor for frame headers of PCAP,
whose structure is described as below:

.. code:: c

    typedef struct pcaprec_hdr_s {
        guint32 ts_sec;     /* timestamp seconds */
        guint32 ts_usec;    /* timestamp microseconds */
        guint32 incl_len;   /* number of octets of packet saved in file */
        guint32 orig_len;   /* actual length of packet */
    } pcaprec_hdr_t;

"""
import collections
import datetime
import importlib
import io
import os
import sys
import time
import traceback

from pcapkit.corekit.infoclass import Info
from pcapkit.protocols.protocol import Protocol
from pcapkit.utilities.compat import cached_property
from pcapkit.utilities.decorators import beholder
from pcapkit.utilities.exceptions import UnsupportedCall

__all__ = ['Frame']

# check Python version
version_info = sys.version_info
py37 = (version_info.major >= 3 and version_info.minor >= 7)


class Frame(Protocol):
    """Per packet frame header extractor."""

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: DefaultDict[int, Tuple[str, str]]: Protocol index mapping for decoding next layer,
    #: c.f. :meth:`self._decode_next_layer <pcapkit.protocols.protocol.Protocol._decode_next_layer>`
    #: & :meth:`self._import_next_layer <pcapkit.protocols.protocol.Protocol._import_next_layer>`.
    #: The values should be a tuple representing the module name and class name.
    __proto__ = collections.defaultdict(lambda: ('pcapkit.protocols.raw', 'Raw'), {
        1:   ('pcapkit.protocols.link', 'Ethernet'),
        228: ('pcapkit.protocols.internet', 'IPv4'),
        229: ('pcapkit.protocols.internet', 'IPv6'),
    })

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        """Name of corresponding protocol.

        :rtype: str
        """
        return f'Frame {self._fnum}'

    @property
    def length(self):
        """Header length of corresponding protocol.

        :rtype: Literal[16]
        """
        return 16

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def register(cls, code, module, class_):
        """Register a new protocol class.

        Arguments:
            code (int): protocol code as in :class:`~pcapkit.const.reg.linktype.LinkType`
            module (str): module name
            class_ (str): class name

        Notes:
            The full qualified class name of the new protocol class
            should be as ``{module}.{class_}``.

        """
        cls.__proto__[code] = (module, class_)

    def index(self, name):
        """Call :meth:`ProtoChain.index <pcapkit.corekit.protochain.ProtoChain.index>`.

        Args:
            name (Union[str, Protocol, Type[Protocol]]): ``name`` to be searched

        Returns:
            int: first index of ``name``

        Raises:
            IndexNotFound: if ``name`` is not present

        """
        return self._protos.index(name)

    def read(self, length=None, **kwargs):  # pylint: disable=unused-argument
        """Read each block after global header.

        Args:
            length (Optional[int]): Length of packet data.

        Keyword Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            DataType_Frame: Parsed packet data.

        Raises:
            EOFError: If :attr:`self._file <pcapkit.protocols.pcap.frame.Frame._file>` reaches EOF.

        """
        # _scur = self._file.tell()
        _temp = self._read_unpack(4, lilendian=True, quiet=True)
        if _temp is None:
            raise EOFError

        _tsss = _temp
        _tsus = self._read_unpack(4, lilendian=True)
        _ilen = self._read_unpack(4, lilendian=True)
        _olen = self._read_unpack(4, lilendian=True)

        if self._nsec:
            _epch = _tsss + _tsus / 1000000000
        else:
            _epch = _tsss + _tsus / 1000000
        _time = datetime.datetime.fromtimestamp(_epch)

        frame = dict(
            frame_info=dict(
                ts_sec=_tsss,
                ts_usec=_tsus,
                incl_len=_ilen,
                orig_len=_olen,
            ),
            time=_time,
            number=self._fnum,
            time_epoch=_epch,
            len=_ilen,
            cap_len=_olen,
        )

        # load packet data
        length = frame['len']
        bytes_ = self._file.read(length)

        # record file pointer
        if self._mpkt and self._mpfp:
            # print(self._fnum, 'ready')
            self._mpfp.put(self._file.tell())
            self._mpkt.pool += 1

        # make BytesIO from frame packet data
        frame['packet'] = bytes_
        self._file = io.BytesIO(bytes_)
        # frame['packet'] = self._read_packet(header=0, payload=length, discard=True)

        return self._decode_next_layer(frame, length)

    def make(self, **kwargs):
        """Make frame packet data.

        Keyword Args:
            timestamp (float): UNIX-Epoch timestamp
            ts_sec (int): timestamp seconds
            ts_usec (int): timestamp microseconds
            incl_len (int): number of octets of packet saved in file
            orig_len (int): actual length of packet
            packet (bytes): raw packet data (default: ``b''``)
            nanosecond (bool): nanosecond-resolution file flag (default: :data:`False`)
            **kwargs: Arbitrary keyword arguments.

        Returns:
            bytes: Constructed packet data.

        """
        # fetch values
        ts_sec, ts_usec = self._make_timestamp(**kwargs)
        packet = kwargs.get('packet', bytes())                   # raw packet data
        incl_len = kwargs.get('incl_len', len(packet))           # number of octets of packet saved in file
        orig_len = kwargs.get('orig_len', len(packet))           # actual length of packet

        # make packet
        return b'%s%s%s%s%s' % (
            self._make_pack(ts_sec, size=4, lilendian=True),
            self._make_pack(ts_usec, size=4, lilendian=True),
            self._make_pack(incl_len, size=4, lilendian=True),
            self._make_pack(orig_len, size=4, lilendian=True),
            packet,
        )

    ##########################################################################
    # Data models.
    ##########################################################################

    def __post_init__(self, file=None, length=None, *, num, proto, nanosecond, **kwargs):  # pylint: disable=arguments-differ
        """Initialisation.

        Args:
            file (Optional[io.BytesIO]): Source packet stream.
            length (Optional[int]): Length of packet data.

        Keyword Args:
            num (int): Frame index number
                (:attr:`self._fnum <pcapkit.protocols.pcap.frame.Frame._fnum>`).
            proto (pcapkit.const.reg.linktype.LinkType): Next layer protocol index
                (:attr:`self._prot <pcapkit.protocols.pcap.frame.Frame._prot>`).
            nanosecond (bool): Nanosecond-timestamp PCAP flag
                (:attr:`self._nsec <pcapkit.protocols.pcap.frame.Frame._nsec>`).
            mpfdp (multiprocessing.Queue): Multiprocessing file descriptor queue
                (:attr:`self._mpfp <pcapkit.protocols.pcap.frame.Frame._mpfp>`).
            mpkit (multiprocessing.Namespace): Multiprocessing auxiliaries
                (:attr:`self._mpkt <pcapkit.protocols.pcap.frame.Frame._mpkt>`).
            **kwargs: Arbitrary keyword arguments.

        For *multiprocessing* related parameters, please refer to
        :class:`pcapkit.foundation.extration.Extrator` for more information.

        See Also:
            For construction argument, please refer to :meth:`make`.

        """
        #: int: frame index number
        self._fnum = num
        #: pcapkit.const.reg.linktype.LinkType: next layer protocol index
        self._prot = proto
        #: bool: nanosecond-timestamp PCAP flag
        self._nsec = nanosecond

        #: multiprocessing.Queue: multiprocessing file descriptor queue (*not available after initialisation*)
        self._mpfp = kwargs.pop('mpfdp', None)
        #: multiprocessing.Namespace: multiprocessing auxiliaries (*not available after initialisation*)
        self._mpkt = kwargs.pop('mpkit', None)

        if file is None:
            #: bytes: Raw packet data.
            self._data = self.make(**kwargs)
            #: io.BytesIO: Source packet stream.
            self._file = io.BytesIO(self._data)
            #: pcapkit.corekit.infoclass.Info: Parsed packet data.
            self._info = Info(self.read())
        else:
            #: io.BytesIO: Source packet stream.
            self._file = file
            #: pcapkit.corekit.infoclass.Info: Parsed packet data.
            self._info = Info(self.read())

            #: bytes: Raw packet data.
            self._data = self._read_packet(self._info.len)  # pylint: disable=no-member
            #: io.BytesIO: Source packet stream.
            self._file = io.BytesIO(self._data)

        # remove temporary multiprocessing support attributes
        [delattr(self, attr) for attr in filter(lambda attr: attr.startswith('_mp'), dir(self))]  # pylint: disable=expression-not-assigned

    @cached_property
    def __len__(self):
        """Total length of corresponding protocol."""
        return self._info.len  # pylint: disable=no-member

    def __length_hint__(self):
        """Return an estimated length for the object.

        :rtype: Literal[16]
        """
        return 16

    def __getitem__(self, key):
        """Subscription (``getitem``) support.

        This method fist checks if ``key`` exists in
        :attr:`self._info <pcapkit.protocols.pcap.frame.Frame._info>`.
        If so, returns the corresponding value, else calls the original
        :meth:`~pcapkit.protocols.protocol.Protocol.__getitem__` method.

        Args:
            key (Union[str, Protocol, Type[Protocol]]): Indexing key.

        Returns:
            * If ``key`` exists in :attr:`self._info <pcapkit.protocols.pcap.frame.Frame._info>`,
              returns the value of the ``key``;
            * else returns the sub-packet from the current packet of indexed protocol.

        """
        # if requested attributes in info dict,
        # else call the original function
        try:
            return self._info[key]
        except KeyError:
            return super().__getitem__(key)

    def __index__(self=None):
        """Index of the protocol.

        Returns:
            int: If the object is initiated, i.e. :attr:`self._fnum <pcapkit.protocols.pcap.frame.Frame._fnum>`
            exists, returns the frame index number of itself; else raises :exc:`UnsupportedCall`.

        Raises:
            UnsupportedCall: This protocol has no registry entry.

        """
        if self is None:
            return 'Frame'
        if getattr(self, '_fnum', None) is None:
            raise UnsupportedCall("'Frame' object cannot be interpreted as an integer")
        return self._fnum

    def __contains__(self, name):
        """Returns if ``name`` is in :attr:`self._info <pcapkit.protocols.protocol.Protocol._info>`
        or in the frame packet :attr:`self._protos <pcapkit.protocols.protocol.Protocol._protos>`.

        Args:
            name (Any): name to search

        Returns:
            bool: if ``name`` exists

        """
        if isinstance(name, type) and issubclass(name, Protocol):
            name = name.id()
        if isinstance(name, tuple):
            for item in name:
                if item in self._protos:
                    return True
            return False
        return (name in self._info) or (name in self._protos)

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _make_timestamp(self, **kwargs):  # pylint: disable=no-self-use
        """Make timestamp.

        Keyword Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Tuple[int, int]: Second and microsecond/nanosecond value of timestamp.

        """
        nanosecond = kwargs.get('nanosecond', False)         # nanosecond-resolution file flag
        timestamp = kwargs.get('timestamp', time.time())     # timestamp
        ts_sec = kwargs.get('ts_sec', int(timestamp))        # timestamp seconds
        if py37 and nanosecond:
            _default_ts_usec = time.time_ns() % 1000000000
        else:
            _default_ts_usec = int((timestamp - ts_sec) * (1000000000 if nanosecond else 1000000))
        ts_usec = kwargs.get('ts_usec', _default_ts_usec)    # timestamp microseconds
        return ts_sec, ts_usec

    def _decode_next_layer(self, data, length=None):  # pylint: disable=arguments-differ
        """Decode next layer protocol.

        Positional arguments:
            data (dict): info buffer
            length (int): valid (*non-padding*) length

        Returns:
            dict: current protocol with packet extracted

        """
        seek_cur = self._file.tell()
        try:
            next_ = self._import_next_layer(self._prot, length)
        except Exception:
            data['error'] = traceback.format_exc(limit=1).strip().split(os.linesep)[-1]
            self._file.seek(seek_cur, os.SEEK_SET)
            next_ = beholder(self._import_next_layer)(self, self._prot, length, error=True)
        info, chain = next_.info, next_.protochain

        # make next layer protocol name
        layer = next_.alias.lower()
        # proto = next_.__class__.__name__

        # write info and protocol chain into dict
        self._next = next_  # pylint: disable=attribute-defined-outside-init
        self._protos = chain  # pylint: disable=attribute-defined-outside-init
        data[layer] = info
        data['protocols'] = self._protos.chain
        return data

    def _import_next_layer(self, proto, length, error=False):  # pylint: disable=arguments-differ
        """Import next layer extractor.

        This method currently supports following protocols as registered in
        :data:`~pcapkit.const.reg.linktype.LinkType`:

        .. list-table::
           :header-rows: 1

           * - ``proto``
             - Protocol
           * - 1
             - :class:`~pcapkit.protocols.link.ethernet.Ethernet`
           * - 228
             - :class:`~pcapkit.protocols.internet.ipv4.IPv4`
           * - 229
             - :class:`~pcapkit.protocols.internet.ipv6.IPv6`

        Arguments:
            proto (pcapkit.const.reg.linktype.LinkType): next layer protocol index
            length (int): valid (*non-padding*) length

        Keyword arguments:
            error (bool): if function called on error

        Returns:
            pcapkit.protocols.protocol.Protocol: instance of next layer

        """
        module, name = self.__proto__[int(proto)]
        try:
            protocol = getattr(importlib.import_module(module), name)
        except (ImportError, AttributeError):
            from pcapkit.protocols.raw import Raw as protocol  # pylint: disable=import-outside-toplevel

        next_ = protocol(self._file, length, error=error,
                         layer=self._exlayer, protocol=self._exproto)
        return next_
