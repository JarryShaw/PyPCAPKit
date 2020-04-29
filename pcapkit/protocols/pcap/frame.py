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
import traceback

from pcapkit.corekit.infoclass import Info
from pcapkit.protocols.protocol import Protocol
from pcapkit.utilities.decorators import beholder

__all__ = ['Frame']


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
        """Name of corresponding protocol."""
        return f'Frame {self._fnum}'

    @property
    def length(self):
        """Header length of corresponding protocol."""
        return 16

    ##########################################################################
    # Methods.
    ##########################################################################

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

    def read_frame(self):
        """Read each block after global header.

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

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, file, *args, num, proto, nanosecond, **kwargs):  # pylint: disable=super-init-not-called
        """Initialisation.

        Args:
            file (io.BytesIO): Source packet stream.
            *args: Arbitrary positional arguments.

        Keyword Args:
            num (int): Frame index number
                (:attr:`self._fnum <pcapkit.protocols.pcap.frame.Frame._fnum>`).
            proto (LinkType): Next layer protocol index
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

        """
        #: int: frame index number
        self._fnum = num
        #: io.BytesIO: source packet stream
        self._file = file
        #: LinkType: next layer protocol index
        self._prot = proto
        #: bool: nanosecond-timestamp PCAP flag
        self._nsec = nanosecond
        #: multiprocessing.Queue: multiprocessing file descriptor queue (*not available after initialisation*)
        self._mpfp = kwargs.pop('mpfdp', None)
        #: multiprocessing.Namespace: multiprocessing auxiliaries (*not available after initialisation*)
        self._mpkt = kwargs.pop('mpkit', None)
        #: Info: info dict of current instance
        self._info = Info(self.read_frame())

        # remove temporary multiprocessing support attributes
        [delattr(self, attr) for attr in filter(lambda attr: attr.startswith('_mp'), dir(self))]  # pylint: disable=expression-not-assigned

    def __length_hint__(self):
        """Return an estimated length (16) for the object."""
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
            * If the object is initiated, i.e. :attr:`self._fnum <pcapkit.protocols.pcap.frame.Frame._fnum>`
              exists, returns the frame index number itself;
            * else returns name of the protocol, i.e. ``'Frame'``.

        """
        if self is None:
            return 'Frame'
        if getattr(self, '_fnum', None) is None:
            return self.__class__.__name__
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
            name = name.__index__()
        if isinstance(name, tuple):
            for item in name:
                if item in self._protos:
                    return True
            return False
        return (name in self._info) or (name in self._protos)

    ##########################################################################
    # Utilities.
    ##########################################################################

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

        Arguments:
            proto (LinkType): next layer protocol index
            length (int): valid (*non-padding*) length

        Keyword arguments:
            error (bool): if function called on error

        Returns:
            Protocol: instance of next layer

        This method supports *currently* following protocols:

        +-----------+----------------------------------------------------------------------+
        | ``proto`` | Protocol                                                             |
        +-----------+----------------------------------------------------------------------+
        | 1         | :class:`~pcapkit.protocols.link.ethernet.Ethernet` (data link layer) |
        +-----------+----------------------------------------------------------------------+
        | 228       | :class:`~pcapkit.protocols.internet.ipv4.IPv4` (internet layer)      |
        +-----------+----------------------------------------------------------------------+
        | 229       | :class:`~pcapkit.protocols.internet.ipv6.IPv6` (internet layer)      |
        +-----------+----------------------------------------------------------------------+

        """
        module, name = self.__proto__[proto]
        protocol = getattr(importlib.import_module(module), name)
        next_ = protocol(self._file, length, error=error,
                         layer=self._exlayer, protocol=self._exproto)
        return next_
