# -*- coding: utf-8 -*-
"""frame header

`pcapkit.protocols.pcap.frame` contains `Frame` only,
which implements extractor for frame headers of PCAP,
whose structure is described as below.

typedef struct pcaprec_hdr_s {
    guint32 ts_sec;     /* timestamp seconds */
    guint32 ts_usec;    /* timestamp microseconds */
    guint32 incl_len;   /* number of octets of packet saved in file */
    guint32 orig_len;   /* actual length of packet */
} pcaprec_hdr_t;

"""
import datetime
import io
import os

from pcapkit.corekit.infoclass import Info
from pcapkit.protocols.protocol import Protocol
from pcapkit.utilities.decorators import beholder

###############################################################################
# from pcapkit.protocols.link import Ethernet
# from pcapkit.protocols.internet import IPv4
# from pcapkit.protocols.internet import IPv6
# from pcapkit.protocols.raw import Raw
###############################################################################

__all__ = ['Frame']


class Frame(Protocol):
    """Per packet frame header extractor.

    Properties:
        * name -- str, name of corresponding protocol
        * info -- Info, info dict of current instance
        * alias -- str, acronym of corresponding protocol
        * length -- int, header length of corresponding protocol
        * protocol -- str, name of next layer protocol
        * protochain -- ProtoChain, protocol chain of current frame

    Methods:
        * decode_bytes -- try to decode bytes into str
        * decode_url -- decode URLs into Unicode
        * index -- call `ProtoChain.index`
        * read_frame -- read each block after global header

    Attributes:
        * _file -- BytesIO, bytes to be extracted
        * _info -- Info, info dict of current instance
        * _protos -- ProtoChain, protocol chain of current instance

    Utilities:
        * _read_protos -- read next layer protocol type
        * _read_fileng -- read file buffer
        * _read_unpack -- read bytes and unpack to integers
        * _read_binary -- read bytes and convert into binaries
        * _read_packet -- read raw packet data
        * _decode_next_layer -- decode next layer protocol type
        * _import_next_layer -- import next layer protocol extractor

    """
    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        """Name of corresponding protocol."""
        return 'Frame {}'.format(self._fnum)

    @property
    def length(self):
        """Header length of corresponding protocol."""
        return 16

    ##########################################################################
    # Methods.
    ##########################################################################

    def index(self, name):
        return self._protos.index(name)

    def read_frame(self):
        """Read each block after global header.

        Structure of record/package header (C):
            typedef struct pcaprec_hdr_s {
                guint32 ts_sec;     /* timestamp seconds */
                guint32 ts_usec;    /* timestamp microseconds */
                guint32 incl_len;   /* number of octets of packet saved in file */
                guint32 orig_len;   /* actual length of packet */
            } pcaprec_hdr_t;

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
            _epch = _tsss + _tsus / 1_000_000_000
        else:
            _epch = _tsss + _tsus / 1_000_000
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

    def __init__(self, file, *, num, proto, nanosecond, **kwargs):
        self._fnum = num
        self._file = file
        self._prot = proto
        self._nsec = nanosecond
        self._mpfp = kwargs.pop('mpfdp', None)
        self._mpkt = kwargs.pop('mpkit', None)
        self._info = Info(self.read_frame())
        [delattr(self, attr) for attr in filter(lambda attr: attr.startswith('_mp'), dir(self))]

    def __length_hint__(self):
        return 16

    def __getitem__(self, key):
        # if requests attributes in info dict,
        # else call the original function
        try:
            return self._info[key]
        except KeyError:
            return super().__getitem__(key)

        # def _getitem_from_ProtoChain(key):
        #     proto = self._protos[key]
        #     if not proto:
        #         raise ProtocolNotFound('ProtoChain index out of range')
        #     elif isinstance(proto, tuple):
        #         if len(proto) > 1:  # if it's a slice with step & stop
        #             raise ProtocolUnbound('frame slice unbound')
        #         else:
        #             start = proto[0]
        #     else:
        #         start = self._protos.index(proto)
        #     return start
        #
        # # fetch slice start point from ProtoChain
        # if not isinstance(key, tuple):
        #     key = (key,)
        # start = None
        # for item in key:
        #     try:
        #         start = _getitem_from_ProtoChain(item)
        #     except ProtocolNotFound:
        #         continue
        #     else:
        #         break
        # if start is None:
        #     raise IndexNotFound(f"'{key}' not in Frame")
        #
        # # make return Info item
        # dict_ = self._info.info2dict()
        # for (level, proto) in enumerate(self._protos):
        #     proto = proto or 'raw'
        #     dict_ = dict_[proto.lower()]
        #     if level >= start:
        #         return Info(dict_)
        # return Info(dict_)

    def __index__(self=None):
        if self is None:
            return 'Frame'
        if getattr(self, '_fnum', None) is None:
            return self.__class__.__name__
        return self._fnum

    def __contains__(self, name):
        if isinstance(name, type) and issubclass(name, Protocol):
            name = name.__index__()
        if isinstance(name, tuple):
            for item in name:
                if item in self._protos:
                    return True
            return False
        return ((name in self._info) or (name in self._protos))

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _decode_next_layer(self, dict_, length=None):
        """Decode next layer protocol.

        Positional arguments:
            dict_ -- dict, info buffer
            proto -- str, next layer protocol name
            length -- int, valid (not padding) length

        Returns:
            * dict -- current protocol with packet extracted

        """
        seek_cur = self._file.tell()
        try:
            next_ = self._import_next_layer(self._prot, length)
        except Exception as error:
            dict_['error'] = str(error)
            self._file.seek(seek_cur, os.SEEK_SET)
            next_ = beholder(self._import_next_layer)(self, self._prot, length, error=True)
        info, chain = next_.info, next_.protochain

        # make next layer protocol name
        layer = next_.alias.lower()
        # proto = next_.__class__.__name__

        # write info and protocol chain into dict
        self._next = next_
        self._protos = chain
        dict_[layer] = info
        dict_['protocols'] = self._protos.chain
        return dict_

    def _import_next_layer(self, proto, length, error=False):
        """Import next layer extractor.

        Positional arguments:
            * proto -- str, next layer protocol name
            * length -- int, valid (not padding) length

        Keyword arguments:
            * error -- bool, if function call on error

        Returns:
            * bool -- flag if extraction of next layer succeeded
            * Info -- info of next layer
            * ProtoChain -- protocol chain of next layer
            * str -- alias of next layer

        Protocols:
            * Ethernet (data link layer)
            * IPv4 (internet layer)
            * IPv6 (internet layer)

        """
        if proto == 1:
            from pcapkit.protocols.link import Ethernet as Protocol
        elif proto == 228:
            from pcapkit.protocols.internet import IPv4 as Protocol
        elif proto == 229:
            from pcapkit.protocols.internet import IPv6 as Protocol
        else:
            from pcapkit.protocols.raw import Raw as Protocol
        next_ = Protocol(self._file, length, error=error,
                         layer=self._exlayer, protocol=self._exproto)
        return next_
