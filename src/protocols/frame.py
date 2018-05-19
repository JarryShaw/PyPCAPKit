# -*- coding: utf-8 -*-
"""frame header

`jspcap.protocols.frame` contains `Frame` only,
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


# Frame Header
# Analyser for record/package headers


from jspcap.exceptions import ProtocolNotFound, ProtocolUnbound
from jspcap.utilities import beholder, Info, ProtoChain
from jspcap.protocols.protocol import Protocol


__all__ = ['Frame']


class Frame(Protocol):
    """Per packet frame header extractor.

    Properties:
        * name -- str, name of corresponding procotol
        * info -- Info, info dict of current instance
        * alias -- str, acronym of corresponding procotol
        * length -- int, header length of corresponding protocol
        * protocol -- str, name of next layer protocol
        * protochain -- ProtoChain, protocol chain of current frame

    Methods:
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
        """Name of corresponding procotol."""
        return f'Frame {self._fnum}'

    @property
    def length(self):
        """Header length of corresponding protocol."""
        return 16

    ##########################################################################
    # Methods.
    ##########################################################################

    def index(self, name):
        return self._proto.index(name)

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
        _temp = self._read_unpack(4, lilendian=True, quiet=True)
        if _temp is None:   raise EOFError

        _time = datetime.datetime.fromtimestamp(_temp)
        _tsss = _temp
        _tsus = self._read_unpack(4, lilendian=True)
        _ilen = self._read_unpack(4, lilendian=True)
        _olen = self._read_unpack(4, lilendian=True)

        frame = dict(
            frame_info = dict(
                ts_sec = _tsss,
                ts_usec = _tsus,
                incl_len = _ilen,
                orig_len = _olen,
            ),
            time = _time,
            number = self._fnum,
            time_epoch = f'{_tsss}.{_tsus} seconds',
            len = _ilen,
            cap_len = _olen,
        )

        length = frame['cap_len']
        frame['packet'] = self._read_packet(header=16, payload=length, discard=True)

        return self._decode_next_layer(frame, length)

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, file, *, num, proto):
        self._fnum = num
        self._prot = proto
        self._file = file
        self._info = Info(self.read_frame())

    def __length_hint__(self):
        return 16

    def __getitem__(self, key):
        if isinstance(key, type) and issubclass(key, Protocol):
            key = key.__index__()

        # if requests attributes in info dict
        if key in self._info:
            return self._info[key]

        def _getitem_from_ProtoChain(key):
            proto = self._protos[key]
            if not proto:
                raise ProtocolNotFound('ProtoChain index out of range')
            elif isinstance(proto, tuple):
                if len(proto) > 1:  # if it's a slice with step & stop
                    raise ProtocolUnbound('frame slice unbound')
                else:
                    start = proto[0]
            else:
                start = self._protos.index(proto)
            return start

        # fetch slice start point from ProtoChain
        if not isinstance(key, tuple):
            key = (key,)
        start = None
        for item in key:
            try:
                start = _getitem_from_ProtoChain(item)
            except ProtocolNotFound:
                continue
            else:
                break
        if start is None:
            raise IndexNotFound(f"'{key}' not in Frame")

        # make return Info item
        dict_ = self._info.infotodict()
        for (level, proto) in enumerate(self._protos):
            proto = proto or 'raw'
            dict_ = dict_[proto.lower()]
            if level >= start:
                return Info(dict_)
        return Info(dict_)

    def __index__(self):
        return self._fnum

    def __contains__(self, name):
        if isinstance(name, type) and issubclass(name, Protocol):
            name = name.__index__()
        if isinstance(name, tuple):
            for item in name:
                flag = (item in self._protos)
                if flag:    break
            return flag
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
        # make BytesIO from frame package data
        bytes_ = io.BytesIO(self._file.read(dict_['len']))
        flag, info, chain, alias = self._import_next_layer(bytes_, length)

        # make next layer protocol name
        if flag:
            proto, name = str(self._prot or 'Raw').lower(), self._prot
        else:
            proto, name = 'raw', 'Raw'

        # write info and protocol chain into dict
        self._protos = ProtoChain(name, chain, alias)
        dict_[proto] = info
        dict_['protocols'] = self._protos.chain
        return dict_

    @beholder
    def _import_next_layer(self, file, length):
        """Import next layer extractor.

        Positional arguments:
            * file -- BytesIO, packet bytes I/O object
            * length -- int, valid (not padding) length

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
        if self._prot == 'Ethernet':
            from jspcap.protocols.link import Ethernet as Protocol
        elif self._prot == 'IPv4':
            from jspcap.protocols.internet import IPv4 as Protocol
        elif self._prot == 'IPv6':
            from jspcap.protocols.internet import IPv6 as Protocol
        else:
            from jspcap.protocols.raw import Raw as Protocol
        next_ = Protocol(file, length)
        return True, next_.info, next_.protochain, next_.alias
