#!/usr/bin/python3
# -*- coding: utf-8 -*-


import datetime
import io


# Frame Header
# Analyser for record/package headers


from .protocol import Protocol
from .utilities import Info, ProtoChain


class Frame(Protocol):

    __all__ = ['name', 'info', 'length', 'protochain']

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        return 'Frame {fnum}'.format(fnum=self._fnum)

    @property
    def info(self):
        return self._info

    @property
    def length(self):
        return 16

    @property
    def protochain(self):
        return self._proto

    ##########################################################################
    # Methods.
    ##########################################################################

    def index(self, name):
        return self._proto.index(name)

    ##########################################################################
    # Data models.
    ##########################################################################

    def __new__(cls, _file, *, num, proto):
        self = super().__new__(cls, _file)
        return self

    def __init__(self, _file, *, num, proto):
        self._fnum = num
        self._prot = proto
        self._file = _file
        self._info = Info(self.read_header())

    def __len__(self):
        return 16

    def __length_hint__(self):
        return 16

    def __getitem__(self, key):
        if key in self._info:
            return self._info[key]

        proto = self._proto[key]

        if not proto:
            raise IndexError
        elif isinstance(proto, tuple):
            if len(proto) > 1:
                raise TypeError
            else:
                start = proto[0]
        else:
            start = self._proto.index(proto)

        dict_ = self._info.infotodict()
        for (level, proto) in enumerate(self._proto.tuple):
            proto = proto or 'raw'
            dict_ = dict_[proto.lower()]
            if level >= start:
                break

        return Info(dict_)

    def __index__(self, name):
        return self._proto.index(name)

    def __contains__(self, name):
        return any(((name in self._info), (name in self._proto)))

    ##########################################################################
    # Utilities.
    ##########################################################################

    def read_header(self):
        """Read each block after global header.

        Keyword arguments:
            _file -- file object

        Structure of record/package header (C):
            typedef struct pcaprec_hdr_s {
            guint32 ts_sec;     /* timestamp seconds */
            guint32 ts_usec;    /* timestamp microseconds */
            guint32 incl_len;   /* number of octets of packet saved in file */
            guint32 orig_len;   /* actual length of packet */
            } pcaprec_hdr_t;

        """
        _temp = self._read_unpack(4, lilendian=True)
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
            time_epoch = '{ts_sec}.{ts_usec} seconds'.format(ts_sec=_tsss, ts_usec=_tsus),
            len = _ilen,
            cap_len = _olen,
        )

        length = frame['cap_len']
        return self._read_next_layer(frame, length)

    def _read_next_layer(self, dict_, length=None):
        # make next layer protocol name
        proto = self._prot or ''
        name_ = proto.lower() or 'raw'

        # make BytesIO from frame package data
        bytes_ = io.BytesIO(self._file.read(dict_['len']))
        next_ = self._import_next_layer(bytes_, length)

        # write info and protocol chain into dict
        self._proto = ProtoChain(self._prot, next_[1])
        dict_[name_] = next_[0]
        dict_['protocols'] = self._proto.chain
        return dict_

    def _import_next_layer(self, file_, length):
        if self._prot == 'Ethernet':
            from .link import Ethernet as Protocol
        elif self._prot == 'IPv4':
            from .internet import IPv4 as Protocol
        elif self._prot == 'IPv6':
            from .internet import IPv6 as Protocol
        else:
            data = file_.read(*[length]) or None
            return data, None
        next_ = Protocol(file_, length)
        return next_.info, next_.protochain
