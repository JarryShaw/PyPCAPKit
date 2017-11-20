#!/usr/bin/python3
# -*- coding: utf-8 -*-


import datetime


# Frame Header
# Analyser for record/package headers


from .protocol import Info, Protocol


class Frame(Protocol):

    __all__ = ['name', 'info', 'length']

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

    ##########################################################################
    # Data models.
    ##########################################################################

    def __new__(cls, _file, _fnum):
        self = super().__new__(cls, _file)
        return self

    def __init__(self, _file, _fnum):
        self._file = _file
        self._fnum = _fnum
        self._info = Info(self.read_header())

    def __len__(self):
        return 16

    def __length_hint__(self):
        return 16

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
        _temp = self.read_unpack(self._file, 4, _lttl=True)
        if _temp is None:   raise EOFError

        _time = datetime.datetime.fromtimestamp(_temp)
        _tsss = _temp
        _tsus = self.read_unpack(self._file, 4, _lttl=True)
        _ilen = self.read_unpack(self._file, 4, _lttl=True)
        _olen = self.read_unpack(self._file, 4, _lttl=True)

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

        return frame
