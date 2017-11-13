#!/usr/bin/python3
# -*- coding: utf-8 -*-


import io


# Analyser for PCAP files
# Extract parametres from a PCAP file


from jsplist import Writer

from frame import Frame
from header import Header


class Analyser:
    """Analyser for PCAP files.

    Properties:
        _frame -- int, frame number
        _plist -- object, temperory output writer

        _dlink -- str, data link layer protocol
        _netwk -- str, network layer protocol
        _trans -- str, transport layer protocol
        _applc -- str, application layer protocol

        _dleng -- int, length of data that ip contains
        _tzone -- int, timezone offset in seconds

        _gbhdr -- object, global header
        _frame -- list, each item contains a tuple of record/package
            |--> frame -- object, record/package header
            |--> dlink -- object, link layer header
            |--> netwk -- object, internet layer header
            |--> trans -- object, transport layer header
            |--> applc -- object, application layer datagram

    Usage:
        reader = Reader('sample.pcap')

    """

    def __init__(self, fname=None):
        """Initialise PCAP Reader.

        Keyword arguemnts:
            fname -- str, file name to be read; if file not exist, raise error

        """
        self._frame = 1                     # frame number
        self._plist = Writer('tmp.plist')   # temp PLIST file
        with open(fname, 'rb') as _file:
            self.record_header(_file)    # read PCAP global header
            self.record_frames(_file)    # read frames

    def record_header(self, _file):
        self._gbhdr = Header(_file)
        self._tzone = self._gbhdr._dict['thiszone']
        self._dlink = self._gbhdr._dict['network']
        self._plist(self._gbhdr._dict, _name='Global Header')

    def record_frames(self, _file):
        self._frame = []
        while True:
            try:
                _frame = Frame(_file, self._frame)

                length = _frame.length - len(_frame)
                bytes_ = io.BytesIO(_file.read(length))
                _dlink = self._link_layer(bytes_)

                length = length - len(_dlink)
                bytes_ = io.BytesIO(bytes_.read(length))
                _netwk = self._internet_layer(bytes_)

                length = length - len(_netwk)
                bytes_ = io.BytesIO(bytes_.read(length))
                _trans = self._transport_layer(bytes_)

                length = length - len(_trans)
                bytes_ = io.BytesIO(bytes_.read(length))
                _applc = self._application_layer(bytes_)

                frame = (_frame, _dlink, _netwk, _trans, _applc)
                self._frame.append(frame)
                self._frame_plist(frame)
            except EOFError:
                break

    def _frame_plist(self, tuple_):
        applc = tuple_[4]

        trans = tuple_[3]._dict
        trans['Application Layer'] = applc

        netwk = tuple_[2]._dict
        netwk[self._trans] = trans

        dlink = tuple_[1]._dict
        dlink[self._netwk] = netwk

        frame = tuple_[0]._dict
        frame[self._dlink] = dlink

        frame['protocols'] = '{link}:{internet}:{transport}'.format(
            link=self._dlink, internet=self._netwk, transport=self._trans
        )
        _fnum = 'Frame {fnum}'.format(fnum=self._frame)

        self._frame += 1
        self._plist(frame, _name=_fnum)

    def _link_layer(self, _file):
        if self._dlink == 'Ethernet':
            from link import ethernet
            return ethernet.Ethernet(_file)
        else:
            raise NotImplementedError

    def _internet_layer(self, _file):
        if self._netwk == 'IPv4':
            from internet import ipv4
            return ipv4.IPv4(_file)
        else:
            raise NotImplementedError

    def _transport_layer(self, _file):
        if self._trans == 'TCP':
            from transport import tcp
            return tcp.TCP(_file)
        elif self._trans == 'UDP':
            from transport import udp
            return udp.UDP(_file)
        else:
            raise NotImplementedError

    def _application_layer(self, _file):
        return _file.read()


if __name__ == '__main__':
    a = Analyser('a.pcap')
