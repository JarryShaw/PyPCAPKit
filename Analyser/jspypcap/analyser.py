#!/usr/bin/python3
# -*- coding: utf-8 -*-


import io
import pprint


# Analyser for PCAP files
# Extract parametres from a PCAP file


from jsplist import Writer

from frame import Frame
from header import Header
from protocol import Info


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
        self._frnum = 1                     # frame number
        self._plist = Writer('tmp.plist')   # temp PLIST file
        with open(fname, 'rb') as _file:
            self.record_header(_file)    # read PCAP global header
            self.record_frames(_file)    # read frames

    def record_header(self, _file):
        self._gbhdr = Header(_file)
        self._dlink = self._gbhdr.protocol
        self._tzone = self._gbhdr.info.thiszone
        self._plist(self._gbhdr.info.infotodict(), _name='Global Header')

    def record_frames(self, _file):
        self._frame = []
        while True:
            try:
                print('Frame', self._frnum)

                # read frame header
                frame = Frame(_file, self._frnum)
                plist = frame.info.infotodict()

                # pprint.pprint(plist)

                # make BytesIO from frame package data
                length = frame.info.len - frame.length
                print(length+16)
                bytes_ = io.BytesIO(_file.read(length))

                # read link layer
                dlink = self._link_layer(bytes_, length)

                # check link layer protocol
                if not dlink[0]:
                    plist['Link Layer'] = dlink[1]
                    self._dlink = 'Unknown'
                    self._netwk = 'Unknown'
                    self._trans = 'Unknown'
                    self._write_record(plist)
                    continue
                else:
                    plist[self._dlink] = dlink[1].info.infotodict()
                    self._netwk = dlink[1].protocol
                    length -= dlink[1].length

                # pprint.pprint(plist)

                # read internet layer
                netwk = self._internet_layer(bytes_, length)

                # check internet layer protocol
                if not netwk[0]:
                    plist[self._dlink]['Network Layer'] = netwk[1]
                    self._netwk = 'Unknown'
                    self._trans = 'Unknown'
                    self._write_record(plist)
                    continue
                else:
                    plist[self._dlink][self._netwk] = netwk[1].info.infotodict()
                    self._trans = netwk[1].protocol
                    length -= netwk[1].length

                # pprint.pprint(plist)

                # read transport layer
                trans = self._transport_layer(bytes_, length)

                # check transport layer protocol
                if not netwk[0]:
                    plist[self._dlink][self._netwk]['Transport Layer'] = trans[1]
                    self._trans = 'Unknown'
                    self._write_record(plist)
                    continue
                else:
                    plist[self._dlink][self._netwk][self._trans] = trans[1].info.infotodict()
                    length -= trans[1].length

                # pprint.pprint(plist)

                # read application layer
                applc = self._application_layer(bytes_, length)

                # check application layer protocol
                plist[self._dlink][self._netwk][self._trans]['Application Layer'] = applc[1]

                # pprint.pprint(plist)

                self._write_record(plist)

            except EOFError:
                break

    def _write_record(self, plist):
        # write plist
        plist['protocols'] = ':'.join((self._dlink, self._netwk, self._trans))
        _fnum = 'Frame {fnum}'.format(fnum=self._frnum)

        print(plist['protocols'])
        pprint.pprint(plist)
        self._plist(plist, _name=_fnum)

        # record frame
        info = Info(plist)
        self._frame.append(info)
        self._frnum += 1

    def _link_layer(self, _file, length):
        if self._dlink == 'Ethernet':
            from link import ethernet
            return True, ethernet.Ethernet(_file)
        else:
            # raise NotImplementedError
            return False, _file.read(length)

    def _internet_layer(self, _file, length):
        if self._netwk == 'IPv4':
            from internet import ipv4
            return True, ipv4.IPv4(_file)
        else:
            # raise NotImplementedError
            return False, _file.read(length)

    def _transport_layer(self, _file, length):
        if self._trans == 'TCP':
            from transport import tcp
            return True, tcp.TCP(_file)
        elif self._trans == 'UDP':
            from transport import udp
            return True, udp.UDP(_file)
        else:
            # raise NotImplementedError
            return False, _file.read(length)

    def _application_layer(self, _file, length):
        return False, _file.read(length)


if __name__ == '__main__':
    a = Analyser('a.pcap')
