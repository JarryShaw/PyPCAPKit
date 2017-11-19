#!/usr/bin/python3
# -*- coding: utf-8 -*-


import io
import textwrap


# Analyser for PCAP files
# Extract parametres from a PCAP file


from frame import Frame
from header import Header
from protocol import Info


class Analyser:
    """Analyser for PCAP files.

    Properties:
        _frame -- int, frame number
        _ofile -- object, temperory output writer

        _dlink -- str, data link layer protocol
        _netwk -- str, network layer protocol
        _trans -- str, transport layer protocol
        _applc -- str, application layer protocol

        _frame -- list, each item contains `Info` of a record/package
            |--> gbhdr -- Info object, global header
            |--> frame -- Info object, record/package header
                    |--> dlink -- Info object, link layer header
                    |--> netwk -- Info object, internet layer header
                    |--> trans -- Info object, transport layer header
                    |--> applc -- Info object, application layer datagram

    Usage:
        reader = Reader('sample.pcap')

    """

    @property
    def info(self):
        return self._frame

    def __init__(self, *, fmt, fin=None, fout=None):
        """Initialise PCAP Reader.

        Keyword arguemnts:
            fmt  -- str, file format of output
                    <keyword> 'plist' / 'json'
            fin  -- str, file name to be read; if file not exist, raise error
            fout -- str, file name to be written

        """
        self._frnum = 1                     # frame number
        self._frame = []                    # frame record

        if fin is None:
            fin = 'in.pcap'
        ifnm = fin

        if fout is None:
            fout = 'out'
        ofnm = '{fout}.{fmt}'.format(fout=fout, fmt=fmt)

        if fmt == 'json':
            from json import JSON
            self._ofile = JSON(ofnm)    # output JSON file
        elif fmt == 'plist':
            from plist import PLIST
            self._ofile = PLIST(ofnm)   # output PLIST file
        else:
            raise KeyError

        with open(ifnm, 'rb') as _ifile:
            self.record_header(_ifile)      # read PCAP global header
            self.record_frames(_ifile)      # read frames

    def record_header(self, _ifile):
        """Read global header.

        - Extract global header.
        - Make Info object out of header properties.
        - Append Info.
        - Write plist file.

        Keyword arguments:
            _ifile -- file object

        """
        self._gbhdr = Header(_ifile)
        self._dlink = self._gbhdr.protocol
        self._frame.append(self._gbhdr.info)
        self._ofile(self._gbhdr.info.infotodict(), _name='Global Header')

    def record_frames(self, _ifile):
        """Read frames.

        - Extract frames and each layer of packets.
        - Make Info object out of frame properties.
        - Append Info.
        - Write plist file.

        Keyword arguments:
            _ifile -- file object

        """
        while True:
            self._netwk = 'Unknown'
            self._trans = 'Unknown'
            self._applc = 'Unknown'
            try:
                # read frame header
                frame = Frame(_ifile, self._frnum)
                plist = frame.info.infotodict()

                # make BytesIO from frame package data
                length = frame.info.len
                bytes_ = io.BytesIO(_ifile.read(length))

                # read link layer
                dlink = self._link_layer(bytes_, length)

                # check link layer protocol
                if not dlink[0]:
                    plist['Link Layer'] = dlink[1]
                    self._write_record(plist)
                    continue
                else:
                    plist[self._dlink] = dlink[1].info.infotodict()
                    self._netwk = dlink[1].protocol
                    length -= dlink[1].length

                # read internet layer
                netwk = self._internet_layer(bytes_, length)

                # check internet layer protocol
                if not netwk[0]:
                    plist[self._dlink]['Network Layer'] = netwk[1]
                    self._write_record(plist)
                    continue
                else:
                    plist[self._dlink][self._netwk] = netwk[1].info.infotodict()
                    self._trans = netwk[1].protocol
                    length -= netwk[1].length

                # read transport layer
                trans = self._transport_layer(bytes_, length)

                # check transport layer protocol
                if not trans[0]:
                    plist[self._dlink][self._netwk]['Transport Layer'] = trans[1]
                    self._write_record(plist)
                    continue
                else:
                    plist[self._dlink][self._netwk][self._trans] = trans[1].info.infotodict()
                    length -= trans[1].length

                # read application layer
                applc = self._application_layer(bytes_, length)

                # check application layer protocol
                plist[self._dlink][self._netwk][self._trans]['Application Layer'] = applc[1]
                self._write_record(plist)
            except EOFError:
                # quit when EOF
                break

    def _write_record(self, plist):
        """Write plist & append Info."""
        # write plist
        _fnum = 'Frame {fnum}'.format(fnum=self._frnum)
        plist['protocols'] = self._merge_protocols()
        self._ofile(plist, _name=_fnum)

        print(_fnum)
        print(plist['protocols'])
        print()

        # record frame
        self._frnum += 1
        info = Info(plist)
        self._frame.append(info)

    def _merge_protocols(self):
        """Make protocols chain."""
        list_ = [self._dlink, self._netwk, self._trans, self._applc]
        for (i, proto) in enumerate(list_):
            if proto == 'Unknown':
                return ':'.join(list_[:i])
        return ':'.join(list_)

    def _link_layer(self, _ifile, length):
        """Read link layer."""
        if self._dlink == 'Ethernet':
            from link import ethernet
            return True, ethernet.Ethernet(_ifile)
        else:
            # raise NotImplementedError
            return False, _ifile.read(length)

    def _internet_layer(self, _ifile, length):
        """Read internet layer."""
        if self._netwk == 'IPv4':
            from internet import ipv4
            return True, ipv4.IPv4(_ifile)
        else:
            # raise NotImplementedError
            return False, _ifile.read(length)

    def _transport_layer(self, _ifile, length):
        """Read transport layer."""
        if self._trans == 'TCP':
            from transport import tcp
            return True, tcp.TCP(_ifile)
        elif self._trans == 'UDP':
            from transport import udp
            return True, udp.UDP(_ifile)
        else:
            # raise NotImplementedError
            return False, _ifile.read(length)

    def _application_layer(self, _ifile, length):
        """Read application layer."""
        return False, _ifile.read(length)


if __name__ == '__main__':
    a = Analyser(fmt='json')
