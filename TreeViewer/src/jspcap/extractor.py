#!/usr/bin/python3
# -*- coding: utf-8 -*-


import re
import io
import textwrap


# Extractor for PCAP files
# Extract parametres from a PCAP file


from .exceptions import FormatError
from .protocols import Info, Frame, Header


FILE = re.compile(r'''
    \A(.+?)[.](?P<exts>.*)\Z
''', re.VERBOSE | re.IGNORECASE)


class Extractor:
    """Extractor for PCAP files.

    Properties:
        _auto -- bool, if run automatically to the end
        _ifnm -- str, input file name (aka _ifile.name)
        _ofnm -- str, output file name (aka _ofile.name)

        _ifile -- FileIO, input file object
        _ofile -- object, temperory output writer

        _frnum -- int, frame number
        _frame -- list, each item contains `Info` of a record/package
            |--> gbhdr -- Info object, global header
            |--> frame 1 -- Info object, record/package header
            |       |--> Info object, first (link layer) header
            |       |--> Info object, next protocol header
            |       |--> ......
            |       |--> Info object, optional protocol trailer
            |--> frame 2 -- Info object, record/package header
            |       |--> ......

        _gbhdr -- Info object, the global header
        _proto -- str, protocol chain of current frame

    Usage:
        reader = Analyer(fmt='plist', fin='in', fout='out', auto=False, extension=False)

    """

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def info(self):
        return self._vinfo

    @property
    def length(self):
        return self._frnum - 1

    @property
    def format(self):
        return self._ofile.kind

    @property
    def input(self):
        return self._ifnm

    @property
    def output(self):
        return self._ofnm

    @property
    def header(self):
        return self._gbhdr

    @property
    def protocol(self):
        return self._proto

    @property
    def frame(self):
        frame = Info(dict(
            tcp = tuple(self._frame[0]),
            ipv4 = tuple(self._frame[1]),
            ipv6 = tuple(self._frame[2]),
        ))
        return frame

    ##########################################################################
    # Data modules.
    ##########################################################################

    # Not hashable
    __hash__ = None

    def __init__(self, *, fmt=None, fin=None, fout=None, auto=True, extension=True,
                    ipv4_reassembly=False, ipv6_reassembly=False, tcp_reassembly=False):
        """Initialise PCAP Reader.

        Keyword arguemnts:
            fmt  -- str, file format of output
                    <keyword> 'plist' / 'json' / 'tree' / 'html'
            fin  -- str, file name to be read; if file not exist, raise error
            fout -- str, file name to be written

            auto -- bool, if automatically run till EOF (default is True)
                    <keyword> True / False
            extension -- bool, if check and append axtensions to output file (default is True)
                         <keyword> True / False

            ipv4_reassembly -- bool, if record data for IPv4 reassembly (default is False)
                               <keyword> True / False
            ipv6_reassembly -- bool, if record data for IPv6 reassembly (default is False)
                               <keyword> True / False
            tcp_reassembly -- bool, if record data for TCP reassembly (default is False)
                              <keyword> True / False

        """
        ifnm, ofnm, fmt = self.make_name(fin, fout, fmt, extension)

        if fmt == 'plist':
            from jsformat import PLIST as output     # output PLIST file
        elif fmt == 'json':
            from jsformat import JSON as output       # output JSON file
        elif fmt == 'tree':
            from jsformat import Tree as output       # output treeview text file
        elif fmt == 'html':
            from jsformat import JavaScript as output # output JavaScript file
            fmt = 'js'
        elif fmt == 'xml':
            from jsformat import XML as output         # output XML file
        else:
            raise FormatError('Unsupported output format: {}'.format(fmt))

        self._ifnm = ifnm       # input file name
        self._ofnm = ofnm       # output file name

        self._auto = auto                   # auto extract flag
        self._frnum = 1                     # frame number
        self._frame = [[], [], []]          # frame record (TCP / IPv4 / IPv6)
        self._ofile = output(ofnm)          # output file

        self._ipv4 = ipv4_reassembly    # IPv4 Reassembly
        self._ipv6 = ipv6_reassembly    # IPv6 Reassembly
        self._tcp = tcp_reassembly      # TCP Reassembly

        self._ifile = open(ifnm, 'rb')
        self.record_header()        # read PCAP global header
        self.record_frames()        # read frames

    def __iter__(self):
        if self._auto:
            return None
        else:
            return self

    def __next__(self):
        try:
            return self._read_frame()
        except EOFError:
            self._ifile.close()
            raise StopIteration

    def __call__(self):
        if not self._auto:
            try:
                return self._read_frame()
            except EOFError:
                self._ifile.close()
                raise EOFError

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def make_name(cls, fin, fout, fmt, extension):
        fmt_none = (fmt is None)

        if fin is None:
            ifnm = 'in.pcap'
        else:
            ifnm = fin if '.pcap' in fin else '{fin}.pcap'.format(fin=fin)

        if fout is None:
            if fmt_none:
                raise FormatError('Output format unspecified.')
            else:
                if fmt == 'html':   ext = 'js'
                elif fmt == 'tree': ext = 'txt'
                else:               ext = fmt
                ofnm = 'out.{ext}'.format(ext=ext)
        else:
            ofmt = FILE.match(fout)
            if ofmt is None:
                if fmt_none:
                    raise FormatError('Output format unspecified.')
                else:
                    if extension:
                        if fmt == 'html':   ext = 'js'
                        elif fmt == 'tree': ext = 'txt'
                        else:               ext = fmt
                        ofnm = '{out}.{ext}'.format(out=fout, ext=ext)
                    else:
                        ofnm = fout
            else:
                ofnm = fout
                fmt = fmt or ofmt.group('exts')

        return ifnm, ofnm, fmt

    def record_header(self):
        """Read global header.

        - Extract global header.
        - Make Info object out of header properties.
        - Append Info.
        - Write plist file.

        """
        self._gbhdr = Header(self._ifile)
        self._dlink = self._gbhdr.protocol
        self._vinfo = self._gbhdr.info
        self._ofile(self._gbhdr.info.infotodict(), name='Global Header')

    def record_frames(self):
        if self._auto:
            while True:
                try:
                    self._read_frame()
                except EOFError:
                    # quit when EOF
                    break
            self._ifile.close()

    ##########################################################################
    # Methods.
    ##########################################################################

    def _read_frame(self):
        """Read frames.

        - Extract frames and each layer of packets.
        - Make Info object out of frame properties.
        - Append Info.
        - Write plist & append Info.

        """
        # read frame header
        frame = Frame(self._ifile, num=self._frnum, proto=self._dlink)

        # write plist
        frnum = 'Frame {fnum}'.format(fnum=self._frnum)
        plist = frame.info.infotodict()
        self._ofile(plist, name=frnum)

        # record frame
        protos = frame.protochain
        tuple_ = protos.tuple

        if self._tcp:
            self._tcp_reassembly(frame)
        if self._ipv4:
            self._ipv4_reassembly(frame)
        if self._ipv6:
            self._ipv6_reassembly(frame)

        self._frnum += 1
        self._proto = protos.chain

    def _tcp_reassembly(self, frame):
        """Store data for TCP reassembly."""
        if 'TCP' in frame:
            # print(frame.name, '\n', frame.info, '\n')
            # print(frame.name, '\n', frame['TCP'], '\n')
            ip = frame['IPv4'] if 'IPv4' in frame else frame['IPv6']
            tcp = frame['TCP']
            data = dict(
                bufid = (
                    ip.src,         # source ip
                    tcp.srcport,    # source port
                    ip.dst,         # destination ip
                    tcp.dstport,    # destination port
                ),
                tcp = tcp,
                raw = bytearray() if tcp.raw is None else bytearray(tcp.raw),
            )
            len_ = 0 if tcp.raw is None else len(tcp.raw)
            data['first'] = tcp.seq
            data['last'] = tcp.seq + len_
            data['len'] = len_
            info = Info(data)
            self._frame[0].append(info)

    def _ipv4_reassembly(self, frame):
        """Store data for IPv4 reassembly."""
        if 'IPv4' in frame:
            ipv4 = frame['IPv4']
            if ipv4.flags.df:
                return
            data = dict(
                bufid = (
                    ipv4.src,   # source
                    ipv4.dst,   # destination
                    ipv4.proto, # protocol
                    ipv4.id,    # identification
                ),
                ipv4 = ipv4,
                raw = bytearray() if ipv4.raw is None else (ipv4.raw),
                header = bytearray(ipv4.header),
            )
            info = Info(data)
            self._frame[1].append(info)

    def _ipv6_reassembly(self, frame):
        """Store data for IPv6 reassembly."""
        if 'IPv6' in frame:
            ipv6 = frame['IPv6']
            if 'frag' not in ipv6:
                return
            data = dict(
                bufid = (
                    ipv6.src,   # source
                    ipv6.dst,   # destination
                    ipv6.proto, # protocol
                    ipv6.label, # identification
                ),
                ipv6 = ipv6,
                raw = bytearray() if ipv6.raw is None else (ipv6.raw),
                header = bytearray(ipv6.header),
            )
            info = Info(data)
            self._frame[2].append(info)
