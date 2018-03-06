#!/usr/bin/python3
# -*- coding: utf-8 -*-


import io
import os
import pathlib
import re
import textwrap


# Extractor for PCAP files
# Extract parametres from a PCAP file


from jspcap.exceptions import FormatError, FileNotFound
from jspcap.protocols import Frame, Header
from jspcap.utilities import Info
from jspcap.validations import bool_check, str_check


__all__ = ['Extractor']


# file name match regex
FILE = re.compile(r'''
    \A(.+?)[.](?P<ext>.*)\Z
''', re.VERBOSE | re.IGNORECASE)


class Extractor:
    """Extractor for PCAP files.

    Properties:
        * info -- VerionInfo, version of input PCAP file
        * length -- int, frame number (of current extracted frame or all)
        * format -- str, format of output file
        * input -- str, name of input PCAP file
        * output -- str, name of output file
        * header -- Info, global header
        * protocol -- ProtoChain, protocol chain of current/last frame
        * frame -- Info, frame record for reassembly
            |--> tcp -- tuple, TCP payload fragments
            |--> ipv4 -- tuple, IPv4 frame fragments
            |--> ipv6 -- tuple, IPv6 frame fragments

    Methods:
        * make_name -- formatting input & output file name
        * record_header -- extract global header
        * record_frames -- extract frames

    Attributes:
        * _auto -- bool, if run automatically to the end
        * _ifnm -- str, input file name (aka _ifile.name)
        * _ofnm -- str, output file name (aka _ofile.name)
        * _fext -- str, output file extension

        * _ifile -- FileIO, input file object
        * _ofile -- object, temperory output writer

        * _frnum -- int, frame number
        * _frame -- list, each item contains `Info` of a record/package
            |--> gbhdr -- Info object, global header
            |--> frame 1 -- Info object, record/package header
            |       |--> Info object, first (link layer) header
            |       |--> Info object, next protocol header
            |       |--> ......
            |       |--> Info object, optional protocol trailer
            |--> frame 2 -- Info object, record/package header
            |       |--> ......

        * _gbhdr -- Info object, the global header
        * _dlink -- str, data link layer protocol of input file
        * _vinfo -- VersionInfo, version of input file
        * _proto -- str, protocol chain of current frame

        * _ip -- bool, flag if perform IPv4 & IPv6 reassembly
        * _ipv4 -- bool, flag if perform IPv4 reassembly
        * _ipv6 -- bool, flag if perform IPv6 reassembly
        * _tcp -- bool, flag if perform TCP payload reassembly

    Utilities:
        * _read_frame -- read frames
        * _tcp_reassembly -- store data for TCP reassembly
        * _ipv4_reassembly -- store data for IPv4 reassembly
        * _ipv6_reassembly -- store data for IPv6 reassembly

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
        frame = Info(
            tcp = tuple(self._frame[0]),
            ipv4 = tuple(self._frame[1]),
            ipv6 = tuple(self._frame[2]),
        )
        return frame

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def make_name(cls, fin, fout, fmt, extension, *, files=False):
        fmt_none = (fmt is None)
        if not fmt_none:
            str_check(fmt)

        if fin is None:
            ifnm = 'in.pcap'
        else:
            str_check(fin)
            ifnm = fin if '.pcap' in fin else f'{fin}.pcap'

        if not os.path.isfile(ifnm):
            raise FileNotFound(f"[Errno 2] No such file or directory: '{ifnm}'")

        if fmt == 'html':
            ext = 'js'
        elif fmt == 'tree':
            ext = 'txt'
        else:
            ext = fmt

        if fout is None:
            if fmt_none:
                raise FormatError('Output format unspecified.')
            elif files:
                ofnm = 'out'
                pathlib.Path(ofnm).mkdir(parents=True, exist_ok=True)
            else:
                ofnm = f'out.{ext}'
        else:
            str_check(fout)
            path, name = os.path.split(fout)
            ofmt = FILE.match(name)
            if ofmt is None:
                if fmt_none:
                    raise FormatError('Output format unspecified.')
                elif files:
                    ofnm = fout
                    pathlib.Path(ofnm).mkdir(parents=True, exist_ok=True)
                else:
                    if extension:
                        ofnm = f'{fout}.{ext}'
                    else:
                        ofnm = fout
            else:
                files = False
                ofnm = fout
                fmt = fmt or ofmt.group('ext')
                if fmt is None:
                    raise FormatError('Output format unspecified.')

        return ifnm, ofnm, fmt, ext, files

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
        if self._flag_f:
            ofile = self._ofile(f'{self._ofnm}/Global Header.{self._fext}')
            ofile(self._gbhdr.info, name='Global Header')
        else:
            self._ofile(self._gbhdr.info, name='Global Header')

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
    # Data modules.
    ##########################################################################

    # Not hashable
    __hash__ = None

    def __init__(self, *, fin=None, fout=None, format=None, auto=True, files=False,
                    extension=True, ip=False, ipv4=False, ipv6=False, tcp=False, verbose=False):
        """Initialise PCAP Reader.

        Keyword arguments:
            fin  -- str, file name to be read; if file not exist, raise error
            fout -- str, file name to be written
            format  -- str, file format of output
                    <keyword> 'plist' / 'json' / 'tree' / 'html'

            auto -- bool, if automatically run till EOF (default is True)
                    <keyword> True / False
            extension -- bool, if check and append axtensions to output file (default is True)
                         <keyword> True / False

            files -- bool, if split each frame into different files (default is False)
                        <keyword> True / False
            verbose -- bool, if print verbose output information (default is True)
                        <keyword> True / False

            ip -- bool, if record data for IPv4 & IPv6 reassembly (default is False)
                    <keyword> True / False
            ipv4 -- bool, if record data for IPv4 reassembly (default is False)
                    <keyword> True / False
            ipv6 -- bool, if record data for IPv6 reassembly (default is False)
                    <keyword> True / False
            tcp -- bool, if record data for TCP reassembly (default is False)
                    <keyword> True / False

        """
        bool_check(ip, ipv4, ipv6, tcp, auto, files, extension, verbose)
        ifnm, ofnm, fmt, ext, files = self.make_name(fin, fout, format, extension, files=files)

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
            raise FormatError(f'Unsupported output format: {fmt}')

        self._ifnm = ifnm               # input file name
        self._ofnm = ofnm               # output file name
        self._fext = ext                # output file extension

        self._flag_f = files            # split file flag
        self._flag_v = verbose          # verbose output flag

        self._auto = auto               # auto extract flag
        self._frnum = 1                 # frame number
        self._frame = [[], [], []]      # frame record (TCP / IPv4 / IPv6)

        self._ipv4 = ipv4 or ip         # IPv4 Reassembly
        self._ipv6 = ipv6 or ip         # IPv6 Reassembly
        self._tcp = tcp                 # TCP Reassembly

        self._ifile = open(ifnm, 'rb')  # input file
        self._ofile = output if self._flag_f else output(ofnm)
                                        # output file

        self.record_header()            # read PCAP global header
        self.record_frames()            # read frames

    def __iter__(self):
        if self._auto:
            raise TypeError("'Extractor_auto' object is not iterable")
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
            except EOFError as error:
                self._ifile.close()
                raise error

    ##########################################################################
    # Utilities.
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
        if self._flag_v:
            print(f' - Frame {self._frnum:>3d}: {frame.protochain}')

        # write plist
        frnum = f'Frame {self._frnum}'
        if self._flag_f:
            ofile = self._ofile(f'{self._ofnm}/{frnum}.{self._fext}')
            ofile(frame.info, name=frnum)
        else:
            self._ofile(frame.info, name=frnum)

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
            ip = frame['IPv4'] if 'IPv4' in frame else frame['IPv6']
            tcp = frame['TCP']
            data = dict(
                bufid = (
                    ip.src,                             # source IP address
                    ip.dst,                             # destination IP address
                    tcp.srcport,                        # source port
                    tcp.dstport,                        # destination port
                ),
                num = frame.info.number,                # original packet range number
                ack = tcp.ack,                          # acknowledgement
                dsn = tcp.seq,                          # data sequence number
                syn = tcp.flags.syn,                    # synchronise flag
                fin = tcp.flags.fin,                    # finish flag
                payload = bytearray(tcp.raw or b''),    # raw bytearray type payload
           )
            raw_len = len(tcp.raw or b'')
            data['first'] = tcp.seq                     # this sequence number
            data['last'] = tcp.seq + raw_len            # next (wanted) sequence number
            data['len'] = raw_len                       # payload length, header excludes
            self._frame[0].append(data)

    def _ipv4_reassembly(self, frame):
        """Store data for IPv4 reassembly."""
        if 'IPv4' in frame:
            ipv4 = frame['IPv4']
            if ipv4.flags.df:
                return
            data = dict(
                bufid = (
                    ipv4.src,                           # source IP address
                    ipv4.dst,                           # destination IP address
                    ipv4.id,                            # identification
                    ipv4.proto,                         # payload protocol type
                    ),
                num = frame.info.number,                # original packet range number
                fo = ipv4.frag_offset,                  # fragment offset
                ihl = ipv4.hdr_len,                     # internet header length
                mf = ipv4.flags.mf,                     # more fragment flag
                tl = ipv4.len,                          # total length, header includes
                header = bytearray(ipv4.header),        # raw bytearray type header
                payload = bytearray(ipv4.raw or b''),   # raw bytearray type payload
            )
            self._frame[1].append(data)

    def _ipv6_reassembly(self, frame):
        """Store data for IPv6 reassembly."""
        if 'IPv6' in frame:
            ipv6 = frame['IPv6']
            if 'frag' not in ipv6:
                return
            data = dict(
                bufid = (
                    ipv6.src,                           # source IP address
                    ipv6.dst,                           # destination IP address
                    ipv6.label,                         # label
                    ipv6.ipv6_frag.next,                # next header field in IPv6 Fragment Header
                ),
                num = frame.info.number,                # original packet range number
                fo = ipv6.ipv6_frag.offset,             # fragment offset
                ihl = ipv6.hdr_len,                     # header length, only headers before IPv6-Frag
                    mf = ipv6.ipv6_frag.mf,             # more fragment flag
                tl = ipv6.hdr_len + ipv6.raw_len,       # total length, header includes
                header = bytearray(ipv6.header),        # raw bytearray type header before IPv6-Frag
                payload = bytearray(ipv6.raw or b''),   # raw bytearray type payload after IPv6-Frag
            )
            self._frame[2].append(data)
