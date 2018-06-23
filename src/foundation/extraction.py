# -*- coding: utf-8 -*-
"""extractor for PCAP files

`jspcap.tools.extraction` contains `Extractor` only, which
synthesises file I/O and protocol analysis, coordinates
information exchange in all network layers, extracst
parametres from a PCAP file.

"""
import collections
import copy
import datetime
import importlib
import io
import ipaddress
import os
import pathlib
import random
import re
import textwrap
import time
import traceback
import warnings

###############################################################################
# import multiprocessing
# 
# import dpkt
# import scapy.all
# 
# from jsformat import PLIST, JSON, Tree, JavaScript, XML
###############################################################################

from jspcap.corekit.infoclass import Info
from jspcap.protocols.pcap.frame import Frame
from jspcap.protocols.pcap.header import Header
from jspcap.protocols.transport.transport import TP_PROTO
from jspcap.utilities.exceptions import stacklevel, CallableError, \
        FileNotFound, UnsupportedCall, IterableError
from jspcap.utilities.warnings import FormatWarning, EngineWarning, \
        LayerWarning, ProtocolWarning, AttributeWarning, DPKTWarning

###############################################################################
# from jspcap.foundation.traceflow import TraceFlow
# from jspcap.reassembly.ipv4 import IPv4_Reassembly
# from jspcap.reassembly.ipv6 import IPv6_Reassembly
# from jspcap.reassembly.tcp import TCP_Reassembly
###############################################################################


__all__ = ['Extractor']


# check list
LAYER_LIST = {'None', 'Link', 'Internet', 'Transport', 'Application'}
PROTO_LIST = {
    'null', 'protocol', 'raw',                              # base protocols
    'header', 'frame',                                      # PCAP headers
    'link', 'arp', 'inarp', 'ethernet', 'l2tp', 'ospf', 'rarp', 'drarp', 'vlan',
                                                            # Link layer
    'internet', 'ah', 'hip', 'hopopt', 'ip', 'ipsec', 'ipv4', 'ipv6', 'ipv6_frag',
    'ipv6_opts', 'ipv6_route', 'ipx', 'mh',                 # Internet layer
    'transport', 'tcp', 'udp',                              # Transport layer
    'application', 'http', 'httpv1', 'httpv2',              # Application layer
}


# CPU number
if os.name == 'posix' and 'SC_NPROCESSORS_CONF' in os.sysconf_names:
    CPU_CNT = os.sysconf('SC_NPROCESSORS_CONF')
elif 'sched_getaffinity' in os.__all__:
    CPU_CNT = len(os.sched_getaffinity(0))
else:
    CPU_CNT = os.cpu_count() or 1


class Extractor:
    """Extractor for PCAP files.

    Properties:
        * info -- VerionInfo, version of input PCAP file
        * length -- int, frame number (of current extracted frame or all)
        * format -- str, format of output file
        * input -- str, name of input PCAP file
        * output -- str, name of output file
        * header -- Info, global header
        * frames -- tuple<Info>, extracted frames
        * protocol -- ProtoChain, protocol chain of current/last frame
        * reassembly -- Info, frame record for reassembly
            |--> tcp -- tuple<TCP_Reassembly>, TCP payload fragment reassembly
            |--> ipv4 -- tuple<IPv4_Reassembly>, IPv4 frame fragment reassembly
            |--> ipv6 -- tuple<IPv6_Reassembly>, IPv6 frame fragment reassembly

    Methods:
        * make_name -- formatting input & output file name
        * record_header -- extract global header
        * record_frames -- extract frames

    Attributes:
        * _flag_a -- bool, if run automatically to the end

        * _ifnm -- str, input file name (aka _ifile.name)
        * _ofnm -- str, output file name (aka _ofile.name)
        * _type -- str, output file kind (aka _ofile.kind)
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
        * _reasm -- list, frame reassembly instance
            |--> IPv4 -- IPv4_Reassembly, reassembly instance
            |--> IPv6 -- IPv6_Reassembly, reassembly instance
            |--> TCP -- TCP_Reassembly, reassembly instance

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
        if self._exeng in ('scapy', 'pyshark'):
            raise UnsupportedCall(f"'Extractor(engine={self._exeng})' object has no attribute 'info'")
        return self._vinfo

    @property
    def length(self):
        return self._frnum

    @property
    def format(self):
        if self._flag_q:
            raise UnsupportedCall("'Extractor(nofile=True)' object has no attribute 'format'")
        return self._type

    @property
    def input(self):
        return self._ifnm

    @property
    def output(self):
        if self._flag_q:
            raise UnsupportedCall("'Extractor(nofile=True)' object has no attribute 'format'")
        return self._ofnm

    @property
    def header(self):
        if self._exeng in ('scapy', 'pyshark'):
            raise UnsupportedCall(f"'Extractor(engine={self._exeng})' object has no attribute 'header'")
        return self._gbhdr

    @property
    def protocol(self):
        if self._flag_a:
            raise UnsupportedCall(f"'Extractor(auto=True)' object has no attribute 'protocol'")
        return self._proto

    @property
    def frame(self):
        if self._flag_d:
            return tuple(self._frame)
        raise UnsupportedCall("'Extractor(store=False)' object has no attribute 'frame'")

    @property
    def reassembly(self):
        data = Info(
            ipv4 = tuple(self._reasm[0].datagram) if self._ipv4 else None,
            ipv6 = tuple(self._reasm[1].datagram) if self._ipv6 else None,
            tcp = tuple(self._reasm[2].datagram) if self._tcp else None,
        )
        return data

    @property
    def trace(self):
        if self._flag_t:
            return self._trace.index
        raise UnsupportedCall("'Extractor(trace=False)' object has no attribute 'trace'")

    @property
    def engine(self):
        return self._exeng

    ##########################################################################
    # Methods.
    ##########################################################################

    def run(self):
        """Start extraction."""
        tempflag = True
        if self._exeng == 'dpkt':
            flag, engine = self.import_test('dpkt', name='DPKT')
            if flag:    return self._run_dpkt(engine)
        elif self._exeng == 'scapy':
            flag, engine = self.import_test('scapy.all', name='Scapy')
            if flag:    return self._run_scapy(engine)
        elif self._exeng == 'pyshark':
            flag, engine = self.import_test('pyshark', name='PyShark')
            if flag:    return self._run_pyshark(engine)
        elif self._exeng == 'pipeline':
            flag, engine = self.import_test('multiprocessing', name='Pipeline Multiprocessing')
            self._flag_m = tempflag = bool(flag and (self._flag_a and CPU_CNT > 1))
            if self._flag_m:
                return self._run_pipeline(engine)
            warnings.warn(f'extraction engine Pipeline Multiprocessing is not available; '
                            'using default engine instead', EngineWarning, stacklevel=stacklevel())
        elif self._exeng == 'server':
            flag, engine = self.import_test('multiprocessing', name='Server Multiprocessing')
            self._flag_m = tempflag = bool(flag and (self._flag_a and CPU_CNT > 2))
            if self._flag_m:
                return self._run_server(engine)
            warnings.warn(f'extraction engine Server Multiprocessing is not available; '
                            'using default engine instead', EngineWarning, stacklevel=stacklevel())
        elif self._exeng not in ('default', 'jspcap'):
            tempflag = False
            warnings.warn(f'unsupported extraction engine: {self._exeng}; '
                            'using default engine instead',
                            EngineWarning, stacklevel=stacklevel())

        # using default/jspcap engine
        self._exeng = self._exeng if tempflag else 'default'
        self.record_header()            # read PCAP global header
        self.record_frames()            # read frames

    def check(self):
        layer = self._exlyr
        if layer is not None:
            if layer not in LAYER_LIST:
                warnings.warn(f'unrecognised layer: {layer}',
                                LayerWarning, stacklevel=stacklevel())

        protocol = self._exptl
        if protocol is not None:
            def check_protocol(*args):
                for arg in args:
                    if arg.lower() not in PROTO_LIST:
                        warnings.warn(f'unrecognised protocol: {protocol}',
                                        ProtocolWarning, stacklevel=stacklevel())
            if isinstance(protocol, tuple): check_protocol(*protocol)
            else:                           check_protocol(protocol)

    @staticmethod
    def import_test(engine, *, name=None):
        try:
            engine = importlib.import_module(engine)
            return True, engine
        except ImportError:
            warnings.warn(f"extraction engine '{name or engine}' not available; "
                            'using default engine instead', EngineWarning, stacklevel=stacklevel())
        return False, None

    @classmethod
    def make_name(cls, fin, fout, fmt, extension, *, files=False, nofile=False):
        if fin is None:
            ifnm = 'in.pcap'
        else:
            if extension:
                ifnm = fin if os.path.splitext(fin)[1] == '.pcap' else f'{fin}.pcap'
            else:
                ifnm = fin

        if not os.path.isfile(ifnm):
            raise FileNotFound(f"[Errno 2] No such file or directory: '{ifnm}'")

        if nofile:
            ofnm = None
            ext = None
        else:
            fmt_none = (fmt is None)

            if fmt == 'html':   ext = 'js'
            elif fmt == 'tree': ext = 'txt'
            else:               ext = fmt

            if fout is None:
                if fmt_none:
                    raise FormatError('Output format unspecified.')
                elif files:
                    ofnm = 'out'
                    pathlib.Path(ofnm).mkdir(parents=True, exist_ok=True)
                else:
                    ofnm = f'out.{ext}'
            else:
                name, fext = os.path.splitext(fout)
                pathlib.Path(fout).parent.mkdir(parents=True, exist_ok=True)
                if fext:
                    files = False
                    ofnm = fout
                    fmt = fmt or fext[1:] or None
                    if fmt is None:
                        raise FormatError('Output format unspecified.')
                elif fmt_none:
                    raise FormatError('Output format unspecified.')
                elif files:
                    ofnm = fout
                    pathlib.Path(ofnm).mkdir(parents=True, exist_ok=True)
                elif extension: ofnm = f'{fout}.{ext}'
                else:           ofnm = fout

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
        self._vinfo = self._gbhdr.version
        if not self._flag_q:
            if self._flag_f:
                ofile = self._ofile(f'{self._ofnm}/Global Header.{self._fext}')
                ofile(self._gbhdr.info, name='Global Header')
                self._type = ofile.kind
            else:
                self._ofile(self._gbhdr.info, name='Global Header')
                self._type = self._ofile.kind

    def record_frames(self):
        if self._flag_a:
            while True:
                try:
                    self._read_frame_hq()
                except (EOFError, StopIteration):
                    # quit when EOF
                    break
            self._cleanup()

    ##########################################################################
    # Data modules.
    ##########################################################################

    # Not hashable
    __hash__ = None

    def __init__(self, *,
                    fin=None, fout=None, format=None,                           # basic settings
                    auto=True, extension=True, store=True,                      # internal settings
                    files=False, nofile=False, verbose=False,                   # output settings
                    engine=None, layer=None, protocol=None,                     # extraction settings
                    ip=False, ipv4=False, ipv6=False, tcp=False, strict=True,   # reassembly settings
                    trace=False, trace_fout=None, trace_format=None):           # trace settings
        """Initialise PCAP Reader.

        Keyword arguments:
            * fin  -- str, file name to be read; if file not exist, raise an error
            * fout -- str, file name to be written
            * format  -- str, file format of output
                            <keyword> 'plist' / 'json' / 'tree' / 'html'

            * auto -- bool, if automatically run till EOF (default is True)
                            <keyword> True / False
            * extension -- bool, if check and append axtensions to output file (default is True)
                            <keyword> True / False
            * store -- bool, if store extracted packet info (default is True)
                            <keyword> True / False

            * files -- bool, if split each frame into different files (default is False)
                            <keyword> True / False
            * nofile -- bool, if no output file is to be dumped (default is False)
                            <keyword> True / False
            * verbose -- bool, if print verbose output information (default is False)
                            <keyword> True / False

            * engine -- str, extraction engine to be used
                            <keyword> 'default | jspcap'
            * layer -- str, extract til which layer
                            <keyword> 'Link' / 'Internet' / 'Transport' / 'Application'
            * protocol -- str, extract til which protocol
                            <keyword> available protocol name

            * ip -- bool, if record data for IPv4 & IPv6 reassembly (default is False)
                            <keyword> True / False
            * ipv4 -- bool, if perform IPv4 reassembly (default is False)
                            <keyword> True / False
            * ipv6 -- bool, if perform IPv6 reassembly (default is False)
                            <keyword> True / False
            * tcp -- bool, if perform TCP reassembly (default is False)
                            <keyword> True / False
            * strict -- bool, if set strict flag for reassembly (default is True)
                            <keyword> True / False

            * trace -- bool, if trace TCP traffic flows (default is False)
                            <keyword> True / False
            * trace_fout -- str, path name for flow tracer if necessary
            * trace_format -- str, output file format of flow tracer
                            <keyword> 'plist' / 'json' / 'tree' / 'html' / 'pcap'

        """
        ifnm, ofnm, fmt, ext, files = \
            self.make_name(fin, fout, format, extension, files=files, nofile=nofile)

        self._ifnm = ifnm               # input file name
        self._ofnm = ofnm               # output file name
        self._fext = ext                # output file extension

        self._flag_a = auto             # auto extract flag
        self._flag_d = store            # store data flag
        self._flag_e = False            # EOF flag
        self._flag_f = files            # split file flag
        self._flag_m = False            # multiprocessing flag
        self._flag_q = nofile           # no output flag
        self._flag_t = trace            # trace flag
        self._flag_v = verbose          # verbose output flag

        self._frnum = 0                 # frame number
        self._frame = list()            # frame record
        self._proto = None              # frame ProtoChain

        self._reasm = [None] * 3        # frame record for reassembly (IPv4 / IPv6 / TCP)
        self._trace = NotImplemented    # flow tracer

        self._ipv4 = ipv4 or ip         # IPv4 Reassembly
        self._ipv6 = ipv6 or ip         # IPv6 Reassembly
        self._tcp = tcp                 # TCP Reassembly

        self._exptl = protocol or 'null'                    # extract til protocol
        self._exlyr = (layer or 'none').capitalize()        # extract til layer
        self._exeng = (engine or 'default').lower()         # extract using engine

        if self._ipv4:
            from jspcap.reassembly.ipv4 import IPv4_Reassembly
            self._reasm[0] = IPv4_Reassembly(strict=strict)
        if self._ipv6:
            from jspcap.reassembly.ipv6 import IPv6_Reassembly
            self._reasm[1] = IPv6_Reassembly(strict=strict)
        if self._tcp:
            from jspcap.reassembly.tcp import TCP_Reassembly
            self._reasm[2] = TCP_Reassembly(strict=strict)

        if trace:
            from jspcap.foundation.traceflow import TraceFlow
            if self._exeng in ('scapy', 'dpkt', 'pyshark') and re.fullmatch('pcap', str(trace_format), re.IGNORECASE):
                warnings.warn(f"'Extractor(engine={self._exeng})' does not support 'trace_format={trace_format}'; "
                                f"using 'trace_format={trace_format}' instead", FormatWarning, stacklevel=stacklevel())
                trace_format = None
            self._trace = TraceFlow(fout=trace_fout, format=trace_format)

        self._ifile = open(ifnm, 'rb')                      # input file
        if not self._flag_q:
            if fmt == 'plist':
                from jsformat import PLIST as output        # output PLIST file
            elif fmt == 'json':
                from jsformat import JSON as output         # output JSON file
            elif fmt == 'tree':
                from jsformat import Tree as output         # output treeview text file
            elif fmt == 'html':
                from jsformat import JavaScript as output   # output JavaScript file
            elif fmt == 'xml':
                from jsformat import XML as output          # output XML file
            else:
                from jspcap.dumpkit import NotImplementedIO as output
                                                            # no output file
                warnings.warn(f'unsupported output format: {fmt}; '
                                'disabled file output feature',
                                FormatWarning, stacklevel=stacklevel())
            self._ofile = output if self._flag_f else output(ofnm)
                                                            # output file

        self.check()                    # check layer & protocol
        self.run()                      # start extraction

    def __iter__(self):
        if not self._flag_a:
            return self
        raise IterableError("'Extractor(auto=True)' object is not iterable")

    def __next__(self):
        try:
            return self._read_frame_hq()
        except (EOFError, StopIteration):
            self._cleanup()
            raise StopIteration

    def __call__(self):
        if not self._flag_a:
            try:
                return self._read_frame_hq()
            except (EOFError, StopIteration) as error:
                self._cleanup()
                raise error from None
        raise CallableError("'Extractor(auto=True)' object is not callable")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self._ifile.close()

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _cleanup(self):
        """Cleanup after extraction & analysis."""
        self._expkg = None
        self._extmp = None
        self._flag_e = True
        self._ifile.close()

    def _aftermathmp(self):
        """Aftermath for multiprocessing."""
        if not self._flag_e and self._flag_m:
            # join processes
            [ proc.join() for proc in self._mpprc ]
            if self._exeng == 'server':
                self._mpsvc.join()

            # restore attributes
            if self._exeng == 'server':
                self._frame = list(self._mpfrm)
                self._reasm = list(self._mprsm)
            if self._exeng == 'pipeline':
                self._frame = [ self._mpkit.frames[x] for x in sorted(self._mpkit.frames) ]
                self._reasm = copy.deepcopy(self._mpkit.reassembly)

            # shutdown & cleanup
            self._mpmng.shutdown()
            for attr in dir(self):
                if re.match('^_mp.*', attr):
                    delattr(self, attr)
            self._frnum -= 2
            # map(lambda attr: delattr(self, attr), filter(lambda attr: re.match('^_mp.*', attr), dir(self)))

    def _update_eof(self):
        """Update EOF flag."""
        self._aftermathmp()
        self._ifile.close()
        self._flag_e = True

    def _read_frame_hq(self):
        """Headquarters for frame reader."""
        if self._exeng == 'scapy':
            return self._scapy_read_frame()
        elif self._exeng == 'dpkt':
            return self._dpkt_read_frame()
        elif self._exeng == 'pyshark':
            return self._pyshark_read_frame()
        else:
            return self._read_frame()

    def _read_frame(self, *, frame=None, mpkit=None):
        """Read frames.

        - Extract frames and each layer of packets.
        - Make Info object out of frame properties.
        - Append Info.
        - Write plist & append Info.

        """
        # read frame header
        if not self._flag_m:
            frame = Frame(self._ifile, num=self._frnum+1, proto=self._dlink,
                            layer=self._exlyr, protocol=self._exptl)
        
        # verbose output
        if self._flag_v:
            print(f' - Frame {self._frnum:>3d}: {frame.protochain}')

        # write plist
        frnum = f'Frame {self._frnum+1}'
        if not self._flag_q:
            if self._flag_f:
                ofile = self._ofile(f'{self._ofnm}/{frnum}.{self._fext}')
                ofile(frame.info, name=frnum)
            else:
                self._ofile(frame.info, name=frnum)

        # record fragments
        if self._tcp:
            self._tcp_reassembly(frame)
        if self._ipv4:
            self._ipv4_reassembly(frame)
        if self._ipv6:
            self._ipv6_reassembly(frame)

        # trace flows
        if self._flag_t:
            self._tcp_traceflow(frame)

        # record frames
        if self._exeng == 'pipeline':
            if self._flag_d:
                # frame._file = NotImplemented
                mpkit.frames[self._frnum] = frame
                # print(self._frnum, 'stored')
            mpkit.curent += 1
        elif self._exeng == 'server':
            # record frames
            if self._flag_d:
                # frame._file = NotImplemented
                self._frame.append(frame)
                # print(self._frnum, 'stored')
            self._frnum += 1
        else:
            if self._flag_d:
                self._frame.append(frame)
            self._frnum += 1
            self._proto = frame.protochain.chain

        # return frame record
        return frame

    def _ipv4_reassembly(self, frame):
        """Store data for IPv4 reassembly."""
        if 'IPv4' in frame:
            ipv4 = frame['IPv4']
            if ipv4.flags.df:   return                  # dismiss not fragmented frame
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
                header = bytearray(ipv4.packet.header), # raw bytearray type header
                payload = bytearray(ipv4.packet.payload or b''),
                                                        # raw bytearray type payload
            )
            self._reasm[0](data)

    def _ipv6_reassembly(self, frame):
        """Store data for IPv6 reassembly."""
        if 'IPv6' in frame:
            ipv6 = frame['IPv6']
            if 'frag' not in ipv6:  return              # dismiss not fragmented frame
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
                mf = ipv6.ipv6_frag.mf,                 # more fragment flag
                tl = ipv6.hdr_len + ipv6.raw_len,       # total length, header includes
                header = bytearray(ipv6.fragment.header),
                                                        # raw bytearray type header before IPv6-Frag
                payload = bytearray(ipv6.fragment.payload or b''),
                                                        # raw bytearray type payload after IPv6-Frag
            )
            self._reasm[1](data)

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
                payload = bytearray(tcp.packet.payload or b''),
                                                        # raw bytearray type payload
            )
            raw_len = len(data['payload'])              # payload length, header excludes
            data['first'] = tcp.seq                     # this sequence number
            data['last'] = tcp.seq + raw_len            # next (wanted) sequence number
            data['len'] = raw_len                       # payload length, header excludes
            self._reasm[2](data)

    def _tcp_traceflow(self, frame):
        """Trace packet flow for TCP."""
        if 'TCP' in frame:
            ip = frame['IPv4'] if 'IPv4' in frame else frame['IPv6']
            tcp = frame['TCP']
            data = dict(
                protocol = self._dlink,                 # data link type from global header
                index = frame.info.number,              # frame number
                frame = frame.info,                     # extracted frame info
                syn = tcp.flags.syn,                    # TCP synchronise (SYN) flag
                fin = tcp.flags.fin,                    # TCP finish (FIN) flag
                src = ip.src,                           # source IP
                dst = ip.dst,                           # destination IP
                srcport = tcp.srcport,                  # TCP source port
                dstport = tcp.dstport,                  # TCP destination port
                timestamp = frame.info.time_epoch,      # frame timestamp
            )
            self._trace(data)

    def _run_scapy(self, scapy_all):
        """Call scapy.all.sniff to extract PCAP files."""
        # if not self._flag_a:
        #     self._flag_a = True
        #     warnings.warn(f"'Extractor(engine=scapy)' object is not iterable; "
        #                     "so 'auto=False' will be ignored", AttributeWarning, stacklevel=stacklevel())

        if self._exlyr != 'None' or self._exptl != 'null':
            warnings.warn("'Extractor(engine=scapy)' does not support protocol and layer threshold; "
                            f"'layer={self._exlyr}' and 'protocol={self._exptl}' ignored", AttributeWarning, stacklevel=stacklevel())

        # extract & analyse file
        self._expkg = scapy_all
        self._extmp = iter(scapy_all.sniff(offline=self._ifnm))

        # start iteration
        self.record_frames()

    def _scapy_read_frame(self):
        """Read frames."""
        packet = self._extmp.__next__()

        def _scapy_packet2chain(packet):
            """Fetch Scapy packet protocol chain."""
            chain = [packet.name,]
            payload = packet.payload
            while not isinstance(payload, self._expkg.packet.NoPayload):
                chain.append(payload.name)
                payload = payload.payload
            return ':'.join(chain)

        def _scapy_packet2dict(packet):
            """Convert Scapy packet into dict."""
            dict_ = packet.fields
            payload = packet.payload
            if not isinstance(payload, self._expkg.packet.NoPayload):
                dict_[payload.name] = _scapy_packet2dict(payload)
            return dict_

        def _scapy_ipv4_reassembly(packet, *, count=NotImplemented):
            """Store data for IPv4 reassembly."""
            if 'IP' in packet:
                ipv4 = packet['IP']
                if ipv4.flags.DF:   return                  # dismiss not fragmented packet
                data = dict(
                    bufid = (
                        ipaddress.ip_address(ipv4.src),     # source IP address
                        ipaddress.ip_address(ipv4.dst),     # destination IP address
                        ipv4.id,                            # identification
                        TP_PROTO.get(ipv4.proto),           # payload protocol type
                    ),
                    num = count,                            # original packet range number
                    fo = ipv4.frag,                         # fragment offset
                    ihl = ipv4.ihl,                         # internet header length
                    mf = bool(ipv4.flags.MF),               # more fragment flag
                    tl = ipv4.len,                          # total length, header includes
                    header = bytearray(ipv4.raw_packet_cache),
                                                            # raw bytearray type header
                    payload = bytearray(bytes(ipv4.payload)),
                                                            # raw bytearray type payload
                )
                self._reasm[0](data)

        def _scapy_ipv6_reassembly(packet, *, count=NotImplemented):
            """Store data for IPv6 reassembly."""
            if 'IPv6' in packet:
                ipv6 = packet['IPv6']
                if self._expkg.IPv6ExtHdrFragment not in ipv6:
                    return                                  # dismiss not fragmented packet
                ipv6_frag = ipv6['IPv6ExtHdrFragment']
                data = dict(
                    bufid = (
                        ipaddress.ip_address(ipv6.src),     # source IP address
                        ipaddress.ip_address(ipv6.dst),     # destination IP address
                        ipv6.fl,                            # label
                        TP_PROTO.get(ipv6_frag.nh),         # next header field in IPv6 Fragment Header
                    ),
                    num = count,                            # original packet range number
                    fo = ipv6_frag.offset,                  # fragment offset
                    ihl = len(ipv6) - len(ipv6_frag),       # header length, only headers before IPv6-Frag
                    mf = bool(ipv6_frag.m),                 # more fragment flag
                    tl = len(ipv6),                         # total length, header includes
                    header = bytearray(bytes(ipv6)[:-len(ipv6_frag)]),
                                                            # raw bytearray type header before IPv6-Frag
                    payload = bytearray(bytes(ipv6_frag.payload)),
                                                            # raw bytearray type payload after IPv6-Frag
                )
                self._reasm[1](data)

        def _scapy_tcp_reassembly(packet, *, count=NotImplemented):
            """Store data for TCP reassembly."""
            if 'TCP' in packet:
                ip = packet['IP'] if 'IP' in packet else packet['IPv6']
                tcp = packet['TCP']
                data = dict(
                    bufid = (
                        ipaddress.ip_address(ip.src),       # source IP address
                        ipaddress.ip_address(ip.dst),       # destination IP address
                        tcp.sport,                          # source port
                        tcp.dport,                          # destination port
                    ),
                    num = count,                            # original packet range number
                    ack = tcp.ack,                          # acknowledgement
                    dsn = tcp.seq,                          # data sequence number
                    syn = bool(tcp.flags.S),                # synchronise flag
                    fin = bool(tcp.flags.F),                # finish flag
                    payload = bytearray(bytes(tcp.payload)),# raw bytearray type payload
                )
                raw_len = len(tcp.payload)                  # payload length, header excludes
                data['first'] = tcp.seq                     # this sequence number
                data['last'] = tcp.seq + raw_len            # next (wanted) sequence number
                data['len'] = raw_len                       # payload length, header excludes
                self._reasm[2](data)

        def _scapy_tcp_traceflow(packet, *, count=NotImplemented):
            """Trace packet flow for TCP."""
            if 'TCP' in packet:
                ip = packet['IP'] if 'IP' in packet else packet['IPv6']
                tcp = packet['TCP']
                data = dict(
                    protocol = packet.name,                 # data link type from global header
                    index = count,                          # frame number
                    frame = _scapy_packet2dict(packet),     # extracted packet
                    syn = bool(tcp.flags.S),                # TCP synchronise (SYN) flag
                    fin = bool(tcp.flags.F),                # TCP finish (FIN) flag
                    src = ipaddress.ip_address(ip.src),     # source IP
                    dst = ipaddress.ip_address(ip.dst),     # destination IP
                    srcport = tcp.sport,                    # TCP source port
                    dstport = tcp.dport,                    # TCP destination port
                    timestamp = time.time(),                # timestamp
                )
                self._trace(data)

        # verbose output
        self._frnum += 1
        self._proto = _scapy_packet2chain(packet)
        if self._flag_v:
            print(f' - Frame {self._frnum:>3d}: {self._proto}')

        # write plist
        frnum = f'Frame {self._frnum}'
        if not self._flag_q:
            info = {packet.name: _scapy_packet2dict(packet)}
            if self._flag_f:
                ofile = self._ofile(f'{self._ofnm}/{frnum}.{self._fext}')
                ofile(info, name=frnum)
            else:
                self._ofile(info, name=frnum)

        # record frames
        if self._flag_d:
            self._frame.append(packet)

        # record fragments
        if self._tcp:
            _scapy_tcp_reassembly(packet, count=self._frnum)
        if self._ipv4:
            _scapy_ipv4_reassembly(packet, count=self._frnum)
        if self._ipv6:
            _scapy_ipv6_reassembly(packet, count=self._frnum)

        # trace flows
        if self._flag_t:
            _scapy_tcp_traceflow(packet, count=self._frnum)

        return packet

    def _run_dpkt(self, dpkt):
        """Call dpkt.pcap.Reader to extract PCAP files."""
        # if not self._flag_a:
        #     self._flag_a = True
        #     warnings.warn(f"'Extractor(engine=dpkt)' object is not iterable; "
        #                     "so 'auto=False' will be ignored", AttributeWarning, stacklevel=stacklevel())

        if self._exlyr != 'None' or self._exptl != 'null':
            warnings.warn("'Extractor(engine=dpkt)' does not support protocol and layer threshold; "
                            f"'layer={self._exlyr}' and 'protocol={self._exptl}' ignored", AttributeWarning, stacklevel=stacklevel())

        # extract global header
        self.record_header()
        self._ifile.seek(0, os.SEEK_SET)

        # extract & analyse file
        self._expkg = dpkt
        self._extmp = iter(dpkt.pcap.Reader(self._ifile))

        # start iteration
        self.record_frames()

    def _dpkt_read_frame(self):
        """Read frames."""
        timestamp, packet = self._extmp.__next__()

        def _dpkt_packet2chain(packet):
            """Fetch DPKT packet protocol chain."""
            chain = [type(packet).__name__,]
            payload = packet.data
            while not isinstance(payload, bytes):
                chain.append(type(payload).__name__)
                payload = payload.data
            return ':'.join(chain)

        def _dpkt_packet2dict(packet):
            """Convert DPKT packet into dict."""
            dict_ = dict()
            for field in packet.__hdr_fields__:
                dict_[field] = getattr(packet, field, None)
            payload = packet.data
            if not isinstance(payload, bytes):
                dict_[type(payload).__name__] = _dpkt_packet2dict(payload)
            return dict_

        def _dpkt_ipv4_reassembly(packet, *, count=NotImplemented):
            """Store data for IPv4 reassembly."""
            ipv4 = getattr(packet, 'ip', None)
            if ipv4 is not None:
                if ipv4.df:   return                        # dismiss not fragmented packet
                data = dict(
                    bufid = (
                        ipaddress.ip_address(ipv4.src),     # source IP address
                        ipaddress.ip_address(ipv4.dst),     # destination IP address
                        ipv4.id,                            # identification
                        TP_PROTO.get(ipv4.p),               # payload protocol type
                    ),
                    num = count,                            # original packet range number
                    fo = ipv4.off,                          # fragment offset
                    ihl = ipv4.__hdr_len__,                 # internet header length
                    mf = bool(ipv4.mf),                     # more fragment flag
                    tl = ipv4.len,                          # total length, header includes
                    header = bytearray(ipv4.pack()[:ipv4.__hdr_len__]),
                                                            # raw bytearray type header
                    payload = bytearray(ipv4.pack()[ipv4.__hdr_len__:]),
                                                            # raw bytearray type payload
                )
                self._reasm[0](data)

        def _dpkt_ipv6_reassembly(packet, *, count=NotImplemented):
            """Store data for IPv6 reassembly."""
            def _dpkt_ipv6_hdr_len(ipv6):
                """Calculate length of headers before IPv6_Frag"""
                hdr_len = ipv6.__hdr_len__
                for code in (0, 60, 43):
                    ext_hdr = ipv6.extension_hdrs.get(code)
                    if ext_hdr is not None:
                        hdr_len += ext_hdr.length
                return hdr_len

            ipv6 = getattr(packet, 'ip6', None)
            if ipv6 is not None:
                ipv6_frag = ipv6.extension_hdrs.get(44)
                if ipv6_frag is None:   return              # dismiss not fragmented packet
                hdr_len = _dpkt_ipv6_hdr_len(ipv6)
                data = dict(
                    bufid = (
                        ipaddress.ip_address(ipv6.src),     # source IP address
                        ipaddress.ip_address(ipv6.dst),     # destination IP address
                        ipv6.flow,                          # label
                        TP_PROTO.get(ipv6_frag.nh),         # next header field in IPv6 Fragment Header
                    ),
                    num = count,                            # original packet range number
                    fo = ipv6_frag.nxt,                     # fragment offset
                    ihl = hdr_len,                          # header length, only headers before IPv6-Frag
                    mf = bool(ipv6_frag.m_flag),            # more fragment flag
                    tl = len(ipv6),                         # total length, header includes
                    header = bytearray(ipv6.pack()[:hdr_len]),
                                                            # raw bytearray type header before IPv6-Frag
                    payload = bytearray(ipv6.pack()[hdr_len+ipv6_frag:]),
                                                            # raw bytearray type payload after IPv6-Frag
                )
                self._reasm[1](data)

        def _dpkt_tcp_reassembly(packet, *, count=NotImplemented):
            """Store data for TCP reassembly."""
            if getattr(packet, 'ip', None):     ip = packet['ip']
            elif getattr(packet, 'ip6', None):  ip = packet['ip6']
            else:                               return
            tcp = getattr(ip, 'tcp', None)
            if tcp is not None:
                flags = bin(tcp.flags)[2:].zfill(8)
                data = dict(
                    bufid = (
                        ipaddress.ip_address(ip.src),       # source IP address
                        ipaddress.ip_address(ip.dst),       # destination IP address
                        tcp.sport,                          # source port
                        tcp.dport,                          # destination port
                    ),
                    num = count,                            # original packet range number
                    ack = tcp.ack,                          # acknowledgement
                    dsn = tcp.seq,                          # data sequence number
                    syn = bool(int(flags[6])),              # synchronise flag
                    fin = bool(int(flags[7])),              # finish flag
                    payload = bytearray(tcp.pack()[tcp.__hdr_len__:]),
                                                            # raw bytearray type payload
                )
                raw_len = len(tcp.data)                     # payload length, header excludes
                data['first'] = tcp.seq                     # this sequence number
                data['last'] = tcp.seq + raw_len            # next (wanted) sequence number
                data['len'] = raw_len                       # payload length, header excludes
                self._reasm[2](data)

        def _dpkt_tcp_traceflow(packet, timestamp, *, count=NotImplemented):
            """Trace packet flow for TCP."""
            if getattr(packet, 'ip', None):     ip = packet['ip']
            elif getattr(packet, 'ip6', None):  ip = packet['ip6']
            else:                               return
            tcp = getattr(ip, 'tcp', None)
            if tcp is not None:
                flags = bin(tcp.flags)[2:].zfill(8)
                data = dict(
                    protocol = self._dlink,                 # data link type from global header
                    index = count,                          # frame number
                    frame = _dpkt_packet2dict(packet),      # extracted packet
                    syn = bool(int(flags[6])),              # TCP synchronise (SYN) flag
                    fin = bool(int(flags[7])),              # TCP finish (FIN) flag
                    src = ipaddress.ip_address(ip.src),     # source IP
                    dst = ipaddress.ip_address(ip.dst),     # destination IP
                    srcport = tcp.sport,                    # TCP source port
                    dstport = tcp.dport,                    # TCP destination port
                    timestamp = timestamp,                  # timestamp
                )
                self._trace(data)
        
        # extract packet
        if self._dlink == 'Ethernet':
            packet = self._expkg.ethernet.Ethernet(packet)
        elif self._dlink == 'IPv4':
            packet = self._expkg.ip.IP(packet)
        elif self._dlink == 'IPv6':
            packet = self._expkg.ip6.IP6(packet)
        else:
            warnings.warn('unrecognised link layer protocol; '
                            'all analysis functions ignored', DPKTWarning, stacklevel=stacklevel())
            self._frnum += 1
            if self._flag_d:
                self._frame.append(packet)
            return packet

        # verbose output
        self._frnum += 1
        self._proto = _dpkt_packet2chain(packet)
        if self._flag_v:
            print(f' - Frame {self._frnum:>3d}: {self._proto}')

        # write plist
        frnum = f'Frame {self._frnum}'
        if not self._flag_q:
            info = {self._dlink: _dpkt_packet2dict(packet)}
            if self._flag_f:
                ofile = self._ofile(f'{self._ofnm}/{frnum}.{self._fext}')
                ofile(info, name=frnum)
            else:
                self._ofile(info, name=frnum)

        # record frames
        if self._flag_d:
            self._frame.append(packet)

        # record fragments
        if self._tcp:
            _dpkt_tcp_reassembly(packet, count=self._frnum)
        if self._ipv4:
            _dpkt_ipv4_reassembly(packet, count=self._frnum)
        if self._ipv6:
            _dpkt_ipv6_reassembly(packet, count=self._frnum)

        # trace flows
        if self._flag_t:
            _dpkt_tcp_traceflow(packet, timestamp, count=self._frnum)

        return packet

    def _run_pyshark(self, pyshark):
        """Call pyshark.FileCapture to extract PCAP files."""
        # if not self._flag_a:
        #     self._flag_a = True
        #     warnings.warn(f"'Extractor(engine=pyshark)' object is not iterable; "
        #                     "so 'auto=False' will be ignored", AttributeWarning, stacklevel=stacklevel())

        if self._exlyr != 'None' or self._exptl != 'null':
            warnings.warn("'Extractor(engine=pyshark)' does not support protocol and layer threshold; "
                            f"'layer={self._exlyr}' and 'protocol={self._exptl}' ignored", AttributeWarning, stacklevel=stacklevel())

        if (self._ipv4 or self._ipv6 or self._tcp):
            self._ipv4 = self._ipv6 = self._tcp = False
            self._reasm = [None] * 3
            warnings.warn(f"'Extractor(engine=pyshark)' object dose not support reassembly; "
                            f"so 'ipv4={self._ipv4}', 'ipv6={self._ipv6}' and 'tcp={self._tcp}' will be ignored",
                            AttributeWarning, stacklevel=stacklevel())

        # extract & analyse file
        self._expkg = pyshark
        self._extmp = iter(pyshark.FileCapture(self._ifnm, keep_packets=False))

        # start iteration
        self.record_frames()

    def _pyshark_read_frame(self):
        """Read frames."""
        packet = self._extmp.__next__()

        def _pyshark_packet2chain(packet):
            """Fetch PyShark packet protocol chain."""
            return ':'.join(map(lambda layer: layer.layer_name.upper(), packet.layers))

        def _pyshark_packet2dict(packet):
            """Convert PyShark packet into dict."""
            dict_ = dict()
            frame = packet.frame_info
            for field in frame.field_names:
                dict_[field] = getattr(frame, field)

            tempdict = dict_
            for layer in packet.layers:
                tempdict[layer.layer_name.upper()] = dict()
                tempdict = tempdict[layer.layer_name.upper()]
                for field in layer.field_names:
                    tempdict[field] = getattr(layer, field)

            return dict_

        def _pyshark_tcp_traceflow(packet):
            """Trace packet flow for TCP."""
            if 'TCP' in packet:
                ip = packet.ip if 'IP' in packet else packet.ipv6
                tcp = packet.tcp
                data = dict(
                    protocol = packet.layers[0].layer_name.upper(),
                                                            # data link type from global header
                    index = int(packet.number),             # frame number
                    frame = _pyshark_packet2dict(packet),   # extracted packet
                    syn = bool(int(tcp.flags_syn)),         # TCP synchronise (SYN) flag
                    fin = bool(int(tcp.flags_fin)),         # TCP finish (FIN) flag
                    src = ipaddress.ip_address(ip.src),     # source IP
                    dst = ipaddress.ip_address(ip.dst),     # destination IP
                    srcport = int(tcp.srcport),             # TCP source port
                    dstport = int(tcp.dstport),             # TCP destination port
                    timestamp = packet.frame_info.time_epoch,
                                                            # timestamp
                )
                self._trace(data)

        # verbose output
        self._frnum = int(packet.number)
        self._proto = _pyshark_packet2chain(packet)
        if self._flag_v:
            print(f' - Frame {self._frnum:>3d}: {self._proto}')

        # write plist
        frnum = f'Frame {self._frnum}'
        if not self._flag_q:
            info = _pyshark_packet2dict(packet)
            if self._flag_f:
                ofile = self._ofile(f'{self._ofnm}/{frnum}.{self._fext}')
                ofile(info, name=frnum)
            else:
                self._ofile(info, name=frnum)

        # record frames
        if self._flag_d:
            self._frame.append(packet)

        # trace flows
        if self._flag_t:
            _pyshark_tcp_traceflow(packet)

        return packet

    def _run_pipeline(self, multiprocessing):
        """Use pipeline multiprocessing to extract PCAP files."""
        if not self._flag_m:
            raise UnsupportedCall(f"Extractor(engine={self._exeng})' has no attribute '_run_pipline'")

        if not self._flag_q:
            self._flag_q = True
            warnings.warn("'Extractor(engine=pipeline)' does not support output; "
                            f"'fout={self._ofnm}' ignored", AttributeWarning, stacklevel=stacklevel())

        self._frnum = 1                                 # frame number (revised)
        self._expkg = multiprocessing                   # multiprocessing module
        self._mpprc = list()                            # multiprocessing process list
        self._mpfdp = collections.defaultdict(multiprocessing.Queue)
                                                        # multiprocessing file pointer

        self._mpmng = multiprocessing.Manager()         # multiprocessing manager
        self._mpkit = self._mpmng.Namespace()           # multiprocessing work kit

        self._mpkit.counter    = 0                      # work count (on duty)
        self._mpkit.pool       = 1                      # work pool (ready)
        self._mpkit.curent     = 1                      # current frame number
        self._mpkit.eof        = False                  # EOF flag
        self._mpkit.frames     = dict()                 # frame storage
        self._mpkit.reassembly = copy.deepcopy(self._reasm)
                                                        # reassembly buffers

        # preparation
        self.record_header()
        self._mpfdp[0].put(self._gbhdr.length)

        # extraction
        while True:
            # check EOF
            if self._mpkit.eof:     self._update_eof();     break

            # check counter
            if self._mpkit.pool and self._mpkit.counter < CPU_CNT:
                # update file offset
                self._ifile.seek(self._mpfdp.pop(self._frnum-1).get(), os.SEEK_SET)

                # create worker
                # print(self._frnum, 'start')
                proc = multiprocessing.Process(target=self._pipeline_read_frame,
                        kwargs={'mpkit': self._mpkit,
                                'mpfdp': self._mpfdp[self._frnum]})

                # update status
                self._mpkit.pool  -= 1
                self._mpkit.counter += 1

                # start and record
                proc.start()
                self._frnum += 1
                self._mpprc.append(proc)

            # check buffer
            if len(self._mpprc) >= CPU_CNT:
                [ proc.join() for proc in self._mpprc[:-4] ]
                del self._mpprc[:-4]

    def _pipeline_read_frame(self, *, mpfdp, mpkit):
        """Extract frame."""
        # check EOF
        if self._flag_e:    raise EOFError

        def _analyse_frame(*, frame, mpkit):
            """Analyse frame."""
            # wait until ready
            while mpkit.curent != self._frnum:
                time.sleep(random.randint(0, datetime.datetime.now().second) // 600)

            # analysis and storage
            # print(self._frnum, 'get')
            self._reasm = mpkit.reassembly
            self._read_frame(frame=frame, mpkit=mpkit)
            # print(self._frnum, 'analysed')
            mpkit.reassembly = copy.deepcopy(self._reasm)
            # print(self._frnum, 'put')

        # extract frame
        try:
            # extraction
            frame = Frame(self._ifile, num=self._frnum, proto=self._dlink,
                            layer=self._exlyr, protocol=self._exptl,
                            mpkit=mpkit, mpfdp=mpfdp)
            # analysis
            _analyse_frame(frame=frame, mpkit=mpkit)
        except EOFError:
            mpkit.eof = True
        finally:
            mpkit.counter -= 1
            self._ifile.close()
            # print(self._frnum, 'done')

    def _run_server(self, multiprocessing):
        """Use server multiprocessing to extract PCAP files."""
        if not self._flag_m:
            raise UnsupportedCall(f"Extractor(engine={self._exeng})' has no attribute '_run_server'")

        if not self._flag_q:
            self._flag_q = True
            warnings.warn("'Extractor(engine=pipeline)' does not support output; "
                            f"'fout={self._ofnm}' ignored", AttributeWarning, stacklevel=stacklevel())

        self._frnum = 1                                 # frame number (revised)
        self._expkg = multiprocessing                   # multiprocessing module
        self._mpsvc = NotImplemented                    # multiprocessing server process
        self._mpprc = list()                            # multiprocessing process list
        self._mpfdp = collections.defaultdict(multiprocessing.Queue)
                                                        # multiprocessing file pointer

        self._mpmng = multiprocessing.Manager()         # multiprocessing manager
        self._mpbuf = self._mpmng.dict()                # multiprocessing frame dict
        self._mpfrm = self._mpmng.list()                # multiprocessing frame storage
        self._mprsm = self._mpmng.list()                # multiprocessing reassembly buffer

        self._mpkit = self._mpmng.Namespace()           # multiprocessing work kit
        self._mpkit.counter = 0                         # work count (on duty)
        self._mpkit.pool    = 1                         # work pool (ready)
        self._mpkit.eof     = False                     # EOF flag

        # preparation
        self.record_header()
        self._mpfdp[0].put(self._gbhdr.length)
        self._mpsvc = multiprocessing.Process(target=self._server_analyse_frame,
                        kwargs={'mpfrm': self._mpfrm, 'mprsm': self._mprsm,
                                'mpbuf': self._mpbuf, 'mpkit': self._mpkit})
        self._mpsvc.start()
        
        # extraction
        while True:
            # check EOF
            if self._mpkit.eof:     self._update_eof();     break

            # check counter
            if self._mpkit.pool and self._mpkit.counter < CPU_CNT - 1:
                # update file offset
                self._ifile.seek(self._mpfdp.pop(self._frnum-1).get(), os.SEEK_SET)

                # create worker
                # print(self._frnum, 'start')
                proc = multiprocessing.Process(target=self._server_extract_frame,
                        kwargs={'mpkit': self._mpkit, 'mpbuf': self._mpbuf,
                                'mpfdp': self._mpfdp[self._frnum]})

                # update status
                self._mpkit.pool  -= 1
                self._mpkit.counter += 1

                # start and record
                proc.start()
                self._frnum += 1
                self._mpprc.append(proc)

            # check buffer
            if len(self._mpprc) >= CPU_CNT - 1:
                [ proc.join() for proc in self._mpprc[:-4] ]
                del self._mpprc[:-4]

    def _server_extract_frame(self, *, mpfdp, mpkit, mpbuf):
        """Extract frame."""
        # check EOF
        if self._flag_e:    raise EOFError

        # extract frame
        try:
            frame = Frame(self._ifile, num=self._frnum, proto=self._dlink,
                            layer=self._exlyr, protocol=self._exptl,
                            mpkit=mpkit, mpfdp=mpfdp)
            # frame._file = NotImplemented
            mpbuf[self._frnum] = frame
        except EOFError:
            mpbuf[self._frnum] = EOFError
            mpkit.eof = True
        finally:
            mpkit.counter -= 1
            self._ifile.close()
            # print(self._frnum, 'done')

    def _server_analyse_frame(self, *, mpkit, mpfrm, mprsm, mpbuf):
        """Analyse frame."""
        while True:
            # fetch frame
            # print(self._frnum, 'trying')
            frame = mpbuf.pop(self._frnum, None)
            if frame is EOFError:   break
            if frame is None:       continue
            # print(self._frnum, 'get')

            self._read_frame(frame=frame)
        mpfrm += self._frame
        mprsm += self._reasm
