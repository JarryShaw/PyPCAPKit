# -*- coding: utf-8 -*-
"""extractor for PCAP files

`pcapkit.foundation.extraction` contains `Extractor` only,
which synthesises file I/O and protocol analysis,
coordinates information exchange in all network layers,
extracst parametres from a PCAP file.

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
import sys
import textwrap
import time
import traceback
import warnings

from pcapkit.corekit.infoclass import Info
from pcapkit.protocols.pcap.frame import Frame
from pcapkit.protocols.pcap.header import Header
from pcapkit.protocols.transport.transport import TP_PROTO
from pcapkit.utilities.exceptions import (CallableError, FileNotFound,
                                          FormatError, IterableError,
                                          UnsupportedCall, stacklevel)
from pcapkit.utilities.warnings import (AttributeWarning, DPKTWarning,
                                        EngineWarning, FormatWarning,
                                        LayerWarning, ProtocolWarning)

###############################################################################
# import enum
# import multiprocessing
#
# import aenum
# import dpkt
# from dictdumper import JSON, PLIST, XML, JavaScript, Tree
# from pcapkit.foundation.traceflow import TraceFlow
# from pcapkit.reassembly.ipv4 import IPv4_Reassembly
# from pcapkit.reassembly.ipv6 import IPv6_Reassembly
# from pcapkit.reassembly.tcp import TCP_Reassembly
# from pcapkit.toolkit.default import (ipv4_reassembly, ipv6_reassembly,
#                                      tcp_reassembly, tcp_traceflow)
# from pcapkit.toolkit.dpkt import (ipv4_reassembly, ipv6_reassembly,
#                                   packet2chain, packet2dict, tcp_reassembly,
#                                   tcp_traceflow)
# from pcapkit.toolkit.pyshark import packet2dict, tcp_traceflow
# from pcapkit.toolkit.scapy import (ipv4_reassembly, ipv6_reassembly,
#                                    packet2chain, packet2dict, tcp_reassembly,
#                                    tcp_traceflow)
#
# import scapy.all
###############################################################################

# TODO: implement engine support for pypcap & pycapfile
__all__ = ['Extractor']
__fmt__ = format

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


def mkdir(p):
    path = pathlib.Path(p)
    try:
        path.mkdir(parents=True)
    except OSError:
        if not path.is_dir():
            raise


class Extractor:
    """Extractor for PCAP files.

    Properties:
        * info -- VersionInfo, version of input PCAP file
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
            raise UnsupportedCall("'Extractor(engine={})' object has no attribute 'info'".format(self._exeng))
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
            raise UnsupportedCall("'Extractor(engine={})' object has no attribute 'header'".format(self._exeng))
        return self._gbhdr

    @property
    def protocol(self):
        if self._flag_a:
            raise UnsupportedCall("'Extractor(auto=True)' object has no attribute 'protocol'".format())
        return self._proto

    @property
    def frame(self):
        if self._flag_d:
            return tuple(self._frame)
        raise UnsupportedCall("'Extractor(store=False)' object has no attribute 'frame'")

    @property
    def reassembly(self):
        data = Info(
            ipv4=tuple(self._reasm[0].datagram) if self._ipv4 else None,
            ipv6=tuple(self._reasm[1].datagram) if self._ipv6 else None,
            tcp=tuple(self._reasm[2].datagram) if self._tcp else None,
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
        flag = True
        if self._exeng == 'dpkt':
            flag, engine = self.import_test('dpkt', name='DPKT')
            if flag:
                return self._run_dpkt(engine)
        elif self._exeng == 'scapy':
            flag, engine = self.import_test('scapy.all', name='Scapy')
            if flag:
                return self._run_scapy(engine)
        elif self._exeng == 'pyshark':
            flag, engine = self.import_test('pyshark', name='PyShark')
            if flag:
                return self._run_pyshark(engine)
        elif self._exeng == 'pipeline':
            flag, engine = self.import_test('multiprocessing', name='Pipeline Multiprocessing')
            self._flag_m = flag = bool(flag and (self._flag_a and CPU_CNT > 1))
            if self._flag_m:
                return self._run_pipeline(engine)
            warnings.warn('extraction engine Pipeline Multiprocessing is not available; '
                          'using default engine instead'.format(), EngineWarning, stacklevel=stacklevel())
        elif self._exeng == 'server':
            flag, engine = self.import_test('multiprocessing', name='Server Multiprocessing')
            self._flag_m = flag = bool(flag and (self._flag_a and CPU_CNT > 2))
            if self._flag_m:
                return self._run_server(engine)
            warnings.warn('extraction engine Server Multiprocessing is not available; '
                          'using default engine instead'.format(), EngineWarning, stacklevel=stacklevel())
        elif self._exeng not in ('default', 'pcapkit'):
            flag = False
            warnings.warn('unsupported extraction engine: {}; '
                          'using default engine instead'.format(self._exeng), EngineWarning, stacklevel=stacklevel())

        # using default/pcapkit engine
        self._exeng = self._exeng if flag else 'default'
        self.record_header()            # read PCAP global header
        self.record_frames()            # read frames

    def check(self):
        layer = self._exlyr
        if layer is not None:
            if layer not in LAYER_LIST:
                warnings.warn('unrecognised layer: {}'.format(layer), LayerWarning, stacklevel=stacklevel())

        protocol = self._exptl
        if protocol is not None:
            def check_protocol(*args):
                for arg in args:
                    if arg.lower() not in PROTO_LIST:
                        warnings.warn('unrecognised protocol: {}'.format(protocol), ProtocolWarning, stacklevel=stacklevel())
            if isinstance(protocol, tuple):
                check_protocol(*protocol)
            else:
                check_protocol(protocol)

    @staticmethod
    def import_test(engine, *, name=None):
        try:
            engine = importlib.import_module(engine)
            return True, engine
        except ImportError:
            warnings.warn("extraction engine '{}' not available; "
                          'using default engine instead'.format(name or engine), EngineWarning, stacklevel=stacklevel())
        return False, None

    @classmethod
    def make_name(cls, fin, fout, fmt, extension, *, files=False, nofile=False):
        if fin is None:
            ifnm = 'in.pcap'
        else:
            if extension:
                ifnm = fin if os.path.splitext(fin)[1] == '.pcap' else '{}.pcap'.format(fin)
            else:
                ifnm = fin

        if not os.path.isfile(ifnm):
            raise FileNotFound(2, 'No such file or directory', ifnm)

        if nofile:
            ofnm = None
            ext = None
        else:
            fmt_none = (fmt is None)

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
                    mkdir(ofnm)
                else:
                    ofnm = 'out.{}'.format(ext)
            else:
                fext = os.path.splitext(fout)[1]
                mkdir(os.path.split(fout)[1])
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
                    mkdir(ofnm)
                elif extension:
                    ofnm = '{}.{}'.format(fout, ext)
                else:
                    ofnm = fout

        return ifnm, ofnm, fmt, ext, files

    def record_header(self):
        """Read global header.

        - Extract global header.
        - Make Info object out of header properties.
        - Append Info.
        - Write plist file.

        """
        self._gbhdr = Header(self._ifile)
        self._vinfo = self._gbhdr.version
        self._dlink = self._gbhdr.protocol
        self._nnsec = self._gbhdr.nanosecond

        if self._trace is not NotImplemented:
            self._trace._endian = self._gbhdr.byteorder
            self._trace._nnsecd = self._gbhdr.nanosecond

        if not self._flag_q:
            if self._flag_f:
                ofile = self._ofile('{}/Global Header.{}'.format(self._ofnm, self._fext))
                ofile(self._gbhdr.info, name='Global Header')
                self._type = ofile.kind
            else:
                self._ofile(self._gbhdr.info, name='Global Header')
                self._type = self._ofile.kind

    def record_frames(self):
        if self._flag_a:
            while True:
                try:
                    self._read_frame()
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
                 fin=None, fout=None, format=None,                          # basic settings
                 auto=True, extension=True, store=True,                     # internal settings
                 files=False, nofile=False, verbose=False,                  # output settings
                 engine=None, layer=None, protocol=None,                    # extraction settings
                 ip=False, ipv4=False, ipv6=False, tcp=False, strict=True,  # reassembly settings
                 trace=False, trace_fout=None, trace_format=None,           # trace settings
                 trace_byteorder=sys.byteorder, trace_nanosecond=False):    # trace settings
        """Initialise PCAP Reader.

        Keyword arguments:
            * fin  -- str, file name to be read; if file not exist, raise an error
            * fout -- str, file name to be written
            * format  -- str, file format of output
                            <keyword> 'plist' / 'json' / 'tree' / 'html'

            * auto -- bool, if automatically run till EOF (default is True)
                            <keyword> True / False
            * extension -- bool, if check and append extensions to output file (default is True)
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
                            <keyword> 'default | pcapkit'
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
            * trace_byteorder -- str, output file byte order
                            <keyword> 'little' / 'big'
            * trace_nanosecond -- bool, output nanosecond-resolution file flag
                            <keyword> True / False


        """
        ifnm, ofnm, fmt, ext, files = \
            self.make_name(fin, fout, format, extension, files=files, nofile=nofile)
        format = __fmt__

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
            from pcapkit.reassembly.ipv4 import IPv4_Reassembly
            self._reasm[0] = IPv4_Reassembly(strict=strict)
        if self._ipv6:
            from pcapkit.reassembly.ipv6 import IPv6_Reassembly
            self._reasm[1] = IPv6_Reassembly(strict=strict)
        if self._tcp:
            from pcapkit.reassembly.tcp import TCP_Reassembly
            self._reasm[2] = TCP_Reassembly(strict=strict)

        if trace:
            from pcapkit.foundation.traceflow import TraceFlow
            if self._exeng in ('pyshark',) and re.fullmatch('pcap', str(trace_format), re.IGNORECASE):
                warnings.warn("'Extractor(engine={})' does not support 'trace_format={}'; "
                              "using 'trace_format=None' instead".format(self._exeng, trace_format), FormatWarning, stacklevel=stacklevel())
                trace_format = None
            self._trace = TraceFlow(fout=trace_fout, format=trace_format,
                                    byteorder=trace_byteorder, nanosecond=trace_nanosecond)

        self._ifile = open(ifnm, 'rb')                                      # input file
        if not self._flag_q:
            if fmt == 'plist':
                from dictdumper import PLIST as output                      # output PLIST file
            elif fmt == 'json':
                from dictdumper import JSON as output                       # output JSON file
            elif fmt == 'tree':
                from dictdumper import Tree as output                       # output treeview text file
            elif fmt == 'html':
                from dictdumper import JavaScript as output                 # output JavaScript file
            elif fmt == 'xml':
                from dictdumper import XML as output                        # output XML file
            else:
                from pcapkit.dumpkit import NotImplementedIO as output      # no output file
                warnings.warn('unsupported output format: {}; disabled file output feature'.format(fmt),
                              FormatWarning, stacklevel=stacklevel())

            class DictDumper(output):
                @classmethod
                def object_hook(cls, obj):
                    import enum
                    import aenum
                    if isinstance(obj, (enum.IntEnum, aenum.IntEnum)):
                        return 'No.{} {}'.format(obj.value, obj.name)
                    if isinstance(obj, ipaddress._BaseAddress):
                        return str(obj)
                    if isinstance(obj, Info):
                        return dict(obj)
                    return super().object_hook(obj)

            self._ofile = DictDumper if self._flag_f else DictDumper(ofnm)  # output file

        self.check()                    # check layer & protocol
        self.run()                      # start extraction

    def __iter__(self):
        if not self._flag_a:
            return self
        raise IterableError("'Extractor(auto=True)' object is not iterable")

    def __next__(self):
        try:
            return self._read_frame()
        except (EOFError, StopIteration):
            self._cleanup()
            raise StopIteration

    def __call__(self):
        if not self._flag_a:
            try:
                return self._read_frame()
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
            [proc.join() for proc in self._mpprc]
            if self._exeng == 'server':
                self._mpsvc.join()

            # restore attributes
            if self._exeng == 'server':
                self._frame = list(self._mpfrm)
                self._reasm = list(self._mprsm)
                self._trace = copy.deepcopy(self._mpkit.trace)
            if self._exeng == 'pipeline':
                self._frame = [self._mpkit.frames[x] for x in sorted(self._mpkit.frames)]
                self._reasm = copy.deepcopy(self._mpkit.reassembly)
                self._trace = copy.deepcopy(self._mpkit.trace)

            # shutdown & cleanup
            self._mpmng.shutdown()
            [delattr(attr) for attr in filter(lambda s: s.startswith('_mp'), dir(self))]
            self._frnum -= 2
            # map(lambda attr: delattr(self, attr), filter(lambda attr: re.match('^_mp.*', attr), dir(self)))

    def _update_eof(self):
        """Update EOF flag."""
        self._aftermathmp()
        self._ifile.close()
        self._flag_e = True

    def _read_frame(self):
        """Headquarters for frame reader."""
        if self._exeng == 'scapy':
            return self._scapy_read_frame()
        elif self._exeng == 'dpkt':
            return self._dpkt_read_frame()
        elif self._exeng == 'pyshark':
            return self._pyshark_read_frame()
        else:
            return self._default_read_frame()

    def _default_read_frame(self, *, frame=None, mpkit=None):
        """Read frames with default engine.

        - Extract frames and each layer of packets.
        - Make Info object out of frame properties.
        - Append Info.
        - Write plist & append Info.

        """
        from pcapkit.toolkit.default import (ipv4_reassembly, ipv6_reassembly,
                                             tcp_reassembly, tcp_traceflow)

        # read frame header
        if not self._flag_m:
            frame = Frame(self._ifile, num=self._frnum+1, proto=self._dlink,
                          layer=self._exlyr, protocol=self._exptl, nanosecond=self._nnsec)
            self._frnum += 1

        # verbose output
        if self._flag_v:
            print(' - Frame {:>3d}: {}'.format(self._frnum, frame.protochain))

        # write plist
        frnum = 'Frame {}'.format(self._frnum)
        if not self._flag_q:
            if self._flag_f:
                ofile = self._ofile('{}/{}.{}'.format(self._ofnm, frnum, self._fext))
                ofile(frame.info, name=frnum)
            else:
                self._ofile(frame.info, name=frnum)

        # record fragments
        if self._ipv4:
            flag, data = ipv4_reassembly(frame)
            if flag:
                self._reasm[0](data)
        if self._ipv6:
            flag, data = ipv6_reassembly(frame)
            if flag:
                self._reasm[1](data)
        if self._tcp:
            flag, data = tcp_reassembly(frame)
            if flag:
                self._reasm[2](data)

        # trace flows
        if self._flag_t:
            flag, data = tcp_traceflow(frame, data_link=self._dlink)
            if flag:
                self._trace(data)

        # record frames
        if self._exeng == 'pipeline':
            if self._flag_d:
                # frame._file = NotImplemented
                mpkit.frames[self._frnum] = frame
                # print(self._frnum, 'stored')
            mpkit.current += 1
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
            self._proto = frame.protochain.chain

        # return frame record
        return frame

    def _run_scapy(self, scapy_all):
        """Call scapy.all.sniff to extract PCAP files."""
        # if not self._flag_a:
        #     self._flag_a = True
        #     warnings.warn(f"'Extractor(engine=scapy)' object is not iterable; "
        #                     "so 'auto=False' will be ignored", AttributeWarning, stacklevel=stacklevel())

        if self._exlyr != 'None' or self._exptl != 'null':
            warnings.warn("'Extractor(engine=scapy)' does not support protocol and layer threshold; "
                          "'layer={}' and 'protocol={}' ignored".format(self._exlyr, self._exptl),
                          AttributeWarning, stacklevel=stacklevel())

        # extract & analyse file
        self._expkg = scapy_all
        self._extmp = iter(scapy_all.sniff(offline=self._ifnm))

        # start iteration
        self.record_frames()

    def _scapy_read_frame(self):
        """Read frames with Scapy."""
        from pcapkit.toolkit.scapy import (ipv4_reassembly, ipv6_reassembly,
                                           packet2chain, packet2dict, tcp_reassembly,
                                           tcp_traceflow)

        # fetch Scapy packet
        packet = next(self._extmp)

        # verbose output
        self._frnum += 1
        self._proto = packet2chain(packet)
        if self._flag_v:
            print(' - Frame {:>3d}: {}'.format(self._frnum, self._proto))

        # write plist
        frnum = 'Frame {}'.format(self._frnum)
        if not self._flag_q:
            info = packet2dict(packet)
            if self._flag_f:
                ofile = self._ofile('{}/{}.{}'.format(self._ofnm, frnum, self._fext))
                ofile(info, name=frnum)
            else:
                self._ofile(info, name=frnum)

        # record frames
        if self._flag_d:
            # setattr(packet, 'packet2dict', packet2dict)
            # setattr(packet, 'packet2chain', packet2chain)
            self._frame.append(packet)

        # record fragments
        if self._ipv4:
            flag, data = ipv4_reassembly(packet, count=self._frnum)
            if flag:
                self._reasm[0](data)
        if self._ipv6:
            flag, data = ipv6_reassembly(packet, count=self._frnum)
            if flag:
                self._reasm[1](data)
        if self._tcp:
            flag, data = tcp_reassembly(packet, count=self._frnum)
            if flag:
                self._reasm[2](data)

        # trace flows
        if self._flag_t:
            flag, data = tcp_traceflow(packet, count=self._frnum)
            if flag:
                self._trace(data)

        return packet

    def _run_dpkt(self, dpkt):
        """Call dpkt.pcap.Reader to extract PCAP files."""
        # if not self._flag_a:
        #     self._flag_a = True
        #     warnings.warn(f"'Extractor(engine=dpkt)' object is not iterable; "
        #                     "so 'auto=False' will be ignored", AttributeWarning, stacklevel=stacklevel())

        if self._exlyr != 'None' or self._exptl != 'null':
            warnings.warn("'Extractor(engine=dpkt)' does not support protocol and layer threshold; "
                          "'layer={}' and 'protocol={}' ignored".format(self._exlyr, self._exptl),
                          AttributeWarning, stacklevel=stacklevel())

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
        from pcapkit.toolkit.dpkt import (ipv4_reassembly, ipv6_reassembly,
                                          packet2chain, packet2dict, tcp_reassembly,
                                          tcp_traceflow)

        # fetch DPKT packet
        timestamp, packet = next(self._extmp)

        # extract packet
        if self._dlink.value == 1:
            packet = self._expkg.ethernet.Ethernet(packet)
        elif self._dlink.value == 228:
            packet = self._expkg.ip.IP(packet)
        elif self._dlink.value == 229:
            packet = self._expkg.ip6.IP6(packet)
        else:
            warnings.warn('unrecognised link layer protocol; all analysis functions ignored',
                          DPKTWarning, stacklevel=stacklevel())
            self._frnum += 1
            if self._flag_d:
                self._frame.append(packet)
            return packet

        # verbose output
        self._frnum += 1
        self._proto = packet2chain(packet)
        if self._flag_v:
            print(' - Frame {:>3d}: {}'.format(self._frnum, self._proto))

        # write plist
        frnum = 'Frame {}'.format(self._frnum)
        if not self._flag_q:
            info = packet2dict(packet, timestamp, data_link=self._dlink)
            if self._flag_f:
                ofile = self._ofile('{}/{}.{}'.format(self._ofnm, frnum, self._fext))
                ofile(info, name=frnum)
            else:
                self._ofile(info, name=frnum)

        # record frames
        if self._flag_d:
            setattr(packet, 'packet2dict', packet2dict)
            setattr(packet, 'packet2chain', packet2chain)
            self._frame.append(packet)

        # record fragments
        if self._ipv4:
            flag, data = ipv4_reassembly(packet, count=self._frnum)
            if flag:
                self._reasm[0](data)
        if self._ipv6:
            flag, data = ipv6_reassembly(packet, count=self._frnum)
            if flag:
                self._reasm[1](data)
        if self._tcp:
            flag, data = tcp_reassembly(packet, count=self._frnum)
            if flag:
                self._reasm[2](data)

        # trace flows
        if self._flag_t:
            flag, data = tcp_traceflow(packet, timestamp, data_link=self._dlink, count=self._frnum)
            if flag:
                self._trace(data)

        return packet

    def _run_pyshark(self, pyshark):
        """Call pyshark.FileCapture to extract PCAP files."""
        # if not self._flag_a:
        #     self._flag_a = True
        #     warnings.warn(f"'Extractor(engine=pyshark)' object is not iterable; "
        #                     "so 'auto=False' will be ignored", AttributeWarning, stacklevel=stacklevel())

        if self._exlyr != 'None' or self._exptl != 'null':
            warnings.warn("'Extractor(engine=pyshark)' does not support protocol and layer threshold; "
                          "'layer={}' and 'protocol={}' ignored".format(self._exlyr, self._exptl),
                          AttributeWarning, stacklevel=stacklevel())

        if (self._ipv4 or self._ipv6 or self._tcp):
            self._ipv4 = self._ipv6 = self._tcp = False
            self._reasm = [None] * 3
            warnings.warn("'Extractor(engine=pyshark)' object dose not support reassembly; "
                          "so 'ipv4={}', 'ipv6={}' and 'tcp={}' will be ignored".format(self._ipv4, self._ipv6, self._tcp),
                          AttributeWarning, stacklevel=stacklevel())

        # extract & analyse file
        self._expkg = pyshark
        self._extmp = iter(pyshark.FileCapture(self._ifnm, keep_packets=False))

        # start iteration
        self.record_frames()

    def _pyshark_read_frame(self):
        """Read frames."""
        from pcapkit.toolkit.pyshark import packet2dict, tcp_traceflow

        # fetch PyShark packet
        packet = next(self._extmp)

        # def _pyshark_packet2chain(packet):
        #     """Fetch PyShark packet protocol chain."""
        #     return ':'.join(map(lambda layer: layer.layer_name.upper(), packet.layers))

        # verbose output
        self._frnum = int(packet.number)
        self._proto = packet.frame_info.protocols
        if self._flag_v:
            print(' - Frame {:>3d}: {}'.format(self._frnum, self._proto))

        # write plist
        frnum = 'Frame {}'.format(self._frnum)
        if not self._flag_q:
            info = packet2dict(packet)
            if self._flag_f:
                ofile = self._ofile('{}/{}.{}'.format(self._ofnm, frnum, self._fext))
                ofile(info, name=frnum)
            else:
                self._ofile(info, name=frnum)

        # record frames
        if self._flag_d:
            setattr(packet, 'packet2dict', packet2dict)
            self._frame.append(packet)

        # trace flows
        if self._flag_t:
            flag, data = tcp_traceflow(packet)
            if flag:
                self._trace(data)

        return packet

    def _run_pipeline(self, multiprocessing):
        """Use pipeline multiprocessing to extract PCAP files."""
        if not self._flag_m:
            raise UnsupportedCall("Extractor(engine={})' has no attribute '_run_pipline'".format(self._exeng))

        if not self._flag_q:
            self._flag_q = True
            warnings.warn("'Extractor(engine=pipeline)' does not support output; "
                          "'fout={}' ignored".format(self._ofnm), AttributeWarning, stacklevel=stacklevel())

        self._frnum = 1                                                 # frame number (revised)
        self._expkg = multiprocessing                                   # multiprocessing module
        self._mpprc = list()                                            # multiprocessing process list
        self._mpfdp = collections.defaultdict(multiprocessing.Queue)    # multiprocessing file pointer

        self._mpmng = multiprocessing.Manager()                         # multiprocessing manager
        self._mpkit = self._mpmng.Namespace()                           # multiprocessing work kit

        self._mpkit.counter = 0                                         # work count (on duty)
        self._mpkit.pool = 1                                            # work pool (ready)
        self._mpkit.current = 1                                         # current frame number
        self._mpkit.eof = False                                         # EOF flag
        self._mpkit.frames = dict()                                     # frame storage
        self._mpkit.trace = self._trace                                 # flow tracer
        self._mpkit.reassembly = copy.deepcopy(self._reasm)             # reassembly buffers

        # preparation
        self.record_header()
        self._mpfdp[0].put(self._gbhdr.length)

        # extraction
        while True:
            # check EOF
            if self._mpkit.eof:
                self._update_eof()
                break

            # check counter
            if self._mpkit.pool and self._mpkit.counter < CPU_CNT:
                # update file offset
                self._ifile.seek(self._mpfdp.pop(self._frnum-1).get(), os.SEEK_SET)

                # create worker
                # print(self._frnum, 'start')
                proc = multiprocessing.Process(
                    target=self._pipeline_read_frame,
                    kwargs={'mpkit': self._mpkit, 'mpfdp': self._mpfdp[self._frnum]}
                )

                # update status
                self._mpkit.pool -= 1
                self._mpkit.counter += 1

                # start and record
                proc.start()
                self._frnum += 1
                self._mpprc.append(proc)

            # check buffer
            if len(self._mpprc) >= CPU_CNT:
                [proc.join() for proc in self._mpprc[:-4]]
                del self._mpprc[:-4]

    def _pipeline_read_frame(self, *, mpfdp, mpkit):
        """Extract frame."""
        # check EOF
        if self._flag_e:
            raise EOFError

        def _analyse_frame(*, frame, mpkit):
            """Analyse frame."""
            # wait until ready
            while mpkit.current != self._frnum:
                time.sleep(random.randint(0, datetime.datetime.now().second) // 600)

            # analysis and storage
            # print(self._frnum, 'get')
            self._trace = mpkit.trace
            self._reasm = mpkit.reassembly
            self._default_read_frame(frame=frame, mpkit=mpkit)
            # print(self._frnum, 'analysed')
            mpkit.trace = copy.deepcopy(self._trace)
            mpkit.reassembly = copy.deepcopy(self._reasm)
            # print(self._frnum, 'put')

        # extract frame
        try:
            # extraction
            frame = Frame(self._ifile, num=self._frnum, proto=self._dlink, layer=self._exlyr,
                          protocol=self._exptl, nanosecond=self._nnsec, mpkit=mpkit, mpfdp=mpfdp)
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
            raise UnsupportedCall("Extractor(engine={})' has no attribute '_run_server'".format(self._exeng))

        if not self._flag_q:
            self._flag_q = True
            warnings.warn("'Extractor(engine=pipeline)' does not support output; "
                          "'fout={}' ignored".format(self._ofnm), AttributeWarning, stacklevel=stacklevel())

        self._frnum = 1                                                 # frame number (revised)
        self._expkg = multiprocessing                                   # multiprocessing module
        self._mpsvc = NotImplemented                                    # multiprocessing server process
        self._mpprc = list()                                            # multiprocessing process list
        self._mpfdp = collections.defaultdict(multiprocessing.Queue)    # multiprocessing file pointer

        self._mpmng = multiprocessing.Manager()                         # multiprocessing manager
        self._mpbuf = self._mpmng.dict()                                # multiprocessing frame dict
        self._mpfrm = self._mpmng.list()                                # multiprocessing frame storage
        self._mprsm = self._mpmng.list()                                # multiprocessing reassembly buffer

        self._mpkit = self._mpmng.Namespace()                           # multiprocessing work kit
        self._mpkit.counter = 0                                         # work count (on duty)
        self._mpkit.pool = 1                                            # work pool (ready)
        self._mpkit.eof = False                                         # EOF flag
        self._mpkit.trace = None                                        # flow tracer

        # preparation
        self.record_header()
        self._mpfdp[0].put(self._gbhdr.length)
        self._mpsvc = multiprocessing.Process(
            target=self._server_analyse_frame,
            kwargs={'mpfrm': self._mpfrm, 'mprsm': self._mprsm, 'mpbuf': self._mpbuf, 'mpkit': self._mpkit}
        )
        self._mpsvc.start()

        # extraction
        while True:
            # check EOF
            if self._mpkit.eof:
                self._update_eof()
                break

            # check counter
            if self._mpkit.pool and self._mpkit.counter < CPU_CNT - 1:
                # update file offset
                self._ifile.seek(self._mpfdp.pop(self._frnum-1).get(), os.SEEK_SET)

                # create worker
                # print(self._frnum, 'start')
                proc = multiprocessing.Process(
                        target=self._server_extract_frame,
                        kwargs={'mpkit': self._mpkit, 'mpbuf': self._mpbuf, 'mpfdp': self._mpfdp[self._frnum]}
                )

                # update status
                self._mpkit.pool -= 1
                self._mpkit.counter += 1

                # start and record
                proc.start()
                self._frnum += 1
                self._mpprc.append(proc)

            # check buffer
            if len(self._mpprc) >= CPU_CNT - 1:
                [proc.join() for proc in self._mpprc[:-4]]
                del self._mpprc[:-4]

    def _server_extract_frame(self, *, mpfdp, mpkit, mpbuf):
        """Extract frame."""
        # check EOF
        if self._flag_e:
            raise EOFError

        # extract frame
        try:
            frame = Frame(self._ifile, num=self._frnum, proto=self._dlink, layer=self._exlyr,
                          protocol=self._exptl, nanosecond=self._nnsec, mpkit=mpkit, mpfdp=mpfdp)
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
            if frame is EOFError:
                break
            if frame is None:
                continue
            # print(self._frnum, 'get')

            self._default_read_frame(frame=frame)
        mpfrm += self._frame
        mprsm += self._reasm
        mpkit.trace = copy.deepcopy(self._trace)
