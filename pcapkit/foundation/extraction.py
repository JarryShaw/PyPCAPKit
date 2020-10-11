# -*- coding: utf-8 -*-
# pylint: disable=import-outside-toplevel,fixme
"""extractor for PCAP files

:mod:`pcapkit.foundation.extraction` contains
:class:`~pcapkit.foundation.extraction.Extractor` only,
which synthesises file I/O and protocol analysis,
coordinates information exchange in all network layers,
extracts parametres from a PCAP file.

"""
# TODO: implement engine support for pypcap & pycapfile

import builtins
import collections
import copy
import datetime
import importlib
import ipaddress
import os
import pathlib
import random
import re
import sys
import time
import warnings

from pcapkit.corekit.infoclass import Info
from pcapkit.protocols.pcap.frame import Frame
from pcapkit.protocols.pcap.header import Header
from pcapkit.utilities.compat import pathlib
from pcapkit.utilities.exceptions import (CallableError, FileNotFound, FormatError, IterableError,
                                          UnsupportedCall, stacklevel)
from pcapkit.utilities.logging import logger
from pcapkit.utilities.warnings import (AttributeWarning, DPKTWarning, EngineWarning, FormatWarning,
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

__all__ = ['Extractor']

# check list
#: List of layers.
LAYER_LIST = {'None', 'Link', 'Internet', 'Transport', 'Application'}
#: List of protocols.
PROTO_LIST = {
    # base protocols
    'null', 'protocol', 'raw',

    # PCAP headers
    'header', 'frame',

    # Link layer
    'link', 'arp', 'inarp', 'ethernet', 'l2tp', 'ospf', 'rarp', 'drarp', 'vlan',

    # Internet layer
    'internet', 'ah', 'hip', 'hopopt', 'ip', 'ipsec', 'ipv4', 'ipv6', 'ipv6_frag',
    'ipv6_opts', 'ipv6_route', 'ipx', 'mh',

    # Transport layer
    'transport', 'tcp', 'udp',

    # Application layer
    'application', 'ftp', 'http', 'httpv1', 'httpv2',
}


# CPU number
if os.name == 'posix' and 'SC_NPROCESSORS_CONF' in os.sysconf_names:
    CPU_CNT = os.sysconf('SC_NPROCESSORS_CONF')
elif 'sched_getaffinity' in os.__all__:  # type: ignore
    CPU_CNT = len(os.sched_getaffinity(0))  # pylint: disable=E1101
else:
    CPU_CNT = os.cpu_count() or 1


class Extractor:
    """Extractor for PCAP files.

    For supported engines, please refer to corresponding driver method for more information:

    * Default drivers:

      * Global header: :meth:`~pcapkit.foundation.extraction.Extractor.record_header`
      * Packet frames: :meth:`~pcapkit.foundation.extraction.Extractor.record_frames`

    * DPKT driver: :meth:`~pcapkit.foundation.extraction.Extractor._run_dpkt`
    * Scapy driver: :meth:`~pcapkit.foundation.extraction.Extractor._run_scapy`
    * PyShark driver: :meth:`~pcapkit.foundation.extraction.Extractor._run_pyshark`
    * Multiprocessing driver:

      * Pipeline model: :meth:`~pcapkit.foundation.extraction.Extractor._run_pipeline`
      * Server model: :meth:`~pcapkit.foundation.extraction.Extractor._run_server`

    """

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def info(self):
        """Version of input PCAP file.

        Raises:
            UnsupportedCall: If :attr:`self._exeng <pcapkit.foundation.extraction.Extractor._exeng>`
                is ``'scapy'`` or ``'pyshark'``, as such engines does not reserve such information.

        :rtype: VersionInfo
        """
        if self._exeng in ('scapy', 'pyshark'):
            raise UnsupportedCall(f"'Extractor(engine={self._exeng})' object has no attribute 'info'")
        return self._vinfo

    @property
    def length(self):
        """Frame number (of current extracted frame or all).

        :rtype: int
        """
        return self._frnum

    @property
    def format(self):
        """Format of output file.

        Raises:
            UnsupportedCall: If :attr:`self._flag_q <pcapkit.foundation.extraction.Extractor._flag_q>`
                is set as :data:`True`, as output is disabled by initialisation parameter.

        :rtype: str
        """
        if self._flag_q:
            raise UnsupportedCall("'Extractor(nofile=True)' object has no attribute 'format'")
        return self._type

    @property
    def input(self):
        """Name of input PCAP file.

        :rtype: str
        """
        return self._ifnm

    @property
    def output(self):
        """Name of output file.

        Raises:
            UnsupportedCall: If :attr:`self._flag_q <pcapkit.foundation.extraction.Extractor._flag_q>`
                is set as :data:`True`, as output is disabled by initialisation parameter.

        :rtype: str
        """
        if self._flag_q:
            raise UnsupportedCall("'Extractor(nofile=True)' object has no attribute 'format'")
        return self._ofnm

    @property
    def header(self):
        """Global header.

        Raises:
            UnsupportedCall: If :attr:`self._exeng <pcapkit.foundation.extraction.Extractor._exeng>`
                is ``'scapy'`` or ``'pyshark'``, as such engines does not reserve such information.

        :rtype: Info[DataType_Header]
        """
        if self._exeng in ('scapy', 'pyshark'):
            raise UnsupportedCall(f"'Extractor(engine={self._exeng})' object has no attribute 'header'")
        return self._gbhdr

    @property
    def protocol(self):
        """Protocol chain of current frame.

        Raises:
            UnsupportedCall: If :attr:`self._flag_a <pcapkit.foundation.extraction.Extractor._flag_a>`
                is :data:`True`, as such attribute is not applicable.

        :rtype: ProtoChain
        """
        if self._flag_a:
            raise UnsupportedCall("'Extractor(auto=True)' object has no attribute 'protocol'")
        return self._proto

    @property
    def frame(self):
        """Extracted frames.

        Raises:
            UnsupportedCall: If :attr:`self._flag_d <pcapkit.foundation.extraction.Extractor._flag_d>`
                is :data:`True`, as storing frame data is disabled.

        :rtype: Tuple[Info[DataType_Frame]]
        """
        if self._flag_d:
            return tuple(self._frame)
        raise UnsupportedCall("'Extractor(store=False)' object has no attribute 'frame'")

    @property
    def reassembly(self):
        """Frame record for reassembly.

        * ``ipv6`` -- tuple of TCP payload fragment (:class:`~pcapkit.reassembly.ipv4.IPv4_Reassembly`)
        * ``ipv4`` -- tuple of TCP payload fragment (:class:`~pcapkit.reassembly.ipv6.IPv6_Reassembly`)
        * ``tcp`` -- tuple of TCP payload fragment (:class:`~pcapkit.reassembly.tcp.TCP_Reassembly`)

        :rtype: Info
        """
        data = Info(
            ipv4=tuple(self._reasm[0].datagram) if self._ipv4 else None,
            ipv6=tuple(self._reasm[1].datagram) if self._ipv6 else None,
            tcp=tuple(self._reasm[2].datagram) if self._tcp else None,
        )
        return data

    @property
    def trace(self):
        """Index table for traced flow.

        Raises:
            UnsupportedCall: If :attr:`self._flag_t <pcapkit.foundation.extraction.Extractor._flag_t>`
                is :data:`True`, as TCP flow tracing is disabled.

        :rtype: Tuple[Info]
        """
        if self._flag_t:
            return self._trace.index
        raise UnsupportedCall("'Extractor(trace=False)' object has no attribute 'trace'")

    @property
    def engine(self):
        """PCAP extraction engine.

        :rtype: str
        """
        return self._exeng

    ##########################################################################
    # Methods.
    ##########################################################################

    def run(self):  # pylint: disable=inconsistent-return-statements
        """Start extraction.

        We uses :meth:`~pcapkit.foundation.extraction.Extractor.import_test` to check if
        a certain engine is available or not. For supported engines, each engine has
        different driver method:

        * Default drivers:

          * Global header: :meth:`~pcapkit.foundation.extraction.Extractor.record_header`
          * Packet frames: :meth:`~pcapkit.foundation.extraction.Extractor.record_frames`

        * DPKT driver: :meth:`~pcapkit.foundation.extraction.Extractor._run_dpkt`
        * Scapy driver: :meth:`~pcapkit.foundation.extraction.Extractor._run_scapy`
        * PyShark driver: :meth:`~pcapkit.foundation.extraction.Extractor._run_pyshark`
        * Multiprocessing driver:

          * Pipeline model: :meth:`~pcapkit.foundation.extraction.Extractor._run_pipeline`
          * Server model: :meth:`~pcapkit.foundation.extraction.Extractor._run_server`

        Warns:
            EngineWarning: If the extraction engine is not available. This is either due to
                dependency not installed, number of CPUs is not enough, or supplied engine
                unknown.

        """
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
                          'using default engine instead', EngineWarning, stacklevel=stacklevel())
        elif self._exeng == 'server':
            flag, engine = self.import_test('multiprocessing', name='Server Multiprocessing')
            self._flag_m = flag = bool(flag and (self._flag_a and CPU_CNT > 2))
            if self._flag_m:
                return self._run_server(engine)
            warnings.warn('extraction engine Server Multiprocessing is not available; '
                          'using default engine instead', EngineWarning, stacklevel=stacklevel())
        elif self._exeng not in ('default', 'pcapkit'):
            flag = False
            warnings.warn(f'unsupported extraction engine: {self._exeng}; '
                          'using default engine instead', EngineWarning, stacklevel=stacklevel())

        # using default/pcapkit engine
        self._exeng = self._exeng if flag else 'default'
        self.record_header()            # read PCAP global header
        self.record_frames()            # read frames

    def check(self):
        """Check layer and protocol thresholds.

        Warns:
            LayerWarning: If :attr:`self._exlyr <pcapkit.foundation.extraction.Extractor._exlyr>`
                is not recognised.
            ProtocolWarning: If :attr:`self._exptl <pcapkit.foundation.extraction.Extractor._exptl>`
                is not recognised.

        See Also:
            * List of available layers: :data:`~pcapkit.foundation.extractor.LAYER_LIST`
            * List of available protocols: :data:`~pcapkit.foundation.extractor.PROTO_LIST`

        """
        layer = self._exlyr
        if layer is not None:
            if layer not in LAYER_LIST:
                warnings.warn(f'unrecognised layer: {layer}', LayerWarning, stacklevel=stacklevel())

        protocol = self._exptl
        if protocol is not None:
            def check_protocol(*args):
                for arg in args:
                    if arg.lower() not in PROTO_LIST:
                        warnings.warn(f'unrecognised protocol: {protocol}', ProtocolWarning, stacklevel=stacklevel())
            if isinstance(protocol, tuple):
                check_protocol(*protocol)
            else:
                check_protocol(protocol)

    @staticmethod
    def import_test(engine, *, name=None):
        """Test import for extractcion engine.

        Args:
            engine (str): Extraction engine module name.

        Keyword Args:
            name (Optional[str]): Extraction engine display name.

        Warns:
            EngineWarning: If the engine module is not installed.

        Returns:
            Tuple[bool, Optional[ModuleType]]: If succeeded, returns :data:`True`
            and the module; otherwise, returns :data:`False` and :data:`None`.

        """
        try:
            engine = importlib.import_module(engine)
            return True, engine
        except ImportError:
            warnings.warn(f"extraction engine '{name or engine}' not available; "
                          'using default engine instead', EngineWarning, stacklevel=stacklevel())
        return False, None

    @classmethod
    def make_name(cls, fin, fout, fmt, extension, *, files=False, nofile=False):
        """Generate input and output filenames.

        The method will perform following processing:

        1. sanitise ``fin`` as the input PCAP filename; ``in.pcap`` as default value and
           append ``.pcap`` extension if needed and ``extension`` is :data:`True`; as well
           as test if the file exists;
        2. if ``nofile`` is :data:`True`, skips following processing;
        3. if ``fmt`` provided, then it presumes corresponding output file extension;
        4. if ``fout`` not provided, it presumes the output file name based on the presumptive
           file extension; the stem of the output file name is set as ``out``; should the file
           extension is not available, then it raises :exc:`~pcapkit.utilities.exceptions.FormatError`;
        5. if ``fout`` provided, it presumes corresponding output format if needed; should the
           presumption cannot be made, then it raises :exc:`~pcapkit.utilities.exceptions.FormatError`;
        6. it will also append corresponding file extension to the output file name if needed
           and ``extension`` is :data:`True`.

        Args:
            fin (Optional[str]): Input filename.
            fout (Optional[str]): Output filename.
            fmt (str): Output file format.
            extension (bool): If append ``.pcap`` file extension to the input filename
                if ``fin`` does not have such file extension; if check and append extensions
                to output file.

        Keyword Args:
            files (bool): If split each frame into different files.
            nofile (bool): If no output file is to be dumped.

        Returns:
            Tuple[str, str, str, str, bool]: Generated input and output filenames:

            0. input filename
            1. output filename / directory name
            2. output format
            3. output file extension (without ``.``)
            4. if split each frame into different files

        Raises:
            FileNotFound: If input file does not exists.
            FormatError: If output format not provided and cannot be presumpted.

        """
        if fin is None:
            ifnm = 'in.pcap'
        else:
            if extension:  # pylint: disable=else-if-used
                ifnm = fin if os.path.splitext(fin)[1] == '.pcap' else f'{fin}.pcap'
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
                if fmt_none:  # pylint: disable=no-else-raise
                    raise FormatError('Output format unspecified.')
                elif files:
                    ofnm = 'out'
                    pathlib.Path(ofnm).mkdir(parents=True, exist_ok=True)
                else:
                    ofnm = f'out.{ext}'
            else:
                fext = os.path.splitext(fout)[1]
                pathlib.Path(os.path.split(fout)[0]).mkdir(parents=True, exist_ok=True)
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
                elif extension:
                    ofnm = f'{fout}.{ext}'
                else:
                    ofnm = fout

        return ifnm, ofnm, fmt, ext, files

    def record_header(self):
        """Read global header.

        The method will parse the PCAP global header and save the parsed result
        as :attr:`self._gbhdr <Extractor._gbhdr>`. Information such as PCAP version,
        data link layer protocol type, nanosecond flag and byteorder will also be
        save the current :class:`Extractor` instance.

        If TCP flow tracing is enabled, the nanosecond flag and byteorder will
        be used for the output PCAP file of the traced TCP flows.

        For output, the method will dump the parsed PCAP global header under
        the name of ``Global Header``.

        """
        # pylint: disable=attribute-defined-outside-init,protected-access
        self._gbhdr = Header(self._ifile)
        self._vinfo = self._gbhdr.version
        self._dlink = self._gbhdr.protocol
        self._nnsec = self._gbhdr.nanosecond

        if self._trace is not NotImplemented:
            self._trace._endian = self._gbhdr.byteorder
            self._trace._nnsecd = self._gbhdr.nanosecond

        if not self._flag_q:
            if self._flag_f:
                ofile = self._ofile(f'{self._ofnm}/Global Header.{self._fext}')
                ofile(self._gbhdr.info, name='Global Header')
                self._type = ofile.kind
            else:
                self._ofile(self._gbhdr.info, name='Global Header')
                self._type = self._ofile.kind

    def record_frames(self):
        """Read packet frames.

        The method calls :meth:`_read_frame` to parse each frame from the input
        PCAP file; and calls :meth:`_cleanup` upon complision.

        Notes:
            Under non-auto mode, i.e. :attr:`self._flag_a <Extractor._flag_a>` is
            :data:`False`, the method performs no action.

        """
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

    def __init__(self,
                 fin=None, fout=None, format=None,                          # basic settings  # pylint: disable=redefined-builtin
                 auto=True, extension=True, store=True,                     # internal settings
                 files=False, nofile=False, verbose=False,                  # output settings
                 engine=None, layer=None, protocol=None,                    # extraction settings
                 ip=False, ipv4=False, ipv6=False, tcp=False, strict=True,  # reassembly settings
                 trace=False, trace_fout=None, trace_format=None,           # trace settings
                 trace_byteorder=sys.byteorder, trace_nanosecond=False):    # trace settings
        """Initialise PCAP Reader.

        Arguments:
            fin (Optiona[str]): file name to be read; if file not exist, raise :exc:`FileNotFound`
            fout (Optiona[str]): file name to be written
            format (Optional[Literal['plist', 'json', 'tree']]): file format of output

            auto (bool): if automatically run till EOF
            extension (bool): if check and append extensions to output file
            store (bool): if store extracted packet info

            files (bool): if split each frame into different files
            nofile (bool): if no output file is to be dumped
            verbose (Union[bool, Callable[[pcapkit.foundation.extraction.Extractor,
                pcapkit.protocol.pcap.frame.Frame]]]): a :obj:`bool` value or a function takes the :class:`Extract`
                instance and current parsed frame (depends on engine selected) as parameters to print verbose output
                information

            engine (Optional[Literal['default', 'pcapkit', 'dpkt', 'scapy', 'pyshark', 'server', 'pipeline']]):
                extraction engine to be used
            layer (Optional[Literal['Link', 'Internet', 'Transport', 'Application']]): extract til which layer
            protocol (Optional[Union[str, Tuple[str], Type[Protocol]]]): extract til which protocol

            ip (bool): if record data for IPv4 & IPv6 reassembly
            ipv4 (bool): if perform IPv4 reassembly
            ipv6 (bool): if perform IPv6 reassembly
            tcp (bool): if perform TCP reassembly
            strict (bool): if set strict flag for reassembly

            trace (bool): if trace TCP traffic flows
            trace_fout (Optional[str]): path name for flow tracer if necessary
            trace_format (Optional[Literal['plist', 'json', 'tree', 'pcap']]): output file
                format of flow tracer
            trace_byteorder (Literal['little', 'big']): output file byte order
            trace_nanosecond (bool): output nanosecond-resolution file flag

        Warns:
            FormatWarning: Warns under following circumstances:

                * If using PCAP output for TCP flow tracing while the extraction engine is PyShark.
                * If output file format is not supported.

        """
        ifnm, ofnm, fmt, ext, files = self.make_name(fin, fout, format, extension, files=files, nofile=nofile)

        # put back builtin
        format = builtins.format

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
        self._flag_v = bool(verbose)    # verbose output flag

        # verbose callback function
        if isinstance(verbose, bool):
            self._vfunc = NotImplemented
        else:
            self._vfunc = verbose

        self._frnum = 0                 # frame number
        self._frame = list()            # frame record
        self._proto = None              # frame ProtoChain

        self._reasm = [None for _ in range(3)]
                                        # frame record for reassembly (IPv4 / IPv6 / TCP)
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
                warnings.warn(f"'Extractor(engine={self._exeng})' does not support 'trace_format={trace_format}'; "
                              "using 'trace_format=None' instead", FormatWarning, stacklevel=stacklevel())
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
            #elif fmt == 'html':
            #    from dictdumper import VueJS as output                      # output JavaScript file
            #elif fmt == 'xml':
            #    from dictdumper import XML as output                        # output XML file
            else:
                from pcapkit.dumpkit import NotImplementedIO as output      # no output file
                warnings.warn(f'unsupported output format: {fmt}; disabled file output feature',
                              FormatWarning, stacklevel=stacklevel())

            class DictDumper(output):
                """Customised :class:`~dictdumper.dumper.Dumper` object."""

                def object_hook(self, o):
                    """Convert content for function call.

                    Args:
                        o (:obj:`Any`): object to convert

                    Returns:
                        :obj:`Any`: the converted object

                    """
                    import enum
                    import aenum

                    if isinstance(o, (enum.IntEnum, aenum.IntEnum)):
                        return dict(
                            enum=type(o).__name__,
                            desc=o.__doc__,
                            name=o.name,
                            value=o.value,
                        )
                    if isinstance(o, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                        return str(o)
                    if isinstance(o, Info):
                        return o.info2dict()
                    return super().object_hook(o)

                def default(self, o):
                    """Check content type for function call."""
                    return 'fallback'

                def _append_fallback(self, value, file):
                    if hasattr(value, '__slots__'):
                        new_value = {key: getattr(value, key) for key in value.__slots__}
                    else:
                        new_value = vars(value)

                    func = self._encode_func(new_value)
                    func(new_value, file)

            self._ofile = DictDumper if self._flag_f else DictDumper(ofnm)  # output file

        self.check()                    # check layer & protocol
        self.run()                      # start extraction

    def __iter__(self):
        """Iterate and parse PCAP frame.

        Raises:
            IterableError: If :attr:`self._flag_a <pcapkit.foundation.extraction.Extractor._flag_a>`
                is :data:`True`, as such operation is not applicable.

        """
        if not self._flag_a:
            return self
        raise IterableError("'Extractor(auto=True)' object is not iterable")

    def __next__(self):
        """Iterate and parse next PCAP frame.

        It will call :meth:`_read_frame` to parse next PCAP frame internally,
        until the EOF reached; then it calls :meth:`_cleanup` for the aftermath.

        """
        try:
            return self._read_frame()
        except (EOFError, StopIteration):
            self._cleanup()
            raise StopIteration

    def __call__(self):
        """Works as a simple wrapper for the iteration protocol.

        Raises:
            IterableError: If :attr:`self._flag_a <pcapkit.foundation.extraction.Extractor._flag_a>`
                is :data:`True`, as iteration is not applicable.

        """
        if not self._flag_a:
            try:
                return self._read_frame()
            except (EOFError, StopIteration) as error:
                self._cleanup()
                raise error from None
        raise CallableError("'Extractor(auto=True)' object is not callable")

    def __enter__(self):
        """Uses :class:`Extractor` as a context manager."""
        return self

    def __exit__(self, exc_type, exc_value, traceback):  # pylint: disable=unused-argument
        """Close the input file when exits."""
        self._ifile.close()

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _cleanup(self):
        """Cleanup after extraction & analysis.

        The method clears the :attr:`self._expkg <Extractor._expkg>` and
        :attr:`self._extmp <Extractor._extmp>` attributes, sets
        :attr:`self._flag_e <pcapkit.foundation.extraction.Extractor._flag_e>`
        as :data:`True` and closes the input file.

        """
        # pylint: disable=attribute-defined-outside-init
        self._expkg = None
        self._extmp = None
        self._flag_e = True
        self._ifile.close()

    def _aftermathmp(self):
        """Aftermath for multiprocessing.

        The method will *join* all child processes forked/spawned as in
        :attr:`self._mpprc <Extractor._mpprc>`, and will *join*
        :attr:`self._mpsrv <Extractor._mpsrv>` server process if using
        multiprocessing server engine.

        For multiprocessing server engine, it will

        * assign :attr:`self._mpfrm <Extractor._mpfrm>` to :attr:`self._frame <Extractor._frame>`
        * assign :attr:`self._mprsm <Extractor._mprsm>` to :attr:`self._reasm <Extractor._reasm>`
        * copy :attr:`self._mpkit.trace <Extractor._mpkit.trace>` to :attr:`self._trace <Extractor._trace>`

        For multiprocessing pipeline engine, it will

        * restore :attr:`self._frame <Extractor._frame>` from :attr:`self._mpkit.frames <Extractor._mpkit.frames>`
        * copy :attr:`self._mpkit.reassembly <Extractor._mpkit.reassembly>` to :attr:`self._reasm <Extractor._reasm>`
        * copy :attr:`self._mpkit.trace <Extractor._mpkit.trace>` to :attr:`self._trace <Extractor._trace>`

        After restoring attributes, it will *shutdown* multiprocessing manager context
        :attr:`self._mpmng <Extractor._mpmng>`, delete all multiprocessing attributes (i.e. starts with `_mp`),
        and deduct the frame number :attr:`self._frnum <Extractor._frnum>` by 2 (*hacking solution*).

        Notes:
            If :attr:`self._flag_e <pcapkit.foundation.extraction.Extractor._flag_e>` is already
            set as :data:`True`, do nothing.

        Raises:
            UnsupportedCall: If :attr:`self._flag_m <pcapkit.foundation.extraction.Extractor._flag_m>`
                is :data:`False`, as such operation is not applicable.

        """
        if not self._flag_m:
            raise UnsupportedCall(f"Extractor(engine={self._exeng})' has no attribute '_aftermathmp'")
        if self._flag_e:
            return

        # join processes
        [proc.join() for proc in self._mpprc]  # pylint: disable=expression-not-assigned
        if self._exeng == 'server':
            self._mpsrv.join()

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
        [delattr(self, attr) for attr in filter(lambda s: s.startswith('_mp'), dir(self))]  # pylint: disable=expression-not-assigned
        self._frnum -= 2

    def _update_eof(self):
        """Update EOF flag.

        This method calls :meth:`_aftermathmp` to cleanup multiproccessing stuff,
        closes the input file and toggle :attr:`self._flag_e <pcapkit.foundation.extraction.Extractor._flag_e>`
        as :data:`True`.

        """
        self._aftermathmp()
        self._ifile.close()
        self._flag_e = True

    def _read_frame(self):
        """Headquarters for frame reader.

        This method is a dispatcher for parsing frames.

        * For Scapy engine, calls :meth:`_scapy_read_frame`.
        * For DPKT engine, calls :meth:`_dpkt_read_frame`.
        * For PyShark engine, calls :meth:`_pyshark_read_frame`.
        * For default (PyPCAPKit) engine, calls :meth:`_default_read_frame`.

        Returns:
            The parsed frame instance.

        """
        if self._exeng == 'scapy':
            return self._scapy_read_frame()
        if self._exeng == 'dpkt':
            return self._dpkt_read_frame()
        if self._exeng == 'pyshark':
            return self._pyshark_read_frame()
        return self._default_read_frame()

    def _default_read_frame(self, *, frame=None, mpkit=None):
        """Read frames with default engine.

        This method performs following operations:

        - extract frames and each layer of packets;
        - make :class:`~pcapkit.corekit.infoclass.Info` object out of frame properties;
        - write to output file with corresponding dumper;
        - reassemble IP and/or TCP datagram;
        - trace TCP flows if any;
        - record frame :class:`~pcapkit.corekit.infoclass.Info` object to frame storage.

        Keyword Args:
            frame (Optional[pcapkit.protocols.pcap.frame.Frame]): The fallback ``frame`` data
                (for multiprocessing engines).
            mpkit (multiprocessing.managers.SyncManager.Namespace): The multiprocess data kit.

        Returns:
            Optional[pcapkit.protocols.pcap.frame.Frame]: Parsed frame instance.

        """
        from pcapkit.toolkit.default import (ipv4_reassembly, ipv6_reassembly,
                                             tcp_reassembly, tcp_traceflow)

        # read frame header
        if not self._flag_m:
            frame = Frame(self._ifile, num=self._frnum+1, proto=self._dlink,
                          layer=self._exlyr, protocol=self._exptl, nanosecond=self._nnsec)
            self._frnum += 1

        # verbose output
        logger.info(f'Frame {self._frnum:>3d}: {frame.protochain}')  # pylint: disable=logging-fstring-interpolation
        if self._flag_v:
            if self._vfunc is NotImplemented:
                print(f' - Frame {self._frnum:>3d}: {frame.protochain}')
            else:
                self._vfunc(self, frame)

        # write plist
        frnum = f'Frame {self._frnum}'
        if not self._flag_q:
            if self._flag_f:
                ofile = self._ofile(f'{self._ofnm}/{frnum}.{self._fext}')
                ofile(frame.info, name=frnum)
            else:
                self._ofile(frame.info, name=frnum)

        # record fragments
        if self._ipv4:
            flag, data = ipv4_reassembly(frame)
            if flag:
                self._reasm[0](data)  # pylint: disable=E1102
        if self._ipv6:
            flag, data = ipv6_reassembly(frame)
            if flag:
                self._reasm[1](data)  # pylint: disable=E1102
        if self._tcp:
            flag, data = tcp_reassembly(frame)
            if flag:
                self._reasm[2](data)  # pylint: disable=E1102

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
        """Call :func:`scapy.all.sniff` to extract PCAP files.

        This method assigns :attr:`self._expkg <Extractor._expkg>` as :mod:`scapy.all`
        and :attr:`self._extmp <Extractor._extmp>` as an iterator from
        :func:`scapy.all.sniff`.

        Args:
            scapy_all (types.ModuleType): The :mod:`scapy.all` module.

        Warns:
            AttributeWarning: If :attr:`self._exlyr <Extractor._exlyr>` and/or
                :attr:`self._exptl <Extractor._exptl>` is provided as the Scapy
                engine currently does not support such operations.

        """
        # pylint: disable=attribute-defined-outside-init
        # if not self._flag_a:
        #     self._flag_a = True
        #     warnings.warn(f"'Extractor(engine=scapy)' object is not iterable; "
        #                     "so 'auto=False' will be ignored", AttributeWarning, stacklevel=stacklevel())

        if self._exlyr != 'None' or self._exptl != 'null':
            warnings.warn("'Extractor(engine=scapy)' does not support protocol and layer threshold; "
                          f"'layer={self._exlyr}' and 'protocol={self._exptl}' ignored",
                          AttributeWarning, stacklevel=stacklevel())

        # extract & analyse file
        self._expkg = scapy_all
        self._extmp = iter(scapy_all.sniff(offline=self._ifnm))

        # start iteration
        self.record_frames()

    def _scapy_read_frame(self):
        """Read frames with Scapy engine.

        Returns:
            scapy.packet.Packet: Parsed frame instance.

        See Also:
            Please refer to :meth:`_default_read_frame` for more operational information.

        """
        from pcapkit.toolkit.scapy import (ipv4_reassembly, ipv6_reassembly,
                                           packet2chain, packet2dict, tcp_reassembly,
                                           tcp_traceflow)

        # fetch Scapy packet
        packet = next(self._extmp)

        # verbose output
        self._frnum += 1
        self._proto = packet2chain(packet)
        logger.info(f'Frame {self._frnum:>3d}: {self._proto}')  # pylint: disable=logging-fstring-interpolation
        if self._flag_v:
            if self._vfunc is NotImplemented:
                print(f' - Frame {self._frnum:>3d}: {self._proto}')
            else:
                self._vfunc(self, packet)

        # write plist
        frnum = f'Frame {self._frnum}'
        if not self._flag_q:
            info = packet2dict(packet)
            if self._flag_f:
                ofile = self._ofile(f'{self._ofnm}/{frnum}.{self._fext}')
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
                self._reasm[0](data)  # pylint: disable=E1102
        if self._ipv6:
            flag, data = ipv6_reassembly(packet, count=self._frnum)
            if flag:
                self._reasm[1](data)  # pylint: disable=E1102
        if self._tcp:
            flag, data = tcp_reassembly(packet, count=self._frnum)
            if flag:
                self._reasm[2](data)  # pylint: disable=E1102

        # trace flows
        if self._flag_t:
            flag, data = tcp_traceflow(packet, count=self._frnum)
            if flag:
                self._trace(data)

        return packet

    def _run_dpkt(self, dpkt):
        """Call :class:`dpkt.pcap.Reader` to extract PCAP files.

        This method assigns :attr:`self._expkg <Extractor._expkg>` as :mod:`dpkt` and
        :attr:`self._extmp <Extractor._extmp>` as an iterator from :class:`dpkt.pcap.Reader`.

        Args:
            dpkt (types.ModuleType): The :mod:`dpkt` module.

        Warns:
            AttributeWarning: If :attr:`self._exlyr <Extractor._exlyr>` and/or
                :attr:`self._exptl <Extractor._exptl>` is provided as the DPKT
                engine currently does not support such operations.

        """
        # pylint: disable=attribute-defined-outside-init
        # if not self._flag_a:
        #     self._flag_a = True
        #     warnings.warn(f"'Extractor(engine=dpkt)' object is not iterable; "
        #                     "so 'auto=False' will be ignored", AttributeWarning, stacklevel=stacklevel())

        if self._exlyr != 'None' or self._exptl != 'null':
            warnings.warn("'Extractor(engine=dpkt)' does not support protocol and layer threshold; "
                          f"'layer={self._exlyr}' and 'protocol={self._exptl}' ignored",
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
        """Read frames with DPKT engine.

        Returns:
            dpkt.dpkt.Packet: Parsed frame instance.

        See Also:
            Please refer to :meth:`_default_read_frame` for more operational information.

        """
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
        logger.info(f'Frame {self._frnum:>3d}: {self._proto}')  # pylint: disable=logging-fstring-interpolation
        if self._flag_v:
            if self._vfunc is NotImplemented:
                print(f' - Frame {self._frnum:>3d}: {self._proto}')
            else:
                self._vfunc(self, packet)

        # write plist
        frnum = f'Frame {self._frnum}'
        if not self._flag_q:
            info = packet2dict(packet, timestamp, data_link=self._dlink)
            if self._flag_f:
                ofile = self._ofile(f'{self._ofnm}/{frnum}.{self._fext}')
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
                self._reasm[0](data)  # pylint: disable=E1102
        if self._ipv6:
            flag, data = ipv6_reassembly(packet, count=self._frnum)
            if flag:
                self._reasm[1](data)  # pylint: disable=E1102
        if self._tcp:
            flag, data = tcp_reassembly(packet, count=self._frnum)
            if flag:
                self._reasm[2](data)  # pylint: disable=E1102

        # trace flows
        if self._flag_t:
            flag, data = tcp_traceflow(packet, timestamp, data_link=self._dlink, count=self._frnum)
            if flag:
                self._trace(data)

        return packet

    def _run_pyshark(self, pyshark):
        """Call :class:`pyshark.FileCapture` to extract PCAP files.

        This method assigns :attr:`self._expkg <Extractor._expkg>` as :mod:`pyshark` and
        :attr:`self._extmp <Extractor._extmp>` as an iterator from :class:`pyshark.FileCapture`.

        Args:
            pyshark (types.ModuleType): The :mod:`pyshark` module.

        Warns:
            AttributeWarning: Warns under following circumstances:

                * if :attr:`self._exlyr <Extractor._exlyr>` and/or
                  :attr:`self._exptl <Extractor._exptl>` is provided as the
                  PyShark engine currently does not support such operations.
                * if reassembly is enabled, as the PyShark engine currently
                  does not support such operation.

        """
        # pylint: disable=attribute-defined-outside-init
        # if not self._flag_a:
        #     self._flag_a = True
        #     warnings.warn(f"'Extractor(engine=pyshark)' object is not iterable; "
        #                     "so 'auto=False' will be ignored", AttributeWarning, stacklevel=stacklevel())

        if self._exlyr != 'None' or self._exptl != 'null':
            warnings.warn("'Extractor(engine=pyshark)' does not support protocol and layer threshold; "
                          f"'layer={self._exlyr}' and 'protocol={self._exptl}' ignored",
                          AttributeWarning, stacklevel=stacklevel())

        if (self._ipv4 or self._ipv6 or self._tcp):
            self._ipv4 = self._ipv6 = self._tcp = False
            self._reasm = [None, None, None]
            warnings.warn("'Extractor(engine=pyshark)' object dose not support reassembly; "
                          f"so 'ipv4={self._ipv4}', 'ipv6={self._ipv6}' and 'tcp={self._tcp}' will be ignored",
                          AttributeWarning, stacklevel=stacklevel())

        # extract & analyse file
        self._expkg = pyshark
        self._extmp = iter(pyshark.FileCapture(self._ifnm, keep_packets=False))

        # start iteration
        self.record_frames()

    def _pyshark_read_frame(self):
        """Read frames with PyShark engine.

        Returns:
            pyshark.packet.packet.Packet: Parsed frame instance.

        Notes:
            This method inserts :func:`~pcapkit.toolkit.pyshark.packet2dict` to the parsed
            frame instance as :meth:`~pyshark.packet.packet.Packet.packet2dict` method.

        See Also:
            Please refer to :meth:`_default_read_frame` for more operational information.

        """
        from pcapkit.toolkit.pyshark import packet2dict, tcp_traceflow

        # fetch PyShark packet
        packet = next(self._extmp)

        # def _pyshark_packet2chain(packet):
        #     """Fetch PyShark packet protocol chain."""
        #     return ':'.join(map(lambda layer: layer.layer_name.upper(), packet.layers))

        # verbose output
        self._frnum = int(packet.number)
        self._proto = packet.frame_info.protocols
        logger.info(f'Frame {self._frnum:>3d}: {self._proto}')  # pylint: disable=logging-fstring-interpolation
        if self._flag_v:
            if self._vfunc is NotImplemented:
                print(f' - Frame {self._frnum:>3d}: {self._proto}')
            else:
                self._vfunc(self, packet)

        # write plist
        frnum = f'Frame {self._frnum}'
        if not self._flag_q:
            info = packet2dict(packet)
            if self._flag_f:
                ofile = self._ofile(f'{self._ofnm}/{frnum}.{self._fext}')
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
        """Use pipeline multiprocessing to extract PCAP files.

        Notes:
            The basic concept of multiprocessing pipeline engine is that we parse the PCAP file as a pipeline.
            Each frame per worker. Once the length of a frame is known, i.e. the PCAP frame header is parsed,
            then we can start a new working and start parsing the next frame concurrently.

            However, as the datagram reassembly and TCP flow tracing require linear sequential processing, we
            still need to *wait* for the completion of analysis on previous frames before proceeding on such
            operations.

        This method assigns :attr:`self._expkg <Extractor._expkg>` as :mod:`multiprocessing`, creates a file
        pointer storage as :attr:`self._mpfdp <Extractor._mpfdp>`, manager context as
        :attr:`self._mpmng <Extractor._mpmng>` and namespace as :attr:`self._mpkit <Extractor._mpkit>`.

        In the namespace, we initiate number of (on duty) workers as ``counter``, pool of (ready) workers
        as ``pool``, current frame number as ``current``, EOF flag as ``eof``, frame storage as ``frames``,
        TCP flow tracer :attr:`self._trace <Extractor._trace>` as ``trace`` and the reassembly buffers
        :attr:`self._reasm <Extractor._reasm>` as ``reassembly``.

        After initial setup, the method calls :meth:`record_header` to parse the PCAP global header and
        *put* the file offset to :attr:`self._mpfdp <Extractor._mpfdp>` as the start of first frame. Then
        it starts the parsing of each PCAP frame.

        During this phrase, it's a :token:`while <while_stmt>` clause until
        :attr:`self._mpkit.eof <Extractor._mpkit.eof>` is set as :data:`True` then it calls :meth:`_update_eof`
        and breaks. In the :token:`while <while_stmt>` clause, it maintains a :class:`multiprocessing.pool.Pool`
        like worker pool. It checks the :attr:`self._mpkit.pool <Extractor._mpkit.pool>` for available workers and
        :attr:`self._mpkit.counter <Extractor._mpkit.counter>` for active workers.

        When starts a new worker, it first update the input file offset to the file offset as specified
        in :attr:`self._mpfdp <Extractor._mpfdp>`. Then creates a child process running :meth:`_pipeline_read_frame`
        with keyword arguments ``mpkit`` as :attr:`self._mpkit <Extractor._mpkit>` and ``mpfdp`` as corresponding
        :class:`~multiprocessing.Queue` from :attr:`self._mpfdp <Extractor._mpfdp>`. Later, it decendants the
        :attr:`self._mpkit.pool <Extractor._mpkit.pool>` and increments the
        :attr:`self._mpkit.counter <Extractor._mpkit.counter>`, both by ``1``. The child process will be appended to
        :attr:`self._mpprc <Extractor._mpprc>`.

        When the number of active workers is greater than or equal to :data:`CPU_CNT`, it waits and *join*
        the leading child processes in :attr:`self._mpprc <Extractor._mpprc>` then removes their reference.

        Args:
            multiprocessing (types.ModuleType): The :mod:`multiprocessing` module.

        Warns:
            AttributeWarning: If :attr:`self._flag_q <pcapkit.foundation.extraction.Extractor._flag_q>`
                is :data:`False`, as multiprocessing engines do not support output.

        Raises:
            UnsupportedCall: If :attr:`self._flag_m <pcapkit.foundation.extraction.Extractor._flag_m>`
                is :data:`False`, as such operation is not applicable.

        """
        # pylint: disable=attribute-defined-outside-init
        if not self._flag_m:
            raise UnsupportedCall(f"Extractor(engine={self._exeng})' has no attribute '_run_pipline'")

        if not self._flag_q:
            self._flag_q = True
            warnings.warn("'Extractor(engine=pipeline)' does not support output; "
                          f"'fout={self._ofnm}' ignored", AttributeWarning, stacklevel=stacklevel())

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
                [proc.join() for proc in self._mpprc[:-4]]  # pylint: disable=expression-not-assigned
                del self._mpprc[:-4]

    def _pipeline_read_frame(self, *, mpfdp, mpkit):
        """Extract frame with multiprocessing pipeline engine.

        The method calls :class:`~pcapkit.protocols.pcap.Frame` to parse the PCAP frame data.
        Should :exc:`EOFError` raised, it will toggle :attr:`self._mpkit.eof <Extractor._mpkit.eof>` as
        :data:`True`. Finally, it will decendant :attr:`self.mpkit.counter <Extractor.mpkit.counter>` by
        ``1`` and closes the input source file (as the child process exits).

        For the parsed :class:`~pcapkit.protocols.pcap.Frame` instance, the instant will first wait
        until :attr:`self.mpkit.current <Extractor.mpkit.current>` is the same as
        :attr:`self._frnum <Extractor._frnum>`, i.e. it's now time to process the parsed frame as in a
        linear sequential order.

        It will proceed by calling :meth:`_default_read_frame`, whilst temporarily assigning
        :attr:`self.mpkit.trace <Extractor.mpkit.trace>` to :attr:`self._trace <Extractor._trace>` and
        :attr:`self.mpkit.reassembly <Extractor.mpkit.reassembly>` to :attr:`self._reasm <Extractor._reasm>`
        then put back.

        Keyword Args:
            mpfdp (multiprocessing.Queue): :class:`~multiprocessing.Queue` for multiprocessing file pointer (offset).
            mpkit (multiprocessing.managers.SyncManager.Namespace):
                :class:`~multiprocessing.managers.SyncManager.Namespace` instance as
                :attr:`self._mpkit <Extractor._mpkit>`.

        Raise:
            EOFError: If :attr:`self._flag_e <pcapkit.foundation.extraction.Extractor._flag_e>`
                is :data:`True`, as the parsing had finished.

        """
        # check EOF
        if self._flag_e:
            raise EOFError

        def _analyse_frame(*, frame, mpkit):
            """Analyse frame."""
            # wait until ready
            while mpkit.current != self._frnum:
                time.sleep(random.randint(0, datetime.datetime.now().second) // 600)  # nosec

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
        """Use server multiprocessing to extract PCAP files.

        Notes:
            The basic concept of multiprocessing server engine is that we further separate the logic of
            PCAP frame parsing and analysis/processing, comparing to the multiprocessing pipeline engine
            (c.f. :meth:`_run_pipeline`).

            We starts a *server* process to perform the datagram reassembly and TCP flow tracing, etc. of
            all parsed PCAP frames, whilst parsing each PCAP frame in the same manner as in multiprocessing
            pipeline engine, i.e. each frame per worker.

        This method assigns :attr:`self._expkg <Extractor._expkg>` as :mod:`multiprocessing`, creates a file
        pointer storage as :attr:`self._mpfdp <Extractor._mpfdp>`, manager context as
        :attr:`self._mpmng <Extractor._mpmng>` and namespace as :attr:`self._mpkit <Extractor._mpkit>`. We will
        also maintain the active process list :attr:`self._mpprc <Extractor._mpprc>` as in :meth:`_run_pipeline`.

        It will also creates a :obj:`dict` as :attr:`self._mpbuf <Extractor._mpbuf>`, frame buffer (temporary
        storage) for the server process to obtain the parsed frames; a :obj:`list` as
        :attr:`self._mpfrm <Extractor._mpfrm>`, eventual frame storage; and another :obj:`list` as
        :attr:`self._mprsm <Extractor._mprsm>`, storing the reassembly buffers :attr:`self._reasm <Extractor._reasm>`
        before the server process exits.

        In the namespace, we initiate number of (on duty) workers as ``counter``, pool of (ready) workers
        as ``pool``, current frame number as ``current``, EOF flag as ``eof``, frame storage as ``frames``,
        and ``trace`` for storing TCP flow tracer :attr:`self._trace <Extractor._trace>` before the server process
        exits.

        After initial setup, the method calls :meth:`record_header` to parse the PCAP global header and
        *put* the file offset to :attr:`self._mpfdp <Extractor._mpfdp>` as the start of first frame. It will then
        starts the server process :attr:`self._mpsrv <Extractor._mpsrv>` from :meth:`_server_analyse_frame`. Finally,
        it starts the parsing of each PCAP frame.

        During this phrase, it's a :token:`while <while_stmt>` clause until
        :attr:`self._mpkit.eof <Extractor._mpkit.eof>` is set as :data:`True` then it calls :meth:`_update_eof` and
        breaks. In the :token:`while <while_stmt>` clause, it maintains a :class:`multiprocessing.pool.Pool` like
        worker pool. It checks the :attr:`self._mpkit.pool <Extractor._mpkit.pool>` for available workers and
        :attr:`self._mpkit.counter <Extractor._mpkit.counter>` for active workers.

        When starts a new worker, it first update the input file offset to the file offset as specified
        in :attr:`self._mpfdp <Extractor._mpfdp>`. Then creates a child process running :meth:`_server_extract_frame`
        with keyword arguments ``mpkit`` as :attr:`self._mpkit <Extractor._mpkit>`, `mpbuf` as
        :attr:`self._mpbuf <Extractor._mpbuf>` and ``mpfdp`` as corresponding :class:`~multiprocessing.Queue` from
        :attr:`self._mpfdp <Extractor._mpfdp>`. Later, it decendants the
        :attr:`self._mpkit.pool <Extractor._mpkit.pool>` and increments the
        :attr:`self._mpkit.counter <Extractor._mpkit.counter>`, both by ``1``. The child process will
        be appended to :attr:`self._mpprc <Extractor._mpprc>`.

        When the number of active workers is greater than or equal to :data:`CPU_CNT`, it waits and *join*
        the leading child processes in :attr:`self._mpprc <Extractor._mpprc>` then removes their reference.

        Args:
            multiprocessing (types.ModuleType): The :mod:`multiprocessing` module.

        Warns:
            AttributeWarning: If :attr:`self._flag_q <pcapkit.foundation.extraction.Extractor._flag_q>`
                is :data:`False`, as multiprocessing engines do not support output.

        Raises:
            UnsupportedCall: If :attr:`self._flag_m <pcapkit.foundation.extraction.Extractor._flag_m>`
                is :data:`False`, as such operation is not applicable.

        """
        # pylint: disable=attribute-defined-outside-init
        if not self._flag_m:
            raise UnsupportedCall(f"Extractor(engine={self._exeng})' has no attribute '_run_server'")

        if not self._flag_q:
            self._flag_q = True
            warnings.warn("'Extractor(engine=pipeline)' does not support output; "
                          f"'fout={self._ofnm}' ignored", AttributeWarning, stacklevel=stacklevel())

        self._frnum = 1                                                 # frame number (revised)
        self._expkg = multiprocessing                                   # multiprocessing module
        self._mpsrv = NotImplemented                                    # multiprocessing server process
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
        self._mpsrv = multiprocessing.Process(
            target=self._server_analyse_frame,
            kwargs={'mpfrm': self._mpfrm, 'mprsm': self._mprsm, 'mpbuf': self._mpbuf, 'mpkit': self._mpkit}
        )
        self._mpsrv.start()

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
                [proc.join() for proc in self._mpprc[:-4]]  # pylint: disable=expression-not-assigned
                del self._mpprc[:-4]

    def _server_extract_frame(self, *, mpfdp, mpkit, mpbuf):
        """Extract frame using multiprocessing server engine.

        The method calls :class:`~pcapkit.protocols.pcap.Frame` to parse the PCAP frame data. The
        parsed frame will be saved to ``mpbuf`` under the corresponding frame number
        :attr:`self._frnum <Extractor._frnum>`.

        Should :exc:`EOFError` raised, it will toggle :attr:`self._mpkit.eof <Extractor._mpkit.eof>`
        as :data:`True`, and save :exc:`EOFError` object to ``mpbuf`` under the corresponding frame
        number :attr:`self._frnum <Extractor._frnum>`.

        Finally, it will decendant :attr:`self.mpkit.counter <Extractor.mpkit.counter>` by ``1`` and
        closes the input source file (as the child process exits).

        Args:
            mpfdp (multiprocessing.Queue): :class:`~multiprocessing.Queue` for multiprocessing file pointer (offset).
            mpkit (multiprocessing.managers.SyncManager.Namespace):
                :class:`~multiprocessing.managers.SyncManager.Namespace` instance as :attr:`_mpkit`.
            mpbuf (multiprocessing.managers.SyncManager.dict): Frame buffer (temporary storage) for the server process
                :attr:`self._mpsrv <Extractor._mpsrv>` to obtain the parsed frames.

        Raise:
            EOFError: If :attr:`self._flag_e <pcapkit.foundation.extraction.Extractor._flag_e>`
                is :data:`True`, as the parsing had finished.

        """
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
        """Analyse frame using multiprocessing server engine.

        This method starts a :token:`while <while_stmt>` clause. For each round, it will *pop* the frame
        :attr:`self._frnum <Extractor._frnum>` from ``mpbuf`` then calls :meth:`_default_read_frame` to perform
        datagram reassembly and TCP flow tracing, etc.

        Once the frame popped is :exc:`EOFError`, i.e. the frame parsing had finished, it
        breaks from the clause and updates ``mpfrm`` with :attr:`self._frame <Extractor._frame>`, ``mprsm`` with
        :attr:`self._reasm <Extractor._reasm>`, and ``mpkit.trace`` with :attr:`self._trace <Extractor._trace>`.

        Keyword Args:
            mpkit (multiprocessing.managers.SyncManager.Namespace):
                :class:`~multiprocessing.managers.SyncManager.Namespace` instance as :attr:`_mpkit`.
            mpfrm (multiprocessing.managers.SyncManager.list): Frame storage.
            mprsm (multiprocessing.managers.SyncManager.list): Reassembly buffers.
            mpbuf (multiprocessing.managers.SyncManager.dict): Frame buffer (temporary storage) for the server process
                :attr:`self._mpsrv <Extractor._mpsrv>` to obtain the parsed frames.

        """
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
