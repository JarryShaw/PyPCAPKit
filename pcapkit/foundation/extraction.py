# -*- coding: utf-8 -*-
# pylint: disable=import-outside-toplevel,fixme
"""Extractor for PCAP Files
==============================

:mod:`pcapkit.foundation.extraction` contains
:class:`~pcapkit.foundation.extraction.Extractor` only,
which synthesises file I/O and protocol analysis,
coordinates information exchange in all network layers,
extracts parametres from a PCAP file.

"""
# TODO: implement engine support for pypcap & pycapfile

import collections
import importlib
import os
import sys
from typing import TYPE_CHECKING, cast

from pcapkit.const.reg.linktype import LinkType as RegType_LinkType
from pcapkit.corekit.infoclass import Info
from pcapkit.protocols.misc.pcap.frame import Frame
from pcapkit.protocols.misc.pcap.header import Header
from pcapkit.utilities.exceptions import (CallableError, FileNotFound, FormatError, IterableError,
                                          UnsupportedCall, stacklevel)
from pcapkit.utilities.logging import logger
from pcapkit.utilities.warnings import (AttributeWarning, DPKTWarning, EngineWarning, FormatWarning,
                                        warn)

if TYPE_CHECKING:
    from types import ModuleType, TracebackType
    from typing import Any, BinaryIO, Callable, DefaultDict, Iterator, Optional, TextIO, Type, Union

    from dictdumper.dumper import Dumper
    from dpkt.dpkt import Packet as DPKTPacket
    from pyshark.packet.packet import Packet as PySharkPacket
    from scapy.packet import Packet as ScapyPacket
    from typing_extensions import Literal

    from pcapkit.corekit.version import VersionInfo
    from pcapkit.foundation.reassembly.ip import Datagram as IP_Datagram
    from pcapkit.foundation.reassembly.ipv4 import IPv4_Reassembly
    from pcapkit.foundation.reassembly.ipv6 import IPv6_Reassembly
    from pcapkit.foundation.reassembly.reassembly import Reassembly
    from pcapkit.foundation.reassembly.tcp import Datagram as TCP_Datagram
    from pcapkit.foundation.reassembly.tcp import TCP_Reassembly
    from pcapkit.foundation.traceflow import Index, TraceFlow
    from pcapkit.protocols.protocol import Protocol

    Formats = Literal['pcap', 'json', 'tree', 'plist']
    Engines = Literal['default', 'pcapkit', 'dpkt', 'scapy', 'pyshark']
    Layers = Literal['link', 'internet', 'transport', 'application', 'none']

    Protocols = Union[str, Protocol, Type[Protocol]]
    VerboseHandler = Callable[['Extractor', Union[Frame, ScapyPacket, DPKTPacket, PySharkPacket]], Any]

__all__ = ['Extractor']


class ReassemblyData(Info):
    """Data storage for reassembly."""

    #: IPv4 reassembled data.
    ipv4: 'Optional[tuple[IP_Datagram, ...]]'
    #: IPv6 reassembled data.
    ipv6: 'Optional[tuple[IP_Datagram, ...]]'
    #: TCP reassembled data.
    tcp: 'Optional[tuple[TCP_Datagram, ...]]'

    if TYPE_CHECKING:
        def __init__(self, ipv4: 'Optional[tuple[IP_Datagram, ...]]', ipv6: 'Optional[tuple[IP_Datagram, ...]]', tcp: 'Optional[tuple[TCP_Datagram, ...]]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long


class Extractor:
    """Extractor for PCAP files.

    Notes:
        For supported engines, please refer to
        :meth:`~pcapkit.foundation.extraction.Extractor.run`.

    """
    #: Input file name.
    _ifnm: 'str'
    #: Output file name.
    _ofnm: 'Optional[str]'
    #: Output file extension.
    _fext: 'Optional[str]'

    #: Auto extract flag.
    _flag_a: 'bool'
    #: Store data flag.
    _flag_d: 'bool'
    #: EOF flag.
    _flag_e: 'bool'
    #: Split file flag.
    _flag_f: 'bool'
    #: No output file.
    _flag_q: 'bool'
    #: Trace flag.
    _flag_t: 'bool'
    #: Verbose flag.
    _flag_v: 'bool'

    #: Verbose callback function.
    #_vfunc: 'VerboseHandler'

    #: Frame number.
    _frnum: 'int'
    #: Frame records.
    _frame: 'list[Frame | ScapyPacket | DPKTPacket]'

    #: Frame record for reassembly.
    _reasm: 'list[Optional[Reassembly]]'
    #: Flow tracer.
    _trace: 'Optional[TraceFlow]'

    #: IPv4 reassembly flag.
    _ipv4: 'bool'
    #: IPv6 reassembly flag.
    _ipv6: 'bool'
    #: TCP reassembly flag.
    _tcp: 'bool'

    #: Extract til protocol.
    _exptl: 'Protocols'
    #: Extract til layer.
    _exlyr: 'Layers'
    #: Extract using engine.
    _exeng: 'Engines'
    #: Extract module instance.
    _expkg: 'Any'
    #: Extract iterator instance.
    _extmp: 'Any'

    #: Input file object.
    _ifile: 'BinaryIO'
    #: Output file object.
    _ofile: 'Dumper | Type[Dumper]'

    #: Global header.
    _gbhdr: 'Header'
    #: Version info.
    _vinfo: 'VersionInfo'
    #: Data link layer protocol.
    _dlink: 'RegType_LinkType'
    #: Nanosecond flag.
    _nnsec: 'bool'
    #: Output format.
    _type: 'Formats'

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: DefaultDict[str, tuple[str, str, str | None]]: Format dumper mapping for
    #: writing output files. The values should be a tuple representing the
    #: module name, class name and file extension.
    __output__ = collections.defaultdict(
        lambda: ('pcapkit.dumpkit', 'NotImplementedIO', None),
        {
            'pcap': ('pcapkit.dumpkit', 'PCAPIO', '.pcap'),
            'cap': ('pcapkit.dumpkit', 'PCAPIO', '.pcap'),
            'plist': ('dictdumper', 'PLIST', '.plist'),
            'xml': ('dictdumper', 'PLIST', '.plist'),
            'json': ('dictdumper', 'JSON', '.json'),
            'tree': ('dictdumper', 'Tree', '.txt'),
            'text': ('dictdumper', 'Text', '.txt'),
            'txt': ('dictdumper', 'Tree', '.txt'),
        }
    )  # type: DefaultDict[str, tuple[str, str, str | None]]

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def info(self) -> 'VersionInfo':
        """Version of input PCAP file.

        Raises:
            UnsupportedCall: If :attr:`self._exeng <pcapkit.foundation.extraction.Extractor._exeng>`
                is ``'scapy'`` or ``'pyshark'``, as such engines does not reserve such information.

        """
        if self._exeng in ('scapy', 'pyshark'):
            raise UnsupportedCall(f"'Extractor(engine={self._exeng})' object has no attribute 'info'")
        return self._vinfo

    @property
    def length(self) -> 'int':
        """Frame number (of current extracted frame or all)."""
        return self._frnum

    @property
    def format(self) -> 'Formats':
        """Format of output file.

        Raises:
            UnsupportedCall: If :attr:`self._flag_q <pcapkit.foundation.extraction.Extractor._flag_q>`
                is set as :data:`True`, as output is disabled by initialisation parameter.

        """
        if self._flag_q:
            raise UnsupportedCall("'Extractor(nofile=True)' object has no attribute 'format'")
        return self._type

    @property
    def input(self) -> 'str':
        """Name of input PCAP file."""
        return self._ifnm

    @property
    def output(self) -> 'str':
        """Name of output file.

        Raises:
            UnsupportedCall: If :attr:`self._flag_q <pcapkit.foundation.extraction.Extractor._flag_q>`
                is set as :data:`True`, as output is disabled by initialisation parameter.

        """
        if self._flag_q:
            raise UnsupportedCall("'Extractor(nofile=True)' object has no attribute 'format'")
        return cast('str', self._ofnm)

    @property
    def header(self) -> 'Header':
        """Global header."""
        return self._gbhdr

    @property
    def frame(self) -> 'tuple[Frame, ...]':
        """Extracted frames.

        Raises:
            UnsupportedCall: If :attr:`self._flag_d <pcapkit.foundation.extraction.Extractor._flag_d>`
                is :data:`True`, as storing frame data is disabled.

        """
        if self._flag_d:
            return tuple(self._frame)
        raise UnsupportedCall("'Extractor(store=False)' object has no attribute 'frame'")

    @property
    def reassembly(self) -> 'ReassemblyData':
        """Frame record for reassembly.

        * ``ipv4`` -- tuple of TCP payload fragment (:term:`ipv4.datagram`)
        * ``ipv6`` -- tuple of TCP payload fragment (:term:`ipv6.datagram`)
        * ``tcp`` -- tuple of TCP payload fragment (:term:`tcp.datagram`)

        """
        data = ReassemblyData(
            ipv4=tuple(cast('IPv4_Reassembly', self._reasm[0]).datagram) if self._ipv4 else None,
            ipv6=tuple(cast('IPv6_Reassembly', self._reasm[1]).datagram) if self._ipv6 else None,
            tcp=tuple(cast('TCP_Reassembly', self._reasm[2]).datagram) if self._tcp else None,
        )
        return data

    @property
    def trace(self) -> 'tuple[Index, ...]':
        """Index table for traced flow.

        Raises:
            UnsupportedCall: If :attr:`self._flag_t <pcapkit.foundation.extraction.Extractor._flag_t>`
                is :data:`True`, as TCP flow tracing is disabled.

        """
        if self._flag_t:
            return cast('TraceFlow', self._trace).index
        raise UnsupportedCall("'Extractor(trace=False)' object has no attribute 'trace'")

    @property
    def engine(self) -> 'Engines':
        """PCAP extraction engine."""
        return self._exeng

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def register(cls, format: 'str', module: 'str', class_: 'str', ext: 'str') -> 'None':  # pylint: disable=redefined-builtin
        r"""Register a new dumper class.

        Notes:
            The full qualified class name of the new dumper class
            should be as ``{module}.{class_}``.

        Arguments:
            format: format name
            module: module name
            class\_: class name
            ext: file extension

        """
        cls.__output__[format] = (module, class_, ext)

    def run(self) -> 'None':  # pylint: disable=inconsistent-return-statements
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

        Warns:
            EngineWarning: If the extraction engine is not available. This is either due to
                dependency not installed, or supplied engine unknown.

        """
        if self._exeng == 'dpkt':
            engine = self.import_test('dpkt', name='DPKT')
            if engine is not None:
                return self._run_dpkt(engine)
        elif self._exeng == 'scapy':
            engine = self.import_test('scapy.all', name='Scapy')
            if engine is not None:
                return self._run_scapy(engine)
        elif self._exeng == 'pyshark':
            engine = self.import_test('pyshark', name='PyShark')
            if engine is not None:
                return self._run_pyshark(engine)
        elif self._exeng not in ('default', 'pcapkit'):
            warn(f'unsupported extraction engine: {self._exeng}; '
                 'using default engine instead', EngineWarning, stacklevel=stacklevel())
            self._exeng = 'default'  # using default/pcapkit engine

        self.record_header()  # read PCAP global header
        self.record_frames()  # read frames

    @staticmethod
    def import_test(engine: 'str', *, name: 'Optional[str]' = None) -> 'Optional[ModuleType]':
        """Test import for extractcion engine.

        Args:
            engine: Extraction engine module name.
            name: Extraction engine display name.

        Warns:
            EngineWarning: If the engine module is not installed.

        Returns:
            If succeeded, returns the module; otherwise, returns :data:`None`.

        """
        try:
            module = importlib.import_module(engine)
        except ImportError:
            module = None
            warn(f"extraction engine '{name or engine}' not available; "
                 'using default engine instead', EngineWarning, stacklevel=stacklevel())
        return module

    @classmethod
    def make_name(cls, fin: 'str' = 'in.pcap', fout: 'str' = 'out', fmt: 'Formats' = 'tree',
                  extension: 'bool' = True, *, files: 'bool' = False,
                  nofile: 'bool' = False) -> 'tuple[str, Optional[str], Formats, Optional[str], bool]':
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
            fin: Input filename.
            fout: Output filename.
            fmt: Output file format.
            extension: If append ``.pcap`` file extension to the input filename
                if ``fin`` does not have such file extension; if check and append extensions
                to output file.
            files: If split each frame into different files.
            nofile: If no output file is to be dumped.

        Returns:
            Generated input and output filenames:

            0. input filename
            1. output filename / directory name
            2. output format
            3. output file extension (without ``.``)
            4. if split each frame into different files

        Raises:
            FileNotFound: If input file does not exists.
            FormatError: If output format not provided and cannot be presumpted.

        """
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
            ext = cls.__output__[fmt][2]
            if ext is None:
                raise FormatError(f'unknown output format: {fmt}')

            if (parent := os.path.split(fout)[0]):
                os.makedirs(parent, exist_ok=True)

            if files:
                ofnm = fout
                os.makedirs(ofnm, exist_ok=True)
            elif extension:
                ofnm = fout if os.path.splitext(fout)[1] == ext else f'{fout}{ext}'
            else:
                ofnm = fout

        return ifnm, ofnm, fmt, ext, files

    def record_header(self) -> 'None':
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

        if self._trace is not None:
            self._trace._endian = self._gbhdr.byteorder
            self._trace._nnsecd = self._gbhdr.nanosecond

        if self._flag_q:
            return

        if self._flag_f:
            ofile = self._ofile(f'{self._ofnm}/Global Header.{self._fext}')
            ofile(self._gbhdr.info, name='Global Header')
        else:
            self._ofile(self._gbhdr.info, name='Global Header')
            ofile = self._ofile
        self._type = ofile.kind

    def record_frames(self) -> 'None':
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
    # Data models.
    ##########################################################################

    def __init__(self,
                 fin: 'Optional[str]' = None, fout: 'Optional[str]' = None, format: 'Optional[Formats]' = None,                 # basic settings # pylint: disable=redefined-builtin
                 auto: 'bool' = True, extension: 'bool' = True, store: 'bool' = True,                                           # internal settings # pylint: disable=line-too-long
                 files: 'bool' = False, nofile: 'bool' = False, verbose: 'bool | VerboseHandler' = False,                       # output settings # pylint: disable=line-too-long
                 engine: 'Optional[Engines]' = None, layer: 'Optional[Layers]' = None, protocol: 'Optional[Protocols]' = None,  # extraction settings # pylint: disable=line-too-long
                 ip: 'bool' = False, ipv4: 'bool' = False, ipv6: 'bool' = False, tcp: 'bool' = False, strict: 'bool' = True,    # reassembly settings # pylint: disable=line-too-long
                 trace: 'bool' = False, trace_fout: 'Optional[str]' = None, trace_format: 'Optional[Formats]' = None,           # trace settings # pylint: disable=line-too-long
                 trace_byteorder: 'Literal["big", "little"]' = sys.byteorder, trace_nanosecond: 'bool' = False) -> 'None':      # trace settings # pylint: disable=line-too-long
        """Initialise PCAP Reader.

        Args:
            fin: file name to be read; if file not exist, raise :exc:`FileNotFound`
            fout: file name to be written
            format: file format of output

            auto: if automatically run till EOF
            extension: if check and append extensions to output file
            store: if store extracted packet info

            files: if split each frame into different files
            nofile: if no output file is to be dumped
            verbose: a :obj:`bool` value or a function takes the :class:`Extractor`
                instance and current parsed frame (depends on engine selected) as
                parameters to print verbose output information

            engine: extraction engine to be used
            layer: extract til which layer
            protocol: extract til which protocol

            ip: if record data for IPv4 & IPv6 reassembly
            ipv4: if perform IPv4 reassembly
            ipv6: if perform IPv6 reassembly
            tcp: if perform TCP reassembly
            strict: if set strict flag for reassembly

            trace: if trace TCP traffic flows
            trace_fout: path name for flow tracer if necessary
            trace_format: output file format of flow tracer
            trace_byteorder: output file byte order
            trace_nanosecond: output nanosecond-resolution file flag

        Warns:
            FormatWarning: Warns under following circumstances:

                * If using PCAP output for TCP flow tracing while the extraction engine is PyShark.
                * If output file format is not supported.

        """
        if fin is None:
            fin = 'in.pcap'
        if fout is None:
            fout = 'out'
        if format is None:
            format = 'tree'

        ifnm, ofnm, fmt, oext, files = self.make_name(fin, fout, format, extension, files=files, nofile=nofile)

        self._ifnm = ifnm  # input file name
        self._ofnm = ofnm  # output file name
        self._fext = oext  # output file extension

        self._flag_a = auto    # auto extract flag
        self._flag_d = store   # store data flag
        self._flag_e = False   # EOF flag
        self._flag_f = files   # split file flag
        self._flag_q = nofile  # no output flag
        self._flag_t = trace   # trace flag
        self._flag_v = False   # verbose flag

        # verbose callback function
        if isinstance(verbose, bool):
            self._flag_v = verbose
            if verbose:
                self._vfunc = lambda e, f: print(
                    f'Frame {e._frnum:>3d}: {f.protochain}'  # pylint: disable=protected-access
                )  # pylint: disable=logging-fstring-interpolation
            else:
                self._vfunc = lambda e, f: None
        else:
            self._flag_v = True
            self._vfunc = verbose

        self._frnum = 0   # frame number
        self._frame = []  # frame record

        self._reasm = [None for _ in range(3)]  # frame record for reassembly (IPv4 / IPv6 / TCP)
        self._trace = None                      # flow tracer

        self._ipv4 = ipv4 or ip  # IPv4 Reassembly
        self._ipv6 = ipv6 or ip  # IPv6 Reassembly
        self._tcp = tcp          # TCP Reassembly

        self._exptl = protocol or 'null'                              # extract til protocol
        self._exlyr = cast('Layers', (layer or 'none').lower())       # extract til layer
        self._exeng = cast('Engines', (engine or 'default').lower())  # extract using engine

        if self._ipv4:
            from pcapkit.foundation.reassembly.ipv4 import IPv4_Reassembly
            self._reasm[0] = IPv4_Reassembly(strict=strict)
        if self._ipv6:
            from pcapkit.foundation.reassembly.ipv6 import IPv6_Reassembly
            self._reasm[1] = IPv6_Reassembly(strict=strict)
        if self._tcp:
            from pcapkit.foundation.reassembly.tcp import TCP_Reassembly
            self._reasm[2] = TCP_Reassembly(strict=strict)

        if trace:
            from pcapkit.foundation.traceflow import TraceFlow  # isort: skip
            if self._exeng in ('pyshark',) and trace_format in ('pcap',):
                warn(f"'Extractor(engine={self._exeng})' does not support 'trace_format={trace_format}'; "
                     "using 'trace_format=None' instead", FormatWarning, stacklevel=stacklevel())
                trace_format = None
            self._trace = TraceFlow(fout=trace_fout, format=trace_format,
                                    byteorder=trace_byteorder, nanosecond=trace_nanosecond)

        self._ifile = open(ifnm, 'rb')  # input file # pylint: disable=unspecified-encoding,consider-using-with
        if not self._flag_q:
            module, class_, ext = self.__output__[fmt]
            if ext is None:
                warn(f'Unsupported output format: {fmt}; disabled file output feature',
                     FormatWarning, stacklevel=stacklevel())
            output = getattr(importlib.import_module(module), class_)  # type: Type[Dumper]

            class DictDumper(output):  # type: ignore[valid-type,misc]
                """Customised :class:`~dictdumper.dumper.Dumper` object."""

                def object_hook(self, o: 'Any') -> 'Any':
                    """Convert content for function call.

                    Args:
                        o: object to convert

                    Returns:
                        Converted object.

                    """
                    import datetime
                    import decimal
                    import enum
                    import ipaddress

                    import aenum

                    if isinstance(o, decimal.Decimal):
                        return str(o)
                    if isinstance(o, datetime.timedelta):
                        return o.total_seconds()
                    if isinstance(o, Info):
                        return o.to_dict()
                    if isinstance(o, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                        return str(o)
                    if isinstance(o, (enum.IntEnum, aenum.IntEnum)):
                        return dict(
                            name=f'{type(o).__name__}::{o.name}',
                            value=o.value,
                        )
                    return super().object_hook(o)  # type: ignore[unreachable]

                def default(self, o: 'Any') -> 'Literal["fallback"]':  # pylint: disable=unused-argument
                    """Check content type for function call."""
                    return 'fallback'

                def _append_fallback(self, value: 'Any', file: 'TextIO') -> 'None':
                    if hasattr(value, '__slots__'):
                        new_value = {key: getattr(value, key) for key in value.__slots__}
                    elif hasattr(value, '__dict__'):
                        new_value = vars(value)
                    else:
                        logger.warning('unsupported object type: %s', type(value))
                        new_value = str(value)  # type: ignore[assignment]

                    func = self._encode_func(new_value)
                    func(new_value, file)

            self._ofile = DictDumper if self._flag_f else DictDumper(ofnm)  # output file

        self.run()    # start extraction

    def __iter__(self) -> 'Extractor':
        """Iterate and parse PCAP frame.

        Raises:
            IterableError: If :attr:`self._flag_a <pcapkit.foundation.extraction.Extractor._flag_a>`
                is :data:`True`, as such operation is not applicable.

        """
        if not self._flag_a:
            return self
        raise IterableError("'Extractor(auto=True)' object is not iterable")

    def __next__(self) -> 'Frame | ScapyPacket | DPKTPacket':
        """Iterate and parse next PCAP frame.

        It will call :meth:`_read_frame` to parse next PCAP frame internally,
        until the EOF reached; then it calls :meth:`_cleanup` for the aftermath.

        """
        try:
            return self._read_frame()
        except (EOFError, StopIteration):
            self._cleanup()
            raise StopIteration  # pylint: disable=raise-missing-from

    def __call__(self) -> 'Frame | ScapyPacket | DPKTPacket':
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
                raise error
        raise CallableError("'Extractor(auto=True)' object is not callable")

    def __enter__(self) -> 'Extractor':
        """Uses :class:`Extractor` as a context manager."""
        return self

    def __exit__(self, exc_type: 'Type[BaseException] | None', exc_value: 'BaseException | None',
                 traceback: 'TracebackType | None') -> 'None':  # pylint: disable=unused-argument
        """Close the input file when exits."""
        self._ifile.close()

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _cleanup(self) -> 'None':
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

    def _read_frame(self) -> 'Frame | ScapyPacket | DPKTPacket':
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

    def _default_read_frame(self) -> 'Frame':
        """Read frames with default engine.

        This method performs following operations:

        - extract frames and each layer of packets;
        - make :class:`~pcapkit.corekit.infoclass.Info` object out of frame properties;
        - write to output file with corresponding dumper;
        - reassemble IP and/or TCP datagram;
        - trace TCP flows if any;
        - record frame :class:`~pcapkit.corekit.infoclass.Info` object to frame storage.

        Returns:
            Parsed frame instance.

        """
        from pcapkit.toolkit.default import (ipv4_reassembly, ipv6_reassembly, tcp_reassembly,
                                             tcp_traceflow)

        # read frame header
        frame = Frame(self._ifile, num=self._frnum+1, header=self._gbhdr.info,
                      layer=self._exlyr, protocol=self._exptl, nanosecond=self._nnsec)
        self._frnum += 1

        # verbose output
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
            data_ipv4 = ipv4_reassembly(frame)
            if data_ipv4 is not None:
                cast('IPv4_Reassembly', self._reasm[0])(data_ipv4)
        if self._ipv6:
            data_ipv6 = ipv6_reassembly(frame)
            if data_ipv6 is not None:
                cast('IPv6_Reassembly', self._reasm[1])(data_ipv6)
        if self._tcp:
            data_tcp = tcp_reassembly(frame)
            if data_tcp is not None:
                cast('TCP_Reassembly', self._reasm[2])(data_tcp)

        # trace flows
        if self._flag_t:
            data_tf = tcp_traceflow(frame, data_link=self._dlink)
            if data_tf is not None:
                cast('TraceFlow', self._trace)(data_tf)

        # record frames
        if self._flag_d:
            self._frame.append(frame)

        # return frame record
        return frame

    def _run_scapy(self, scapy_all: 'ModuleType') -> 'None':
        """Call :func:`scapy.all.sniff` to extract PCAP files.

        This method assigns :attr:`self._expkg <Extractor._expkg>` as :mod:`scapy.all`
        and :attr:`self._extmp <Extractor._extmp>` as an iterator from
        :func:`scapy.all.sniff`.

        Args:
            scapy_all: The :mod:`scapy.all` module.

        Warns:
            AttributeWarning: If :attr:`self._exlyr <Extractor._exlyr>` and/or
                :attr:`self._exptl <Extractor._exptl>` is provided as the Scapy
                engine currently does not support such operations.

        """
        if self._exlyr != 'none' or self._exptl != 'null':
            warn("'Extractor(engine=scapy)' does not support protocol and layer threshold; "
                 f"'layer={self._exlyr}' and 'protocol={self._exptl}' ignored",
                 AttributeWarning, stacklevel=stacklevel())

        # setup verbose handler
        if self._flag_v:
            from pcapkit.toolkit.scapy import packet2chain  # isort:skip
            self._vfunc = lambda e, f: print(
                f'Frame {e._frnum:>3d}: {packet2chain(f)}'  # pylint: disable=protected-access
            )  # pylint: disable=logging-fstring-interpolation

        # extract global header
        self.record_header()
        self._ifile.seek(0, os.SEEK_SET)

        # extract & analyse file
        self._expkg = scapy_all
        self._extmp = iter(scapy_all.sniff(offline=self._ifnm))  # type: Iterator[ScapyPacket]

        # start iteration
        self.record_frames()

    def _scapy_read_frame(self) -> 'ScapyPacket':
        """Read frames with Scapy engine.

        Returns:
            Parsed frame instance.

        See Also:
            Please refer to :meth:`_default_read_frame` for more operational information.

        """
        from pcapkit.toolkit.scapy import (ipv4_reassembly, ipv6_reassembly, packet2dict,
                                           tcp_reassembly, tcp_traceflow)

        # fetch Scapy packet
        packet = next(self._extmp)

        # verbose output
        self._frnum += 1
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

        # record fragments
        if self._ipv4:
            data_ipv4 = ipv4_reassembly(packet, count=self._frnum)
            if data_ipv4 is not None:
                cast('IPv4_Reassembly', self._reasm[0])(data_ipv4)
        if self._ipv6:
            data_ipv6 = ipv6_reassembly(packet, count=self._frnum)
            if data_ipv6 is not None:
                cast('IPv6_Reassembly', self._reasm[1])(data_ipv6)
        if self._tcp:
            data_tcp = tcp_reassembly(packet, count=self._frnum)
            if data_tcp is not None:
                cast('TCP_Reassembly', self._reasm[2])(data_tcp)

        # trace flows
        if self._flag_t:
            data_tf = tcp_traceflow(packet, count=self._frnum)
            if data_tf is not None:
                cast('TraceFlow', self._trace)(data_tf)

        # record frames
        if self._flag_d:
            # setattr(packet, 'packet2dict', packet2dict)
            # setattr(packet, 'packet2chain', packet2chain)
            self._frame.append(packet)

        # return frame record
        return packet

    def _run_dpkt(self, dpkt: 'ModuleType') -> 'None':
        """Call :class:`dpkt.pcap.Reader` to extract PCAP files.

        This method assigns :attr:`self._expkg <Extractor._expkg>` as :mod:`dpkt` and
        :attr:`self._extmp <Extractor._extmp>` as an iterator from :class:`dpkt.pcap.Reader`.

        Args:
            dpkt: The :mod:`dpkt` module.

        Warns:
            AttributeWarning: If :attr:`self._exlyr <Extractor._exlyr>` and/or
                :attr:`self._exptl <Extractor._exptl>` is provided as the DPKT
                engine currently does not support such operations.

        """
        if TYPE_CHECKING:
            import dpkt  # type: ignore[no-redef]

        if self._exlyr != 'none' or self._exptl != 'null':
            warn("'Extractor(engine=dpkt)' does not support protocol and layer threshold; "
                 f"'layer={self._exlyr}' and 'protocol={self._exptl}' ignored",
                 AttributeWarning, stacklevel=stacklevel())

        # setup verbose handler
        if self._flag_v:
            from pcapkit.toolkit.dpkt import packet2chain  # isort:skip
            self._vfunc = lambda e, f: print(
                f'Frame {e._frnum:>3d}: {packet2chain(f)}'  # pylint: disable=protected-access
            )  # pylint: disable=logging-fstring-interpolation

        # extract global header
        self.record_header()
        self._ifile.seek(0, os.SEEK_SET)

        if self._dlink == RegType_LinkType.ETHERNET:
            pkg = dpkt.ethernet.Ethernet
        elif self._dlink.value == RegType_LinkType.IPV4:
            pkg = dpkt.ip.IP
        elif self._dlink.value == RegType_LinkType.IPV6:
            pkg = dpkt.ip6.IP6
        else:
            warn('unrecognised link layer protocol; all analysis functions ignored',
                 DPKTWarning, stacklevel=stacklevel())

            class RawPacket(dpkt.dpkt.Packet):  # type: ignore[name-defined]
                """Raw packet."""

                def __len__(self) -> 'int':
                    return len(self.data)

                def __bytes__(self) -> 'bytes':
                    return self.data

                def unpack(self, buf: 'bytes') -> 'None':
                    self.data = buf

            pkg = RawPacket

        # extract & analyse file
        self._expkg = pkg
        self._extmp = iter(dpkt.pcap.Reader(self._ifile))  # type: Iterator[tuple[float, DPKTPacket]]

        # start iteration
        self.record_frames()

    def _dpkt_read_frame(self) -> 'DPKTPacket':
        """Read frames with DPKT engine.

        Returns:
            dpkt.dpkt.Packet: Parsed frame instance.

        See Also:
            Please refer to :meth:`_default_read_frame` for more operational information.

        """
        from pcapkit.toolkit.dpkt import (ipv4_reassembly, ipv6_reassembly, packet2dict,
                                          tcp_reassembly, tcp_traceflow)

        # fetch DPKT packet
        timestamp, pkt = cast('tuple[float, bytes]', next(self._extmp))
        packet = self._expkg(pkt)  # type: DPKTPacket

        # verbose output
        self._frnum += 1
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

        # record fragments
        if self._ipv4:
            data_ipv4 = ipv4_reassembly(packet, count=self._frnum)
            if data_ipv4 is not None:
                cast('IPv4_Reassembly', self._reasm[0])(data_ipv4)
        if self._ipv6:
            data_ipv6 = ipv6_reassembly(packet, count=self._frnum)
            if data_ipv6 is not None:
                cast('IPv6_Reassembly', self._reasm[1])(data_ipv6)
        if self._tcp:
            data_tcp = tcp_reassembly(packet, count=self._frnum)
            if data_tcp is not None:
                cast('TCP_Reassembly', self._reasm[2])(data_tcp)

        # trace flows
        if self._flag_t:
            data_tf = tcp_traceflow(packet, timestamp, data_link=self._dlink, count=self._frnum)
            if data_tf is not None:
                cast('TraceFlow', self._trace)(data_tf)

        # record frames
        if self._flag_d:
            # setattr(packet, 'packet2dict', packet2dict)
            # setattr(packet, 'packet2chain', packet2chain)
            self._frame.append(packet)

        # return frame record
        return packet

    def _run_pyshark(self, pyshark: 'ModuleType') -> 'None':
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
        if self._exlyr != 'none' or self._exptl != 'null':
            warn("'Extractor(engine=pyshark)' does not support protocol and layer threshold; "
                 f"'layer={self._exlyr}' and 'protocol={self._exptl}' ignored",
                 AttributeWarning, stacklevel=stacklevel())

        if (self._ipv4 or self._ipv6 or self._tcp):
            self._ipv4 = self._ipv6 = self._tcp = False
            self._reasm = [None, None, None]
            warn("'Extractor(engine=pyshark)' object dose not support reassembly; "
                 f"so 'ipv4={self._ipv4}', 'ipv6={self._ipv6}' and 'tcp={self._tcp}' will be ignored",
                 AttributeWarning, stacklevel=stacklevel())

        # setup verbose handler
        if self._flag_v:
            self._vfunc = lambda e, f: print(
                f'Frame {e._frnum:>3d}: {f.frame_info.protocols}'  # pylint: disable=protected-access
            )  # pylint: disable=logging-fstring-interpolation

        # extract & analyse file
        self._expkg = pyshark
        self._extmp = iter(pyshark.FileCapture(self._ifnm, keep_packets=False))

        # start iteration
        self.record_frames()

    def _pyshark_read_frame(self) -> 'PySharkPacket':
        """Read frames with PyShark engine.

        Returns:
            Parsed frame instance.

        See Also:
            Please refer to :meth:`_default_read_frame` for more operational information.

        """
        from pcapkit.toolkit.pyshark import packet2dict, tcp_traceflow

        # fetch PyShark packet
        packet = cast('PySharkPacket', next(self._extmp))

        # verbose output
        self._frnum = int(packet.number)
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

        # trace flows
        if self._flag_t:
            data_tf = tcp_traceflow(packet)
            if data_tf is not None:
                cast('TraceFlow', self._trace)(data_tf)

        # record frames
        if self._flag_d:
            # setattr(packet, 'packet2dict', packet2dict)
            self._frame.append(packet)

        # return frame record
        return packet
