# -*- coding: utf-8 -*-
# pylint: disable=import-outside-toplevel,fixme
"""Extractor for PCAP Files
==============================

.. module:: pcapkit.foundation.extraction

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
from typing import TYPE_CHECKING, Generic, TypeVar, cast

from pcapkit.const.reg.linktype import LinkType as Enum_LinkType
from pcapkit.dumpkit.common import _append_fallback as dumpkit_append_fallback
from pcapkit.dumpkit.common import default as dumpkit_default
from pcapkit.dumpkit.common import object_hook as dumpkit_object_hook
from pcapkit.foundation.engines.pcap import PCAP as PCAP_Engine
from pcapkit.foundation.reassembly import ReassemblyManager
from pcapkit.foundation.traceflow import TraceFlowManager
from pcapkit.protocols.misc.pcap.frame import Frame
from pcapkit.protocols.misc.pcap.header import Header
from pcapkit.utilities.exceptions import (CallableError, FileNotFound, FormatError, IterableError,
                                          UnsupportedCall, stacklevel)
from pcapkit.utilities.warnings import EngineWarning, FormatWarning, warn

if TYPE_CHECKING:
    from types import ModuleType, TracebackType
    from typing import IO, Any, Callable, DefaultDict, Optional, Type, Union

    from dictdumper.dumper import Dumper
    from dpkt.dpkt import Packet as DPKTPacket
    from pyshark.packet.packet import Packet as PySharkPacket
    from scapy.packet import Packet as ScapyPacket
    from typing_extensions import Literal

    from pcapkit.corekit.version import VersionInfo
    from pcapkit.foundation.engines.engine import Engine
    from pcapkit.foundation.reassembly.data import ReassemblyData
    from pcapkit.foundation.traceflow.data import TraceFlowData
    from pcapkit.protocols.protocol import Protocol

    Formats = Literal['pcap', 'json', 'tree', 'plist']
    Engines = Literal['default', 'pcapkit', 'dpkt', 'scapy', 'pyshark']
    Layers = Literal['link', 'internet', 'transport', 'application', 'none']

    Protocols = Union[str, Protocol, Type[Protocol]]
    VerboseHandler = Callable[['Extractor', Union[Frame, ScapyPacket, DPKTPacket, PySharkPacket]], Any]

__all__ = ['Extractor']

P = TypeVar('P')


class Extractor(Generic[P]):
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
    _reasm: 'ReassemblyManager'
    #: Flow tracer.
    _trace: 'TraceFlowManager'

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
    #: Extraction engine name.
    _exnam: 'Engines'
    #: Extraction engine instance.
    _exeng: 'Engine[P]'

    #: Input file object.
    _ifile: 'IO[bytes]'
    #: Output file object.
    _ofile: 'Dumper | Type[Dumper]'

    #: Magic number.
    _magic: 'bytes'
    #: Global header.
    _gbhdr: 'Header'
    #: Version info.
    _vinfo: 'VersionInfo'
    #: Data link layer protocol.
    _dlink: 'Enum_LinkType'
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
        },
    )  # type: DefaultDict[str, tuple[str, str, str | None]]

    #: dict[str, tuple[str, str]]: Engine mapping for extracting frames.
    #: The values should be a tuple representing the module name and class name.
    __engine__ = {
        'scapy': ('pcapkit.foundation.engine.scapy', 'Scapy'),
        'dpkt': ('pcapkit.foundation.engine.dpkt', 'DPKT'),
        'pyshark': ('pcapkit.foundation.engine.pyshark', 'PyShark'),
    }  # type: dict[str, tuple[str, str]]

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def info(self) -> 'VersionInfo':
        """Version of input PCAP file.

        Raises:
            UnsupportedCall: If :attr:`self._exnam <pcapkit.foundation.extraction.Extractor._exnam>`
                is ``'scapy'`` or ``'pyshark'``, as such engines does not reserve such information.

        """
        if self._exnam in ('scapy', 'pyshark'):
            raise UnsupportedCall(f"'Extractor(engine={self._exnam})' object has no attribute 'info'")
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

        * ``ipv4`` -- tuple of TCP payload fragment (:term:`reasm.ipv4.datagram`)
        * ``ipv6`` -- tuple of TCP payload fragment (:term:`reasm.ipv6.datagram`)
        * ``tcp`` -- tuple of TCP payload fragment (:term:`reasm.tcp.datagram`)

        """
        data = ReassemblyData(
            ipv4=tuple(self._reasm.ipv4.datagram) if self._ipv4 else None,
            ipv6=tuple(self._reasm.ipv6.datagram) if self._ipv6 else None,
            tcp=tuple(self._reasm.tcp.datagram) if self._tcp else None,
        )
        return data

    @property
    def trace(self) -> 'TraceFlowData':
        """Index table for traced flow."""
        data = TraceFlowData(
            tcp=tuple(self._trace.tcp.index) if self._tcp else None,
        )
        return data

    @property
    def engine(self) -> 'Engine':
        """PCAP extraction engine."""
        return self._exeng

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def register_dumper(cls, format: 'str', module: 'str', class_: 'str', ext: 'str') -> 'None':
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

    @classmethod
    def register_engine(cls, engine: 'str', module: 'str', class_: 'str') -> 'None':
        r"""Register a new extraction engine.

        Notes:
            The full qualified class name of the new extraction engine
            should be as ``{module}.{class_}``.

        Arguments:
            engine: engine name
            module: module name
            class\_: class name

        """
        cls.__engine__[engine] = (module, class_)

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
        if self._exnam in self.__engine__:  # check if engine is supported
            mod, cls = self.__engine__[self._exnam]
            eng = cast('Type[Engine]', getattr(importlib.import_module(mod), cls))

            if self.import_test(eng.module(), name=eng.name()) is not None:
                self._exeng = eng(self)
                self._exeng.run()

                # start iteration
                self.record_frames()
                return

            warn(f'engine {eng.name()} (`{eng.module()}`) is not installed; '
                 'using default engine instead', EngineWarning, stacklevel=stacklevel())
            self._exnam = 'default'  # using default/pcapkit engine

        if self._exnam not in ('default', 'pcapkit'):
            warn(f'unsupported extraction engine: {self._exnam}; '
                 'using default engine instead', EngineWarning, stacklevel=stacklevel())
            self._exnam = 'default'  # using default/pcapkit engine

        self._exeng = cast('Engine[P]', PCAP_Engine(self))
        self._exeng.run()

        # start iteration
        self.record_frames()

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
        if self._magic in PCAP_Engine.MAGIC_NUMBER:
            PCAP_Engine(self).run()
            self._ifile.seek(0, os.SEEK_SET)
            return
        raise FormatError(f'unknown PCAP file format: {self._magic!r}')

    def record_frames(self) -> 'None':
        """Read packet frames.

        The method calls :meth:`self._exeng.read_frame <pcapkit.foundation.engine.engine.Engin.read_frame>`
        to parse each frame from the input PCAP file; and
        performs cleanup by calling :meth:`self._exeng.close <pcapkit.foundation.engine.engine.Engin.close>`
        upon completion of the parsing process.

        Notes:
            Under non-auto mode, i.e. :attr:`self._flag_a <Extractor._flag_a>` is
            :data:`False`, the method performs no action.

        """
        if self._flag_a:
            while True:
                try:
                    self._exeng.read_frame()
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
                 reassembly: 'bool' = False, strict: 'bool' = True,                                                             # reassembly settings # pylint: disable=line-too-long
                 trace: 'bool' = False, trace_fout: 'Optional[str]' = None, trace_format: 'Optional[Formats]' = None,           # trace settings # pylint: disable=line-too-long
                 trace_byteorder: 'Literal["big", "little"]' = sys.byteorder, trace_nanosecond: 'bool' = False,                 # trace settings # pylint: disable=line-too-long
                 ip: 'bool' = False, ipv4: 'bool' = False, ipv6: 'bool' = False, tcp: 'bool' = False) -> 'None':
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

            reassembly: if perform reassembly
            strict: if set strict flag for reassembly

            trace: if trace TCP traffic flows
            trace_fout: path name for flow tracer if necessary
            trace_format: output file format of flow tracer
            trace_byteorder: output file byte order
            trace_nanosecond: output nanosecond-resolution file flag

            ip: if record data for IPv4 & IPv6 reassembly
            ipv4: if perform IPv4 reassembly
            ipv6: if perform IPv6 reassembly
            tcp: if perform TCP reassembly and/or flow tracing

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

        self._flag_a = auto        # auto extract flag
        self._flag_d = store       # store data flag
        self._flag_e = False       # EOF flag
        self._flag_f = files       # split file flag
        self._flag_q = nofile      # no output flag
        self._flag_r = reassembly  # reassembly flag
        self._flag_t = trace       # trace flag
        self._flag_v = False       # verbose flag

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

        self._ipv4 = ipv4 or ip  # IPv4 Reassembly
        self._ipv6 = ipv6 or ip  # IPv6 Reassembly
        self._tcp = tcp          # TCP Reassembly

        self._exptl = protocol or 'null'                              # extract til protocol
        self._exlyr = cast('Layers', (layer or 'none').lower())       # extract til layer
        self._exnam = cast('Engines', (engine or 'default').lower())  # extract using engine

        if reassembly:
            from pcapkit.foundation.reassembly.ipv4 import IPv4 as IPv4_Reassembly
            from pcapkit.foundation.reassembly.ipv6 import IPv6 as IPv6_Reassembly
            from pcapkit.foundation.reassembly.tcp import TCP as TCP_Reassembly

            self._reasm = ReassemblyManager(
                ipv4=IPv4_Reassembly(strict=strict) if self._ipv4 else None,
                ipv6=IPv6_Reassembly(strict=strict) if self._ipv6 else None,
                tcp=TCP_Reassembly(strict=strict) if self._tcp else None,
            )

        if trace:
            from pcapkit.foundation.traceflow.tcp import TCP as TCP_TraceFlow  # isort: skip

            if self._exnam in ('pyshark',) and trace_format in ('pcap',):
                warn(f"'Extractor(engine={self._exnam})' does not support 'trace_format={trace_format}'; "
                     "using 'trace_format=None' instead", FormatWarning, stacklevel=stacklevel())
                trace_format = None

            self._trace = TraceFlowManager(
                tcp=TCP_TraceFlow(fout=trace_fout, format=trace_format, byteorder=trace_byteorder,
                                  nanosecond=trace_nanosecond) if self._tcp else None,
            )

        self._ifile = open(ifnm, 'rb')  # input file # pylint: disable=unspecified-encoding,consider-using-with
        if not self._flag_q:
            module, class_, ext = self.__output__[fmt]
            if ext is None:
                warn(f'Unsupported output format: {fmt}; disabled file output feature',
                     FormatWarning, stacklevel=stacklevel())
            output = getattr(importlib.import_module(module), class_)  # type: Type[Dumper]

            class DictDumper(output):  # type: ignore[valid-type,misc]
                """Customised :class:`~dictdumper.dumper.Dumper` object."""

                object_hook = dumpkit_object_hook
                default = dumpkit_default
                _append_fallback = dumpkit_append_fallback

            self._ofile = DictDumper if self._flag_f else DictDumper(ofnm)  # output file

        self._magic = self._ifile.read(4)  # magic number
        self._ifile.seek(0, os.SEEK_SET)

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

    def __next__(self) -> 'P':
        """Iterate and parse next PCAP frame.

        It will call :meth:`_read_frame` to parse next PCAP frame internally,
        until the EOF reached; then it calls :meth:`_cleanup` for the aftermath.

        """
        try:
            return self._exeng.read_frame()
        except (EOFError, StopIteration):
            self._cleanup()
            raise StopIteration  # pylint: disable=raise-missing-from

    def __call__(self) -> 'P':
        """Works as a simple wrapper for the iteration protocol.

        Raises:
            IterableError: If :attr:`self._flag_a <pcapkit.foundation.extraction.Extractor._flag_a>`
                is :data:`True`, as iteration is not applicable.

        """
        if not self._flag_a:
            try:
                return self._exeng.read_frame()
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
        self._exeng.close()

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
        self._flag_e = True
        self._ifile.close()
        self._exeng.close()
