# -*- coding: utf-8 -*-
# pylint: disable=import-outside-toplevel,fixme
# mypy: disable-error-code=dict-item
"""Extractor for PCAP Files
==============================

.. module:: pcapkit.foundation.extraction

:mod:`pcapkit.foundation.extraction` contains
:class:`~pcapkit.foundation.extraction.Extractor` only,
which synthesises file I/O and protocol analysis,
coordinates information exchange in all network layers,
extracts parametres from a PCAP file.

"""
import collections
import importlib
import io
import os
import sys
from typing import TYPE_CHECKING, Generic, TypeVar, cast

from dictdumper.dumper import Dumper

from pcapkit.corekit.io import SeekableReader
from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.dumpkit.common import make_dumper
from pcapkit.foundation.engines.engine import Engine
from pcapkit.foundation.engines.pcap import PCAP as PCAP_Engine
from pcapkit.foundation.engines.pcapng import PCAPNG as PCAPNG_Engine
from pcapkit.foundation.reassembly import ReassemblyManager
from pcapkit.foundation.reassembly.data import ReassemblyData
from pcapkit.foundation.reassembly.reassembly import Reassembly
from pcapkit.foundation.traceflow import TraceFlowManager
from pcapkit.foundation.traceflow.data import TraceFlowData
from pcapkit.foundation.traceflow.traceflow import TraceFlow
from pcapkit.utilities.exceptions import (CallableError, FileNotFound, FormatError, IterableError,
                                          RegistryError, UnsupportedCall, stacklevel)
from pcapkit.utilities.logging import logger
from pcapkit.utilities.warnings import (EngineWarning, ExtractionWarning, FormatWarning,
                                        RegistryWarning, warn)

if TYPE_CHECKING:
    from io import BufferedReader
    from types import ModuleType, TracebackType
    from typing import IO, Any, Callable, DefaultDict, Optional, Type, Union

    from dpkt.dpkt import Packet as DPKTPacket
    from pyshark.packet.packet import Packet as PySharkPacket
    from scapy.packet import Packet as ScapyPacket
    from typing_extensions import Literal

    from pcapkit.foundation.reassembly.ipv4 import IPv4 as IPv4_Reassembly
    from pcapkit.foundation.reassembly.ipv6 import IPv6 as IPv6_Reassembly
    from pcapkit.foundation.reassembly.tcp import TCP as TCP_Reassembly
    from pcapkit.foundation.traceflow.tcp import TCP as TCP_TraceFlow
    from pcapkit.protocols.misc.pcap.frame import Frame
    from pcapkit.protocols.misc.pcapng import PCAPNG
    from pcapkit.protocols.protocol import ProtocolBase as Protocol

    Formats = Literal['pcap', 'json', 'tree', 'plist']
    Engines = Literal['default', 'pcapkit', 'dpkt', 'scapy', 'pyshark']
    Layers = Literal['link', 'internet', 'transport', 'application', 'none']

    Packet = Union[Frame, PCAPNG, ScapyPacket, DPKTPacket, PySharkPacket]

    Protocols = Union[str, Protocol, Type[Protocol]]
    VerboseHandler = Callable[['Extractor', Packet], Any]

__all__ = ['Extractor']

_P = TypeVar('_P')


class Extractor(Generic[_P]):
    """Extractor for PCAP files.

    Notes:
        For supported engines, please refer to
        :meth:`~pcapkit.foundation.extraction.Extractor.run`.

    """
    if TYPE_CHECKING:
        #: Input file name.
        _ifnm: 'str'
        #: Output file name.
        _ofnm: 'Optional[str]'
        #: Output file extension.
        _fext: 'Optional[str]'

        #: Auto extract flag. It indicates if the extraction process should
        #: continue automatically until the EOF is reached.
        _flag_a: 'bool'
        #: Store data flag. It indicates if the extracted frames should be
        #: stored in memory.
        _flag_d: 'bool'
        #: EOF flag. It indicates if the EOF is reached.
        _flag_e: 'bool'
        #: Split file flag, i.e. dump each frame into different files.
        _flag_f: 'bool'
        #: No output file, i.e., no output file is to be generated.
        _flag_q: 'bool'
        #: Trace flag. It indicates if the flow tracing is enabled.
        _flag_t: 'bool'
        #: Verbose flag. This is used to determine if the verbose callback
        #: function should be called at each frame.
        _flag_v: 'bool'
        #: No EOF flag. It is useful when the input file is a live capture,
        #: as the extraction process will not stop until the user interrupt
        #: the process.
        _flag_n: 'bool'
        #: Input filename flag. It indicates if the input file is a file
        #: name or a binary IO object. For the latter, we should not close
        #: the file object after extraction.
        _flag_s: 'bool'

        #: Verbose callback function.
        #_vfunc: 'VerboseHandler'

        #: Frame number.
        _frnum: 'int'
        #: Frame records.
        _frame: 'list[Packet]'

        #: Frame record for reassembly.
        _reasm: 'ReassemblyManager'
        #: Frame record for flow tracing.
        _trace: 'TraceFlowManager'

        #: IPv4 flag. It indicates if the IPv4 reassembly and/or flow tracing
        #: is enabled.
        _ipv4: 'bool'
        #: IPv6 flag. It indicates if the IPv6 reassembly and/or flow tracing
        #: is enabled.
        _ipv6: 'bool'
        #: TCP flag. It indicates if the TCP reassembly and/or flow tracing
        #: is enabled.
        _tcp: 'bool'

        #: Extract til protocol.
        _exptl: 'Protocols'
        #: Extract til layer.
        _exlyr: 'Layers'
        #: Extraction engine name.
        _exnam: 'Engines'
        #: Extraction engine instance.
        _exeng: 'Engine[_P]'

        #: Input file object.
        _ifile: 'BufferedReader'
        #: Output file object.
        _ofile: 'Dumper | Type[Dumper]'

        #: Magic number.
        _magic: 'bytes'
        #: Output format.
        _offmt: 'Formats'

    #: List of potential PCAP file extentions.
    PCAP_EXT = ['.pcap', '.cap', '.pcapng']

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Format dumper mapping for writing output files. The values should be a
    #: tuple representing the module name and class name, or a
    #: :class:`dictdumper.dumper.Dumper` subclass, and corresponding file extension.
    __output__ = collections.defaultdict(
        lambda: (ModuleDescriptor('pcapkit.dumpkit', 'NotImplementedIO'), None),
        {
            'pcap': (ModuleDescriptor('pcapkit.dumpkit', 'PCAPIO'), '.pcap'),
            'cap': (ModuleDescriptor('pcapkit.dumpkit', 'PCAPIO'), '.pcap'),
            'plist': (ModuleDescriptor('dictdumper', 'PLIST'), '.plist'),
            'xml': (ModuleDescriptor('dictdumper', 'PLIST'), '.plist'),
            'json': (ModuleDescriptor('dictdumper', 'JSON'), '.json'),
            'tree': (ModuleDescriptor('dictdumper', 'Tree'), '.txt'),
            'text': (ModuleDescriptor('dictdumper', 'Text'), '.txt'),
            'txt': (ModuleDescriptor('dictdumper', 'Tree'), '.txt'),
        },
    )  # type: DefaultDict[str, tuple[ModuleDescriptor[Dumper] | Type[Dumper], str | None]]

    #: Engine mapping for extracting frames. The values should be a tuple representing
    #: the module name and class name, or an :class:`~pcapkit.foundation.engines.engine.Engine`
    #: subclass.
    __engine__ = {
        'scapy': ModuleDescriptor('pcapkit.foundation.engines.scapy', 'Scapy'),
        'dpkt': ModuleDescriptor('pcapkit.foundation.engines.dpkt', 'DPKT'),
        'pyshark': ModuleDescriptor('pcapkit.foundation.engines.pyshark', 'PyShark'),
    }  # type: dict[str, ModuleDescriptor[Engine] | Type[Engine]]

    #: Reassembly support mapping for extracting frames. The values should be a tuple
    #: representing the module name and class name, or a :class:`~pcapkit.foundation.reassembly.reassembly.Reassembly`
    #: subclass.
    __reassembly__ = {
        'ipv4': ModuleDescriptor('pcapkit.foundation.reassembly.ipv4', 'IPv4'),
        'ipv6': ModuleDescriptor('pcapkit.foundation.reassembly.ipv6', 'IPv6'),
        'tcp': ModuleDescriptor('pcapkit.foundation.reassembly.tcp', 'TCP'),
    }  # type: dict[str, ModuleDescriptor[Reassembly] | Type[Reassembly]]

    #: Flow tracing support mapping for extracting frames. The values should be a tuple
    #: representing the module name and class name, or a :class:`~pcapkit.foundation.traceflow.traceflow.TraceFlow`
    #: subclass.
    __traceflow__ = {
        'tcp': ModuleDescriptor('pcapkit.foundation.traceflow.tcp', 'TCP'),
    }  # type: dict[str, ModuleDescriptor[TraceFlow] | Type[TraceFlow]]

    ##########################################################################
    # Properties.
    ##########################################################################

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
        return self._offmt

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
    def frame(self) -> 'tuple[Packet, ...]':
        """Extracted frames.

        Raises:
            UnsupportedCall: If :attr:`self._flag_d <pcapkit.foundation.extraction.Extractor._flag_d>`
                is :data:`False`, as storing frame data is disabled.

        """
        if self._flag_d:
            return tuple(self._frame)
        raise UnsupportedCall("'Extractor(store=False)' object has no attribute 'frame'")

    @property
    def reassembly(self) -> 'ReassemblyData':
        """Frame record for reassembly.

        * ``ipv4`` -- tuple of IPv4 payload fragment (:term:`reasm.ipv4.datagram`)
        * ``ipv6`` -- tuple of IPv6 payload fragment (:term:`reasm.ipv6.datagram`)
        * ``tcp`` -- tuple of TCP payload fragment (:term:`reasm.tcp.datagram`)

        Raises:
            UnsupportedCall: If :attr:`self._flag_r <pcapkit.foundation.extraction.Extractor._flag_r>`
                is :data:`False`, as reassembly is disabled.

        """
        if self._flag_r:
            data = ReassemblyData(
                ipv4=tuple(self._reasm.ipv4.datagram) if self._ipv4 else None,
                ipv6=tuple(self._reasm.ipv6.datagram) if self._ipv6 else None,
                tcp=tuple(self._reasm.tcp.datagram) if self._tcp else None,
            )
            return data
        raise UnsupportedCall("'Extractor(reassembly=False)' object has no attribute 'reassembly'")

    @property
    def trace(self) -> 'TraceFlowData':
        """Index table for traced flow.

        * ``tcp`` -- tuple of TCP flows (:term:`trace.tcp.index`)

        Raises:
            UnsupportedCall: If :attr:`self._flag_t <pcapkit.foundation.extraction.Extractor._flag_t>`
                is :data:`False`, as flow tracing is disabled.

        """
        if self._flag_t:
            data = TraceFlowData(
                tcp=tuple(self._trace.tcp.index) if self._tcp else None,
            )
            return data
        raise UnsupportedCall("'Extractor(trace=False)' object has no attribute 'trace'")

    @property
    def engine(self) -> 'Engine':
        """PCAP extraction engine."""
        return self._exeng

    @property
    def magic_number(self) -> 'bytes':
        """Magic number of input PCAP file."""
        return self._magic

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def register_dumper(cls, format: 'str', dumper: 'ModuleDescriptor[Dumper] | Type[Dumper]', ext: 'str') -> 'None':
        r"""Register a new dumper class.

        Notes:
            The full qualified class name of the new dumper class
            should be as ``{dumper.module}.{dumper.name}``.

        Arguments:
            format: format name
            dumper: module descriptor or a :class:`dictdumper.dumper.Dumper` subclass
            ext: file extension

        """
        if isinstance(dumper, ModuleDescriptor):
            dumper = dumper.klass
        if not issubclass(dumper, Dumper):
            raise RegistryError(f'dumper must be a Dumper subclass, not {dumper!r}')
        if format in cls.__output__:
            warn(f'dumper {format} already registered, overwriting', RegistryWarning)
        cls.__output__[format] = (dumper, ext)

    @classmethod
    def register_engine(cls, name: 'str', engine: 'ModuleDescriptor[Engine] | Type[Engine]') -> 'None':
        r"""Register a new extraction engine.

        Notes:
            The full qualified class name of the new extraction engine
            should be as ``{engine.module}.{engine.name}``.

        Arguments:
            name: engine name
            engine: module descriptor or an
                :class:`~pcapkit.foundation.engines.engine.Engine` subclass

        """
        if isinstance(engine, ModuleDescriptor):
            engine = engine.klass
        if not issubclass(engine, Engine):
            raise RegistryError(f'engine must be an Engine subclass, not {engine!r}')
        if name in cls.__engine__:
            warn(f'engine {name} already registered, overwriting', RegistryWarning)
        cls.__engine__[name] = engine

    @classmethod
    def register_reassembly(cls, protocol: 'str', reassembly: 'ModuleDescriptor[Reassembly] | Type[Reassembly]') -> 'None':
        r"""Register a new reassembly engine.

        Notes:
            The full qualified class name of the new reassembly engine
            should be as ``{reassembly.module}.{reassembly.name}``.

        Arguments:
            protocol: protocol name
            reassembly: module descriptor or a
                :class:`~pcapkit.foundation.reassembly.reassembly.Reassembly` subclass

        """
        if isinstance(reassembly, ModuleDescriptor):
            reassembly = reassembly.klass
        if not issubclass(reassembly, Reassembly):
            raise RegistryError(f'reassembly must be a Reassembly subclass, not {reassembly!r}')
        if protocol in cls.__reassembly__:
            warn(f'reassembly {protocol} already registered, overwriting', RegistryWarning)
        cls.__reassembly__[protocol] = reassembly

    @classmethod
    def register_traceflow(cls, protocol: 'str', traceflow: 'ModuleDescriptor[TraceFlow] | Type[TraceFlow]') -> 'None':
        r"""Register a new flow tracing engine.

        Notes:
            The full qualified class name of the new flow tracing engine
            should be as ``{traceflow.module}.{traceflow.name}``.

        Arguments:
            protocol: protocol name
            traceflow: module descriptor or a
                :class:`~pcapkit.foundation.traceflow.traceflow.TraceFlow` subclass

        """
        if isinstance(traceflow, ModuleDescriptor):
            traceflow = traceflow.klass
        if not issubclass(traceflow, TraceFlow):
            raise RegistryError(f'traceflow must be a TraceFlow subclass, not {traceflow!r}')
        if protocol in cls.__traceflow__:
            warn(f'traceflow {protocol} already registered, overwriting', RegistryWarning)
        cls.__traceflow__[protocol] = traceflow

    def run(self) -> 'None':  # pylint: disable=inconsistent-return-statements
        """Start extraction.

        We uses :meth:`~pcapkit.foundation.extraction.Extractor.import_test` to check if
        a certain engine is available or not. For supported engines, each engine has
        different driver method:

        * Default drivers:

          - PCAP Format: :class:`pcapkit.foundation.engines.pcap.PCAP`
          - PCAP-NG Format: :class:`pcapkit.foundation.engines.pcapng.PCAPNG`

        * DPKT driver: :class:`pcapkit.foundation.engines.dpkt.DPKT`
        * Scapy driver: :class:`pcapkit.foundation.engines.scapy.Scapy`
        * PyShark driver: :class:`pcapkit.foundation.engines.pyshark.PyShark`

        Warns:
            pcapkit.utilities.warnings.EngineWarning: If the extraction engine is not
                available. This is either due to dependency not installed, or supplied
                engine unknown.

        :rtype: None
        """
        if self._exnam in self.__engine__:  # check if engine is supported
            eng = self.__engine__[self._exnam]
            if isinstance(eng, ModuleDescriptor):
                eng = eng.klass

            if self.import_test(eng.module, name=eng.name) is not None:  # type: ignore[arg-type]
                self._exeng = eng(self)
                self._exeng.run()

                # start iteration
                self.record_frames()
                return

            warn(f'engine {eng.name} (`{eng.module}`) is not installed; '
                 'using default engine instead', EngineWarning, stacklevel=stacklevel())
            self._exnam = 'default'  # using default/pcapkit engine

        if self._exnam not in ('default', 'pcapkit'):
            warn(f'unsupported extraction engine: {self._exnam}; '
                 'using default engine instead', EngineWarning, stacklevel=stacklevel())
            self._exnam = 'default'  # using default/pcapkit engine

        if self._magic in PCAP_Engine.MAGIC_NUMBER:
            self._exeng = cast('Engine[_P]', PCAP_Engine(self))
        elif self._magic in PCAPNG_Engine.MAGIC_NUMBER:
            self._exeng = cast('Engine[_P]', PCAPNG_Engine(self))
        else:
            raise FormatError(f'unknown file format: {self._magic!r}')

        # start engine
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
            pcapkit.utilities.warnings.EngineWarning: If the engine module is not installed.

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
    def make_name(cls, fin: 'str | IO[bytes]' = 'in.pcap', fout: 'str' = 'out',
                  fmt: 'Formats' = 'tree', extension: 'bool' = True, *, files: 'bool' = False,
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

        And the method returns the generated input and output filenames as follows:

        0. input filename
        1. output filename / directory name
        2. output format
        3. output file extension (without ``.``)
        4. if split each frame into different files

        Args:
            fin: Input filename or a binary IO object.
            fout: Output filename.
            fmt: Output file format.
            extension: If append ``.pcap`` file extension to the input filename
                if ``fin`` does not have such file extension; if check and append extensions
                to output file.
            files: If split each frame into different files.
            nofile: If no output file is to be dumped.

        Returns:
            Generated input and output filenames.

        Raises:
            FileNotFound: If input file does not exists.
            FormatError: If output format not provided and cannot be presumpted.

        """
        if isinstance(fin, str):
            if extension:  # pylint: disable=else-if-used
                ifnm = fin if os.path.splitext(fin)[1] in cls.PCAP_EXT else f'{fin}.pcap'
            else:
                ifnm = fin

            if not os.path.isfile(ifnm):
                raise FileNotFound(2, 'No such file or directory', ifnm)
        else:
            ifnm = fin.name

        if nofile:
            ofnm = None
            ext = None
        else:
            ext = cls.__output__[fmt][1]
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

    def record_header(self) -> 'Engine':
        """Read global header.

        The method will parse the PCAP global header and save the parsed result
        to its extraction context. Information such as PCAP version, data link
        layer protocol type, nanosecond flag and byteorder will also be save
        the current :class:`~pcapkit.foundation.engins.engine.Engine` instance
        as well.

        If TCP flow tracing is enabled, the nanosecond flag and byteorder will
        be used for the output PCAP file of the traced TCP flows.

        For output, the method will dump the parsed PCAP global header under
        the name of ``Global Header``.

        """
        # pylint: disable=attribute-defined-outside-init,protected-access
        if self._magic in PCAP_Engine.MAGIC_NUMBER:
            engine = PCAP_Engine(self)
            engine.run()

            self._ifile.seek(0, os.SEEK_SET)
            return engine  # type: ignore[return-value]

        if self._magic in PCAPNG_Engine.MAGIC_NUMBER:
            engine = PCAPNG_Engine(self)  # type: ignore[assignment]
            engine.run()

            self._ifile.seek(0, os.SEEK_SET)
            return engine  # type: ignore[return-value]

        raise FormatError(f'unknown file format: {self._magic!r}')

    def record_frames(self) -> 'None':
        """Read packet frames.

        The method calls :meth:`self._exeng.read_frame <pcapkit.foundation.engines.engine.Engine.read_frame>`
        to parse each frame from the input PCAP file; and
        performs cleanup by calling :meth:`self._exeng.close <pcapkit.foundation.engines.engine.Engine.close>`
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
                    warn('EOF reached', ExtractionWarning, stacklevel=stacklevel())

                    if self._flag_n:
                        continue

                    # quit when EOF
                    break
                except KeyboardInterrupt:
                    self._cleanup()
                    raise

            self._cleanup()

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self,
                 fin: 'Optional[str | IO[bytes]]' = None, fout: 'Optional[str]' = None, format: 'Optional[Formats]' = None,     # basic settings # pylint: disable=redefined-builtin
                 auto: 'bool' = True, extension: 'bool' = True, store: 'bool' = True,                                           # internal settings # pylint: disable=line-too-long
                 files: 'bool' = False, nofile: 'bool' = False, verbose: 'bool | VerboseHandler' = False,                       # output settings # pylint: disable=line-too-long
                 engine: 'Optional[Engines]' = None, layer: 'Optional[Layers]' = None, protocol: 'Optional[Protocols]' = None,  # extraction settings # pylint: disable=line-too-long
                 reassembly: 'bool' = False, reasm_strict: 'bool' = True, reasm_store: 'bool' = True,                           # reassembly settings # pylint: disable=line-too-long
                 trace: 'bool' = False, trace_fout: 'Optional[str]' = None, trace_format: 'Optional[Formats]' = None,           # trace settings # pylint: disable=line-too-long
                 trace_byteorder: 'Literal["big", "little"]' = sys.byteorder, trace_nanosecond: 'bool' = False,                 # trace settings # pylint: disable=line-too-long
                 ip: 'bool' = False, ipv4: 'bool' = False, ipv6: 'bool' = False, tcp: 'bool' = False,                           # reassembly/trace settings # pylint: disable=line-too-long
                 buffer_size: 'int' = io.DEFAULT_BUFFER_SIZE, buffer_save: 'bool' = False, buffer_path: 'Optional[str]' = None, # buffer settings # pylint: disable=line-too-long
                 no_eof: 'bool' = False) -> 'None':
        """Initialise PCAP Reader.

        Args:
            fin: file name to be read or a binary IO object;
                if file not exist, raise :exc:`FileNotFound`
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
            reasm_strict: if set strict flag for reassembly
            reasm_store: if store reassembled datagrams

            trace: if trace TCP traffic flows
            trace_fout: path name for flow tracer if necessary
            trace_format: output file format of flow tracer
            trace_byteorder: output file byte order
            trace_nanosecond: output nanosecond-resolution file flag

            ip: if record data for IPv4 & IPv6 reassembly (must be used with ``reassembly=True``)
            ipv4: if perform IPv4 reassembly (must be used with ``reassembly=True``)
            ipv6: if perform IPv6 reassembly (must be used with ``reassembly=True``)
            tcp: if perform TCP reassembly and/or flow tracing
                (must be used with ``reassembly=True`` or ``trace=True``)

            buffer_size: buffer size for reading input file (for :class:`~pcapkit.corekit.io.SeekableReader` only)
            buffer_save: if save buffer to file (for :class:`~pcapkit.corekit.io.SeekableReader` only)
            buffer_path: path name for buffer file if necessary (for :class:`~pcapkit.corekit.io.SeekableReader` only)

            no_eof: if raise :exc:`EOFError` when EOF

        Warns:
            pcapkit.utilities.warnings.FormatWarning: Warns under following circumstances:

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

        self._flag_a = auto                  # auto extract flag
        self._flag_d = store                 # store data flag
        self._flag_e = False                 # EOF flag
        self._flag_f = files                 # split file flag
        self._flag_q = nofile                # no output flag
        self._flag_r = reassembly            # reassembly flag
        self._flag_t = trace                 # trace flag
        self._flag_v = False                 # verbose flag
        self._flag_s = isinstance(fin, str)  # input filename flag
        self._flag_n = no_eof                # no EOF flag

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
            reasm_obj_ipv4 = reasm_obj_ipv6 = reasm_obj_tcp = None

            if self._ipv4:
                logger.info('IPv4 reassembly enabled')

                reasm_cls_ipv4 = self.__reassembly__['ipv4']
                if isinstance(reasm_cls_ipv4, ModuleDescriptor):
                    reasm_cls_ipv4 = reasm_cls_ipv4.klass
                    self.__reassembly__['ipv4'] = reasm_cls_ipv4  # update mapping upon import
                reasm_obj_ipv4 = cast('IPv4_Reassembly', reasm_cls_ipv4(strict=reasm_strict, store=reasm_store))
            if self._ipv6:
                logger.info('IPv6 reassembly enabled')

                reasm_cls_ipv6 = self.__reassembly__['ipv6']
                if isinstance(reasm_cls_ipv6, ModuleDescriptor):
                    reasm_cls_ipv6 = reasm_cls_ipv6.klass
                    self.__reassembly__['ipv6'] = reasm_cls_ipv6  # update mapping upon import
                reasm_obj_ipv6 = cast('IPv6_Reassembly', reasm_cls_ipv6(strict=reasm_strict, store=reasm_store))
            if self._tcp:
                logger.info('TCP reassembly enabled')

                reasm_cls_tcp = self.__reassembly__['tcp']
                if isinstance(reasm_cls_tcp, ModuleDescriptor):
                    reasm_cls_tcp = reasm_cls_tcp.klass
                    self.__reassembly__['tcp'] = reasm_cls_tcp  # update mapping upon import
                reasm_obj_tcp = cast('TCP_Reassembly', reasm_cls_tcp(strict=reasm_strict, store=reasm_store))

            self._reasm = ReassemblyManager(
                ipv4=reasm_obj_ipv4,
                ipv6=reasm_obj_ipv6,
                tcp=reasm_obj_tcp,
            )

        if trace:
            trace_obj_tcp = None

            if self._exnam in ('pyshark',) and trace_format in ('pcap',):
                warn(f"'Extractor(engine={self._exnam})' does not support 'trace_format={trace_format}'; "
                     "using 'trace_format=None' instead", FormatWarning, stacklevel=stacklevel())
                trace_format = None

            if self._tcp:
                logger.info('TCP flow tracing enabled')

                trace_cls_tcp = self.__traceflow__['tcp']
                if isinstance(trace_cls_tcp, ModuleDescriptor):
                    trace_cls_tcp = trace_cls_tcp.klass
                    self.__traceflow__['tcp'] = trace_cls_tcp  # update mapping upon import
                trace_obj_tcp = cast('TCP_TraceFlow', trace_cls_tcp(fout=trace_fout, format=trace_format,
                                                                    byteorder=trace_byteorder, nanosecond=trace_nanosecond))

            self._trace = TraceFlowManager(
                tcp=trace_obj_tcp,
            )

        if self._flag_s:
            self._ifile = open(ifnm, 'rb')  # input file # pylint: disable=unspecified-encoding,consider-using-with
        else:
            self._ifile = cast('BufferedReader', fin)

        if not self._ifile.seekable():
            self._ifile = SeekableReader(self._ifile, buffer_size, buffer_save, buffer_path,
                                         stream_closing=not self._flag_s)

        if not self._flag_q:
            output, ext = self.__output__[fmt]
            if ext is None:
                warn(f'Unsupported output format: {fmt}; disabled file output feature',
                     FormatWarning, stacklevel=stacklevel())
            if isinstance(output, ModuleDescriptor):
                output = output.klass
                self.__output__[fmt] = (output, ext)  # update mapping upon import
            dumper = make_dumper(output)

            self._ofile = dumper if self._flag_f else dumper(ofnm)  # output file

        # NOTE: we use peek() to read the magic number, as the file pointer
        # will not be moved after reading; however, the returned bytes object
        # may not be exactly 4 bytes, so we use [:4] to get the first 4 bytes
        self._magic = self._ifile.peek(4)[:4]
        #self._magic = self._ifile.read(4)  # magic number
        #self._ifile.seek(0, os.SEEK_SET)

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

    def __next__(self) -> '_P':
        """Iterate and parse next PCAP frame.

        It will call :meth:`self._exeng.read_frame <pcapkit.foundation.engines.engine.Engine.read_frame>`
        to parse next PCAP frame internally, until the EOF reached;
        then it calls :meth:`self._cleanup <_cleanup>` for the aftermath.

        """
        while True:
            try:
                return self._exeng.read_frame()
            except (EOFError, StopIteration) as error:
                warn('EOF reached', ExtractionWarning, stacklevel=stacklevel())

                if self._flag_n:
                    continue

                self._cleanup()
                raise StopIteration from error  # pylint: disable=raise-missing-from
            except KeyboardInterrupt:
                self._cleanup()
                raise

    def __call__(self) -> '_P':
        """Works as a simple wrapper for the iteration protocol.

        Raises:
            IterableError: If :attr:`self._flag_a <pcapkit.foundation.extraction.Extractor._flag_a>`
                is :data:`True`, as iteration is not applicable.

        """
        if not self._flag_a:
            while True:
                try:
                    return self._exeng.read_frame()
                except (EOFError, StopIteration):
                    warn('EOF reached', ExtractionWarning, stacklevel=stacklevel())

                    if self._flag_n:
                        continue

                    self._cleanup()
                    raise
                except KeyboardInterrupt:
                    self._cleanup()
                    raise
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

        The method calls :meth:`self._exeng.close <pcapkit.foundation.engines.engine.Engine.close>`,
        sets :attr:`self._flag_e <pcapkit.foundation.extraction.Extractor._flag_e>`
        as :data:`True` and closes the input file (if necessary).

        """
        # pylint: disable=attribute-defined-outside-init
        self._flag_e = True
        if isinstance(self._ifile, SeekableReader):
            self._ifile.close()
        elif not self._flag_s:
            self._ifile.close()
        self._exeng.close()
