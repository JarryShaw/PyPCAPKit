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

from pcapkit.corekit.context import ContextRegistry
from pcapkit.corekit.io import SeekableReader
from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.dumpkit.common import make_dumper
from pcapkit.foundation.engines.engine import Engine, EngineBase
from pcapkit.foundation.engines.pcap import PCAP as PCAP_Engine
from pcapkit.foundation.engines.pcapng import PCAPNG as PCAPNG_Engine
from pcapkit.foundation.reassembly import ReassemblyManager
from pcapkit.foundation.reassembly.data import ReassemblyData
from pcapkit.foundation.reassembly.reassembly import Reassembly, ReassemblyBase
from pcapkit.foundation.traceflow import TraceFlowManager
from pcapkit.foundation.traceflow.data import TraceFlowData
from pcapkit.foundation.traceflow.traceflow import TraceFlow, TraceFlowBase
from pcapkit.utilities.exceptions import (CallableError, FileNotFound, FormatError, IterableError,
                                          RegistryError, UnsupportedCall, stacklevel)
from pcapkit.utilities.logging import get_logger
from pcapkit.utilities.warnings import (AttributeWarning, EngineWarning, ExtractionWarning,
                                        FormatWarning, RegistryWarning, warn)

if TYPE_CHECKING:
    from io import BufferedReader
    from types import ModuleType, TracebackType
    from typing import IO, Any, Callable, DefaultDict, Iterable, Mapping, Optional, Type, Union

    from dpkt.dpkt import Packet as DPKTPacket
    from pcapfile.structs import pcap_packet as PCAPFilePacket
    from pyshark.packet.packet import Packet as PySharkPacket
    from scapy.packet import Packet as ScapyPacket
    from typing_extensions import Literal

    from pcapkit.corekit.context import ProtocolContext
    from pcapkit.foundation.reassembly.ipv4 import IPv4 as IPv4_Reassembly
    from pcapkit.foundation.reassembly.ipv6 import IPv6 as IPv6_Reassembly
    from pcapkit.foundation.reassembly.tcp import TCP as TCP_Reassembly
    from pcapkit.foundation.traceflow.tcp import TCP as TCP_TraceFlow
    from pcapkit.protocols.misc.pcap.frame import Frame
    from pcapkit.protocols.misc.pcapng import PCAPNG
    from pcapkit.protocols.protocol import ProtocolBase

    #: Every key registered in :attr:`Extractor.__output__` and in
    #: :attr:`TraceFlowBase.__output__
    #: <pcapkit.foundation.traceflow.traceflow.TraceFlowBase.__output__>` -- the two
    #: registries expose the same eight keys. This used to name only four of them,
    #: which made ``'cap'`` and the ``'txt'``/``'xml'`` aliases unspellable for a
    #: type checker even though every one of them is accepted at runtime.
    Formats = Literal['pcap', 'cap', 'json', 'tree', 'text', 'txt', 'plist', 'xml']
    # NOTE: this alias is duplicated verbatim in ``pcapkit.interface.misc``; both
    # copies need updating when a new engine lands. The duplication predates the
    # engines added here and is left as-is on purpose.
    Engines = Literal['default', 'pcapkit', 'dpkt', 'scapy', 'pyshark', 'pypcap', 'pcap_ct',
                      'pypcapfile']
    Layers = Literal['link', 'internet', 'transport', 'application', 'none']

    # NOTE: the PyPCAP and PCAP_CT engines perform no dissection, so their
    # "packet" is the ``(timestamp, bytes)`` pair that ``pcap.pcap`` yields.
    # One member covers both: they read the same interface, from two independent
    # distributions of it.
    Packet = Union[Frame, PCAPNG, ScapyPacket, DPKTPacket, PySharkPacket,
                   PCAPFilePacket, tuple[float, bytes]]

    Protocols = Union[str, ProtocolBase, Type[ProtocolBase]]
    VerboseHandler = Callable[['Extractor', Packet], Any]

__all__ = ['Extractor']

#: logging.Logger: Module-level logger, a child of the package-wide
#: :data:`pcapkit.utilities.logging.logger`.
logger = get_logger(__name__)

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
        #: Output file extension, bare, i.e. without the leading ``.`` --
        #: ``'json'``, not ``'.json'``. Normalised by
        #: :meth:`~pcapkit.foundation.extraction.Extractor.make_name`, whose
        #: docstring is the contract; the engines compose a per-frame filename
        #: as ``f'{name}.{ext._fext}'`` and supply the dot themselves.
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
        #: Reassembly flag. It indicates if datagram reassembly is enabled.
        #: Every engine reads it to decide whether to feed
        #: :attr:`~pcapkit.foundation.extraction.Extractor._reasm`, and the
        #: engines that cannot reassemble clear it on startup.
        _flag_r: 'bool'
        #: Trace flag. It indicates if the flow tracing is enabled.
        _flag_t: 'bool'
        #: Verbose flag. This is used to determine if the verbose callback
        #: function should be called at each frame.
        _flag_v: 'bool'
        #: No EOF flag. It is useful when the input is a live capture on a pipe or
        #: on standard input, where reaching the end of what has arrived so far
        #: does not mean the capture is over: the extraction retries instead of
        #: stopping. It retries only while the input is still producing, though --
        #: see :meth:`~pcapkit.foundation.extraction.Extractor._note_eof_progress`
        #: for the rule and for what it narrows, without which an exhausted stream
        #: spins forever (#620).
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
        #: Caller supplied parsing context, c.f. :mod:`pcapkit.corekit.context`.
        _exctx: 'ContextRegistry'
        #: Extraction engine name.
        _exnam: 'Engines'
        #: Extraction engine instance.
        _exeng: 'Engine[_P]'

        #: Input file object.
        _ifile: 'BufferedReader'
        #: Output file object.
        _ofile: 'Dumper | Type[Dumper]'

        #: Position of the input stream at the previous end of stream, or
        #: :data:`None` before the first one. Comparing it against the position
        #: at the next end of stream is what tells a live capture that has paused
        #: -- retry, more may arrive -- from one that is finished, which is the
        #: termination condition ``no_eof`` was missing (#620).
        _eof_mark: 'Optional[int]'

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
            'text': (ModuleDescriptor('dictdumper', 'Tree'), '.txt'),
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
        'pypcap': ModuleDescriptor('pcapkit.foundation.engines.pypcap', 'PyPCAP'),
        # NOTE: ``pcap-ct`` is a separate distribution that reimplements the
        # ``pypcap`` interface, and it installs the same top-level ``pcap``
        # module. It gets its own entry rather than sharing ``pypcap``'s because
        # the two are independent projects with different install requirements
        # and different Python version coverage; ``PCAP_CT.__engine_module__``
        # explains how ``import_test`` tells them apart.
        'pcap_ct': ModuleDescriptor('pcapkit.foundation.engines.pcap_ct', 'PCAP_CT'),
        'pypcapfile': ModuleDescriptor('pcapkit.foundation.engines.pypcapfile', 'PyPCAPFile'),
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

            The overwrite guard fires only when the incumbent dumper differs
            from the replacement, so re-registering the exact same object is
            a silent no-op rather than a warning about nothing displaced --
            the identity guard GitHub issue #718 gave the code-keyed
            registrars, extended here by GitHub issue #739. ``__output__``
            maps each format to a ``(dumper, ext)`` pair, so the identity
            check compares the incumbent *dumper* (index ``0``), not the
            pair -- a re-registration that only changes ``ext`` is still
            identity-equal on the dumper and stays silent, since the dumper
            is what "the same object" means here, not the pair as a whole.
            ``__output__`` is also a :class:`collections.defaultdict`,
            unlike the other three
            registrars this issue touches; :meth:`dict.get` does not invoke
            the default factory the way ``cls.__output__[format]`` would, so
            it stays non-inserting here as well.

        Arguments:
            format: format name
            dumper: module descriptor or a :class:`dictdumper.dumper.Dumper` subclass
            ext: file extension

        """
        if isinstance(dumper, ModuleDescriptor):
            dumper = dumper.klass
        if not issubclass(dumper, Dumper):
            raise RegistryError(f'dumper must be a Dumper subclass, not {dumper!r}')
        incumbent_entry = cls.__output__.get(format)
        incumbent = incumbent_entry[0] if incumbent_entry is not None else None
        if incumbent is not None and incumbent is not dumper:
            warn(f'dumper {format} already registered, overwriting', RegistryWarning)
        cls.__output__[format] = (dumper, ext)

    @classmethod
    def register_engine(cls, name: 'str', engine: 'ModuleDescriptor[Engine] | Type[Engine]') -> 'None':
        r"""Register a new extraction engine.

        Notes:
            The full qualified class name of the new extraction engine
            should be as ``{engine.module}.{engine.name}``.

            The overwrite guard fires only when the incumbent differs from
            the replacement, so re-registering the exact same object is a
            silent no-op rather than a warning about nothing displaced --
            the identity guard GitHub issue #718 gave the code-keyed
            registrars, extended here by GitHub issue #739.

        Arguments:
            name: engine name
            engine: module descriptor or an
                :class:`~pcapkit.foundation.engines.engine.Engine` subclass

        """
        if isinstance(engine, ModuleDescriptor):
            engine = engine.klass
        # NOTE: checked against ``EngineBase`` rather than ``Engine``: every built-in
        # engine subclasses the base directly (``engines/pcap.py`` imports it as
        # ``EngineBase as Engine``) precisely so that it is *not* auto-registered by
        # ``Engine.__init_subclass__``, which made this check reject pcapkit's own
        # classes. ``Engine`` is itself an ``EngineBase``, so this only widens. See #513.
        if not issubclass(engine, EngineBase):
            raise RegistryError(f'engine must be an Engine subclass, not {engine!r}')
        incumbent = cls.__engine__.get(name)
        if incumbent is not None and incumbent is not engine:
            warn(f'engine {name} already registered, overwriting', RegistryWarning)
        cls.__engine__[name] = engine

    @classmethod
    def register_reassembly(cls, protocol: 'str', reassembly: 'ModuleDescriptor[Reassembly] | Type[Reassembly]') -> 'None':
        r"""Register a new reassembly engine.

        Notes:
            The full qualified class name of the new reassembly engine
            should be as ``{reassembly.module}.{reassembly.name}``.

            The overwrite guard fires only when the incumbent differs from
            the replacement, so re-registering the exact same object is a
            silent no-op rather than a warning about nothing displaced --
            the identity guard GitHub issue #718 gave the code-keyed
            registrars, extended here by GitHub issue #739.

        Arguments:
            protocol: protocol name
            reassembly: module descriptor or a
                :class:`~pcapkit.foundation.reassembly.reassembly.Reassembly` subclass

        """
        if isinstance(reassembly, ModuleDescriptor):
            reassembly = reassembly.klass
        # NOTE: ``ReassemblyBase`` rather than ``Reassembly``, for the reason given in
        # :meth:`register_engine` above -- see #513.
        if not issubclass(reassembly, ReassemblyBase):
            raise RegistryError(f'reassembly must be a Reassembly subclass, not {reassembly!r}')
        incumbent = cls.__reassembly__.get(protocol)
        if incumbent is not None and incumbent is not reassembly:
            warn(f'reassembly {protocol} already registered, overwriting', RegistryWarning)
        cls.__reassembly__[protocol] = reassembly

    @classmethod
    def register_traceflow(cls, protocol: 'str', traceflow: 'ModuleDescriptor[TraceFlow] | Type[TraceFlow]') -> 'None':
        r"""Register a new flow tracing engine.

        Notes:
            The full qualified class name of the new flow tracing engine
            should be as ``{traceflow.module}.{traceflow.name}``.

            The overwrite guard fires only when the incumbent differs from
            the replacement, so re-registering the exact same object is a
            silent no-op rather than a warning about nothing displaced --
            the identity guard GitHub issue #718 gave the code-keyed
            registrars, extended here by GitHub issue #739.

        Arguments:
            protocol: protocol name
            traceflow: module descriptor or a
                :class:`~pcapkit.foundation.traceflow.traceflow.TraceFlow` subclass

        """
        if isinstance(traceflow, ModuleDescriptor):
            traceflow = traceflow.klass
        # NOTE: ``TraceFlowBase`` rather than ``TraceFlow``, for the reason given in
        # :meth:`register_engine` above -- see #513.
        if not issubclass(traceflow, TraceFlowBase):
            raise RegistryError(f'traceflow must be a TraceFlow subclass, not {traceflow!r}')
        incumbent = cls.__traceflow__.get(protocol)
        if incumbent is not None and incumbent is not traceflow:
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
        * PyPCAP driver: :class:`pcapkit.foundation.engines.pypcap.PyPCAP`
        * pcap-ct driver: :class:`pcapkit.foundation.engines.pcap_ct.PCAP_CT`
        * PyPCAPFile driver: :class:`pcapkit.foundation.engines.pypcapfile.PyPCAPFile`

        Warns:
            pcapkit.utilities.warnings.EngineWarning: If the extraction engine is not
                available. This is either due to dependency not installed, or supplied
                engine unknown.

        :rtype: None
        """
        logger.debug('requested extraction engine: %s', self._exnam)

        if self._exnam in self.__engine__:  # check if engine is supported
            eng = self.__engine__[self._exnam]
            if isinstance(eng, ModuleDescriptor):
                eng = eng.klass

            # An engine may rule itself out before the import is even attempted.
            # Asking it is necessary because ``import_test`` can only see whether
            # the top-level module imports, which is not the same question: a
            # package whose *submodules* fail leaves the guard satisfied and the
            # failure to escape from the engine's constructor instead. The base
            # class answers :data:`None`, so only engines with a real limitation
            # override it.
            reason = eng.unsupported_reason()
            if reason is not None:
                logger.debug('engine %s is unavailable: %s', eng.name, reason)
                warn(f'engine {eng.name} is not supported on this interpreter '
                     f'({reason}); using default engine instead',
                     EngineWarning, stacklevel=stacklevel())
                self._exnam = 'default'
            elif self.import_test(eng.module, name=eng.name) is not None:  # type: ignore[arg-type]
                logger.debug('using engine %s (%s)', eng.name, eng.module)
                self._exeng = eng(self)
                self._exeng.run()

                # start iteration
                self.record_frames()
                return
            else:
                warn(f'engine {eng.name} (`{eng.module}`) is not installed; '
                     'using default engine instead', EngineWarning, stacklevel=stacklevel())
                self._exnam = 'default'  # using default/pcapkit engine

        if self._exnam not in ('default', 'pcapkit'):
            warn(f'unsupported extraction engine: {self._exnam}; '
                 'using default engine instead', EngineWarning, stacklevel=stacklevel())
            self._exnam = 'default'  # using default/pcapkit engine

        if self._magic in PCAP_Engine.MAGIC_NUMBER:
            logger.debug('magic number %r identifies a PCAP file', self._magic)
            self._exeng = cast('Engine[_P]', PCAP_Engine(self))
        elif self._magic in PCAPNG_Engine.MAGIC_NUMBER:
            logger.debug('magic number %r identifies a PCAP-NG file', self._magic)
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
            logger.debug('engine module %r is not importable', engine)
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
        3. output file extension, bare, i.e. **without** the leading ``.``, so
           that a caller composing a per-frame filename writes
           ``f'{name}.{ext}'``
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
            registered = cls.__output__[fmt][1]
            if registered is None:
                raise FormatError(f'unknown output format: {fmt}')

            # NOTE: ``__output__`` spells its extensions with the leading dot,
            # and so does every ``ext=`` handed to
            # :func:`pcapkit.foundation.registry.foundation.register_dumper`.
            # The value we hand back, though, is documented bare and is used
            # bare -- ``Extractor._fext`` reaches the engines, which each
            # compose a per-frame name as ``f'{name}.{ext._fext}'``. Leaving the
            # dot on is what produced ``Frame 1..json`` (see #358), so
            # normalise it away once, here, rather than at six call sites.
            ext = registered[1:] if registered.startswith('.') else registered

            if (parent := os.path.split(fout)[0]):
                os.makedirs(parent, exist_ok=True)

            if files:
                ofnm = fout
                os.makedirs(ofnm, exist_ok=True)
            elif extension:
                # NOTE: The dot belongs to the separator here, not to ``ext``.
                ofnm = fout if os.path.splitext(fout)[1] == f'.{ext}' else f'{fout}.{ext}'
            else:
                ofnm = fout

        return ifnm, ofnm, fmt, ext, files

    def record_header(self) -> 'Engine':
        """Read global header.

        The method will parse the PCAP global header and save the parsed result
        to its extraction context. Information such as PCAP version, data link
        layer protocol type, nanosecond flag and byteorder will also be save
        the current :class:`~pcapkit.foundation.engines.engine.Engine` instance
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
            logger.debug('reading frames from %s', self._ifnm)
            while True:
                try:
                    self._exeng.read_frame()
                except (EOFError, StopIteration):
                    warn('EOF reached', ExtractionWarning, stacklevel=stacklevel())

                    # ``no_eof`` retries -- but only while the input is still
                    # producing, or an exhausted stream spins here forever (#620).
                    if self._flag_n and self._note_eof_progress():
                        continue

                    # quit when EOF
                    break
                except KeyboardInterrupt:
                    logger.debug('interrupted after %d frame(s)', self._frnum)
                    self._cleanup()
                    raise

            logger.debug('read %d frame(s) from %s', self._frnum, self._ifnm)
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
                 reasm_timeout: 'Optional[float]' = None,                                                                       # reassembly settings # pylint: disable=line-too-long
                 trace: 'bool' = False, trace_fout: 'Optional[str]' = None, trace_format: 'Optional[Formats]' = None,           # trace settings # pylint: disable=line-too-long
                 trace_byteorder: 'Literal["big", "little"]' = sys.byteorder, trace_nanosecond: 'bool' = False,                 # trace settings # pylint: disable=line-too-long
                 trace_bidirectional: 'bool' = True, trace_analyse: 'bool' = False,                                            # trace settings # pylint: disable=line-too-long
                 ip: 'bool' = False, ipv4: 'bool' = False, ipv6: 'bool' = False, tcp: 'bool' = False,                           # reassembly/trace settings # pylint: disable=line-too-long
                 buffer_size: 'int' = io.DEFAULT_BUFFER_SIZE, buffer_save: 'bool' = False, buffer_path: 'Optional[str]' = None, # buffer settings # pylint: disable=line-too-long
                 no_eof: 'bool' = False,                                                                                      # EOF settings # pylint: disable=line-too-long
                 context: 'Optional[ContextRegistry | ProtocolContext | Mapping[str, ProtocolContext] | Iterable[ProtocolContext]]' = None) -> 'None':  # context settings # pylint: disable=line-too-long
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
            reasm_timeout: reassembly timeout in seconds, measured on the
                *capture's* own clock rather than the host's, since an offline
                parser has no other notion of time passing; :data:`None` selects
                each protocol's own default -- 60 seconds for IPv4
                (:rfc:`1122#section-3.3.2`) and IPv6 (:rfc:`8200#section-4.5`),
                disabled for TCP, which no specification gives a deadline. Pass
                :data:`math.inf` to disable it everywhere

            trace: if trace TCP traffic flows
            trace_fout: path name for flow tracer if necessary
            trace_format: output file format of flow tracer
            trace_byteorder: output file byte order
            trace_nanosecond: output nanosecond-resolution file flag
            trace_bidirectional: whether both halves of a conversation are
                traced as one flow, which is the default; :data:`False` restores
                the older behaviour of a flow per direction
            trace_analyse: whether each traced flow reassembles its application
                layer, so that its ``packet`` can be read. Off by default,
                because it buffers every traced payload -- a cost tracing does
                not otherwise pay. Unavailable on the ``pyshark`` engine, which
                reports dissected fields rather than the octets behind them

            ip: if record data for IPv4 & IPv6 reassembly (must be used with ``reassembly=True``)
            ipv4: if perform IPv4 reassembly (must be used with ``reassembly=True``)
            ipv6: if perform IPv6 reassembly (must be used with ``reassembly=True``)
            tcp: if perform TCP reassembly and/or flow tracing
                (must be used with ``reassembly=True`` or ``trace=True``)

            buffer_size: buffer size for reading input file (for :class:`~pcapkit.corekit.io.SeekableReader` only)
            buffer_save: if save buffer to file (for :class:`~pcapkit.corekit.io.SeekableReader` only)
            buffer_path: path name for buffer file if necessary (for :class:`~pcapkit.corekit.io.SeekableReader` only)

            no_eof: if not raise :exc:`EOFError` when reach EOF -- retry instead,
                which is what a live capture on a pipe or on standard input wants,
                since a read there blocks until the writer produces more or closes.
                Retrying stops as soon as one retry finds nothing new, so an
                exhausted input finishes rather than spinning; on a *seekable*
                input, where nothing blocks, that means a file still being appended
                to ends at the data present when the extraction reached it

            context: caller supplied parsing context for protocols that need
                information not carried on the wire, keyed by protocol index
                ID -- c.f. :mod:`pcapkit.corekit.context`. Accepts a
                :class:`~pcapkit.corekit.context.ContextRegistry`, a single
                :class:`~pcapkit.corekit.context.ProtocolContext`, a mapping,
                or any iterable of contexts. The channel is honoured by the
                ``default``, ``pcap`` and ``pcapng`` engines, which parse with
                :mod:`pcapkit`'s own protocol implementations; the third party
                engines ignore it.

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
        self._eof_mark = None                # stream position at the last EOF

        # verbose callback function
        if isinstance(verbose, bool):
            self._flag_v = verbose
            if verbose:
                # NOTE: ``verbose=True`` and the CLI's ``-v`` are a request for
                # user-facing output on stdout, not diagnostics -- the frame
                # chains are a feature of the tool, so they stay on ``print``
                # rather than becoming log records a consumer has to configure
                # a handler to see (and on a different stream at that).
                self._vfunc = lambda e, f: print(
                    f'Frame {e._frnum:>3d}: {f.protochain}'  # pylint: disable=protected-access
                )
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
        self._exctx = ContextRegistry.make(context)                   # caller supplied context

        if reassembly:
            reasm_obj_ipv4 = reasm_obj_ipv6 = reasm_obj_tcp = None

            if self._ipv4:
                logger.debug('IPv4 reassembly enabled')

                reasm_cls_ipv4 = self.__reassembly__['ipv4']
                if isinstance(reasm_cls_ipv4, ModuleDescriptor):
                    reasm_cls_ipv4 = reasm_cls_ipv4.klass
                    self.__reassembly__['ipv4'] = reasm_cls_ipv4  # update mapping upon import
                reasm_obj_ipv4 = cast('IPv4_Reassembly', reasm_cls_ipv4(strict=reasm_strict, store=reasm_store,
                                                                       timeout=reasm_timeout))
            if self._ipv6:
                logger.debug('IPv6 reassembly enabled')

                reasm_cls_ipv6 = self.__reassembly__['ipv6']
                if isinstance(reasm_cls_ipv6, ModuleDescriptor):
                    reasm_cls_ipv6 = reasm_cls_ipv6.klass
                    self.__reassembly__['ipv6'] = reasm_cls_ipv6  # update mapping upon import
                reasm_obj_ipv6 = cast('IPv6_Reassembly', reasm_cls_ipv6(strict=reasm_strict, store=reasm_store,
                                                                       timeout=reasm_timeout))
            if self._tcp:
                logger.debug('TCP reassembly enabled')

                reasm_cls_tcp = self.__reassembly__['tcp']
                if isinstance(reasm_cls_tcp, ModuleDescriptor):
                    reasm_cls_tcp = reasm_cls_tcp.klass
                    self.__reassembly__['tcp'] = reasm_cls_tcp  # update mapping upon import
                reasm_obj_tcp = cast('TCP_Reassembly', reasm_cls_tcp(strict=reasm_strict, store=reasm_store,
                                                                    timeout=reasm_timeout))

            self._reasm = ReassemblyManager(
                ipv4=reasm_obj_ipv4,
                ipv6=reasm_obj_ipv6,
                tcp=reasm_obj_tcp,
            )

        if trace:
            trace_obj_tcp = None

            # NOTE: these engines' flow tracing adapters report the frame as a
            # plain :obj:`dict`, which the PCAP trace dumper cannot re-serialise
            # -- :meth:`PCAPIO._append_value
            # <pcapkit.dumpkit.pcap.PCAPIO._append_value>` reaches for
            # ``frame.packet`` and dies with ``AttributeError: 'dict' object has no
            # attribute 'packet'``. ``None`` has to be caught along with ``'pcap'``
            # here, and replaced by a format that *can* take a mapping, because
            # :meth:`TraceFlow.__init__
            # <pcapkit.foundation.traceflow.traceflow.TraceFlowBase.__init__>`
            # itself substitutes ``'pcap'`` for ``None``.
            #
            # DPKT and Scapy belong on this list and were once left off it. Their
            # adapters build the frame with ``packet2dict`` exactly as the other two
            # do, so both crash the same way -- but only DPKT did so visibly. The
            # Scapy engine imports just :mod:`scapy.sendrecv`, which leaves the L2
            # link types unregistered, so every frame dissects as ``Raw``, no TCP
            # layer is ever found, and the tracer is never fed at all (#406). That
            # hides this defect rather than avoiding it: register the link types --
            # as importing :mod:`scapy.all` does -- and the same ``AttributeError``
            # appears. So the guard is written from what the adapters produce, not
            # from which engines happen to crash today.
            if (self._exnam in ('dpkt', 'scapy', 'pyshark', 'pypcapfile')
                    and trace_format in ('pcap', 'cap', None)):
                warn(f"'Extractor(engine={self._exnam})' does not support 'trace_format={trace_format}'; "
                     "using 'trace_format=\"json\"' instead", FormatWarning, stacklevel=stacklevel())
                trace_format = 'json'

            # NOTE: PyShark hands the tracer dissected *fields*, not the octets
            # behind them, so there is no payload for a flow to reassemble -- which
            # is the same reason :mod:`pcapkit.toolkit.pyshark` carries no
            # ``tcp_reassembly`` at all. Refuse rather than analyse empty payloads
            # into an empty answer that looks like a real one.
            if trace_analyse and self._exnam == 'pyshark':
                warn(f"'Extractor(engine={self._exnam})' does not expose packet payloads; "
                     "using 'trace_analyse=False' instead", AttributeWarning,
                     stacklevel=stacklevel())
                trace_analyse = False

            if self._tcp:
                logger.debug('TCP flow tracing enabled')

                trace_cls_tcp = self.__traceflow__['tcp']
                if isinstance(trace_cls_tcp, ModuleDescriptor):
                    trace_cls_tcp = trace_cls_tcp.klass
                    self.__traceflow__['tcp'] = trace_cls_tcp  # update mapping upon import
                trace_obj_tcp = cast('TCP_TraceFlow', trace_cls_tcp(fout=trace_fout, format=trace_format,
                                                                    byteorder=trace_byteorder, nanosecond=trace_nanosecond,
                                                                    bidirectional=trace_bidirectional,
                                                                    analyse=trace_analyse))

            self._trace = TraceFlowManager(
                tcp=trace_obj_tcp,
            )

        if self._flag_s:
            logger.debug('opening input file %s', ifnm)
            self._ifile = open(ifnm, 'rb')  # input file # pylint: disable=unspecified-encoding,consider-using-with
        else:
            logger.debug('reading from the pre-opened stream %r', fin)
            self._ifile = cast('BufferedReader', fin)

        if not self._ifile.seekable():
            logger.debug('input stream is not seekable, wrapping it in SeekableReader')
            # NOTE: ``stream_closing`` decides whether closing the wrapper also
            # closes the stream underneath it, so it follows *ownership*: only a
            # handle this class opened itself is ours to release. A non-seekable
            # stream always came from the caller, so the polarity here is the
            # same one ``_cleanup`` uses, and it was inverted in both places --
            # see #610.
            self._ifile = SeekableReader(self._ifile, buffer_size, buffer_save, buffer_path,
                                         stream_closing=self._flag_s)

        if not self._flag_q:
            output, ext = self.__output__[fmt]
            if ext is None:
                warn(f'Unsupported output format: {fmt}; disabled file output feature',
                     FormatWarning, stacklevel=stacklevel())
            if isinstance(output, ModuleDescriptor):
                output = output.klass
                self.__output__[fmt] = (output, ext)  # update mapping upon import
            dumper = make_dumper(output)

            # NOTE: make_dumper() names every subclass it builds 'DictDumper', so the
            # useful name is the output class it wraps.
            logger.debug('dumping %s output to %s via %s', fmt, ofnm, output.__name__)
            self._ofile = dumper if self._flag_f else dumper(ofnm)  # output file
        else:
            logger.debug('file output disabled')

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

                # See :meth:`_note_eof_progress`: ``no_eof`` retries a live capture
                # that has merely paused, and gives up on an exhausted one (#620).
                if self._flag_n and self._note_eof_progress():
                    continue

                self._cleanup()
                raise StopIteration from error  # pylint: disable=raise-missing-from
            except KeyboardInterrupt:
                self._cleanup()
                raise

    def __call__(self) -> '_P':
        """Works as a simple wrapper for the iteration protocol.

        Raises:
            CallableError: If :attr:`self._flag_a <pcapkit.foundation.extraction.Extractor._flag_a>`
                is :data:`True`, as such operation is not applicable.

        """
        if not self._flag_a:
            while True:
                try:
                    return self._exeng.read_frame()
                except (EOFError, StopIteration):
                    warn('EOF reached', ExtractionWarning, stacklevel=stacklevel())

                    # See :meth:`_note_eof_progress`. Once the input is finished
                    # there is no frame left to return, so the error is the only
                    # truthful answer this form can give -- ``no_eof`` defers it
                    # rather than suppressing it outright (#620).
                    if self._flag_n and self._note_eof_progress():
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
        logger.debug('closing %s on context exit after %d frame(s)', self._ifnm, self._frnum)
        self._ifile.close()
        self._exeng.close()

    def __del__(self) -> 'None':
        """Release the input stream if this class still owns an open one.

        A backstop for the extraction that is *abandoned* rather than finished:
        with ``auto=False`` the caller drives :meth:`__next__` itself, and one that
        stops before end of file never reaches :meth:`_cleanup` at all, so the
        ownership rule there never gets to run. The handle then survives until the
        interpreter collects it, and CPython announces that with the
        ``ResourceWarning`` #606 was tripping over -- from an unrelated test, in an
        unrelated file, which is what made that flake so hard to place.

        This is a backstop and not the recommended route: collection is not
        deterministic, and :class:`Extractor` takes part in a reference cycle
        through its engine, so a handle can outlive its last reference until the
        cyclic collector runs. Use :class:`Extractor` as a context manager -- see
        :meth:`__enter__` -- where the moment of release matters.

        Note:
            A finaliser must not raise, so this reads through
            :attr:`~object.__dict__` rather than attribute access. That matters
            for more than tidiness: ``_flag_s`` is assigned early in
            :meth:`__init__` and ``_ifile`` only much later, so a constructor
            that fails in between -- an unreadable path, an unknown format --
            leaves an instance whose flag says "mine" and which has no stream at
            all. The close itself is guarded too, that being what a close during
            interpreter shutdown can fail at.

        """
        if not self._owns_input():
            return
        try:
            ifile = self.__dict__['_ifile']
            if not ifile.closed:
                ifile.close()
        except (OSError, ValueError):  # pragma: no cover
            # Nothing useful can be reported from a finaliser, and raising here
            # would only produce an "Exception ignored in __del__" on stderr.
            pass

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _owns_input(self) -> 'bool':
        """Whether the input stream is this class's to close.

        The one place the ownership rule of #610 is written down, so that
        :meth:`_cleanup` and :meth:`__del__` cannot drift apart on it.

        Returns:
            :data:`True` when the input stream was opened by this class and is
            therefore its to release -- ``fin`` given as a path, i.e.
            :attr:`self._flag_s <Extractor._flag_s>` set, or a
            :class:`~pcapkit.corekit.io.SeekableReader` this class wrapped around
            a caller's non-seekable stream. :data:`False` for a stream the caller
            supplied and still owns, and :data:`False` when there is no stream at
            all.

        Note:
            The two :data:`True` cases are written as separate tests rather than
            folded together because they *can* in principle coincide -- a path
            naming something non-seekable would be opened here and then wrapped --
            and the answer has to be :data:`True` for both halves of it. That
            cannot arise today, since :meth:`make_name` admits a path only through
            :func:`os.path.isfile`, which is :data:`False` for a FIFO or a device,
            and a regular file is always seekable. The second test is therefore
            defensive rather than dead, and is the reason
            ``SeekableReader(..., stream_closing=self._flag_s)`` passes the flag
            instead of :data:`False`.

        """
        # NOTE: read through ``__dict__``, and answer for the *stream* rather
        # than for the flag alone, so that this is :data:`False` rather than
        # raising on a partially constructed instance -- ``_flag_s`` is assigned
        # early in ``__init__`` and ``_ifile`` only much later, so a constructor
        # that failed in between leaves the flag set and no stream behind it.
        ifile = self.__dict__.get('_ifile')
        if ifile is None:
            return False
        if self.__dict__.get('_flag_s'):
            return True
        return isinstance(ifile, SeekableReader)

    def _note_eof_progress(self) -> 'bool':
        """Record this end of stream, and say whether the input advanced to reach it.

        This is the termination condition ``no_eof`` was missing. The flag means
        "end of stream is not necessarily the end of the capture" -- which is true
        of a live capture, and is why :mod:`pcapkit.__main__` sets it for
        ``fin='-'`` -- so the extraction retries rather than stopping. What it had
        no way to decide was when the stream is *genuinely* finished, and for an
        exhausted one every retry raises end of stream again immediately, which is
        the spin #620 reported.

        The signal is the input's own position. End of stream is raised by
        :func:`~pcapkit.utilities.decorators.prepare` when the bytes remaining in
        the stream measure zero, and it restores the position before raising, so
        the position at end of stream is stable. Two consecutive ends of stream at
        the *same* position therefore mean nothing arrived between them.

        What "between them" covers, exactly
        -----------------------------------

        For a **pipe**, everything, and the live-capture case is safe. A blocking
        read on a pipe whose writer is open but idle *blocks*; it does not report
        end of stream. So a pipe reports it only once the writer has closed --
        permanently -- and a capture that merely pauses never reaches here at all.
        Measured: a pipe paused mid-capture for 1.5s blocked for the whole pause
        and then delivered its remaining frames, with this method not consulted
        until after the writer closed.

        For a **seekable regular file**, only the microseconds between two
        immediately consecutive probes, because such a file does not block -- it
        reports end of stream at once. So an extraction over a file that is still
        being appended to ends at the data present when it got there, rather than
        following the writer. That is a deliberate narrowing of what ``no_eof``
        used to do, and it is measured: on ``6c3d1b0d9`` a file gaining its last
        record 0.6s in yielded all six frames, and here it yields five. The
        previous behaviour was unbounded by construction -- it is the defect #620
        reports -- so *some* stopping rule had to be chosen, and a timed grace
        period would only make the cut-off intermittent rather than absent.
        Following a growing file wants a deliberate policy of its own; see the
        note in :file:`docs/source/changelog/1.5.0.rst`.

        Warning:
            **Not idempotent.** Each call consumes one end-of-stream observation
            by overwriting :attr:`_eof_mark`, so calling it twice for one end of
            stream spends the retry it would have granted. Call it exactly once
            per handler, which is what the three call sites do.

        Returns:
            :data:`True` when retrying may yet produce a frame -- this is the first
            end of stream, or the input has advanced since the last one.
            :data:`False` when the input is standing still and the loop should stop.

        """
        try:
            position = self._ifile.tell()
        except (OSError, ValueError):
            # An input that cannot say where it is cannot be shown to be making
            # progress either, and stopping is the safe answer: the alternative
            # is the unbounded loop this method exists to end.
            return False

        previous, self._eof_mark = self._eof_mark, position
        return previous is None or position > previous

    def _cleanup(self) -> 'None':
        """Cleanup after extraction & analysis.

        The method calls :meth:`self._exeng.close <pcapkit.foundation.engines.engine.Engine.close>`,
        sets :attr:`self._flag_e <pcapkit.foundation.extraction.Extractor._flag_e>`
        as :data:`True` and closes the input file *if this class opened it*.

        That proviso is the whole of it: a handle opened here -- ``fin`` given as
        a path, i.e. :attr:`self._flag_s <Extractor._flag_s>` set -- is closed,
        and a stream the caller supplied is left alone for the caller to close
        when it is done with it.

        It also tells the flow tracer the capture has ended, via
        :meth:`TraceFlow.finish <pcapkit.foundation.traceflow.traceflow.TraceFlowBase.finish>`.
        That is the point at which a traced flow nothing has superseded can be
        said to be over, so it is where such a flow is finalised and its callbacks
        run. This method can be reached twice for one extraction -- the EOF path in
        :meth:`_read_frame` and again from :meth:`run` -- so ``finish`` is required
        to be idempotent rather than guarded here.

        """
        # pylint: disable=attribute-defined-outside-init
        logger.debug('cleaning up after %d frame(s) from %s', self._frnum, self._ifnm)
        self._flag_e = True

        if self._flag_t and self._tcp:
            self._trace.tcp.finish()

        # NOTE: *Ownership* decides who closes the input, not seekability --
        # see :meth:`_owns_input`. Before #610 this read ``not self._flag_s``,
        # which got both halves wrong at once: the handle this class opened
        # itself was never closed, leaking a descriptor and emitting the
        # ``ResourceWarning`` #606 tripped over, while a stream the caller
        # supplied and still needed *was* closed.
        if self._owns_input():
            self._ifile.close()
        self._exeng.close()
