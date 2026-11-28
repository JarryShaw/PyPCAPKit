# -*- coding: utf-8 -*-
# mypy: disable-error-code=dict-item
"""Base Class
================

.. module:: pcapkit.foundation.traceflow.traceflow

:mod:`pcapkit.foundation.traceflow.traceflow` contains
:class:`~pcapkit.foundation.traceflow.traceflow.TraceFlow` only,
which is an abstract base class for all flow tracing classes.

"""
import abc
import collections
import decimal
import math
import numbers
import os
import sys
import types
import weakref
from typing import TYPE_CHECKING, Generic, TypeVar, cast, overload

from dictdumper.dumper import Dumper

from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.corekit.registry import restore_shipped_dumper, same_entry
from pcapkit.dumpkit.common import make_dumper
from pcapkit.protocols.misc.raw.protocol import Raw
from pcapkit.protocols.protocol import ProtocolBase
from pcapkit.utilities import config
from pcapkit.utilities.callbacks import run_callbacks
from pcapkit.utilities.exceptions import (FieldValueError, FileExists, RegistryError,
                                          UnsupportedCall, stacklevel)
from pcapkit.utilities.logging import get_logger
from pcapkit.utilities.warnings import FileWarning, FormatWarning, RegistryWarning, warn

__all__ = ['TraceFlow']

#: logging.Logger: Module-level logger, a child of the package-wide
#: :data:`pcapkit.utilities.logging.logger`.
logger = get_logger(__name__)

# NB: declared above the ``TYPE_CHECKING`` block, not below it, so that
# ``CallbackFn`` can name ``_IT`` outright. As a quoted forward reference it would
# resolve only from this module's namespace, and every module that spells
# ``CallbackFn`` in an annotation -- ``pcapkit.foundation.registry.foundation``
# does -- has to evaluate the alias in its own.
_DT = TypeVar('_DT')
_BT = TypeVar('_BT', bound='Info')
_IT = TypeVar('_IT', bound='Info')
_PT = TypeVar('_PT', bound='Info')

if TYPE_CHECKING:
    from typing import Any, Callable, DefaultDict, Optional, Type

    from typing_extensions import Literal, Self

    from pcapkit.corekit.infoclass import Info

    CallbackFn = Callable[[_IT], None]


#: decimal.Context: Context whose sums and differences are exact, so the idle timeout
#: is compared with no rounding, however many digits a timestamp carries.
_EXACT = decimal.Context(prec=decimal.MAX_PREC, Emax=decimal.MAX_EMAX, Emin=decimal.MIN_EMIN)


def _exact(seconds: 'numbers.Real | float | decimal.Decimal') -> 'decimal.Decimal':
    """Read a capture timestamp, or a timeout, as the decimal it was written as.

    Args:
        seconds: a number of seconds

    Returns:
        A :class:`~decimal.Decimal` as is; otherwise the decimal its shortest
        :func:`repr` spells, which is the capture's own value for a timestamp of at
        most microsecond resolution, rather than the binary fraction the
        :obj:`float` approximates it by. So ``0.4 - 0.1`` is ``0.3``, as the
        capture recorded it, not the larger ``0.30000000000000004``.

    """
    if isinstance(seconds, decimal.Decimal):
        return seconds
    return decimal.Decimal(repr(float(seconds)))


def _close_files(files: 'collections.OrderedDict[int, Dumper]') -> 'None':
    """Close every dumper of ``files``, least recently written first, and forget it.

    Args:
        files: a tracer's :attr:`~TraceFlowBase._fopen`

    """
    while files:
        files.popitem(last=False)[1].close()


class TraceFlowMeta(abc.ABCMeta):
    """Meta class to add dynamic support to :class:`TraceFlow`.

    It provides :attr:`TraceFlow.name`, :attr:`TraceFlow.protocol` and
    :attr:`TraceFlow.registry` as class properties, the first two read from
    ``__protocol_name__`` and ``__protocol_type__`` where a subclass sets them.

    """
    if TYPE_CHECKING:
        #: Protocol name of current object.
        __protocol_name__: 'str'
        #: Protocol of current object.
        __protocol_type__: 'Type[ProtocolBase]'

    @property
    def name(cls) -> 'str':
        """Protocol name of current object."""
        if hasattr(cls, '__protocol_name__'):
            return cls.__protocol_name__
        return cls.__name__

    @property
    def protocol(cls) -> 'Type[ProtocolBase]':
        """Protocol of current object."""
        if hasattr(cls, '__protocol_type__'):
            return cls.__protocol_type__
        return ProtocolBase.get_protocol(cls.name, Raw)

    @property
    def registry(cls) -> 'dict[str, ModuleDescriptor[TraceFlowBase] | Type[TraceFlowBase]]':
        """Mapping of protocol names to flow tracing classes.

        Note:
            Unlike :attr:`EnumSchema.registry
            <pcapkit.protocols.schema.EnumSchema.registry>`, this is not
            a per-class mapping: every flow tracing registration lands in the
            single :attr:`Extractor.__traceflow__
            <pcapkit.foundation.extraction.Extractor.__traceflow__>` table, so
            reading it through any subclass returns that same object. The
            property exists so ``MyTraceFlow.registry`` is spelled the same way
            here as it is for schemas.

            Note also that :class:`EnumSchema` carries *two* ``registry``
            properties, one on its metaclass and one on the class body, so it
            answers on an instance as well. This one is on the metaclass only,
            so it is available as a class attribute and **not** on an instance.

            This is *not* :attr:`TraceFlow.__output__
            <pcapkit.foundation.traceflow.traceflow.TraceFlow.__output__>`,
            which is the separate output-dumper table this class also owns.

        """
        from pcapkit.foundation.extraction import \
            Extractor  # pylint: disable=import-outside-toplevel

        return Extractor.__traceflow__


class TraceFlowBase(Generic[_DT, _BT, _IT, _PT], metaclass=TraceFlowMeta):
    """Base flow tracing class.

    Arguments:
        fout: output path
        format: output format
        byteorder: output file byte order
        nanosecond: output nanosecond-resolution file flag
        bidirectional: trace both halves of a conversation as one flow
        analyze: reassemble each flow's application layer
        timeout: idle timeout in seconds, on the capture's clock; :data:`None`
            keeps every flow until :meth:`finish`

    Note:
        This class is for internal use only. For customisation, please use
        :class:`TraceFlow` instead.

    """
    if TYPE_CHECKING:
        #: Protocol name of current flow tracing object.
        __protocol_name__: 'str'
        #: Protocol of current flow tracing object.
        __protocol_type__: 'Type[ProtocolBase]'

        #: List of callback functions upon a finalised flow.
        __callback_fn__: 'list[CallbackFn]'

        #: Every flow label this tracer has handed out, created with the first
        #: flow and read by :meth:`_unique_label` to keep labels unique.
        _labels: 'set[str]'

    # Internal data storage for cached properties.
    __cached__: 'dict[str, Any]'

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Format dumper mapping for writing output files. Each value pairs the dumper,
    #: as a module descriptor or a :class:`dictdumper.dumper.Dumper` subclass, with
    #: the file extension of its format.
    __output__ = collections.defaultdict(
        lambda: (ModuleDescriptor('pcapkit.dumpkit', 'NotImplementedIO'), None),
        {
            'pcap': (ModuleDescriptor('pcapkit.dumpkit', 'PCAPIO'), '.pcap'),
            'cap': (ModuleDescriptor('pcapkit.dumpkit', 'PCAPIO'), '.pcap'),
            'pcapng': (ModuleDescriptor('pcapkit.dumpkit', 'PCAPNGIO'), '.pcapng'),
            'plist': (ModuleDescriptor('dictdumper', 'PLIST'), '.plist'),
            'xml': (ModuleDescriptor('dictdumper', 'PLIST'), '.plist'),
            'json': (ModuleDescriptor('dictdumper', 'JSON'), '.json'),
            'tree': (ModuleDescriptor('dictdumper', 'Tree'), '.txt'),
            'text': (ModuleDescriptor('dictdumper', 'Tree'), '.txt'),
            'txt': (ModuleDescriptor('dictdumper', 'Tree'), '.txt'),
        },
    )  # type: DefaultDict[str, tuple[ModuleDescriptor[Dumper] | Type[Dumper], str | None]]

    # Read-only copy of ``__output__`` as shipped. :meth:`register_dumper`
    # handed the dumper a format shipped with restores this entry, so an
    # override can be undone (#1363).
    _shipped_output = types.MappingProxyType(dict(__output__))

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'str':
        """Protocol name of current flow tracing object.

        Note:
            The same value is also available as a class attribute,
            from the property of the same name on :class:`TraceFlowMeta`.

        """
        if hasattr(self, '__protocol_name__'):
            return self.__protocol_name__
        return type(self).name  # type: ignore[return-value]

    @property
    def protocol(self) -> 'Type[ProtocolBase]':
        """Protocol of current flow tracing object.

        Note:
            The same value is also available as a class attribute,
            from the property of the same name on :class:`TraceFlowMeta`.

        """
        if hasattr(self, '__protocol_type__'):
            return self.__protocol_type__
        return type(self).protocol  # type: ignore[return-value]

    @property
    def index(self) -> 'tuple[_IT, ...]':
        """Index table for traced flows."""
        if self._buffer:
            return self.submit()
        return tuple(self._stream)

    @property
    def timeout(self) -> 'float':
        """Idle timeout, in seconds, of the current flow tracing object.

        A flow whose latest packet is more than this many seconds old **on the
        capture's own clock** is finalised -- see :meth:`advance`. :data:`math.inf`,
        for a tracer given no timeout, keeps every flow until :meth:`finish`.

        .. versionadded:: 1.10.0

        """
        return self._timeout

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def register_dumper(cls, format: 'str', dumper: 'ModuleDescriptor[Dumper] | Type[Dumper]', *,  # pylint: disable=redefined-builtin
                        ext: 'str') -> 'None':
        r"""Register a new dumper class.

        Notes:
            The fully qualified class name of the new dumper class
            should be ``{dumper.module}.{dumper.name}``.

            The overwrite guard fires only when the incumbent dumper differs
            from the replacement, so re-registering the exact same object is
            a silent no-op rather than a warning about nothing displaced --
            the identity guard of the code-keyed registrars (:issue:`718`,
            :issue:`739`). ``__output__``
            maps each format to a ``(dumper, ext)`` pair, so the identity
            check compares the incumbent *dumper* (index ``0``), not the
            pair -- a re-registration that only changes ``ext`` is still
            identity-equal on the dumper and stays silent, since the dumper
            is what "the same object" means here, not the pair as a whole.
            ``__output__`` is also a :class:`collections.defaultdict`,
            unlike the :class:`~pcapkit.foundation.extraction.Extractor` engine,
            reassembly and flow tracing registries; :meth:`dict.get` does not invoke
            the default factory the way ``cls.__output__[format]`` would, so
            it stays non-inserting here as well.

            The dumper ``format`` shipped with, as its descriptor or as the
            class it names, restores the shipped entry rather than storing
            the class, so an override can be undone and the deferred import
            is kept (:issue:`1363`, :issue:`1364`).

        Arguments:
            format: format name
            dumper: module descriptor or a :class:`dictdumper.dumper.Dumper` subclass
            ext: file extension

        Raises:
            RegistryError: If ``dumper`` is not a class, or not a
                :class:`dictdumper.dumper.Dumper` subclass, such as
                :class:`~pcapkit.dumpkit.common.Dumper`.

        Warns:
            RegistryWarning: If a different dumper is already registered for
                ``format``; it is overwritten.

        .. versionremoved:: 1.1.1.post2

           ``register``, which this replaces with no alias.

        .. versionchanged:: 1.3.0

           ``dumper``, a module descriptor or a class, replaces the ``module``
           and ``class_`` name pair, with no alias.

        .. versionchanged:: 1.7.0

           ``ext`` is keyword-only (:issue:`2839`).

        """
        shipped = cls._shipped_output.get(format)
        if isinstance(dumper, ModuleDescriptor) and (shipped is None or dumper != shipped[0]):
            dumper = dumper.klass
        if shipped is not None and same_entry(shipped[0], dumper):
            restore_shipped_dumper(cls.__output__, format, shipped, ext)
            return
        if not isinstance(dumper, type):
            raise RegistryError(f'dumper must be a class, not {dumper!r}')
        if not issubclass(dumper, Dumper):
            raise RegistryError(f'dumper must be a Dumper subclass, not {dumper!r}')
        incumbent_entry = cls.__output__.get(format)
        incumbent = incumbent_entry[0] if incumbent_entry is not None else None
        if incumbent is not None and incumbent is not dumper:
            warn(f'dumper {format} already registered, overwriting', RegistryWarning)
        cls.__output__[format] = (dumper, ext)

    @classmethod
    def register_callback(cls, callback: 'CallbackFn', *, index: 'Optional[int]' = None) -> 'None':
        """Register callback function.

        Arguments:
            callback: callback function, which will be called
                when a traced flow is finalised, with the flow's
                index entry (:term:`trace.tcp.index`) as its only argument
            index: index to be inserted in the callback list; by
                default, the callback will be appended to the end
                of the list

        Every callback runs on each finalised flow, once its output file holds
        every frame the entry lists. One raising an :exc:`Exception` does not
        stop the rest, and the first such error propagates once they have run.

        .. versionchanged:: 1.7.0

           A callback that raises no longer stops the ones after it (:issue:`2855`).

        """
        if index is not None:
            cls.__callback_fn__.insert(index, callback)
        else:
            cls.__callback_fn__.append(callback)

    @classmethod
    def make_fout(cls, fout: 'str' = './tmp', *,
                  format: 'str' = 'pcap') -> 'tuple[Type[Dumper], str | None]':  # pylint: disable=redefined-builtin
        """Make root path for output.

        Args:
            fout: root path for output
            format: output format

        Returns:
            Dumper of specified format and file extension of output file.

        Warns:
            FormatWarning: If ``format`` is not supported.
            FileWarning: If ``fout`` exists but is not a directory, and
                ``format`` is not supported.

        Raises:
            FileExists: If ``fout`` exists but is not a directory, and
                ``format`` is supported.

        .. versionchanged:: 1.7.0

           ``fmt`` is renamed ``format``, with no alias, and is keyword-only
           (:issue:`2839`).

        """
        output, ext = cls.__output__[format]
        if ext is None:
            warn(f'unsupported output format: {format!r}; disabled file output feature',
                 FormatWarning, stacklevel=stacklevel())
        if isinstance(output, ModuleDescriptor):
            output = output.klass

        try:
            os.makedirs(fout, exist_ok=True)
        except FileExistsError as error:
            if ext is None:
                warn(error.strerror, FileWarning, stacklevel=stacklevel())
            else:
                raise FileExists(*error.args).with_traceback(error.__traceback__)

        dumper = make_dumper(output)
        # NOTE: logs ``output``, not ``dumper`` -- make_dumper()'s subclass is
        # always called 'DictDumper'.
        logger.debug('flow tracing output root %s, format %s via %s', fout, format, output.__name__)
        return dumper, ext

    def make_bufid(self, packet: '_PT') -> '_DT':
        """Derive the buffer ID a packet belongs to.

        Arguments:
            packet: a flow packet

        Returns:
            Buffer ID: the packet's two endpoints, as :meth:`_endpoints` reads
            them, in one flat :obj:`tuple` -- ``(address, port, address, port)``
            for TCP and UDP, ``(address, address)`` for IP.

        Tracing bidirectionally means both halves of a conversation have to land
        on the *same* key, so the two endpoints are ordered canonically -- the
        lesser first -- rather than as (source, destination): the client's
        ``A→B`` and the server's ``B→A`` both reduce to ``min(A, B), max(A, B)``.

        The result stays a plain :obj:`tuple`, which is deliberate and not merely
        convenient: it is a :obj:`dict` key, and an
        :class:`~pcapkit.corekit.infoclass.Info` cannot be one -- inheriting
        :class:`collections.abc.Mapping` sets ``__hash__`` to :data:`None`.

        Note:
            Both endpoints of a flow are of the same address family, so the
            comparison never has to order an :class:`~ipaddress.IPv4Address`
            against an :class:`~ipaddress.IPv6Address` -- which raises
            :exc:`TypeError`.

        .. versionchanged:: 1.10.0

           Defined here for every flow tracer, reading the endpoints from
           :meth:`_endpoints`, where :class:`~pcapkit.foundation.traceflow.tcp.traceflow.TCP`
           defined it (:issue:`2956`).

        """
        near, far = self._endpoints(packet)
        if self._bidir and far < near:
            return cast('_DT', (*far, *near))
        return cast('_DT', (*near, *far))

    @abc.abstractmethod
    def dump(self, packet: '_PT') -> 'None':
        """Dump frame to output files.

        Arguments:
            packet: a flow packet (:term:`trace.tcp.packet`)

        """

    @overload
    def trace(self, packet: '_PT', *, output: 'Literal[True]' = ...) -> 'Dumper': ...
    @overload
    def trace(self, packet: '_PT', *, output: 'Literal[False]' = ...) -> 'str': ...

    @abc.abstractmethod
    def trace(self, packet: '_PT', *, output: 'bool' = False) -> 'Dumper | str':
        """Trace packets.

        Arguments:
            packet: a flow packet (:term:`trace.tcp.packet`)
            output: flag if has formatted dumper

        Returns:
            If ``output`` is :data:`True`, returns the initiated
            :class:`~dictdumper.dumper.Dumper` object, which will dump data to
            the output file named after the flow label; otherwise, returns the
            flow label itself.

        """

    @abc.abstractmethod
    def submit(self) -> 'tuple[_IT, ...]':
        """Submit traced TCP flows.

        Returns:
            Traced TCP flow (:term:`trace.tcp.index`).

        """

    def advance(self, timestamp: 'float') -> 'None':
        """Advance the capture clock, finalising every flow it leaves idle.

        Arguments:
            timestamp: Capture timestamp of the current frame, in seconds since
                the Unix epoch.

        A flow is idle once more than :attr:`timeout` seconds separate
        ``timestamp`` from its latest packet, and is finalised then, its callbacks
        run, as :meth:`finish` finalises it at the end of the capture. The two are
        compared exactly, as the decimals :func:`_exact` reads, so a flow exactly
        :attr:`timeout` seconds idle is kept whatever its timestamps' binary
        rounding. That is the
        idle timeout by which IPFIX ends a flow, flowEndReason ``0x01`` of
        Information Element 136. The
        :class:`~pcapkit.foundation.extraction.Extractor` calls this with every
        frame's timestamp before the frame is fed, and a flow packet calls it with
        its own, so a tracer fed by hand times flows out too.

        A flow tracer whose flows never record a packet's time, as one built on
        :class:`TraceFlow` that does not call :meth:`_touch`, has nothing to time
        out, and nothing is finalised.

        .. versionadded:: 1.10.0

        """
        if math.isinf(self._timeout) or not self._seen:
            return

        # NOTE: exact, as a float difference can exceed the timeout it equals: 0.4 - 0.1 > 0.3.
        deadline = _EXACT.subtract(_exact(timestamp), self._idle)
        for bufid in [bufid for (bufid, seen) in self._seen.items() if seen < deadline]:
            logger.debug('%s flow %s idle for over %.6fs', self.name, bufid, self._timeout)
            self._finalise(bufid)

    def finish(self) -> 'None':
        """Finalise every flow still being traced.

        Called by :meth:`Extractor._cleanup
        <pcapkit.foundation.extraction.Extractor._cleanup>` once the capture has
        been read to its end, which is the point at which a flow that was never
        superseded can be said to be over.

        The base implementation only calls :meth:`close`, so a tracer that has no
        such notion need not override it. :meth:`submit` must remain able to report
        a flow that was never finalised, since nothing guarantees this is called: a
        tracer driven directly rather than through an
        :class:`~pcapkit.foundation.extraction.Extractor` never sees an end of
        capture.

        Implementations must be **idempotent**: :meth:`Extractor._cleanup
        <pcapkit.foundation.extraction.Extractor._cleanup>` can run more than once
        for one extraction.

        .. versionchanged:: 1.7.0

           The base implementation calls :meth:`close` (:issue:`2815`).

        """
        self.close()

    def close(self) -> 'None':
        """Close every flow output file this tracer keeps open.

        :meth:`_write` keeps a flow's file open between its frames. A flow
        written to after this reopens its file, so tracing can go on.
        :meth:`finish` calls this, and so does :meth:`__call__` when tracing a
        frame raises; a tracer dropped before either closes them when it is
        collected.

        .. versionadded:: 1.7.0

        """
        _close_files(self._fopen)

    ##########################################################################
    # Data models.
    ##########################################################################

    def __new__(cls, *args: 'Any', **kwargs: 'Any') -> 'Self':  # pylint: disable=unused-argument
        self = super().__new__(cls)

        # NOTE: Assign this attribute after ``__new__`` to avoid shared memory
        # reference between instances.
        self.__cached__ = {}

        return self

    def __init__(self, *, fout: 'str' = './tmp', format: 'str' = 'pcap',  # pylint: disable=redefined-builtin
                 byteorder: 'Literal["little", "big"]' = sys.byteorder,
                 nanosecond: 'bool' = False, bidirectional: 'bool' = True,
                 analyze: 'bool' = False, timeout: 'Optional[float]' = None) -> 'None':
        """Initialise instance.

        Arguments:
            fout: output root path, made if missing
            format: output format, a key of :attr:`__output__`
            byteorder: output file byte order
            nanosecond: output nanosecond-resolution file flag
            bidirectional: whether the two halves of a conversation are one flow.
                :data:`True` -- the default -- keys a flow on the *pair* of
                endpoints rather than on (source, destination), so a connection
                is traced as the one thing it is; pass :data:`False` to trace
                each direction as a flow of its own.
            analyze: whether to reassemble each flow's application layer, so that
                its ``packet`` can be read. Off by default: it buffers every
                traced payload, a cost tracing does not otherwise pay.
            timeout: idle timeout in seconds, measured on the capture's own clock
                rather than the host's (see :meth:`advance`); :data:`None` keeps
                every flow until :meth:`finish`

        Raises:
            FieldValueError: If ``timeout`` is negative, NaN, or no real number of
                seconds, as a :obj:`bool` or a :obj:`str` is not.

        .. versionchanged:: 1.10.0

           Takes ``timeout`` (:issue:`2956`).

        """
        # NOTE: checked before make_fout() below creates the output root; a bool is no number of seconds.
        given = cast('Any', timeout)
        if given is not None and (isinstance(given, bool) or not isinstance(given, (numbers.Real, decimal.Decimal))
                                  or _exact(given).is_nan() or given < 0):
            raise FieldValueError(f'{type(self).__name__}: flow tracing timeout must be a non-negative '
                                  f'number of seconds, got {timeout!r}')
        #: float: Idle timeout in seconds, on the capture's clock. :data:`math.inf`
        #: keeps every flow until :meth:`finish`.
        self._timeout = math.inf if timeout is None else float(timeout)
        #: decimal.Decimal: :attr:`_timeout` exactly as given, which :meth:`advance`
        #: compares with.
        self._idle = _exact(self._timeout if timeout is None else timeout)
        #: dict[_DT, decimal.Decimal]: Capture timestamp of each open flow's latest
        #: packet, by buffer ID, which :meth:`advance` reads; written by
        #: :meth:`_touch`, and only while :attr:`timeout` is finite.
        self._seen = {}  # type: dict[_DT, decimal.Decimal]

        #: str: Output root path.
        self._fproot = fout

        #: dict[_DT, _BT]: Buffer field (:term:`trace.tcp.buffer`).
        self._buffer = {}  # type: dict[_DT, _BT]
        #: list[_IT]: Stream index (:term:`trace.tcp.index`).
        self._stream = []  # type: list[_IT]

        #: Literal['little', 'big']: Output file byte order.
        self._endian = byteorder
        #: bool: Output nanosecond-resolution file flag.
        self._nnsecd = nanosecond
        #: bool: Bidirectional tracing flag. If set to :data:`True`, both halves
        #: of a conversation share one buffer entry, one label and one output
        #: file; otherwise each direction is a flow of its own.
        self._bidir = bidirectional
        #: bool: Application-layer analysis flag. If set to :data:`True`, each
        #: flow reassembles the payload it carries so that its ``packet`` can be
        #: read; otherwise no payload is buffered and ``packet`` is
        #: :data:`None`.
        self._analyze = analyze
        #: dict[str, Any]: Keyword arguments a reassembled payload's parse takes
        #: under ``analyze``: the stops and context the engine parses its frames
        #: with, as :meth:`EngineBase._setup_traceflow
        #: <pcapkit.foundation.engines.engine.EngineBase._setup_traceflow>` hands
        #: them over (:issue:`2946`).
        self._parse_keywords = {}  # type: dict[str, Any]

        # dump I/O object
        fio, ext = self.make_fout(fout, format=format)
        #: ~typing.Type[Dumper]: Dumper class.
        self._foutio = fio
        #: Optional[str]: Output file extension.
        self._fdpext = ext
        #: collections.OrderedDict[int, Dumper]: Dumpers keeping their flow's
        #: output file open, by :func:`id`, least recently written first; see
        #: :meth:`_write`.
        self._fopen = collections.OrderedDict()  # type: collections.OrderedDict[int, Dumper]
        # NOTE: closes them for a tracer dropped before finish(); a ``weakref.finalize``,
        # as GraalPy never calls ``__del__`` (#1997), holding the files only, never ``self``.
        self._finalizer = weakref.finalize(self, _close_files, self._fopen)

        logger.debug('%s flow tracing initialised (root=%s, format=%s, byteorder=%s, '
                     'nanosecond=%s, bidirectional=%s, analyze=%s, timeout=%s)', self.name, fout,
                     format, byteorder, nanosecond, bidirectional, analyze, self._timeout)

    def __call__(self, packet: '_PT') -> 'None':
        """Dump frame to output files.

        Arguments:
            packet: a flow packet (:term:`trace.tcp.packet`)

        An error closes every output file kept open (:meth:`close`), since the
        caller may then stop before :meth:`finish`.

        """
        # trace frame record
        try:
            self.dump(packet)
        except BaseException:
            self.close()
            raise

    def __init_subclass__(cls) -> 'None':
        """Initialise subclass.

        This method is to be used for generating necessary attributes
        for the :class:`TraceFlow` class. It can be useful to reduce
        unnecessary registry calls and simplify the customisation process.

        """
        cls.__callback_fn__ = []

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _write(self, dumper: 'Dumper', value: 'Any', name: 'str', *, hold: 'bool' = True) -> 'None':
        """Write a frame to a flow's output file, keeping the file open.

        Arguments:
            dumper: the flow's output dumper
            value: the frame
            name: name of the frame's block
            hold: whether the flow takes more frames, and so whether its file is
                worth keeping open

        Keeping the file open between frames, through
        :meth:`~pcapkit.dumpkit.common.DumperBase.open`, saves reopening it per
        frame (:issue:`2815`). At most
        :data:`~pcapkit.utilities.config.TRACE_OPEN_FILE_LIMIT` files are kept
        open: past it, the one written least recently is closed, and reopened on
        its flow's next frame.

        """
        files = self._fopen
        key = id(dumper)
        if key in files:
            files.move_to_end(key)
        elif hold and (limit := config.TRACE_OPEN_FILE_LIMIT):
            while 0 < limit <= len(files):
                files.popitem(last=False)[1].close()
            dumper.open()
            files[key] = dumper
        dumper(value, name=name)

    def _release(self, dumper: 'Dumper') -> 'None':
        """Close a flow's output file, once the flow takes no more frames.

        Arguments:
            dumper: the flow's output dumper

        """
        held = self._fopen.pop(id(dumper), None)
        if held is not None:
            held.close()

    def _endpoints(self, packet: '_PT') -> 'tuple[tuple[Any, ...], tuple[Any, ...]]':
        """The endpoints of a flow packet: its sender's, then its receiver's.

        Arguments:
            packet: a flow packet

        Returns:
            ``(address, port)`` of the source, then of the destination, which is
            how TCP and UDP key a flow. A tracer whose protocol has no ports, as
            :class:`~pcapkit.foundation.traceflow.ip.traceflow.IP`, overrides it.

        :meth:`make_bufid` keys a flow on them, :meth:`_make_label` names it after
        them, and :meth:`_append` tells the directions apart by them.

        .. versionadded:: 1.10.0

        """
        info = cast('Any', packet)
        return (info.src, info.srcport), (info.dst, info.dstport)

    def _make_label(self, packet: '_PT') -> 'str':
        """Label a new flow after the packet that opens it.

        Arguments:
            packet: the flow packet opening the flow

        Returns:
            The fields of each endpoint :meth:`_endpoints` reads, joined by ``_``,
            source first, then the packet's timestamp, the three joined by ``-``,
            and made unique within the tracer by :meth:`_unique_label`. On an IPv6
            flow every ``:`` is replaced by ``.``, since a Windows file name cannot
            carry one, where it separates the drive letter.

        So the label names the initiator first, and the reverse half of a
        bidirectional conversation joins the flow rather than minting a label of
        its own.

        .. versionadded:: 1.10.0

        """
        info = cast('Any', packet)
        near, far = self._endpoints(packet)
        label = '-'.join(['_'.join(map(str, near)), '_'.join(map(str, far)), str(info.timestamp)])
        if info.src.version != 4:
            label = label.replace(':', '.')
        return self._unique_label(label)

    def _unique_label(self, label: 'str') -> 'str':
        """Make a new flow's label unique within this tracer.

        Arguments:
            label: the label built from the packet that opens the flow

        Returns:
            ``label`` itself if no earlier flow carries it; otherwise ``label``
            suffixed with the first of ``-1``, ``-2``, ... that is still unused.

        The label names the flow's output file, which is opened -- and so
        truncated -- when the flow starts. Two flows with one label would
        therefore share one file, and the later would erase the earlier: the
        same endpoints opening a second flow at the same capture timestamp, as a
        flow superseded or timed out on its endpoints' next packet can. A label
        that does not collide is returned unchanged.

        .. versionchanged:: 1.10.0

           Defined here for every flow tracer, where
           :class:`~pcapkit.foundation.traceflow.tcp.traceflow.TCP` defined it
           (:issue:`2956`).

        """
        used = self.__dict__.setdefault('_labels', set())  # type: set[str]
        unique, count = label, 0
        while unique in used:
            count += 1
            unique = f'{label}-{count}'
        used.add(unique)
        return unique

    def _make_fpout(self, label: 'str', protocol: 'Any') -> 'Dumper':
        """Make the dumper a new flow writes its output file through.

        Arguments:
            label: the flow's label, which names the file
            protocol: data link type of the frames the file holds

        Returns:
            A dumper of the tracer's output format, writing the file
            :meth:`_output_path` reports, or no file when the format writes none.

        .. versionadded:: 1.10.0

        """
        return self._foutio(fname=f'{self._fproot}/{label}{self._fdpext or ""}', protocol=protocol,
                            byteorder=self._endian, nanosecond=self._nnsecd)

    def _output_path(self, label: 'str') -> 'Optional[str]':
        """Path of a flow's output file, as an index entry reports it.

        Arguments:
            label: the flow's label

        Returns:
            The file :meth:`trace` writes the flow to, or :data:`None` when the
            output format writes no file at all. An *empty* extension still
            writes one, named after the label alone.

        :meth:`submit` and :meth:`_finalise` both report through this, so an
        open flow and a finalised one name the same file (:issue:`2237`).

        .. versionchanged:: 1.10.0

           Defined here for every flow tracer, where
           :class:`~pcapkit.foundation.traceflow.tcp.traceflow.TCP` defined it
           (:issue:`2956`).

        """
        if self._fdpext is None:
            return None
        return f'{self._fproot}/{label}{self._fdpext}'

    def _append(self, buffer: '_BT', packet: '_PT') -> 'None':
        """Record a packet's frame number in its flow, and in the direction it went.

        Arguments:
            buffer: the flow's buffer, holding ``index``, ``origin``, ``forward``
                and ``reverse`` as each built-in flow tracer's does
            packet: a flow packet

        The frame joins ``index``, which keeps both directions in capture order,
        and ``forward`` if its source endpoint is the ``origin`` that opened the
        flow, ``reverse`` otherwise, so each half stays recoverable on its own.

        .. versionadded:: 1.10.0

        """
        info, flow = cast('Any', packet), cast('Any', buffer)
        flow.index.append(info.index)
        if self._endpoints(packet)[0] == flow.origin:
            flow.forward.append(info.index)
        else:
            flow.reverse.append(info.index)

    def _touch(self, bufid: '_DT', timestamp: 'float') -> 'None':
        """Note when an open flow last saw a packet, for :meth:`advance` to time it out.

        Arguments:
            bufid: buffer identifier of the flow
            timestamp: capture timestamp of the packet

        The latest timestamp is kept, so a capture whose timestamps step back
        does not age a flow. Nothing is noted while :attr:`timeout` is infinite.

        .. versionadded:: 1.10.0

        """
        if math.isinf(self._timeout):
            return
        exact, seen = _exact(timestamp), self._seen.get(bufid)
        self._seen[bufid] = exact if seen is None else max(seen, exact)

    def _make_index(self, buffer: '_BT') -> '_IT':
        """Report a flow's buffer as its index entry.

        Arguments:
            buffer: a flow buffer

        Returns:
            The flow's index entry.

        Raises:
            NotImplementedError: Unless the flow tracer overrides it, as each
                built-in does; only :meth:`_finalise` and the built-ins'
                :meth:`submit` call it.

        .. versionadded:: 1.10.0

        """
        raise NotImplementedError(f'{type(self).__name__} reports no index entry of its own')

    def _finalise(self, bufid: '_DT') -> '_IT':
        """Finalise a flow: report it, and stop tracing into it.

        Arguments:
            bufid: buffer identifier of the flow to finalise

        Returns:
            The flow's index entry, from :meth:`_make_index`.

        Called once per flow, from where its tracer ends it: :meth:`finish` at
        the end of the capture, :meth:`advance` once it is idle, or a rule of
        the tracer's own, such as a TCP connection's reuse.

        The flow's file is closed and its entry stored before the callbacks run,
        so a callback that raises propagates and leaves the flow in the index.
        One raising an :exc:`Exception` does not stop the callbacks after it: the
        first such error is re-raised once all have run, and a later one logged,
        by :func:`~pcapkit.utilities.callbacks.run_callbacks`, to the logger of
        the module the tracer is defined in.

        .. versionchanged:: 1.10.0

           Defined here for every flow tracer, where
           :class:`~pcapkit.foundation.traceflow.tcp.traceflow.TCP` defined it
           (:issue:`2956`).

        """
        buf = cast('Any', self._buffer.pop(bufid))
        self._seen.pop(bufid, None)
        self.__cached__['submit'] = None
        label = buf.label
        # NOTE: closed before the callbacks run, so they find the file closed.
        self._release(buf.fpout)

        log = get_logger(type(self).__module__)
        log.debug('%s flow %s finalised after %d frame(s) (%d forward, %d reverse)',
                  self.name, label, len(buf.index), len(buf.forward), len(buf.reverse))
        index = self._make_index(buf)
        # NOTE: stored before the callbacks run, so one that raises cannot drop the flow
        # from the index (#2827).
        self._stream.append(index)
        run_callbacks(self.__callback_fn__, index, logger=log, subject=f'{self.name} flow {label}')
        return index


class TraceFlow(TraceFlowBase[_DT, _BT, _IT, _PT], Generic[_DT, _BT, _IT, _PT]):
    """Base flow tracing class.

    Example:

        Registration is opt-in. Pass keyword argument ``protocol`` at class
        definition to register the flow tracing class under that protocol name:

        .. code-block:: python

           class MyProtocol(TraceFlow, protocol='my_protocol'):
               ...

        Omit it and the subclass is *not* registered, which is how a class
        that is not meant to be selectable by name declines:

        .. code-block:: python

           class MyMixin(TraceFlow):  # not registered
               ...

        Such a class can still be registered later, on demand:

        .. code-block:: python

           Extractor.register_traceflow('my_mixin', MyMixin)

    Arguments:
        fout: output path
        format: output format
        byteorder: output file byte order
        nanosecond: output nanosecond-resolution file flag
        bidirectional: trace both halves of a conversation as one flow
        analyze: reassemble each flow's application layer
        timeout: idle timeout in seconds, on the capture's clock; :data:`None`
            keeps every flow until :meth:`finish`

    .. versionchanged:: 1.3.0

       :attr:`name` and :attr:`protocol` are read from ``__protocol_name__``
       and ``__protocol_type__``, where they were abstract properties each
       flow tracing class implemented, and the built-in name is short:
       ``'TCP'`` rather than ``'Transmission Control Protocol'``. A subclass
       registers itself with :class:`~pcapkit.foundation.extraction.Extractor`
       at class definition.

    .. versionchanged:: 1.5.0

       Registration is opt-in, under the ``protocol`` class keyword; 1.4.x
       registered every subclass, under its :attr:`name` when the keyword was
       omitted (:issue:`514`). The ``bidirectional`` and ``analyse`` arguments
       are added, and a flow covers both directions of a conversation unless
       ``bidirectional=False`` is passed.

    .. versionchanged:: 1.7.0

       Every argument is keyword-only, with its real default in the signature,
       where ``fout`` and ``format`` were required and took :data:`None` for
       ``'./tmp'`` and ``'pcap'``; ``analyse`` is renamed ``analyze``, with no
       alias (:issue:`2839`).

    .. versionchanged:: 1.10.0

       Takes ``timeout``, and a flow idle for longer is finalised (:issue:`2956`).

    """

    def __init_subclass__(cls, /, protocol: 'Optional[str]' = None, *args: 'Any', **kwargs: 'Any') -> 'None':
        """Initialise subclass.

        This method is to be used for registering the flow tracing class to
        :class:`~pcapkit.foundation.extraction.Extractor` class.

        Args:
            protocol: Protocol name to register the subclass under, lowercased.
                :data:`None` (the default) skips registration entirely.
            *args: Arbitrary positional arguments.
            **kwargs: Arbitrary keyword arguments.

        Raises:
            UnsupportedCall: If any unrecognised class keyword is given.

        Registration is **opt-in**: the subclass is registered if and only if
        ``protocol`` is given. This is what lets a subclass decline registration
        rather than having to inherit :class:`TraceFlowBase` to avoid it, and it
        matches :meth:`EnumSchema.__init_subclass__
        <pcapkit.protocols.schema.EnumSchema.__init_subclass__>`, which
        guards on its own ``code`` keyword the same way.

        Note:
            :attr:`__protocol_name__` is *not* an opt-in. It supplies the
            :attr:`name <pcapkit.foundation.traceflow.traceflow.TraceFlow.name>`
            the class reports, which it does whether or not the class is
            registered; only the keyword decides registration.

        See Also:
            For more details, please refer to
            :meth:`pcapkit.foundation.extraction.Extractor.register_traceflow`.

        """
        # NOTE: ``engine=`` or ``name=`` here is the expected mistake, and left in ``**kwargs``
        # it would silently skip registration; see ``Engine.__init_subclass__``.
        if args or kwargs:
            unexpected = ', '.join([*map(repr, args), *sorted(kwargs)])
            raise UnsupportedCall(f'{cls.__name__}: unexpected class keyword(s): {unexpected}')

        if protocol is not None:
            from pcapkit.foundation.extraction import \
                Extractor  # pylint: disable=import-outside-toplevel

            Extractor.register_traceflow(protocol.lower(), cls)

        return super().__init_subclass__()
