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
import os
import sys
from typing import TYPE_CHECKING, Generic, TypeVar, overload

from dictdumper.dumper import Dumper

from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.dumpkit.common import make_dumper
from pcapkit.protocols import __proto__ as protocol_registry
from pcapkit.protocols.misc.raw import Raw
from pcapkit.utilities.exceptions import FileExists, RegistryError, UnsupportedCall, stacklevel
from pcapkit.utilities.logging import get_logger
from pcapkit.utilities.warnings import FileWarning, FormatWarning, RegistryWarning, warn

__all__ = ['TraceFlow']

#: logging.Logger: Module-level logger, a child of the package-wide
#: :data:`pcapkit.utilities.logging.logger`.
logger = get_logger(__name__)

# NB: declared above the ``TYPE_CHECKING`` block, not below it, so that
# ``CallbackFn`` can name ``_IT`` outright. As a quoted forward reference it was
# resolvable only from this module's namespace, and every module that spells
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
    from pcapkit.protocols.protocol import ProtocolBase as Protocol

    CallbackFn = Callable[[_IT], None]


class TraceFlowMeta(abc.ABCMeta):
    """Meta class to add dynamic support to :class:`TraceFlow`.

    This meta class is used to generate necessary attributes for the
    :class:`TraceFlow` class. It can be useful to reduce unnecessary
    registry calls and simplify the customisation process.

    """
    if TYPE_CHECKING:
        #: Protocol name of current object.
        __protocol_name__: 'str'
        #: Protocol of current object.
        __protocol_type__: 'Type[Protocol]'

    @property
    def name(cls) -> 'str':
        """Protocol name of current object."""
        if hasattr(cls, '__protocol_name__'):
            return cls.__protocol_name__
        return cls.__name__

    @property
    def protocol(cls) -> 'Type[Protocol]':
        """Protocol of current object."""
        if hasattr(cls, '__protocol_type__'):
            return cls.__protocol_type__
        return protocol_registry.get(cls.name.upper(), Raw)

    @property
    def registry(cls) -> 'dict[str, ModuleDescriptor[TraceFlow] | Type[TraceFlow]]':
        """Mapping of protocol names to flow tracing classes.

        Note:
            Unlike :attr:`EnumSchema.registry
            <pcapkit.protocols.schema.schema.EnumSchema.registry>`, this is not
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
            <pcapkit.foundation.traceflow.traceflow.TraceFlowBase.__output__>`,
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
        analyse: reassemble each flow's application layer

    Note:
        This class is for internal use only. For customisation, please use
        :class:`TraceFlow` instead.

    """
    if TYPE_CHECKING:
        #: Protocol name of current reassembly object.
        __protocol_name__: 'str'
        #: Protocol of current reassembly object.
        __protocol_type__: 'Type[Protocol]'

        #: List of callback functions upon reassembled datagram.
        __callback_fn__: 'list[CallbackFn]'

    # Internal data storage for cached properties.
    __cached__: 'dict[str, Any]'

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: DefaultDict[str, tuple[ModuleDescriptor[Dumper] | ~typing.Type[Dumper], str | None]]:
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

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'str':
        """Protocol name of current flow tracing object.

        Note:
            This property is not available as a class
            attribute.

        """
        if hasattr(self, '__protocol_name__'):
            return self.__protocol_name__
        return type(self).name  # type: ignore[return-value]

    @property
    def protocol(self) -> 'Type[Protocol]':
        """Protocol of current flow tracing object.

        Note:
            This property is not available as a class
            attribute.

        """
        if hasattr(self, '__protocol_type__'):
            return self.__protocol_type__
        return type(self).protocol  # type: ignore[return-value]

    @property
    def index(self) -> 'tuple[_IT, ...]':
        """_IT table for traced flow."""
        if self._buffer:
            return self.submit()
        return tuple(self._stream)

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
    def register_callback(cls, callback: 'CallbackFn', *, index: 'Optional[int]' = None) -> 'None':
        """Register callback function.

        Arguments:
            callback: callback function, which will be called
                when reassembled datagram is obtained, with the
                list of reassembled datagrams as its only argument
            index: index of datagram to be called

        """
        if index is not None:
            cls.__callback_fn__.insert(index, callback)
        else:
            cls.__callback_fn__.append(callback)

    @classmethod
    def make_fout(cls, fout: 'str' = './tmp', fmt: 'str' = 'pcap') -> 'tuple[Type[Dumper], str | None]':
        """Make root path for output.

        Args:
            fout: root path for output
            fmt: output format

        Returns:
            Dumper of specified format and file extension of output file.

        Warns:
            FormatWarning: If ``fmt`` is not supported.
            FileWarning: If ``fout`` exists and ``fmt`` is :data:`None`.

        Raises:
            FileExists: If ``fout`` exists and ``fmt`` is **NOT** :data:`None`.

        """
        output, ext = cls.__output__[fmt]
        if ext is None:
            warn(f'Unsupported output format: {fmt}; disabled file output feature',
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
        # NOTE: as above -- make_dumper()'s subclass is always called 'DictDumper'.
        logger.debug('flow tracing output root %s, format %s via %s', fout, fmt, output.__name__)
        return dumper, ext

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

    def finish(self) -> 'None':
        """Finalise every flow still being traced.

        Called by :meth:`Extractor._cleanup
        <pcapkit.foundation.extraction.Extractor._cleanup>` once the capture has
        been read to its end, which is the point at which a flow that was never
        superseded can be said to be over.

        The base implementation does nothing, so a tracer that has no such notion
        -- or an existing third-party subclass that predates this method -- keeps
        working unchanged. :meth:`submit` must remain able to report a flow that
        was never finalised, since nothing guarantees this is called: a tracer
        driven directly rather than through an
        :class:`~pcapkit.foundation.extraction.Extractor` never sees an end of
        capture.

        Implementations must be **idempotent**: :meth:`Extractor._cleanup
        <pcapkit.foundation.extraction.Extractor._cleanup>` can run more than once
        for one extraction.

        """

    ##########################################################################
    # Data models.
    ##########################################################################

    def __new__(cls, *args: 'Any', **kwargs: 'Any') -> 'Self':  # pylint: disable=unused-argument
        self = super().__new__(cls)

        # NOTE: Assign this attribute after ``__new__`` to avoid shared memory
        # reference between instances.
        self.__cached__ = {}

        return self

    def __init__(self, fout: 'Optional[str]', format: 'Optional[str]',  # pylint: disable=redefined-builtin
                 byteorder: 'Literal["little", "big"]' = sys.byteorder,
                 nanosecond: bool = False, bidirectional: 'bool' = True,
                 analyse: 'bool' = False) -> 'None':
        """Initialise instance.

        Arguments:
            fout: output path
            format: output format
            byteorder: output file byte order
            nanosecond: output nanosecond-resolution file flag
            bidirectional: whether the two halves of a conversation are one flow.
                :data:`True` -- the default -- keys a flow on the *pair* of
                endpoints rather than on (source, destination), so a connection
                is traced as the one thing it is; pass :data:`False` for the
                older per-direction behaviour.
            analyse: whether to reassemble each flow's application layer, so that
                its ``packet`` can be read. Off by default: it buffers every
                traced payload, a cost tracing does not otherwise pay.

        """
        if fout is None:
            fout = './tmp'
        if format is None:
            format = 'pcap'

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
        self._analyse = analyse

        # dump I/O object
        fio, ext = self.make_fout(fout, format)
        #: ~typing.Type[Dumper]: Dumper class.
        self._foutio = fio
        #: Optional[str]: Output file extension.
        self._fdpext = ext

        logger.debug('%s flow tracing initialised (root=%s, format=%s, byteorder=%s, '
                     'nanosecond=%s, bidirectional=%s, analyse=%s)', self.name, fout,
                     format, byteorder, nanosecond, bidirectional, analyse)

    def __call__(self, packet: '_PT') -> 'None':
        """Dump frame to output files.

        Arguments:
            packet: a flow packet (:term:`trace.tcp.packet`)

        """
        # trace frame record
        self.dump(packet)

    def __init_subclass__(cls) -> 'None':
        """Initialise subclass.

        This method is to be used for generating necessary attributes
        for the :class:`TraceFlow` class. It can be useful to reduce
        unnecessary registry calls and simplify the customisation process.

        """
        cls.__callback_fn__ = []


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
        analyse: reassemble each flow's application layer

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
        <pcapkit.protocols.schema.schema.EnumSchema.__init_subclass__>`, which
        has guarded on its own ``code`` keyword all along.

        Note:
            :attr:`__protocol_name__` is *not* an opt-in. It supplies the
            :attr:`name <pcapkit.foundation.traceflow.traceflow.TraceFlowMeta.name>`
            the class reports, which it does whether or not the class is
            registered; only the keyword decides registration.

        See Also:
            For more details, please refer to
            :meth:`pcapkit.foundation.extraction.Extractor.register_traceflow`.

        """
        # NOTE: the keyword here is ``protocol``, but ``Engine`` spells the same
        # idea ``name`` -- so guessing ``name=`` by analogy is the expected
        # mistake, not a careless one. It used to land in ``**kwargs``, get
        # dropped by the bare ``super().__init_subclass__()`` below, and leave
        # the class registered under its own class name instead: no exception, no
        # warning. See the sibling note in ``Engine.__init_subclass__``.
        if args or kwargs:
            unexpected = ', '.join([*map(repr, args), *sorted(kwargs)])
            raise UnsupportedCall(f'{cls.__name__}: unexpected class keyword(s): {unexpected}')

        if protocol is not None:
            from pcapkit.foundation.extraction import \
                Extractor  # pylint: disable=import-outside-toplevel

            Extractor.register_traceflow(protocol.lower(), cls)

        return super().__init_subclass__()
