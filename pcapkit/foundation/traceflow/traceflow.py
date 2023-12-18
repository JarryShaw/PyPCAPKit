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
from typing import TYPE_CHECKING, Generic, TypeVar, cast, overload

from dictdumper.dumper import Dumper

from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.dumpkit.common import make_dumper
from pcapkit.protocols import __proto__ as protocol_registry
from pcapkit.protocols.misc.raw import Raw
from pcapkit.utilities.exceptions import FileExists, RegistryError, stacklevel
from pcapkit.utilities.warnings import FileWarning, FormatWarning, RegistryWarning, warn

__all__ = ['TraceFlow']

if TYPE_CHECKING:
    from typing import Any, Callable, DefaultDict, Optional, Type

    from typing_extensions import Literal, Self

    from pcapkit.corekit.infoclass import Info
    from pcapkit.protocols.protocol import ProtocolBase as Protocol

    CallbackFn = Callable[['_IT'], None]

_DT = TypeVar('_DT')
_BT = TypeVar('_BT', bound='Info')
_IT = TypeVar('_IT', bound='Info')
_PT = TypeVar('_PT', bound='Info')


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


class TraceFlowBase(Generic[_DT, _BT, _IT, _PT], metaclass=TraceFlowMeta):
    """Base flow tracing class.

    Arguments:
        fout: output path
        format: output format
        byteorder: output file byte order
        nanosecond: output nanosecond-resolution file flag

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

    #: DefaultDict[str, tuple[ModuleDescriptor[Dumper] | Type[Dumper], str | None]]:
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
        return make_dumper(output), ext

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
                 nanosecond: bool = False) -> 'None':
        """Initialise instance.

        Arguments:
            fout: output path
            format: output format
            byteorder: output file byte order
            nanosecond: output nanosecond-resolution file flag

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

        # dump I/O object
        fio, ext = self.make_fout(fout, format)
        #: Type[Dumper]: Dumper class.
        self._foutio = fio
        #: Optional[str]: Output file extension.
        self._fdpext = ext

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

        Use keyword argument ``protocol`` to specify the protocol
        name at class definition:

        .. code-block:: python

           class MyProtocol(TraceFlow, protocol='my_protocol'):
               ...

    Arguments:
        fout: output path
        format: output format
        byteorder: output file byte order
        nanosecond: output nanosecond-resolution file flag

    """

    def __init_subclass__(cls, /, protocol: 'Optional[str]' = None, *args: 'Any', **kwargs: 'Any') -> 'None':
        """Initialise subclass.

        This method is to be used for registering the engine class to
        :class:`~pcapkit.foundation.extraction.Extractor` class.

        Args:
            name: Protocol name, default to class name.
            *args: Arbitrary positional arguments.
            **kwargs: Arbitrary keyword arguments.

        See Also:
            For more details, please refer to
            :meth:`pcapkit.foundation.extraction.Extractor.register_traceflow`.

        """
        if protocol is None:
            protocol = cast('str', cls.name)

        from pcapkit.foundation.extraction import Extractor
        Extractor.register_traceflow(protocol.lower(), cls)

        return super().__init_subclass__()
