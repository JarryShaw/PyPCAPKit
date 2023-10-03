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
from pcapkit.utilities.exceptions import FileExists, RegistryError, stacklevel
from pcapkit.utilities.warnings import FileWarning, FormatWarning, RegistryWarning, warn

__all__ = ['TraceFlow']

if TYPE_CHECKING:
    from typing import Any, Callable, DefaultDict, Optional, Type

    from typing_extensions import Literal, Self

    from pcapkit.corekit.infoclass import Info
    from pcapkit.protocols.protocol import Protocol

    CallbackFn = Callable[['Index'], None]

BufferID = TypeVar('BufferID')
Buffer = TypeVar('Buffer', bound='Info')
Index = TypeVar('Index', bound='Info')
Packet = TypeVar('Packet', bound='Info')


class TraceFlow(Generic[BufferID, Buffer, Index, Packet], metaclass=abc.ABCMeta):
    """Base flow tracing class.

    Arguments:
        fout: output path
        format: output format
        byteorder: output file byte order
        nanosecond: output nanosecond-resolution file flag
        *args: Arbitrary positional arguments.
        **kwargs: Arbitrary keyword arguments.

    """

    # Internal data storage for cached properties.
    __cached__: 'dict[str, Any]'

    #: List of callback functions upon reassembled datagram.
    __callback_fn__: 'list[CallbackFn]' = []

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
    @abc.abstractmethod
    def name(self) -> 'str':
        """Protocol name of current reassembly object."""

    @property
    @abc.abstractmethod
    def protocol(self) -> 'Type[Protocol]':
        """Protocol of current reassembly object."""

    @property
    def index(self) -> 'tuple[Index, ...]':
        """Index table for traced flow."""
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
    def dump(self, packet: 'Packet') -> 'None':
        """Dump frame to output files.

        Arguments:
            packet: a flow packet (:term:`trace.tcp.packet`)

        """

    @overload
    def trace(self, packet: 'Packet', *, output: 'Literal[True]' = ...) -> 'Dumper': ...
    @overload
    def trace(self, packet: 'Packet', *, output: 'Literal[False]' = ...) -> 'str': ...

    @abc.abstractmethod
    def trace(self, packet: 'Packet', *, output: 'bool' = False) -> 'Dumper | str':
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
    def submit(self) -> 'tuple[Index, ...]':
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

        #: dict[BufferID, Buffer]: Buffer field (:term:`trace.tcp.buffer`).
        self._buffer = {}  # type: dict[BufferID, Buffer]
        #: list[Index]: Stream index (:term:`trace.tcp.index`).
        self._stream = []  # type: list[Index]

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

    def __call__(self, packet: 'Packet') -> 'None':
        """Dump frame to output files.

        Arguments:
            packet: a flow packet (:term:`trace.tcp.packet`)

        """
        # trace frame record
        self.dump(packet)
