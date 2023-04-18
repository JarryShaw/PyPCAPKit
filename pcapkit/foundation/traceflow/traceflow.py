# -*- coding: utf-8 -*-
"""Base Class
================

.. module:: pcapkit.foundation.traceflow.traceflow

:mod:`pcapkit.foundation.traceflow.traceflow` contains
:class:`~pcapkit.foundation.traceflow.traceflow.TraceFlow` only,
which is an abstract base class for all flow tracing classes.

"""
import abc
import collections
import importlib
import os
import sys
from typing import TYPE_CHECKING, Generic, TypeVar, overload

from pcapkit.corekit.infoclass import Info
from pcapkit.dumpkit.common import _append_fallback as dumpkit_append_fallback
from pcapkit.dumpkit.common import default as dumpkit_default
from pcapkit.dumpkit.common import object_hook as dumpkit_object_hook
from pcapkit.utilities.exceptions import FileExists, stacklevel
from pcapkit.utilities.warnings import FileWarning, FormatWarning, warn

__all__ = ['TraceFlow']

if TYPE_CHECKING:
    from typing import Any, DefaultDict, Optional, Type

    from dictdumper.dumper import Dumper
    from typing_extensions import Literal

    from pcapkit.protocols.protocol import Protocol

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
        module, class_, ext = cls.__output__[fmt]
        if ext is None:
            warn(f'Unsupported output format: {fmt}; disabled file output feature',
                 FormatWarning, stacklevel=stacklevel())
        output = getattr(importlib.import_module(module), class_)  # type: Type[Dumper]

        try:
            os.makedirs(fout, exist_ok=True)
        except FileExistsError as error:
            if ext is None:
                warn(error.strerror, FileWarning, stacklevel=stacklevel())
            else:
                raise FileExists(*error.args).with_traceback(error.__traceback__)

        class DictDumper(output):  # type: ignore[valid-type,misc]
            """Customised :class:`~dictdumper.dumper.Dumper` object."""

            object_hook = dumpkit_object_hook
            default = dumpkit_default
            _append_fallback = dumpkit_append_fallback

        return DictDumper, ext

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

    def __new__(cls, *args: 'Any', **kwargs: 'Any') -> 'TraceFlow':  # pylint: disable=unused-argument
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
