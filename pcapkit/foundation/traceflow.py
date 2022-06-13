# -*- coding: utf-8 -*-
# pylint: disable=import-outside-toplevel
"""Trace TCP Flows
=====================

:mod:`pcapkit.foundation.traceflow` is the interface to trace
TCP flows from a series of packets and connections.

.. note::

   This was implemented as the demand of my mate
   `@gousaiyang <https://github.com/gousaiyang>`__.

"""
import collections
import importlib
import os
import sys
from typing import TYPE_CHECKING, Generic, TypeVar, overload

from pcapkit.corekit.infoclass import Info
from pcapkit.utilities.exceptions import FileExists, stacklevel
from pcapkit.utilities.logging import logger
from pcapkit.utilities.warnings import FileWarning, FormatWarning, warn

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv6Address
    from typing import Any, DefaultDict, Optional, TextIO, Type

    from dictdumper.dumper import Dumper
    from typing_extensions import Literal

    from pcapkit.const.reg.linktype import LinkType as RegType_LinkType
    from pcapkit.protocols.data.misc.pcap.frame import Frame as DataType_Frame

__all__ = ['TraceFlow']

IPAddress = TypeVar('IPAddress', 'IPv4Address', 'IPv6Address')

###############################################################################
# Data Models
###############################################################################

BufferID = tuple[IPAddress, int, IPAddress, int]


class Packet(Info, Generic[IPAddress]):
    """Data structure for **TCP flow tracing**.

    See Also:
        * :meth:`pcapkit.foundation.traceflow.TraceFlow.dump`
        * :term:`trace.packet`

    """

    #: Data link type from global header.
    protocol: 'RegType_LinkType'
    #: Frame number.
    index: 'int'
    #: Extracted frame info.
    frame: 'DataType_Frame | dict[str, Any]'
    #: TCP synchronise (SYN) flag.
    syn: 'bool'
    #: TCP finish (FIN) flag.
    fin: 'bool'
    #: Source IP.
    src: 'IPAddress'
    #: Destination IP.
    dst: 'IPAddress'
    #: TCP source port.
    srcport: 'int'
    #: TCP destination port.
    dstport: 'int'
    #: Frame timestamp.
    timestamp: 'float'

    if TYPE_CHECKING:
        def __init__(self, protocol: 'RegType_LinkType', index: 'int', frame: 'DataType_Frame | dict[str, Any]', syn: 'bool', fin: 'bool', src: 'IPAddress', dst: 'IPAddress', srcport: 'int', dstport: 'int', timestamp: 'float') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long


class Buffer(Info):
    """Data structure for **TCP flow tracing**.

    See Also:
        * :attr:`pcapkit.foundation.traceflow.TraceFlow.index`
        * :term:`trace.buffer`

    """

    #: Output dumper object.
    fpout: 'Dumper'
    #: List of frame index.
    index: 'list[int]'
    #: Flow label generated from ``BUFID``.
    label: 'str'

    if TYPE_CHECKING:
        def __init__(self, fpout: 'Dumper', index: 'list[int]', label: 'str') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


class Index(Info):
    """Data structure for **TCP flow tracing**.

    See Also:
        * element from :attr:`pcapkit.foundation.traceflow.TraceFlow.index`
          *tuple*
        * :term:`trace.index`

    """

    #: Output filename if exists.
    fpout: 'Optional[str]'
    #: Tuple of frame index.
    index: 'tuple[int, ...]'
    #: Flow label generated from ``BUFID``.
    label: 'str'

    if TYPE_CHECKING:
        def __init__(self, fpout: 'Optional[str]', index: 'tuple[int, ...]', label: 'str') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


###############################################################################
# Algorithm Implementation
###############################################################################


class TraceFlow:
    """Trace TCP flows."""

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

        return DictDumper, ext

    def dump(self, packet: 'Packet') -> 'None':
        """Dump frame to output files.

        Arguments:
            packet (Dict[str, Any]): a flow packet (:term:`trace.packet`)

        """
        # fetch flow label
        output = self.trace(packet, output=True)

        # dump files
        output(packet.frame, name=f'Frame {packet.index}')  # pylint: disable=not-callable

    @overload
    def trace(self, packet: 'Packet', *, output: 'Literal[True]' = ...) -> 'Dumper': ...
    @overload
    def trace(self, packet: 'Packet', *, output: 'Literal[False]' = ...) -> 'str': ...

    def trace(self, packet: 'Packet', *, output: 'bool' = False) -> 'Dumper | str':
        """Trace packets.

        Arguments:
            packet: a flow packet (:term:`trace.packet`)
            output: flag if has formatted dumper

        Returns:
            If ``output`` is :data:`True`, returns the initiated
            :class:`~dictdumper.dumper.Dumper` object, which will dump data to
            the output file named after the flow label; otherwise, returns the
            flow label itself.

        Notes:
            The flow label is formatted as following:

            .. code-block:: python

               f'{packet.src}_{packet.srcport}-{packet.dst}_{info.dstport}-{packet.timestamp}'

        """
        # clear cache
        self.__cached__['submit'] = None

        # Buffer Identifier
        BUFID = (packet.src, packet.srcport, packet.dst, packet.dstport)  # type: BufferID
        # SYN = packet.syn  # Synchronise Flag (Establishment)
        FIN = packet.fin  # Finish Flag (Termination)

        # # when SYN is set, reset buffer of this seesion
        # if SYN and BUFID in self._buffer:
        #     temp = self._buffer.pop(BUFID)
        #     temp['fpout'] = (self._fproot, self._fdpext)
        #     temp['index'] = tuple(temp['index'])
        #     self._stream.append(Info(temp))

        # initialise buffer with BUFID
        if BUFID not in self._buffer:
            label = f'{packet.src}_{packet.srcport}-{packet.dst}_{packet.dstport}-{packet.timestamp}'
            self._buffer[BUFID] = Buffer(
                fpout=self._foutio(fname=f'{self._fproot}/{label}{self._fdpext or ""}', protocol=packet.protocol,
                                   byteorder=self._endian, nanosecond=self._nnsecd),
                index=[],
                label=label,
            )

        # trace frame record
        self._buffer[BUFID].index.append(packet.index)
        fpout = self._buffer[BUFID].fpout
        label = self._buffer[BUFID].label

        # when FIN is set, submit buffer of this session
        if FIN:
            buf = self._buffer.pop(BUFID)
            # fpout, label = buf['fpout'], buf['label']
            self._stream.append(Index(
                fpout=f'{self._fproot}/{label}{self._fdpext}' if self._fdpext is not None else None,
                index=tuple(buf.index),
                label=label,
            ))

        # return label or output object
        return fpout if output else label

    def submit(self) -> 'tuple[Index, ...]':
        """Submit traced TCP flows.

        Returns:
            Traced TCP flow (:term:`trace.index`).

        """
        if (cached := self.__cached__.get('submit')) is not None:
            return cached

        ret = []  # type: list[Index]
        for buf in self._buffer.values():
            ret.append(Index(fpout=f"{self._fproot}/{buf.label}{self._fdpext}" if self._fdpext else None,
                             index=tuple(buf.index),
                             label=buf.label,))
        ret.extend(self._stream)
        ret_submit = tuple(ret)

        self.__cached__['submit'] = ret_submit
        return ret_submit

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

        #: dict[BufferID, Buffer]: Buffer field (:term:`trace.buffer`).
        self._buffer = {}  # type: dict[BufferID, Buffer]
        #: list[Index]: Stream index (:term:`trace.index`).
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
            packet: a flow packet (:term:`trace.packet`)

        """
        # trace frame record
        self.dump(packet)
