# -*- coding: utf-8 -*-
# pylint: disable=import-outside-toplevel
"""trace TCP flows

:mod:`pcapkit.foundation.traceflow` is the interface to trace
TCP flows from a series of packets and connections.

.. note::

    This was implemented as the demand of my mate @gousaiyang.

Glossary
--------

trace.packet
    Data structure for **TCP flow tracing**
    (:meth:`~pcapkit.foundation.traceflow.TraceFlow.dump`)
    is as following:

    .. code:: python

       tract_dict = dict(
           protocol=data_link,                     # data link type from global header
           index=frame.info.number,                # frame number
           frame=frame.info,                       # extracted frame info
           syn=tcp.flags.syn,                      # TCP synchronise (SYN) flag
           fin=tcp.flags.fin,                      # TCP finish (FIN) flag
           src=ip.src,                             # source IP
           dst=ip.dst,                             # destination IP
           srcport=tcp.srcport,                    # TCP source port
           dstport=tcp.dstport,                    # TCP destination port
           timestamp=frame.info.time_epoch,        # frame timestamp
       )

trace.buffer
    Data structure for internal buffering when performing flow tracing algorithms
    (:attr:`~pcapkit.foundation.traceflow.TraceFlow._buffer`) is as following:

    .. code:: python

       (dict) buffer --> memory buffer for reassembly
        |--> (tuple) BUFID : (dict)
        |       |--> ip.src      |
        |       |--> ip.dst      |
        |       |--> tcp.srcport |
        |       |--> tcp.dstport |
        |                        |--> 'fpout' : (dictdumper.dumper.Dumper) output dumper object
        |                        |--> 'index': (list) list of frame index
        |                        |              |--> (int) frame index
        |                        |--> 'label': (str) flow label generated from ``BUFID``
        |--> (tuple) BUFID ...

trace.index
    Data structure for **TCP flow tracing** (element from
    :attr:`~pcapkit.foundation.traceflow.TraceFlow.index` *tuple*)
    is as following:

    .. code:: python

       (tuple) index
        |--> (Info) data
        |     |--> 'fpout' : (Optional[str]) output filename if exists
        |     |--> 'index': (tuple) tuple of frame index
        |     |              |--> (int) frame index
        |     |--> 'label': (str) flow label generated from ``BUFID``
        |--> (Info) data ...

"""
import ipaddress
import pathlib
import sys
import warnings

from pcapkit.corekit.infoclass import Info
from pcapkit.utilities.compat import pathlib
from pcapkit.utilities.exceptions import FileExists, stacklevel
from pcapkit.utilities.validations import pkt_check
from pcapkit.utilities.warnings import FileWarning, FormatWarning

###############################################################################
# from dictdumper import JSON, PLIST, XML, JavaScript, Tree
# from pcapkit.dumpkit import PCAP, NotImplementedIO
###############################################################################

__all__ = ['TraceFlow']


class TraceFlow:
    """Trace TCP flows."""

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def index(self):
        """Index table for traced flow.

        :rtype: Tuple[Info]
        """
        if self._newflg:
            return self.submit()
        return tuple(self._stream)

    ##########################################################################
    # Methods.
    ##########################################################################

    @staticmethod
    def make_fout(fout='./tmp', fmt='pcap'):
        """Make root path for output.

        Positional arguments:
            fout (str): root path for output
            fmt (str): output format

        Returns:
            Tuple[Type[dictdumper.dumper.Dumper], str]: dumper of specified format and file
            extension of output file

        Warns:
            FormatWarning: If ``fmt`` is not supported.
            FileWarning: If ``fout`` exists and ``fmt`` is :data:`None`.

        Raises:
            FileExists: If ``fout`` exists and ``fmt`` is **NOT** :data:`None`.

        """
        if fout is None:
            fout = './tmp'

        if fmt == 'pcap':       # output PCAP file
            from pcapkit.dumpkit import PCAPIO as output
        elif fmt == 'plist':    # output PLIST file
            from dictdumper import PLIST as output
        elif fmt == 'json':     # output JSON file
            from dictdumper import JSON as output
        elif fmt == 'tree':     # output treeview text file
            from dictdumper import Tree as output
            fmt = 'txt'
        elif fmt == 'html':     # output JavaScript file
            from dictdumper import VueJS as output
            fmt = 'js'
        elif fmt == 'xml':      # output XML file
            from dictdumper import XML as output
        else:                   # no output file
            from pcapkit.dumpkit import NotImplementedIO as output
            if fmt is not None:
                warnings.warn(f'Unsupported output format: {fmt}; disabled file output feature',
                              FormatWarning, stacklevel=stacklevel())
            return output, ''

        try:
            pathlib.Path(fout).mkdir(parents=True, exist_ok=True)
        except FileExistsError as error:
            if fmt is None:
                warnings.warn(error.strerror, FileWarning, stacklevel=stacklevel())
            else:
                raise FileExists(*error.args).with_traceback(error.__traceback__) from None

        class DictDumper(output):
            """Customised :class:`~dictdumper.dumper.Dumper` object."""

            def object_hook(self, o):
                """Convert content for function call.

                Args:
                    o (:obj:`Any`): object to convert

                Returns:
                    :obj:`Any`: the converted object

                """
                import enum
                import aenum

                if isinstance(o, (enum.IntEnum, aenum.IntEnum)):
                    return dict(
                        enum=type(o).__name__,
                        desc=o.__doc__,
                        name=o.name,
                        value=o.value,
                    )
                if isinstance(o, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                    return str(o)
                if isinstance(o, Info):
                    return o.info2dict()
                return super().object_hook(o)

            def default(self, o):
                """Check content type for function call."""
                return 'fallback'

            def _append_fallback(self, value, file):
                if hasattr(value, '__slots__'):
                    new_value = {key: getattr(value, key) for key in value.__slots__}
                else:
                    new_value = vars(value)

                func = self._encode_func(new_value)
                func(new_value, file)

        return DictDumper, fmt

    def dump(self, packet):
        """Dump frame to output files.

        Arguments:
            packet (Dict[str, Any]): a flow packet (:term:`trace.packet`)

        """
        # fetch flow label
        output = self.trace(packet, check=False, output=True)

        # dump files
        output(packet['frame'], name=f"Frame {packet['index']}")

    def trace(self, packet, *, check=True, output=False):
        """Trace packets.

        Arguments:
            packet (Dict[str, Any]): a flow packet (:term:`trace.packet`)

        Keyword Arguments:
            check (bool): flag if run validations
            output (bool): flag if has formatted dumper

        Returns:
            Union[dictdumper.dumper.Dumper, str]: If ``output`` is :data:`True`,
            returns the initiated :class:`~dictdumper.dumper.Dumper` object, which
            will dump data to the output file named after the flow label;
            otherwise, returns the flow label itself.

        Notes:
            The flow label is formatted as following::

                f'{packet.src}_{packet.srcport}-{packet.dst}_{info.dstport}-{packet.timestamp}'

        """
        self._newflg = True
        if check:
            pkt_check(packet)
        info = Info(packet)

        # Buffer Identifier
        BUFID = tuple(sorted([str(info.src), str(info.srcport),    # pylint: disable=E1101
                              str(info.dst), str(info.dstport)]))  # pylint: disable=E1101
        # SYN = info.syn      # Synchronise Flag (Establishment)
        # Finish Flag (Termination)
        FIN = info.fin        # pylint: disable=E1101

        # # when SYN is set, reset buffer of this seesion
        # if SYN and BUFID in self._buffer:
        #     temp = self._buffer.pop(BUFID)
        #     temp['fpout'] = (self._fproot, self._fdpext)
        #     temp['index'] = tuple(temp['index'])
        #     self._stream.append(Info(temp))

        # initialise buffer with BUFID
        if BUFID not in self._buffer:
            label = f'{info.src}_{info.srcport}-{info.dst}_{info.dstport}-{info.timestamp}'  # pylint: disable=E1101
            self._buffer[BUFID] = dict(
                fpout=self._foutio(fname=f'{self._fproot}/{label}.{self._fdpext}', protocol=info.protocol,  # pylint: disable=E1101
                                   byteorder=self._endian, nanosecond=self._nnsecd),
                index=list(),
                label=label,
            )

        # trace frame record
        self._buffer[BUFID]['index'].append(info.index)  # pylint: disable=E1101
        fpout = self._buffer[BUFID]['fpout']
        label = self._buffer[BUFID]['label']

        # when FIN is set, submit buffer of this session
        if FIN:
            buf = self._buffer.pop(BUFID)
            # fpout, label = buf['fpout'], buf['label']
            if self._fdpext:
                buf['fpout'] = f'{self._fproot}/{label}.{self._fdpext}'
            else:
                del buf['fpout']
            buf['index'] = tuple(buf['index'])
            self._stream.append(Info(buf))

        # return label or output object
        return fpout if output else label

    def submit(self):
        """Submit traced TCP flows.

        Returns:
            Tuple[Info]: traced TCP flow (:term:`trace.buffer`)

        """
        self._newflg = False
        ret = list()
        for buf in self._buffer.values():
            lbl = buf['label']
            ret.append(Info(fpout=f"{self._fproot}/{lbl}.{self._fdpext}" if self._fdpext else NotImplemented,
                            index=tuple(buf['index']),
                            label=lbl,))
        ret += self._stream
        return tuple(ret)

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, fout=None, format=None, byteorder=sys.byteorder, nanosecond=False):  # pylint: disable=redefined-builtin
        """Initialise instance.

        Arguments:
            fout (Optional[str]): output path
            format (Optional[str]): output format
            byteorder (str): output file byte order
            nanosecond (bool): output nanosecond-resolution file flag

        """
        #: bool: New packet flag.
        self._newflg = False
        #: str: Output root path.
        self._fproot = fout

        #: dict: Buffer field (:term:`trace.buffer`).
        self._buffer = dict()
        #: list: Stream index (:term:`trace.index`).
        self._stream = list()

        #: Literal['little', 'big']: Output file byte order.
        self._endian = byteorder
        #: bool: Output nanosecond-resolution file flag.
        self._nnsecd = nanosecond

        # dump I/O object
        fio, ext = self.make_fout(fout, format)
        #: Type[dictdumper.dumper.Dumper]: Dumper class.
        self._foutio = fio
        #: str: Output file extension.
        self._fdpext = ext

    def __call__(self, packet):
        """Dump frame to output files.

        Arguments:
            packet (Dict[str, Any]): a flow packet (:term:`trace.packet`)

        """
        self._newflg = True
        self.dump(packet)
