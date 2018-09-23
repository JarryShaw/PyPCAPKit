# -*- coding: utf-8 -*-
"""trace TCP flows

`pcapkit.foundation.traceflow` is the interface to trace
TCP flows from a series of packets and connections. This
was implemented as the demand of my mate @gousaiyang.

"""
import copy
import pathlib
import sys
import warnings

from pcapkit.corekit.infoclass import Info
from pcapkit.utilities.exceptions import FileExists, stacklevel
from pcapkit.utilities.validations import pkt_check
from pcapkit.utilities.warnings import FileWarning, FormatWarning

###############################################################################
# from dictdumper import JSON, PLIST, XML, JavaScript, Tree
# from pcapkit.dumpkit import PCAP, NotImplementedIO
###############################################################################


class TraceFlow:
    """Trace TCP flows.

    Properties:
        * index -- tuple<Info>, index table for traced flows

    Methods:
        * make_fout -- make root path for output
        * dump -- dump frame to output files
        * trace -- trace packets

    """
    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def index(self):
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
            * fout -- str, root path for output
            * fmt -- str, output format

        Returns:
            * output -- dumper of specified format

        """
        if fmt == 'pcap':       # output PCAP file
            from pcapkit.dumpkit import PCAP as output
        elif fmt == 'plist':    # output PLIST file
            from dictdumper import PLIST as output
        elif fmt == 'json':     # output JSON file
            from dictdumper import JSON as output
        elif fmt == 'tree':     # output treeview text file
            from dictdumper import Tree as output
            fmt = 'txt'
        elif fmt == 'html':     # output JavaScript file
            from dictdumper import JavaScript as output
            fmt = 'js'
        elif fmt == 'xml':      # output XML file
            from dictdumper import XML as output
        else:                   # no output file
            from pcapkit.dumpkit import NotImplementedIO as output
            if fmt is not None:
                warnings.warn('Unsupported output format: {}; disabled file output feature'.format(fmt),
                              FormatWarning, stacklevel=stacklevel())
            return output, ''

        try:
            path = pathlib.Path(fout)
            path.mkdir(parents=True)
        except FileExistsError as error:
            if path.is_dir():
                pass
            elif fmt is None:
                warnings.warn(error.strerror, FileWarning, stacklevel=stacklevel())
            else:
                raise FileExists(*error.args) from None
        except OSError:
            if not path.is_dir():
                raise

        return output, fmt

    def dump(self, packet):
        """Dump frame to output files.

        Positional arguments:
            * packet -- dict, a flow packet
                |-- (str) protocol -- data link type from global header
                |-- (int) index -- frame number
                |-- (Info) frame -- extracted frame info
                |-- (bool) syn -- TCP synchronise (SYN) flag
                |-- (bool) fin -- TCP finish (FIN) flag
                |-- (str) src -- source IP
                |-- (int) srcport -- TCP source port
                |-- (str) dst -- destination IP
                |-- (int) dstport -- TCP destination port
                |-- (numbers.Real) timestamp -- frame timestamp

        """
        # fetch flow label
        output = self.trace(packet, _check=False, _output=True)

        # dump files
        output(packet['frame'], name="Frame {}".format(packet['index']),
               byteorder=self._endian, nanosecond=self._nnsecd)

    def trace(self, packet, *, _check=True, _output=False):
        """Trace packets.

        Positional arguments:
            * packet -- dict, a flow packet

        Keyword arguments:
            * _check -- bool, flag if run validations
            * _output -- bool, flag if has formatted dumper

        """
        self._newflg = True
        if _check:
            pkt_check(packet)
        info = Info(packet)

        # Buffer Identifier
        BUFID = tuple(sorted([str(info.src), str(info.srcport), str(info.dst), str(info.dstport)]))
        # SYN = info.syn      # Synchronise Flag (Establishment)
        FIN = info.fin      # Finish Flag (Termination)

        # # when SYN is set, reset buffer of this seesion
        # if SYN and BUFID in self._buffer:
        #     temp = self._buffer.pop(BUFID)
        #     temp['fpout'] = (self._fproot, self._fdpext)
        #     temp['index'] = tuple(temp['index'])
        #     self._stream.append(Info(temp))

        # initialise buffer with BUFID
        if BUFID not in self._buffer:
            label = '{}_{}-{}_{}-{}'.format(info.src, info.srcport, info.dst, info.dstport, info.timestamp)
            self._buffer[BUFID] = dict(
                fpout=self._foutio('{}/{}.{}'.format(self._fproot, label, self._fdpext), protocol=info.protocol),
                index=list(),
                label=label,
            )

        # trace frame record
        self._buffer[BUFID]['index'].append(info.index)
        fpout = self._buffer[BUFID]['fpout']
        label = self._buffer[BUFID]['label']

        # when FIN is set, submit buffer of this session
        if FIN:
            buf = self._buffer.pop(BUFID)
            # fpout, label = buf['fpout'], buf['label']
            if self._fdpext:
                buf['fpout'] = '{}/{}.{}'.format(self._fproot, label, self._fdpext)
            else:
                del buf['fpout']
            buf['index'] = tuple(buf['index'])
            self._stream.append(Info(buf))

        # return label or output object
        return fpout if _output else label

    def submit(self):
        """Submit traced TCP flows."""
        self._newflg = False
        ret = list()
        for buf in self._buffer.values():
            buf = copy.deepcopy(buf)
            if self._fdpext:
                buf['fpout'] = "{}/{}.{}".format(self._fproot, buf['label'], self._fdpext)
            else:
                del buf['fpout']
            buf['index'] = tuple(buf['index'])
            ret.append(Info(buf))
        ret += self._stream
        return tuple(ret)

    ##########################################################################
    # Data models.
    ##########################################################################

    # Not hashable
    __hash__ = None

    def __init__(self, *, fout=None, format=None, byteorder=sys.byteorder, nanosecond=False):
        """Initialise instance.

        Keyword arguments:
            * fout -- str, output path
            * format -- str, output format
            * byteorder -- str, output file byte order
            * nanosecond -- bool, output nanosecond-resolution file flag

        """
        self._newflg = False    # new packet flag
        self._fproot = fout     # output root path
        self._buffer = dict()   # buffer field
        self._stream = list()   # stream index
        self._endian = byteorder
        self._nnsecd = nanosecond

        # dump I/O object
        self._foutio, self._fdpext = self.make_fout(fout, format)

    def __call__(self, packet):
        """Dump frame to output files.

        Positional arguments:
            * packet -- dict, a flow packet

        """
        self._newflg = True
        self.dump(packet)
