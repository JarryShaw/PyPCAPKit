# -*- coding: utf-8 -*-
"""

"""
import copy
import pathlib
import warnings

###############################################################################
# from jsformat import PLIST, JSON, Tree, JavaScript, XML
###############################################################################

from jspcap.corekit.infoclass import Info
from jspcap.utilities.exceptions import stacklevel, FileExists
from jspcap.utilities.warnings import FormatWarning, FileWarning
from jspcap.utilities.validations import pkt_check

###############################################################################
# from jspcap.dumpkit import PCAP, NotImplementedIO
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
        if fmt == 'pcap':
            from jspcap.dumpkit import PCAP as output       # output PCAP file 
        elif fmt == 'plist':
            from jsformat import PLIST as output            # output PLIST file
        elif fmt == 'json':
            from jsformat import JSON as output             # output JSON file
        elif fmt == 'tree':
            from jsformat import Tree as output             # output treeview text file
            fmt = 'txt'
        elif fmt == 'html':
            from jsformat import JavaScript as output       # output JavaScript file
            fmt = 'js'
        elif fmt == 'xml':
            from jsformat import XML as output              # output XML file
        else:
            from jspcap.dumpkit import NotImplementedIO as output
                                                            # no output file
            if fmt is not None:
                warnings.warn(f'Unsupported output format: {fmt}; '
                                'disabled file output feature',
                                FormatWarning, stacklevel=stacklevel())
            return output, ''

        try:
            pathlib.Path(fout).mkdir(parents=True, exist_ok=True)
        except FileExistsError as error:
            if fmt is None:
                warnings.warn(str(error), FileWarning, stacklevel=stacklevel())
            else:
                raise FileExists(str(error)) from None

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
        output(packet['frame'], name=f"Frame {packet['index']}")

    def trace(self, packet, *, _check=True, _output=False):
        """Trace packets.

        """
        self._newflg = True
        if _check:
            pkt_check(packet)
        info = Info(packet)

        BUFID = tuple(sorted([str(info.src), str(info.srcport), str(info.dst), str(info.dstport)]))
                            # Buffer Identifier
        SYN = info.syn      # Synchronise Flag (Establishment)
        FIN = info.fin      # Finish Flag (Termination)

        # # when SYN is set, reset buffer of this seesion
        # if SYN and BUFID in self._buffer:
        #     temp = self._buffer.pop(BUFID)
        #     temp['fpout'] = (self._fproot, self._fdpext)
        #     temp['index'] = tuple(temp['index'])
        #     self._stream.append(Info(temp))

        # initialise buffer with BUFID
        if BUFID not in self._buffer:
            label = f'{info.src}_{info.srcport}-{info.dst}_{info.dstport}-{info.timestamp}'.replace('.', '_')
            self._buffer[BUFID] = dict(
                fpout = self._foutio(f'{self._fproot}/{label}.{self._fdpext}', protocol=info.protocol),
                index = list(),
                label = label,
            )

        # trace frame record
        self._buffer[BUFID]['index'].append(info.index)
        fpout = self._buffer[BUFID]['fpout']
        label = self._buffer[BUFID]['label']

        # when FIN is set, submit buffer of this session
        if FIN:
            buf = self._buffer.pop(BUFID)
            fpout, label = buf['fpout'], buf['label']
            if self._fdpext:    buf['fpout'] = f'{self._fproot}/{label}.{self._fdpext}'
            else:               del buf['fpout']
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
            if self._fdpext:    buf['fpout'] = f"{self._fproot}/{buf['label']}.{self._fdpext}"
            else:               del buf['fpout']
            buf['index'] = tuple(buf['index'])
            ret.append(Info(buf))
        ret += self._stream
        return tuple(ret)

    ##########################################################################
    # Data models.
    ##########################################################################

    # Not hashable
    __hash__ = None

    def __init__(self, *, fout=None, format=None):
        """Initialise instance.

        """
        self._newflg = False    # new packet flag
        self._fproot = fout     # output root path
        self._buffer = dict()   # buffer field
        self._stream = list()   # stream index
        self._foutio, self._fdpext \
                    = self.make_fout(fout, format)
                                # dump I/O object

    def __call__(self, packet):
        """Dump frame to output files."""
        return self.dump(packet)
