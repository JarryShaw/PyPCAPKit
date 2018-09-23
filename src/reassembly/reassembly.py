# -*- coding: utf-8 -*-
"""reassembly fragmented packets

`pcapkit.reassembly.reassembly` contains `Reassembly`
only, which is an abstract base class for all reassembly
classes, bases on algorithms described in
[`RFC 815`](https://tools.ietf.org/html/rfc815),
implements datagram reassembly of IP and TCP packets.

"""
import abc
import copy

from pcapkit.corekit.infoclass import Info
from pcapkit.utilities.validations import frag_check, int_check

__all__ = ['Reassembly']


class Reassembly(object):
    """Base class for reassembly procedure.

    Properties:
        * name -- str, name of current protocol
        * count -- int, total number of reassembled packets
        * datagram -- tuple, reassembled datagram, which structure may vary
                        according to its protocol
        * protocol -- str, protocol of current reassembly object

    Methods:
        * reassembly -- perform the reassembly procedure
        * submit -- submit reassembled payload
        * fetch -- fetch datagram
        * index -- return datagram index
        * run -- run automatically

    Attributes:
        * _strflg -- bool, strict mode flag
        * _newflg -- bool, if new packets reassembled flag
        * _buffer -- dict, buffer field
        * _dtgram -- list, reassembled datagram

    """
    __metaclass__ = abc.ABCMeta

    ##########################################################################
    # Properties.
    ##########################################################################

    # protocol of current packet
    @property
    @abc.abstractmethod
    def name(self):
        """Protocol of current packet."""
        pass

    # total number of reassembled packets
    @property
    def count(self):
        """Total number of reassembled packets."""
        return len(self.fetch())

    # reassembled datagram
    @property
    def datagram(self):
        """Reassembled datagram."""
        return self.fetch()

    @property
    @abc.abstractmethod
    def protocol(self):
        """Protocol of current reassembly object."""
        pass

    ##########################################################################
    # Methods.
    ##########################################################################

    # reassembly procedure
    @abc.abstractmethod
    def reassembly(self, info):
        """Reassembly procedure.

        Positional arguments:
            * info - Info, info dict of packets to be reassembled

        Returns:
            * NotImplemented

        """
        pass

    # submit reassembled payload
    @abc.abstractmethod
    def submit(self, buf, **kwargs):
        """Submit reassembled payload.

        Positional arguments:
            * buf -- dict, buffer dict of reassembled packets

        Returns:
            * NotImplemented

        """
        pass

    # fetch datagram
    def fetch(self):
        """Fetch datagram."""
        if self._newflg:
            self._newflg = False
            temp_dtgram = copy.deepcopy(self._dtgram)
            for (bufid, buffer) in self._buffer.items():
                temp_dtgram += self.submit(buffer, bufid=bufid)
            return tuple(temp_dtgram)
        return tuple(self._dtgram)

    # return datagram index
    def index(self, pkt_num):
        """Return datagram index."""
        int_check(pkt_num)
        for counter, datagram in enumerate(self.datagram):
            if pkt_num in datagram.index:
                return counter
        return None

    # run automatically
    def run(self, packets):
        """Run automatically.

        Positional arguments:
            * packets -- list<dict>, list of packet dicts to be reassembled

        """
        for packet in packets:
            frag_check(packet, protocol=self.protocol)
            info = Info(packet)
            self.reassembly(info)
        self._newflg = True

    ##########################################################################
    # Data models.
    ##########################################################################

    # Not hashable
    __hash__ = None

    def __init__(self, *, strict=True):
        """Initialise packet reassembly.

        Keyword arguments:
            * strict -- bool, if return all datagrams (including those not
                        implemented) when submit (default is True)
                            <keyword> True / False

        """
        self._newflg = False    # new packets reassembled
        self._strflg = strict   # strict mode flag
        self._buffer = dict()   # buffer field
        self._dtgram = list()   # reassembled datagram

    def __call__(self, packet):
        """Call packet reassembly.

        Positional arguments:
            * packet -- dict, packet dict to be reassembled
                        (detailed format described in corresponding protocol)

        """
        frag_check(packet, protocol=self.protocol)
        info = Info(packet)
        self.reassembly(info)
        self._newflg = True
