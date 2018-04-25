# -*- coding: utf-8 -*-
"""reassembly fragmented packets

``jspcap.reassembly.reassembly`` contains ``Reassembly``
only, which is an abstract base class for all reassembly
classes, bases on algorithms described in
```RFC 815`` <https://tools.ietf.org/html/rfc815>`__,
implements datagram reassembly of IP and TCP packets.

"""
import abc
import copy


# Reassembly of Packets
# Abstract Base Class for Reassembly


from jspcap.utilities import Info
from jspcap.validations import bool_check, dict_check, int_check


__all__ = ['Reassembly']


ABCMeta = abc.ABCMeta
abstractmethod = abc.abstractmethod
abstractproperty = abc.abstractproperty


class Reassembly(object):
    """Base class for reassembly procedure.

    Keyword arguments:
        * strict -- bool, if strict set to True, all datagram will return
                    else only implemented ones will submit (False in default)
                    < True / False >

    Properties:
        * name -- str, protocol of current packet
        * count -- int, total number of reassembled packets
        * datagram -- tuple, reassembled datagram, which structure may vary
                        according to its protocol

    Methods:
        * reassembly -- perform the reassembly procedure
        * submit -- submit reassembled payload
        * fetch -- fetch datagram
        * index -- return datagram index
        * run -- run automatically

    Attributes:
        * _strflg -- bool, stirct mode flag
        * _newflg -- bool, if new packets reassembled flag
        * _buffer -- dict, buffer field
        * _dtgram -- list, reassembled datagram

    """
    __metaclass__ = ABCMeta

    ##########################################################################
    # Properties.
    ##########################################################################

    # protocol of current packet
    @abstractproperty
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

    ##########################################################################
    # Methods.
    ##########################################################################

    # reassembly procedure
    @abstractmethod
    def reassembly(self, info):
        """Reassembly procedure.

        Keyword arguments:
            * info - Info, info dict of packets to be reassembled

        """
        pass

    # submit reassembled payload
    @abstractmethod
    def submit(self, buf, **kwargs):
        """Submit reassembled payload.

        Keyword arguments:
            * buf -- dict, buffer dict of reassembled packets

        """
        pass

    # fetch datagram
    def fetch(self):
        """Fetch datagram."""
        if self._newflg:
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

        Keyword arguments:
            * packets -- list[dict], list of packet dicts to be reassembled

        """
        for packet in packets:
            dict_check(packet)
            info = Info(packet)
            self.reassembly(info)
        self._newflg = True

    ##########################################################################
    # Data models.
    ##########################################################################

    # Not hashable
    __hash__ = None

    def __init__(self, *, strict=False):
        """Initialise packet reassembly.

        Keyword arguments:
            * strict -- bool, if return all datagrams (including those not implemented) when submit (default is False)
                            <keyword> True / False

        """
        bool_check(strict)
        self._newflg = False    # new packets reassembled
        self._strflg = strict   # stirct mode flag
        self._buffer = dict()   # buffer field
        self._dtgram = list()   # reassembled datagram

    def __call__(self, packet_dict):
        """Call packet reassembly.

        Keyword arguments:
            * packet_dict -- dict, packet dict to be reassembled

        """
        dict_check(packet_dict)
        info = Info(packet_dict)
        self.reassembly(info)
        self._newflg = True
