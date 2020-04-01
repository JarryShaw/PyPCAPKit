# -*- coding: utf-8 -*-
"""fragmented packets reassembly

:mod:`pcapkit.reassembly.reassembly` contains
class:`~pcapkit.reassembly.reassembly.Reassembly` only,
which is an abstract base class for all reassembly classes,
bases on algorithms described in :rfc:`815`, implements
datagram reassembly of IP and TCP packets.

"""
import abc
import copy

from pcapkit.corekit.infoclass import Info
from pcapkit.utilities.validations import frag_check, int_check

__all__ = ['Reassembly']


class Reassembly(metaclass=abc.ABCMeta):
    """Base class for reassembly procedure.

    Attributes:
        name (str): name of current protocol
        count (int): total number of reassembled packets
        datagram (tuple): reassembled datagram, which structure may vary
            according to its protocol
        protocol (str): protocol of current reassembly object

        _strflg (bool): strict mode flag
        _newflg (bool): if new packets reassembled flag
        _buffer (dict): buffer field
        _dtgram (list): reassembled datagram

    """
    ##########################################################################
    # Properties.
    ##########################################################################

    # protocol of current packet
    @property
    @abc.abstractmethod
    def name(self):
        """str: Protocol of current packet."""

    # total number of reassembled packets
    @property
    def count(self):
        """int: Total number of reassembled packets."""
        return len(self.fetch())

    # reassembled datagram
    @property
    def datagram(self):
        """tuple: Reassembled datagram."""
        return self.fetch()

    @property
    @abc.abstractmethod
    def protocol(self):
        """str: Protocol of current reassembly object."""

    ##########################################################################
    # Methods.
    ##########################################################################

    # reassembly procedure
    @abc.abstractmethod
    def reassembly(self, info):
        """Reassembly procedure.

        Arguments:
            info (Info): info dict of packets to be reassembled

        """

    # submit reassembled payload
    @abc.abstractmethod
    def submit(self, buf, **kwargs):
        """Submit reassembled payload.

        Arguments:
            buf (dict): buffer dict of reassembled packets

        """

    # fetch datagram
    def fetch(self):
        """Fetch datagram.

        Fetch reassembled datagrams from
        :attr:`~pcapkit.reassembly.reassembly.Reassembly._dtgram`
        and returns a *tuple* of such datagrams.

        If :attr:`~pcapkit.reassembly.reassembly.Reassembly._newflg`
        set as ``True``, the method will call
        :meth:`~pcapkit.reassembly.reassembly.Reassembly.submit` to
        (*force*) obtain newly reassembled payload. Otherwise, the
        already calculated :attr:`~pcapkit.reassembly.reassembly.Reassembly._dtgram`
        will be returned.

        """
        if self._newflg:
            self._newflg = False
            temp_dtgram = copy.deepcopy(self._dtgram)
            for (bufid, buffer) in self._buffer.items():
                temp_dtgram += self.submit(buffer, bufid=bufid)
            return tuple(temp_dtgram)
        return tuple(self._dtgram)

    # return datagram index
    def index(self, pkt_num):
        """Return datagram index.

        Arguments:
            pkt_num (int): index of packet

        Returns:
            int: reassembled datagram index which was from No. ``pkt_num`` packet;
                if not found, returns ``None``

        """
        int_check(pkt_num)
        for counter, datagram in enumerate(self.datagram):
            if pkt_num in datagram.index:
                return counter
        return None

    # run automatically
    def run(self, packets):
        """Run automatically.

        Arguments:
            packets (List[dict]): list of packet dicts to be reassembled

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
            strict (bool): if return all datagrams (including those not
                implemented) when submit

        """
        self._newflg = False    # new packets reassembled
        self._strflg = strict   # strict mode flag
        self._buffer = dict()   # buffer field
        self._dtgram = list()   # reassembled datagram

    def __call__(self, packet):
        """Call packet reassembly.

        Arguments:
            packet (dict): packet dict to be reassembled
                (detailed format described in corresponding protocol)

        """
        frag_check(packet, protocol=self.protocol)
        info = Info(packet)
        self.reassembly(info)
        self._newflg = True
