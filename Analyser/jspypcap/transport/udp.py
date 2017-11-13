#!/usr/bin/python3
# -*- coding: utf-8 -*-


# User Datagram Protocol
# Analyser for UDP header


from transport import Transport

from ..exceptions import StringError


class UDP(Transport):

    __all__ = ['name', 'layer', 'length', 'source', 'destination']

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        return 'User Datagram Protocol'

    @property
    def layer(self):
        return self.__layer__

    @property
    def length(self):
        return self._dict['len']

    @property
    def source(self):
        self._dict['src']

    @property
    def destination(self):
        self._dict['dst']

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, _file):
        self._file = _file
        self._dict = self.read_udp()

    def __len__(self):
        return 8

    def __length_hint__(self):
        return 8

    def __getitem__(self, key):
        if isinstance(key, str):
            try:
                return self._dict[key]
            except KeyError:
                return None
        else:
            raise StringError

    ##########################################################################
    # Utilities.
    ##########################################################################

    def read_udp(self):
        """Read User Datagram Protocol (UDP).

        Structure of UDP header:
            Octets          Bits          Name                      Discription
              0              0          udp.srcport             Source Port
              2              16         udp.dstport             Destination Port
              4              32         udp.len                 Length
              6              48         udp.checksum            Checksum

        """
        _srcp = self._read_unpack(self._file, 2, _bige=True)
        _dstp = self._read_unpack(self._file, 2, _bige=True)
        _tlen = self._read_unpack(self._file, 2, _bige=True)
        _csum = self._read_unpack(self._file, 2, _bige=True)

        udp = dict(
            srcport = _srcp,
            dstport = _dstp,
            len = _tlen,
            checksum = _csum,
        )

        return udp
