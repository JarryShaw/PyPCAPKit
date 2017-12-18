#!/usr/bin/python3
# -*- coding: utf-8 -*-


# Encapsulating Security Payload
# Analyser for ESP header


from .ipsec import IPsec


class ESP(IPsec):

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        return 'Encapsulating Security Payload'

    @property
    def length(self):
        return self._hlen

    @property
    def protocol(self):
        return self._info.next

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, _file, *, version, length):
        self._file = _file
        self._vers = version
        self._hlen = length
        self._info = Info(self.read_esp())

    def __len__(self):
        return self._hlen

    def __length_hint__(self):
        return 256

    ##########################################################################
    # Utilities.
    ##########################################################################

    def read_esp(self):
        """Read Encapsulating Security Payload.

        Structure of ESP header [RFC 4303]:

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ----
           |               Security Parameters Index (SPI)                 | ^Int.
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |Cov-
           |                      Sequence Number                          | |ered
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ | ----
           |                    Payload Data* (variable)                   | |   ^
           ~                                                               ~ |   |
           |                                                               | |Conf.
           +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |Cov-
           |               |     Padding (0-255 bytes)                     | |ered*
           +-+-+-+-+-+-+-+-+               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |   |
           |                               |  Pad Length   | Next Header   | v   v
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ------
           |         Integrity Check Value-ICV   (variable)                |
           ~                                                               ~
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        """
        pass
