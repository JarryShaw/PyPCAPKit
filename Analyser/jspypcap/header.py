#!/usr/bin/python3
# -*- coding: utf-8 -*-


# Global Header
# Analyser for PCAP global headers


from exceptions import FileError, StringError
from protocol import Protocol

from link.link import LINKTYPE


class Header(Protocol):

    __all__ = ['name', 'length', 'protocol']

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        return 'Global Header'

    @property
    def layer(self):
        pass

    @property
    def length(self):
        return self._dict['snaplen']

    @property
    def protocol(self):
        return self._dict['network']

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, _file):
        self._file = _file
        self._dict = self.read_header()

    def __len__(self):
        return 24

    def __length_hint__(self):
        return 24

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

    def read_header(self):
        """Read global header of *.pcap file.

        Structure of global header (C):
            typedef struct pcap_hdr_s {
            guint32 magic_number;   /* magic number */
            guint16 version_major;  /* major version number */
            guint16 version_minor;  /* minor version number */
            gint32  thiszone;       /* GMT to local correction */
            guint32 sigfigs;        /* accuracy of timestamps */
            guint32 snaplen;        /* max length of captured packets, in octets */
            guint32 network;        /* data link type */
            } pcap_hdr_t;

        """
        _temp = self._file.read(4)
        if _temp != b'\xd4\xc3\xb2\xa1':
            raise FileError

        _magn = _temp
        _vmaj = self.read_unpack(self._file, 2)
        _vmin = self.read_unpack(self._file, 2)
        _zone = self.read_unpack(self._file, 4, _sign=True)
        _acts = self.read_unpack(self._file, 4)
        _slen = self.read_unpack(self._file, 4)
        _type = self.read_unpack(self._file, 4)

        header = dict(
            magic_number = _magn,
            version_major = _vmaj,
            version_minor = _vmin,
            thiszone = _zone,
            sigfigs = _acts,
            snaplen = _slen,
            network = LINKTYPE.get(_type),
        )

        return header
