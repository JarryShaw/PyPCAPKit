#!/usr/bin/python3
# -*- coding: utf-8 -*-


# Global Header
# Analyser for PCAP global headers


from .link import LINKTYPE
from .protocol import Protocol
from .utilities import Info
from ..exceptions import FileError


class VersionInfo(Info):
    """Version Info alikes `sys.version_info`."""

    def __init__(self, vmaj, vmin):
        self._vers = (vmaj, vmin)

    def __str__(self):
        str_ = 'pcap version {major}.{minor}'.format(
                    major=self._vers[0], minor=self._vers[1]
                )
        return str_

    def __repr__(self):
        repr_ = 'pcap.version_info(major={major}, minor={minor})'.format(
                    major=self._vers[0], minor=self._vers[1]
                )
        return repr_

    def __getattribute__(self, name):
        raise AttributeError("'VersionInfo' object has no attribute '{name}'".format(name=name))

    def __getitem__(self, key):
        return self._vers[key]


class Header(Protocol):

    __all__ = ['name', 'info', 'length', 'version', 'protocol']

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        return 'Global Header'

    @property
    def info(self):
        return self._info

    @property
    def length(self):
        return 24

    @property
    def version(self):
        return VersionInfo(self._info.version_major, self._info.version_minor)

    @property
    def protocol(self):
        return self.info.network

    ##########################################################################
    # Methods.
    ##########################################################################

    def _read_protos(self, size):
        _byte = self._read_unpack(4, lilendian=True)
        _prot = LINKTYPE.get(_byte)
        return _prot

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, _file):
        self._file = _file
        self._info = Info(self.read_header())

    def __len__(self):
        return 24

    def __length_hint__(self):
        return 24

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
        _temp = self._read_fileng(4)
        if _temp != b'\xd4\xc3\xb2\xa1':
            raise FileError

        _magn = _temp
        _vmaj = self._read_unpack(2, lilendian=True)
        _vmin = self._read_unpack(2, lilendian=True)
        _zone = self._read_unpack(4, lilendian=True, sign=True)
        _acts = self._read_unpack(4, lilendian=True)
        _slen = self._read_unpack(4, lilendian=True)
        _type = self._read_protos(4)

        header = dict(
            magic_number = _magn,
            version_major = _vmaj,
            version_minor = _vmin,
            thiszone = _zone,
            sigfigs = _acts,
            snaplen = _slen,
            network = _type,
        )

        return header
