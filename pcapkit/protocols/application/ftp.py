# -*- coding: utf-8 -*-
"""file transfer protocol

"""
import re

from pcapkit._common.ftp_command import Command
from pcapkit._common.ftp_return_code import ReturnCode
from pcapkit.corekit.infoclass import Info
from pcapkit.corekit.protochain import ProtoChain
from pcapkit.protocols.application.application import Application
from pcapkit.protocols.null import NoPayload
from pcapkit.utilities.exceptions import ProtocolError, UnsupportedCall


class FTP(Application):
    """This class implements File Transfer Protocol.

    Properties:
        * name -- str, name of corresponding protocol
        * info -- Info, info dict of current instance
        * alias -- str, acronym of corresponding protocol
        * layer -- str, `Application`
        * protocol -- str, name of next layer protocol
        * protochain -- ProtoChain, protocol chain of current instance

    Methods:
        * read_ftp -- read File Transfer Protocol

    Attributes:
        * _file -- BytesIO, bytes to be extracted
        * _info -- Info, info dict of current instance
        * _protos -- ProtoChain, protocol chain of current instance

    """
    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        """Name of current protocol."""
        return 'File Transfer Protocol'

    @property
    def length(self):
        """Deprecated."""
        raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute 'length'")

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, _file, length=None, **kwargs):
        self._file = _file
        self._info = Info(self.read_ftp(length))

        self._next = NoPayload()
        self._protos = ProtoChain(self.__class__, self.alias)

    ##########################################################################
    # Methods.
    ##########################################################################

    def read_ftp(self, length):
        text = self._read_fileng(length)
        if not text.endswith(b'\r\n'):
            raise ProtocolError('FTP: invalid format', quiet=True)

        temp = text.strip().split(maxsplit=1)
        if len(temp) == 2:
            pref, suff = temp
        else:
            pref = temp[0].strip(b'-')
            suff = bytes()

        try:
            code = ReturnCode.get(int(pref))
            ftp = dict(
                type='response',
                code=code,
                arg=self.decode(suff),
            )
        except ValueError:
            cmmd = Command.get(self.decode(pref))
            ftp = dict(
                type='request',
                command=cmmd,
                arg=self.decode(suff),
            )
        return ftp
