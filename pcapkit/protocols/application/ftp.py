# -*- coding: utf-8 -*-
"""file transfer protocol

:mod:`pcapkit.protocols.application.ftp` contains
:class:`~pcapkit.protocols.application.ftp.FTP` only,
which implements extractor for File Transfer Protocol
(FTP) [*]_.

.. [*] https://en.wikipedia.org/wiki/File_Transfer_Protocol

"""
import re

from pcapkit.const.ftp.command import Command
from pcapkit.const.ftp.return_code import ReturnCode
from pcapkit.protocols.application.application import Application
from pcapkit.utilities.exceptions import ProtocolError, UnsupportedCall

__all__ = ['FTP']


class FTP(Application):
    """This class implements File Transfer Protocol."""

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        """Name of current protocol.

        :rtype: Literal['File Transfer Protocol']
        """
        return 'File Transfer Protocol'

    @property
    def length(self):
        """Header length of current protocol.

        Raises:
            UnsupportedCall: This protocol doesn't support :attr:`length`.

        """
        raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute 'length'")

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length=None, **kwargs):  # pylint: disable=unused-argument
        """Read File Transfer Protocol (FTP).

        Args:
            length (Optional[int]): Length of packet data.

        Keyword Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Union[DataType_FTP_Request, DataType_FTP_Response]: Parsed packet data.

        Raises:
            ProtocolError: If the packet is malformed.

        """
        if length is None:
            length = len(self)

        byte = self._read_fileng(length)
        if (not byte.endswith(b'\r\n')) or (len(byte.splitlines()) > 1):
            raise ProtocolError('FTP: invalid format', quiet=True)
        text = self.decode(byte.strip())

        if re.match(r'^\d{3}', text):
            pref = int(text[:3])
            try:
                flag = text[3] == '-'
            except IndexError:
                flag = False
            suff = text[4:] or None

            code = ReturnCode.get(pref)
            ftp = dict(
                type='response',
                code=code,
                arg=suff,
                mf=flag,
                raw=byte,
            )
        else:
            temp = text.split(maxsplit=1)
            if len(temp) == 2:
                pref, suff = temp
            else:
                pref, suff = text, None

            cmmd = Command.get(pref)
            ftp = dict(
                type='request',
                command=cmmd,
                arg=suff,
                raw=byte,
            )

        return ftp

    def make(self, **kwargs):
        """Make (construct) packet data.

        Keyword Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            bytes: Constructed packet data.

        """
        raise NotImplementedError
