# -*- coding: utf-8 -*-
"""file transfer protocol

:mod:`pcapkit.protocols.application.ftp` contains
:class:`~pcapkit.protocols.application.ftp.FTP` only,
which implements extractor for File Transfer Protocol
(FTP) [*]_.

.. [*] https://en.wikipedia.org/wiki/File_Transfer_Protocol

"""
import re
from typing import TYPE_CHECKING

from pcapkit.const.ftp.command import Command
from pcapkit.const.ftp.return_code import ReturnCode
from pcapkit.protocols.application.application import Application
from pcapkit.protocols.data.application.ftp import FTP as DataType_FTP
from pcapkit.protocols.data.application.ftp import Request as DataType_Request
from pcapkit.protocols.data.application.ftp import Response as DataType_Response
from pcapkit.utilities.exceptions import ProtocolError, UnsupportedCall

if TYPE_CHECKING:
    from typing import Any, NoReturn, Optional

    from typing_extensions import Literal

__all__ = ['FTP']


class FTP(Application[DataType_FTP]):
    """This class implements File Transfer Protocol."""

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["File Transfer Protocol"]':
        """Name of current protocol."""
        return 'File Transfer Protocol'

    @property
    def length(self) -> 'NoReturn':
        """Header length of current protocol.

        Raises:
            UnsupportedCall: This protocol doesn't support :attr:`length`.

        """
        raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute 'length'")

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'DataType_FTP':  # pylint: disable=unused-argument
        """Read File Transfer Protocol (FTP).

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If the packet is malformed.

        """
        if length is None:
            length = len(self)

        byte = self._read_fileng(length)
        if (not byte.endswith(b'\r\n')) or (len(byte.splitlines()) > 1):
            raise ProtocolError('FTP: invalid format')
        text = self.decode(byte.strip())

        if TYPE_CHECKING:
            pref: 'int | str'
            ftp: 'DataType_Request | DataType_Response'

        if re.match(r'^\d{3}', text):
            pref = int(text[:3])
            try:
                flag = text[3] == '-'
            except IndexError:
                flag = False
            suff = text[4:] or None

            code = ReturnCode.get(pref)
            ftp = DataType_Response(
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

            cmmd = Command[pref]
            ftp = DataType_Request(
                type='request',
                command=cmmd,
                arg=suff,
                raw=byte,
            )

        return ftp

    def make(self, **kwargs: 'Any') -> 'NoReturn':
        """Make (construct) packet data.

        Args:
            Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        """
        raise NotImplementedError
