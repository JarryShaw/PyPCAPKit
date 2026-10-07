# -*- coding: utf-8 -*-
"""FTP - File Transfer Protocol
================================

.. module:: pcapkit.protocols.application.ftp

:mod:`pcapkit.protocols.application.ftp` contains
:class:`~pcapkit.protocols.application.ftp.FTP`,
which implements extractor for File Transfer Protocol
(FTP) [*]_, and
:class:`~pcapkit.protocols.application.ftp.FTP_DATA`
for its data channel.

.. [*] https://en.wikipedia.org/wiki/File_Transfer_Protocol

"""
import re
from typing import TYPE_CHECKING

from pcapkit.const.ftp.command import Command as Enum_Command
from pcapkit.const.ftp.return_code import ReturnCode as Enum_ReturnCode
from pcapkit.corekit.enum import EnumLookup
from pcapkit.protocols.application.application import Application
from pcapkit.protocols.data.application.ftp import FTP as Data_FTP
from pcapkit.protocols.data.application.ftp import Request as Data_Request
from pcapkit.protocols.data.application.ftp import Response as Data_Response
from pcapkit.protocols.misc.raw import Raw
from pcapkit.protocols.schema.application.ftp import FTP as Schema_FTP
from pcapkit.utilities.chardet import detect
from pcapkit.utilities.compat import StrEnum, auto
from pcapkit.utilities.exceptions import ProtocolError, UnsupportedCall

if TYPE_CHECKING:
    from typing import Any, NoReturn, Optional

    from typing_extensions import Literal

__all__ = ['FTP', 'FTP_DATA']

# regex for FTP, per :rfc:`959#section-4` (replies) and :rfc:`959#section-5`
# (commands): a command is ``<command> [<SP> <argument>] <CRLF>``, a reply line is
# ``<code> [<SP> <text>] <CRLF>``, and the first line of a multi-line reply is
# ``<code>-<text> <CRLF>`` with the text following the hyphen immediately. Only
# the one separating SP is syntax; anything after it is the argument verbatim, so
# that ``make`` writes back exactly the line that was read. ``\Z`` rather than
# ``$``, which would also match before a trailing ``\n`` left outside the match.
FTP_REQUEST = re.compile(rb'^(?P<cmmd>[A-Z]{3,4})(?: (?P<args>.*))?\r\n\Z', re.I)
FTP_RESPONSE = re.compile(rb'^(?P<code>[0-9]{3})'
                          rb'(?:(?P<more>-)(?P<text>.*)|(?: (?P<args>.*))?)\r\n\Z', re.I)


class Type(EnumLookup, StrEnum):
    """FTP packet type.

    Built on :class:`~pcapkit.corekit.enum.EnumLookup`, the lookup contract
    shared by every non-registry enumeration (:issue:`877`). The class defines
    neither ``get`` nor ``_missing_`` of its own.

    """

    #: Request packet.
    REQUEST = auto()
    #: Response packet.
    RESPONSE = auto()


class FTP(Application[Data_FTP, Schema_FTP],
          data=Data_FTP, schema=Schema_FTP):
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

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_FTP':  # pylint: disable=unused-argument
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
        schema = self.__header__

        data = schema.data
        if (match := FTP_REQUEST.match(data)) is not None:
            cmmd = match.group('cmmd').decode()
            args = match.group('args')

            cmmd_val = Enum_Command.get(cmmd)
            args_val, charset = self._decode_args(args)

            ftp = Data_Request(
                type=Type.REQUEST,
                cmmd=cmmd_val,
                args=args_val,
                charset=charset,
            )  # type: Data_FTP
        elif (match := FTP_RESPONSE.match(data)) is not None:
            code = int(match.group('code'))
            more = bool(match.group('more'))
            args = match.group('text') if more else match.group('args')

            code_val = Enum_ReturnCode.get(code)
            args_val, charset = self._decode_args(args)

            ftp = Data_Response(
                type=Type.RESPONSE,
                code=code_val,
                more=more,
                args=args_val,
                charset=charset,
            )
        else:
            raise ProtocolError('FTP: invalid packet format')
        return ftp

    def make(self,
             cmmd: 'Optional[Enum_Command | str | bytes]' = None,
             code: 'Optional[Enum_ReturnCode | int | str | bytes]' = None,
             args: 'Optional[str | bytes]' = None,
             more: 'bool' = False,
             charset: 'Optional[str]' = None,
             **kwargs: 'Any') -> 'Schema_FTP':
        """Make (construct) packet data.

        The line is terminated with CRLF. Arguments of :obj:`None` write no
        argument and no separator; otherwise a single SP separates them from
        the command or code, except after the hyphen of a multi-line reply,
        which the text follows immediately (:rfc:`959#section-4`).

        Args:
            cmmd: FTP command.
            code: FTP status code.
            args: Optional FTP command arguments and/or status messages.
            more: More status messages to follow for response packets.
            charset: Encoding for :obj:`str` arguments, **UTF-8** if not given.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        """
        if cmmd is not None and code is None:
            if isinstance(cmmd, bytes):
                prefix = cmmd
            elif isinstance(cmmd, str):
                prefix = cmmd.encode()
            else:
                prefix = cmmd.value

            mf = b''
        elif cmmd is None and code is not None:
            code_val = int(code)
            prefix = str(code_val).encode()

            mf = b'-' if more else b''
        else:
            raise ProtocolError('FTP: invalid packet type')

        if args is None:
            suffix = b''
        elif isinstance(args, bytes):
            suffix = args
        else:
            suffix = args.encode(charset or 'utf-8')

        # the separating SP, absent with no arguments and after a hyphen
        sep = b'' if args is None or mf else b' '
        return Schema_FTP(
            data=b'%s%s%s%s\r\n' % (prefix, mf, sep, suffix),
        )

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_FTP') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        return {
            'cmmd': getattr(data, 'cmmd', None),
            'code': getattr(data, 'code', None),
            'args': getattr(data, 'args', None),
            'more': getattr(data, 'more', False),
            'charset': getattr(data, 'charset', None),
        }

    def _decode_args(self, args: 'Optional[bytes]') -> 'tuple[Optional[str], Optional[str]]':
        """Decode arguments, recording how to encode them back.

        The arguments are decoded by :meth:`self.decode
        <pcapkit.protocols.protocol.Protocol.decode>`. Where the result does
        not encode back to ``args`` as UTF-8 -- which :meth:`make` uses by
        default -- the detected charset is returned with it, or ``'latin-1'``
        (decoding again) if that does not reproduce ``args`` either, so that the
        original octets survive a rebuild.

        Args:
            args: Raw arguments, :obj:`None` if the line carries none.

        Returns:
            The decoded arguments and the charset to encode them with, the
            latter :obj:`None` for UTF-8.

        """
        if args is None:
            return None, None
        value = self.decode(args)
        for charset in (None, detect(args)):
            try:
                if value.encode(charset or 'utf-8') == args:
                    return value, charset
            except (LookupError, UnicodeError):
                pass
        return args.decode('latin-1'), 'latin-1'


class FTP_DATA(Raw):
    """This class implements FTP data channel transmission."""

    ##########################################################################
    # Properties.
    ##########################################################################

    # name of current protocol
    @property
    def name(self) -> 'Literal["FTP_DATA"]':  # type: ignore[override]
        """Name of current protocol."""
        return 'FTP_DATA'
