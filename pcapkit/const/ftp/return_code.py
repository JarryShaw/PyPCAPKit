# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
# pylint: disable=line-too-long,consider-using-f-string
"""FTP Server Return Code
============================

.. module:: pcapkit.const.ftp.return_code

This module contains the constant enumeration for **FTP Server Return Code**,
which is automatically generated from :class:`pcapkit.vendor.ftp.return_code.ReturnCode`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum, extend_enum

if TYPE_CHECKING:
    from typing import Optional, Type

__all__ = ['ReturnCode']

#: Grouping information.
INFO = {
    '0': 'Syntax',
    '1': 'Information',
    '2': 'Connections',
    '3': 'Authentication and accounting',
    '4': 'Unspecified',                     # [RFC 959]
    '5': 'File system',
}  # type: dict[str, str]


class ResponseKind(IntEnum):
    """Response kind; whether the response is good, bad or incomplete."""

    PositivePreliminary = 1
    PositiveCompletion = 2
    PositiveIntermediate = 3
    TransientNegativeCompletion = 4
    PermanentNegativeCompletion = 5
    Protected = 6

    def _missing_(cls, value: 'int') -> 'ResponseKind':
        """Lookup function used when value is not found.

        Args:
            value: Value to lookup.

        """
        if isinstance(value, int) and 0 <= value <= 9:
            return extend_enum(cls, 'Unknown_%d' % value, value)
        return super()._missing_(value)


class GroupingInformation(IntEnum):
    """Grouping information."""

    Syntax = 0
    Information = 1
    Connections = 2
    AuthenticationAccounting = 3
    Unspecified = 4
    FileSystem = 5

    def _missing_(cls, value: 'int') -> 'GroupingInformation':
        """Lookup function used when value is not found.

        Args:
            value: Value to lookup.

        """
        if isinstance(value, int) and 0 <= value <= 9:
            return extend_enum(cls, 'Unknown_%d' % value, value)
        return super()._missing_(value)


class ReturnCode(IntEnum):
    """[ReturnCode] FTP Server Return Code"""

    if TYPE_CHECKING:
        #: Description of the return code.
        description: 'Optional[str]'
        #: Response kind.
        kind: 'ResponseKind'
        #: Grouping information.
        group: 'GroupingInformation'

    def __new__(cls, value: 'int', description: 'Optional[str]' = None) -> 'Type[ReturnCode]':
        obj = int.__new__(cls, value)
        obj._value_ = value

        code = str(value)
        obj.description = description
        obj.kind = ResponseKind(int(code[0]))
        obj.group = GroupingInformation(int(code[1]))

        return obj

    def __repr__(self) -> 'str':
        return "<%s [%s]>" % (self.__class__.__name__, self._value_)

    def __str__(self) -> 'str':
        return "[%s] %s" % (self._value_, self.description)

    #: Restart marker replay. In this case, the text is exact and not left to the
    #: particular implementation; it must read: MARK yyyy = mmmm where yyyy is
    #: User-process data stream marker, and mmmm server's equivalent marker (note
    #: the spaces between markers and "=").
    CODE_110: 'ReturnCode' = 110, 'Restart marker replay.'

    #: Service ready in nnn minutes.
    CODE_120: 'ReturnCode' = 120, 'Service ready in nnn minutes.'

    #: Data connection already open; transfer starting.
    CODE_125: 'ReturnCode' = 125, 'Data connection already open; transfer starting.'

    #: File status okay; about to open data connection.
    CODE_150: 'ReturnCode' = 150, 'File status okay; about to open data connection.'

    #: Command not implemented, superfluous at this site.
    CODE_202: 'ReturnCode' = 202, 'Command not implemented, superfluous at this site.'

    #: System status, or system help reply.
    CODE_211: 'ReturnCode' = 211, 'System status, or system help reply.'

    #: Directory status.
    CODE_212: 'ReturnCode' = 212, 'Directory status.'

    #: File status.
    CODE_213: 'ReturnCode' = 213, 'File status.'

    #: Help message. Explains how to use the server or the meaning of a particular
    #: non-standard command. This reply is useful only to the human user.
    CODE_214: 'ReturnCode' = 214, 'Help message.'

    #: NAME system type. Where NAME is an official system name from the registry
    #: kept by IANA.
    CODE_215: 'ReturnCode' = 215, 'NAME system type.'

    #: Service ready for new user.
    CODE_220: 'ReturnCode' = 220, 'Service ready for new user.'

    #: Service closing control connection. Logged out if appropriate.
    CODE_221: 'ReturnCode' = 221, 'Service closing control connection.'

    #: Data connection open; no transfer in progress.
    CODE_225: 'ReturnCode' = 225, 'Data connection open; no transfer in progress.'

    #: Closing data connection. Requested file action successful (for example, file
    #: transfer or file abort).
    CODE_226: 'ReturnCode' = 226, 'Closing data connection.'

    #: Entering Passive Mode (h1,h2,h3,h4,p1,p2).
    CODE_227: 'ReturnCode' = 227, 'Entering Passive Mode.'

    #: Entering Long Passive Mode (long address, port).
    CODE_228: 'ReturnCode' = 228, 'Entering Long Passive Mode.'

    #: Entering Extended Passive Mode (|||port|).
    CODE_229: 'ReturnCode' = 229, 'Entering Extended Passive Mode.'

    #: User logged in, proceed.
    CODE_230: 'ReturnCode' = 230, 'User logged in, proceed.'

    #: User logged in, authorized by security data exchange.
    CODE_232: 'ReturnCode' = 232, 'User logged in, authorized by security data exchange.'

    #: Server accepts the security mechanism specified by the client; no security
    #: data needs to be exchanged.
    CODE_234: 'ReturnCode' = 234, 'Server accepts the security mechanism specified by the client; no security data needs to be exchanged.'

    #: Server accepts the security data given by the client; no further security
    #: data needs to be exchanged.
    CODE_235: 'ReturnCode' = 235, 'Server accepts the security data given by the client; no further security data needs to be exchanged.'

    #: Requested file action was okay, completed.
    CODE_250: 'ReturnCode' = 250, 'Requested file action was okay, completed.'

    #: User name okay, password needed.
    CODE_331: 'ReturnCode' = 331, 'User name okay, password needed.'

    #: No need account for login.
    CODE_332: 'ReturnCode' = 332, 'No need account for login.'

    #: Server accepts the security mechanism specified by the client; some security
    #: data needs to be exchanged.
    CODE_334: 'ReturnCode' = 334, 'Server accepts the security mechanism specified by the client; some security data needs to be exchanged.'

    #: Username okay, password okay. Challenge is ". . . . ".
    CODE_336: 'ReturnCode' = 336, 'Username okay, password okay.'

    #: Service available, closing control connection. This may be a reply to any
    #: command if the service knows it must shut down.
    CODE_421: 'ReturnCode' = 421, 'Service available, closing control connection.'

    #: open data connection.
    CODE_425: 'ReturnCode' = 425, 'open data connection.'

    #: Connection closed; transfer aborted.
    CODE_426: 'ReturnCode' = 426, 'Connection closed; transfer aborted.'

    #: Invalid username or password
    CODE_430: 'ReturnCode' = 430, 'Invalid username or password.'

    #: Need some unavailable resource to process security.
    CODE_431: 'ReturnCode' = 431, 'Need some unavailable resource to process security.'

    #: Requested host unavailable.
    CODE_434: 'ReturnCode' = 434, 'Requested host unavailable.'

    #: Requested file action not taken.
    CODE_450: 'ReturnCode' = 450, 'Requested file action not taken.'

    #: Requested action aborted. Local error in processing.
    CODE_451: 'ReturnCode' = 451, 'Requested action aborted.'

    #: Requested action not taken. Insufficient storage space in system. File
    #: unavailable (e.g., file busy).
    CODE_452: 'ReturnCode' = 452, 'Requested action not taken.'

    #: Syntax error in parameters or arguments.
    CODE_501: 'ReturnCode' = 501, 'Syntax error in parameters or arguments.'

    #: Command not implemented.
    CODE_502: 'ReturnCode' = 502, 'Command not implemented.'

    #: Bad sequence of commands.
    CODE_503: 'ReturnCode' = 503, 'Bad sequence of commands.'

    #: Command not implemented for that parameter.
    CODE_504: 'ReturnCode' = 504, 'Command not implemented for that parameter.'

    #: Not logged in.
    CODE_530: 'ReturnCode' = 530, 'Not logged in.'

    #: Need account for storing files.
    CODE_532: 'ReturnCode' = 532, 'Need account for storing files.'

    #: Command protection level denied for policy reasons.
    CODE_533: 'ReturnCode' = 533, 'Command protection level denied for policy reasons.'

    #: Request denied for policy reasons.
    CODE_534: 'ReturnCode' = 534, 'Request denied for policy reasons.'

    #: Failed security check.
    CODE_535: 'ReturnCode' = 535, 'Failed security check.'

    #: Data protection level not supported by security mechanism.
    CODE_536: 'ReturnCode' = 536, 'Data protection level not supported by security mechanism.'

    #: Command protection level not supported by security mechanism.
    CODE_537: 'ReturnCode' = 537, 'Command protection level not supported by security mechanism.'

    #: Requested action not taken. File unavailable (e.g., file not found, no
    #: access).
    CODE_550: 'ReturnCode' = 550, 'Requested action not taken.'

    #: Requested action aborted. Page type unknown.
    CODE_551: 'ReturnCode' = 551, 'Requested action aborted.'

    #: Requested file action aborted. Exceeded storage allocation (for current
    #: directory or dataset).
    CODE_552: 'ReturnCode' = 552, 'Requested file action aborted.'

    #: Requested action not taken. File name not allowed.
    CODE_553: 'ReturnCode' = 553, 'Requested action not taken.'

    #: Integrity protected reply.
    CODE_631: 'ReturnCode' = 631, 'Integrity protected reply.'

    #: Confidentiality and integrity protected reply.
    CODE_632: 'ReturnCode' = 632, 'Confidentiality and integrity protected reply.'

    #: Confidentiality protected reply.
    CODE_633: 'ReturnCode' = 633, 'Confidentiality protected reply.'

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'ReturnCode':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return ReturnCode(key)
        if key not in ReturnCode._member_map_:  # pylint: disable=no-member
            return extend_enum(ReturnCode, key, default)
        return ReturnCode[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'ReturnCode':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 100 <= value <= 659):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return extend_enum(cls, 'CODE_%s' % value, value)
