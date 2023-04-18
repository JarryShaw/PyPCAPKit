# -*- coding: utf-8 -*-
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

#: Response kind; whether the response is good, bad or incomplete.
KIND = {
    '1': 'Positive Preliminary',
    '2': 'Positive Completion',
    '3': 'Positive Intermediate',
    '4': 'Transient Negative Completion',
    '5': 'Permanent Negative Completion',
    '6': 'Protected',
}  # type: dict[str, str]

#: Grouping information.
INFO = {
    '0': 'Syntax',
    '1': 'Information',
    '2': 'Connections',
    '3': 'Authentication and accounting',
    '4': 'Unspecified',                     # [RFC 959]
    '5': 'File system',
}  # type: dict[str, str]


class ReturnCode(IntEnum):
    """[ReturnCode] FTP Server Return Code"""

    def __new__(cls, value: 'int', description: 'Optional[str]' = None) -> 'Type[ReturnCode]':
        obj = int.__new__(cls, value)
        obj._value_ = value

        code = str(value)
        #: Description of the return code.
        obj.description = description
        #: Response kind.
        obj.kind = KIND.get(str(value)[0], 'Reserved')
        #: Grouping information.
        obj.group = INFO.get(str(value)[1], 'Reserved')

        return obj

    def __repr__(self) -> 'str':
        return "<%s [%s]>" % (self.__class__.__name__, self._value_)

    #: Restart marker replay. In this case, the text is exact and not left to the
    #: particular implementation; it must read: MARK yyyy = mmmm where yyyy is
    #: User-process data stream marker, and mmmm server's equivalent marker (note
    #: the spaces between markers and "=").
    CODE_110 = 110, 'Restart marker replay. In this case, the text is exact and not left to the particular implementation; it must read: MARK yyyy = mmmm where yyyy is User-process data stream marker, and mmmm server\'s equivalent marker (note the spaces between markers and "=").'

    #: Service ready in nnn minutes.
    CODE_120 = 120, 'Service ready in nnn minutes.'

    #: Data connection already open; transfer starting.
    CODE_125 = 125, 'Data connection already open; transfer starting.'

    #: File status okay; about to open data connection.
    CODE_150 = 150, 'File status okay; about to open data connection.'

    #: Command not implemented, superfluous at this site.
    CODE_202 = 202, 'Command not implemented, superfluous at this site.'

    #: System status, or system help reply.
    CODE_211 = 211, 'System status, or system help reply.'

    #: Directory status.
    CODE_212 = 212, 'Directory status.'

    #: File status.
    CODE_213 = 213, 'File status.'

    #: Help message. Explains how to use the server or the meaning of a particular
    #: non-standard command. This reply is useful only to the human user.
    CODE_214 = 214, 'Help message. Explains how to use the server or the meaning of a particular non-standard command. This reply is useful only to the human user.'

    #: NAME system type. Where NAME is an official system name from the registry
    #: kept by IANA.
    CODE_215 = 215, 'NAME system type. Where NAME is an official system name from the registry kept by IANA.'

    #: Service ready for new user.
    CODE_220 = 220, 'Service ready for new user.'

    #: Service closing control connection. Logged out if appropriate.
    CODE_221 = 221, 'Service closing control connection. Logged out if appropriate.'

    #: Data connection open; no transfer in progress.
    CODE_225 = 225, 'Data connection open; no transfer in progress.'

    #: Closing data connection. Requested file action successful (for example, file
    #: transfer or file abort).
    CODE_226 = 226, 'Closing data connection. Requested file action successful (for example, file transfer or file abort).'

    #: Entering Passive Mode (h1,h2,h3,h4,p1,p2).
    CODE_227 = 227, 'Entering Passive Mode (h1,h2,h3,h4,p1,p2).'

    #: Entering Long Passive Mode (long address, port).
    CODE_228 = 228, 'Entering Long Passive Mode (long address, port).'

    #: Entering Extended Passive Mode (|||port|).
    CODE_229 = 229, 'Entering Extended Passive Mode (|||port|).'

    #: User logged in, proceed.
    CODE_230 = 230, 'User logged in, proceed.'

    #: User logged in, authorized by security data exchange.
    CODE_232 = 232, 'User logged in, authorized by security data exchange.'

    #: Server accepts the security  mechanism specified by the client; no security
    #: data needs to be exchanged.
    CODE_234 = 234, 'Server accepts the security  mechanism specified by the client; no security data needs to be exchanged.'

    #: Server accepts the security data given by the client; no further security
    #: data needs to be exchanged.
    CODE_235 = 235, 'Server accepts the security data given by the client; no further security data needs to be exchanged.'

    #: Requested file action okay, completed.
    CODE_250 = 250, 'Requested file action okay, completed.'

    #: "PATHNAME" created.
    CODE_257 = 257, '"PATHNAME" created.'

    #: User name okay, need password.
    CODE_331 = 331, 'User name okay, need password.'

    #: Need account for login.
    CODE_332 = 332, 'Need account for login.'

    #: Server accepts the security mechanism specified by the client; some security
    #: data needs to be exchanged.
    CODE_334 = 334, 'Server accepts the security mechanism specified by the client; some security data needs to be exchanged.'

    #: Server accepts the security data given by the client; more security data
    #: needs to be exchanged.
    CODE_335 = 335, 'Server accepts the security data given by the client; more security data needs to be exchanged.'

    #: Username okay, need password. Challenge is ". . . . ".
    CODE_336 = 336, 'Username okay, need password. Challenge is ". . . . ".'

    #: Requested file action pending further information
    CODE_350 = 350, 'Requested file action pending further information'

    #: Service not available, closing control connection. This may be a reply to
    #: any command if the service knows it must shut down.
    CODE_421 = 421, 'Service not available, closing control connection. This may be a reply to any command if the service knows it must shut down.'

    #: Can't open data connection.
    CODE_425 = 425, "Can't open data connection."

    #: Connection closed; transfer aborted.
    CODE_426 = 426, 'Connection closed; transfer aborted.'

    #: Invalid username or password
    CODE_430 = 430, 'Invalid username or password'

    #: Need some unavailable resource to process security.
    CODE_431 = 431, 'Need some unavailable resource to process security.'

    #: Requested host unavailable.
    CODE_434 = 434, 'Requested host unavailable.'

    #: Requested file action not taken.
    CODE_450 = 450, 'Requested file action not taken.'

    #: Requested action aborted. Local error in processing.
    CODE_451 = 451, 'Requested action aborted. Local error in processing.'

    #: Requested action not taken. Insufficient storage space in system. File
    #: unavailable (e.g., file busy).
    CODE_452 = 452, 'Requested action not taken. Insufficient storage space in system. File unavailable (e.g., file busy).'

    #: Syntax error in parameters or arguments.
    CODE_501 = 501, 'Syntax error in parameters or arguments.'

    #: Command not implemented.
    CODE_502 = 502, 'Command not implemented.'

    #: Bad sequence of commands.
    CODE_503 = 503, 'Bad sequence of commands.'

    #: Command not implemented for that parameter.
    CODE_504 = 504, 'Command not implemented for that parameter.'

    #: Not logged in.
    CODE_530 = 530, 'Not logged in.'

    #: Need account for storing files.
    CODE_532 = 532, 'Need account for storing files.'

    #: Command protection level denied for policy reasons.
    CODE_533 = 533, 'Command protection level denied for policy reasons.'

    #: Request denied for policy reasons.
    CODE_534 = 534, 'Request denied for policy reasons.'

    #: Failed security check.
    CODE_535 = 535, 'Failed security check.'

    #: Data protection level not supported by security mechanism.
    CODE_536 = 536, 'Data protection level not supported by security mechanism.'

    #: Command protection level not supported by security mechanism.
    CODE_537 = 537, 'Command protection level not supported by security mechanism.'

    #: Requested action not taken. File unavailable (e.g., file not found, no
    #: access).
    CODE_550 = 550, 'Requested action not taken. File unavailable (e.g., file not found, no access).'

    #: Requested action aborted. Page type unknown.
    CODE_551 = 551, 'Requested action aborted. Page type unknown.'

    #: Requested file action aborted. Exceeded storage allocation (for current
    #: directory or dataset).
    CODE_552 = 552, 'Requested file action aborted. Exceeded storage allocation (for current directory or dataset).'

    #: Requested action not taken. File name not allowed.
    CODE_553 = 553, 'Requested action not taken. File name not allowed.'

    #: Integrity protected reply.
    CODE_631 = 631, 'Integrity protected reply.'

    #: Confidentiality and integrity protected reply.
    CODE_632 = 632, 'Confidentiality and integrity protected reply.'

    #: Confidentiality protected reply.
    CODE_633 = 633, 'Confidentiality protected reply.'

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
            extend_enum(ReturnCode, key, default)
        return ReturnCode[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'ReturnCode':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 100 <= value <= 659):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'CODE_%s' % value, value)
        return cls(value)
