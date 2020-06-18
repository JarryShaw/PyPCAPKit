# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""FTP Server Return Code"""

from aenum import IntEnum, extend_enum

__all__ = ['ReturnCode']

#: Response kind; whether the response is good, bad or incomplete.
KIND = {
    '1': 'Positive Preliminary',
    '2': 'Positive Completion',
    '3': 'Positive Intermediate',
    '4': 'Transient Negative Completion',
    '5': 'Permanent Negative Completion',
    '6': 'Protected',
}

#: Grouping information.
INFO = {
    '0': 'Syntax',
    '1': 'Information',
    '2': 'Connections',
    '3': 'Authentication and accounting',
    '4': 'Unspecified',                     # [RFC 959]
    '5': 'File system',
}


class ReturnCode(IntEnum):
    """[ReturnCode] FTP Server Return Code"""

    #: Restart marker replay. In this case, the text is exact and not left to the
    #: particular implementation; it must read: MARK yyyy = mmmm where yyyy is
    #: User-process data stream marker, and mmmm server's equivalent marker (note
    #: the spaces between markers and "=").
    CODE_110 = 110

    #: Service ready in nnn minutes.
    CODE_120 = 120

    #: Data connection already open; transfer starting.
    CODE_125 = 125

    #: File status okay; about to open data connection.
    CODE_150 = 150

    #: Command not implemented, superfluous at this site.
    CODE_202 = 202

    #: System status, or system help reply.
    CODE_211 = 211

    #: Directory status.
    CODE_212 = 212

    #: File status.
    CODE_213 = 213

    #: Help message. Explains how to use the server or the meaning of a particular
    #: non-standard command. This reply is useful only to the human user.
    CODE_214 = 214

    #: NAME system type. Where NAME is an official system name from the registry
    #: kept by IANA.
    CODE_215 = 215

    #: Service ready for new user.
    CODE_220 = 220

    #: Service closing control connection.
    CODE_221 = 221

    #: Data connection open; no transfer in progress.
    CODE_225 = 225

    #: Closing data connection. Requested file action successful (for example, file
    #: transfer or file abort).
    CODE_226 = 226

    #: Entering Passive Mode (h1,h2,h3,h4,p1,p2).
    CODE_227 = 227

    #: Entering Long Passive Mode (long address, port).
    CODE_228 = 228

    #: Entering Extended Passive Mode (|||port|).
    CODE_229 = 229

    #: User logged in, proceed. Logged out if appropriate.
    CODE_230 = 230

    #: User logged out; service terminated.
    CODE_231 = 231

    #: Logout command noted, will complete when transfer done.
    CODE_232 = 232

    #: Specifies that the server accepts the authentication mechanism specified by
    #: the client, and the exchange of security data is complete. A higher level
    #: nonstandard code created by Microsoft.
    CODE_234 = 234

    #: Requested file action okay, completed.
    CODE_250 = 250

    #: "PATHNAME" created.
    CODE_257 = 257

    #: User name okay, need password.
    CODE_331 = 331

    #: Need account for login.
    CODE_332 = 332

    #: Requested file action pending further information
    CODE_350 = 350

    #: Service not available, closing control connection. This may be a reply to
    #: any command if the service knows it must shut down.
    CODE_421 = 421

    #: Can't open data connection.
    CODE_425 = 425

    #: Connection closed; transfer aborted.
    CODE_426 = 426

    #: Invalid username or password
    CODE_430 = 430

    #: Requested host unavailable.
    CODE_434 = 434

    #: Requested file action not taken.
    CODE_450 = 450

    #: Requested action aborted. Local error in processing.
    CODE_451 = 451

    #: Requested action not taken. Insufficient storage space in system. File
    #: unavailable (e. g. , file busy).
    CODE_452 = 452

    #: Syntax error in parameters or arguments.
    CODE_501 = 501

    #: Command not implemented.
    CODE_502 = 502

    #: Bad sequence of commands.
    CODE_503 = 503

    #: Command not implemented for that parameter.
    CODE_504 = 504

    #: Not logged in.
    CODE_530 = 530

    #: Need account for storing files.
    CODE_532 = 532

    #: Could Not Connect to Server - Policy Requires SSL
    CODE_534 = 534

    #: Requested action not taken. File unavailable (e. g. , file not found, no
    #: access).
    CODE_550 = 550

    #: Requested action aborted. Page type unknown.
    CODE_551 = 551

    #: Requested file action aborted. Exceeded storage allocation (for current
    #: directory or dataset).
    CODE_552 = 552

    #: Requested action not taken. File name not allowed.
    CODE_553 = 553

    #: Integrity protected reply.
    CODE_631 = 631

    #: Confidentiality and integrity protected reply.
    CODE_632 = 632

    #: Confidentiality protected reply.
    CODE_633 = 633

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return ReturnCode(key)
        if key not in ReturnCode._member_map_:  # pylint: disable=no-member
            extend_enum(ReturnCode, key, default)
        return ReturnCode[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 100 <= value <= 659):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        code = str(value)
        kind = KIND.get(code[0], 'Reserved')
        info = INFO.get(code[1], 'Reserved')
        extend_enum(cls, '%s - %s [%s]' % (kind, info, value), value)
        return cls(value)
