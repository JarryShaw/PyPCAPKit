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

    _ignore_ = 'ReturnCode _'
    ReturnCode = vars()

    #: Restart marker replay. In this case, the text is exact and not left to the particular implementation; it must read: MARK yyyy = mmmm where yyyy is User-process data stream marker, and mmmm server's equivalent marker (note the spaces between markers and "=").
    ReturnCode['Code_110'] = 110

    #: Service ready in nnn minutes.
    ReturnCode['Code_120'] = 120

    #: Data connection already open; transfer starting.
    ReturnCode['Code_125'] = 125

    #: File status okay; about to open data connection.
    ReturnCode['Code_150'] = 150

    #: Command not implemented, superfluous at this site.
    ReturnCode['Code_202'] = 202

    #: System status, or system help reply.
    ReturnCode['Code_211'] = 211

    #: Directory status.
    ReturnCode['Code_212'] = 212

    #: File status.
    ReturnCode['Code_213'] = 213

    #: Help message. Explains how to use the server or the meaning of a particular non-standard command. This reply is useful only to the human user.
    ReturnCode['Code_214'] = 214

    #: NAME system type. Where NAME is an official system name from the registry kept by IANA.
    ReturnCode['Code_215'] = 215

    #: Service ready for new user.
    ReturnCode['Code_220'] = 220

    #: Service closing control connection.
    ReturnCode['Code_221'] = 221

    #: Data connection open; no transfer in progress.
    ReturnCode['Code_225'] = 225

    #: Closing data connection. Requested file action successful (for example, file transfer or file abort).
    ReturnCode['Code_226'] = 226

    #: Entering Passive Mode (h1,h2,h3,h4,p1,p2).
    ReturnCode['Code_227'] = 227

    #: Entering Long Passive Mode (long address, port).
    ReturnCode['Code_228'] = 228

    #: Entering Extended Passive Mode (|||port|).
    ReturnCode['Code_229'] = 229

    #: User logged in, proceed. Logged out if appropriate.
    ReturnCode['Code_230'] = 230

    #: User logged out; service terminated.
    ReturnCode['Code_231'] = 231

    #: Logout command noted, will complete when transfer done.
    ReturnCode['Code_232'] = 232

    #: Specifies that the server accepts the authentication mechanism specified by the client, and the exchange of security data is complete. A higher level nonstandard code created by Microsoft.
    ReturnCode['Code_234'] = 234

    #: Requested file action okay, completed.
    ReturnCode['Code_250'] = 250

    #: "PATHNAME" created.
    ReturnCode['Code_257'] = 257

    #: User name okay, need password.
    ReturnCode['Code_331'] = 331

    #: Need account for login.
    ReturnCode['Code_332'] = 332

    #: Requested file action pending further information
    ReturnCode['Code_350'] = 350

    #: Service not available, closing control connection. This may be a reply to any command if the service knows it must shut down.
    ReturnCode['Code_421'] = 421

    #: Can't open data connection.
    ReturnCode['Code_425'] = 425

    #: Connection closed; transfer aborted.
    ReturnCode['Code_426'] = 426

    #: Invalid username or password
    ReturnCode['Code_430'] = 430

    #: Requested host unavailable.
    ReturnCode['Code_434'] = 434

    #: Requested file action not taken.
    ReturnCode['Code_450'] = 450

    #: Requested action aborted. Local error in processing.
    ReturnCode['Code_451'] = 451

    #: Requested action not taken. Insufficient storage space in system. File unavailable (e. g. , file busy).
    ReturnCode['Code_452'] = 452

    #: Syntax error in parameters or arguments.
    ReturnCode['Code_501'] = 501

    #: Command not implemented.
    ReturnCode['Code_502'] = 502

    #: Bad sequence of commands.
    ReturnCode['Code_503'] = 503

    #: Command not implemented for that parameter.
    ReturnCode['Code_504'] = 504

    #: Not logged in.
    ReturnCode['Code_530'] = 530

    #: Need account for storing files.
    ReturnCode['Code_532'] = 532

    #: Could Not Connect to Server - Policy Requires SSL
    ReturnCode['Code_534'] = 534

    #: Requested action not taken. File unavailable (e. g. , file not found, no access).
    ReturnCode['Code_550'] = 550

    #: Requested action aborted. Page type unknown.
    ReturnCode['Code_551'] = 551

    #: Requested file action aborted. Exceeded storage allocation (for current directory or dataset).
    ReturnCode['Code_552'] = 552

    #: Requested action not taken. File name not allowed.
    ReturnCode['Code_553'] = 553

    #: Integrity protected reply.
    ReturnCode['Code_631'] = 631

    #: Confidentiality and integrity protected reply.
    ReturnCode['Code_632'] = 632

    #: Confidentiality protected reply.
    ReturnCode['Code_633'] = 633

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
