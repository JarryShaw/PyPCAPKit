# -*- coding: utf-8 -*-

from aenum import IntEnum, extend_enum

KIND = {
    '1': 'Positive Preliminary',
    '2': 'Positive Completion',
    '3': 'Positive Intermediate',
    '4': 'Transient Negative Completion',
    '5': 'Permanent Negative Completion',
    '6': 'Protected',
}

INFO = {
    '0': 'Syntax',
    '1': 'Information',
    '2': 'Connections',
    '3': 'Authentication and accounting',
    '4': 'Unspecified',                     # [RFC 959]
    '5': 'File system',
}


class ReturnCode(IntEnum):
    """Enumeration class for ReturnCode."""
    _ignore_ = 'ReturnCode _'
    ReturnCode = vars()

    # FTP Server Return Code
    ReturnCode['Restart marker replay.'] = 110
    ReturnCode['Service ready in nnn minutes.'] = 120
    ReturnCode['Data connection already open; transfer starting.'] = 125
    ReturnCode['File status okay; about to open data connection.'] = 150
    ReturnCode['Command not implemented, superfluous at this site.'] = 202
    ReturnCode['System status, or system help reply.'] = 211
    ReturnCode['Directory status.'] = 212
    ReturnCode['File status.'] = 213
    ReturnCode['Help message.'] = 214
    ReturnCode['NAME system type.'] = 215
    ReturnCode['Service ready for new user.'] = 220
    ReturnCode['Service closing control connection.'] = 221
    ReturnCode['Data connection open; no transfer in progress.'] = 225
    ReturnCode['Closing data connection.'] = 226
    ReturnCode['Entering Passive Mode (h1,h2,h3,h4,p1,p2).'] = 227
    ReturnCode['Entering Long Passive Mode (long address, port).'] = 228
    ReturnCode['Entering Extended Passive Mode (|||port|).'] = 229
    ReturnCode['User logged in, proceed.'] = 230
    ReturnCode['User logged out; service terminated.'] = 231
    ReturnCode['Logout command noted, will complete when transfer done.'] = 232
    ReturnCode['Specifies that the server accepts the authentication mechanism specified by the client, and the exchange of security data is complete.'] = 234
    ReturnCode['Requested file action okay, completed.'] = 250
    ReturnCode['"PATHNAME" created.'] = 257
    ReturnCode['User name okay, need password.'] = 331
    ReturnCode['Need account for login.'] = 332
    ReturnCode['Requested file action pending further information.'] = 350
    ReturnCode['Service not available, closing control connection.'] = 421
    ReturnCode["Can't open data connection."] = 425
    ReturnCode['Connection closed; transfer aborted.'] = 426
    ReturnCode['Invalid username or password.'] = 430
    ReturnCode['Requested host unavailable.'] = 434
    ReturnCode['Requested file action not taken.'] = 450
    ReturnCode['Requested action aborted. [451]'] = 451
    ReturnCode['Requested action not taken. [452]'] = 452
    ReturnCode['Syntax error in parameters or arguments.'] = 501
    ReturnCode['Command not implemented.'] = 502
    ReturnCode['Bad sequence of commands.'] = 503
    ReturnCode['Command not implemented for that parameter.'] = 504
    ReturnCode['Not logged in.'] = 530
    ReturnCode['Need account for storing files.'] = 532
    ReturnCode['Could Not Connect to Server - Policy Requires SSL.'] = 534
    ReturnCode['Requested action not taken. [550]'] = 550
    ReturnCode['Requested action aborted. [551]'] = 551
    ReturnCode['Requested file action aborted.'] = 552
    ReturnCode['Requested action not taken. [553]'] = 553
    ReturnCode['Integrity protected reply.'] = 631
    ReturnCode['Confidentiality and integrity protected reply.'] = 632
    ReturnCode['Confidentiality protected reply.'] = 633

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return ReturnCode(key)
        if key not in ReturnCode._member_map_:
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
