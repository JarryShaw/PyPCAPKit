# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""FTP Command
=================

.. module:: pcapkit.const.ftp.command

This module contains the constant enumeration for **FTP Command**,
which is automatically generated from :class:`pcapkit.vendor.ftp.command.Command`.

"""

from typing import TYPE_CHECKING

from aenum import StrEnum, extend_enum

if TYPE_CHECKING:
    from typing import Optional, Type

__all__ = ['Command']


class Command(StrEnum):
    """[Command] FTP Command"""

    def __new__(cls, name: 'str', feat: 'Optional[str]' = None, desc: 'Optional[str]' = None,
                type: 'Optional[tuple[str, ...]]' = None, conf: 'Optional[str]' = None,
                note: 'Optional[tuple[str, ...]]' = None) -> 'Type[Command]':
        obj = str.__new__(cls, name)
        obj._value_ = name

        #: Feature of command.
        obj.feat = feat
        #: Description of command.
        obj.desc = desc
        #: Type of command.
        obj.type = type
        #: Conformance of command.
        obj.conf = conf
        #: Note of command.
        obj.note = note

        return obj

    def __repr__(self) -> 'str':
        return "<%s.%s>" % (self.__class__.__name__, self._name_)

    #: Abort [:rfc:`959`]
    ABOR = 'ABOR', '<base>', 'Abort', ('service execution',), 'mandatory to implement', ('RFC 959',)

    #: Account [:rfc:`959`]
    ACCT = 'ACCT', '<base>', 'Account', ('access control',), 'mandatory to implement', ('RFC 959',)

    #: Authentication/Security Data [:rfc:`2228`][:rfc:`2773`][:rfc:`4217`]
    ADAT = 'ADAT', '<secu>', 'Authentication/Security Data', ('access control',), 'optional', ('RFC 2228', 'RFC 2773', 'RFC 4217')

    #: FTP64 ALG status [:rfc:`6384`][Section 11]
    ALGS = 'ALGS', None, 'FTP64 ALG status', None, 'optional', ('RFC 6384',)

    #: Allocate [:rfc:`959`]
    ALLO = 'ALLO', '<base>', 'Allocate', ('service execution',), 'mandatory to implement', ('RFC 959',)

    #: Append (with create) [:rfc:`959`]
    APPE = 'APPE', '<base>', 'Append (with create)', ('service execution',), 'mandatory to implement', ('RFC 959',)

    #: Authentication/Security Mechanism [2][:rfc:`2773`][:rfc:`4217`]
    AUTH = 'AUTH', 'AUTH', 'Authentication/Security Mechanism', ('access control',), 'optional', ('RFC 2773', 'RFC 4217')

    #: Clear Command Channel [:rfc:`2228`]
    CCC = 'CCC', '<secu>', 'Clear Command Channel', ('access control',), 'optional', ('RFC 2228',)

    #: Change to Parent Directory [:rfc:`959`]
    CDUP = 'CDUP', '<base>', 'Change to Parent Directory', ('access control',), 'optional', ('RFC 959',)

    #: Confidentiality Protected Command [:rfc:`2228`]
    CONF = 'CONF', '<secu>', 'Confidentiality Protected Command', ('access control',), 'optional', ('RFC 2228',)

    #: Change Working Directory [:rfc:`959`]
    CWD = 'CWD', '<base>', 'Change Working Directory', ('access control',), 'mandatory to implement', ('RFC 959',)

    #: Delete File [:rfc:`959`]
    DELE = 'DELE', '<base>', 'Delete File', ('service execution',), 'mandatory to implement', ('RFC 959',)

    #: Privacy Protected Command [:rfc:`2228`][:rfc:`2773`][:rfc:`4217`]
    ENC = 'ENC', '<secu>', 'Privacy Protected Command', ('access control',), 'optional', ('RFC 2228', 'RFC 2773', 'RFC 4217')

    #: Extended Port [:rfc:`2428`]
    EPRT = 'EPRT', '<nat6>', 'Extended Port', ('parameter setting',), 'optional', ('RFC 2428',)

    #: Extended Passive Mode [:rfc:`2428`]
    EPSV = 'EPSV', '<nat6>', 'Extended Passive Mode', ('parameter setting',), 'optional', ('RFC 2428',)

    #: Feature Negotiation [:rfc:`2389`]
    FEAT = 'FEAT', '<feat>', 'Feature Negotiation', ('access control',), 'mandatory to implement', ('RFC 2389',)

    #: Help [:rfc:`959`]
    HELP = 'HELP', '<base>', 'Help', ('service execution',), 'mandatory to implement', ('RFC 959',)

    #: Hostname [:rfc:`7151`]
    HOST = 'HOST', 'HOST', 'Hostname', ('access control',), 'optional', ('RFC 7151',)

    #: Language (for Server Messages) [:rfc:`2640`]
    LANG = 'LANG', 'UTF8', 'Language (for Server Messages)', ('parameter setting',), 'optional', ('RFC 2640',)

    #: List [:rfc:`959`][:rfc:`1123`]
    LIST = 'LIST', '<base>', 'List', ('service execution',), 'mandatory to implement', ('RFC 959', 'RFC 1123')

    #: Data Port [:rfc:`1545`][:rfc:`1639`]
    LPRT = 'LPRT', '<hist>', 'Data Port', ('parameter setting',), 'historic', ('RFC 1545', 'RFC 1639')

    #: Passive Mode [:rfc:`1545`][:rfc:`1639`]
    LPSV = 'LPSV', '<hist>', 'Passive Mode', ('parameter setting',), 'historic', ('RFC 1545', 'RFC 1639')

    #: File Modification Time [:rfc:`3659`]
    MDTM = 'MDTM', 'MDTM', 'File Modification Time', ('service execution',), 'optional', ('RFC 3659',)

    #: Integrity Protected Command [:rfc:`2228`][:rfc:`2773`][:rfc:`4217`]
    MIC = 'MIC', '<secu>', 'Integrity Protected Command', ('access control',), 'optional', ('RFC 2228', 'RFC 2773', 'RFC 4217')

    #: Make Directory [:rfc:`959`]
    MKD = 'MKD', '<base>', 'Make Directory', ('service execution',), 'optional', ('RFC 959',)

    #: List Directory (for machine) [:rfc:`3659`]
    MLSD = 'MLSD', 'MLST', 'List Directory (for machine)', ('service execution',), 'optional', ('RFC 3659',)

    #: List Single Object [:rfc:`3659`]
    MLST = 'MLST', 'MLST', 'List Single Object', ('service execution',), 'optional', ('RFC 3659',)

    #: Transfer Mode [:rfc:`959`]
    MODE = 'MODE', '<base>', 'Transfer Mode', ('parameter setting',), 'mandatory to implement', ('RFC 959',)

    #: Name List [:rfc:`959`][:rfc:`1123`]
    NLST = 'NLST', '<base>', 'Name List', ('service execution',), 'mandatory to implement', ('RFC 959', 'RFC 1123')

    #: No-Op [:rfc:`959`]
    NOOP = 'NOOP', '<base>', 'No-Op', ('service execution',), 'mandatory to implement', ('RFC 959',)

    #: Options [:rfc:`2389`]
    OPTS = 'OPTS', '<feat>', 'Options', ('parameter setting',), 'mandatory to implement', ('RFC 2389',)

    #: Password [:rfc:`959`]
    PASS = 'PASS', '<base>', 'Password', ('access control',), 'mandatory to implement', ('RFC 959',)

    #: Passive Mode [:rfc:`959`][:rfc:`1123`]
    PASV = 'PASV', '<base>', 'Passive Mode', ('parameter setting',), 'mandatory to implement', ('RFC 959', 'RFC 1123')

    #: Protection Buffer Size [:rfc:`4217`]
    PBSZ = 'PBSZ', 'PBSZ', 'Protection Buffer Size', ('parameter setting',), 'optional', ('RFC 4217',)

    #: Data Port [:rfc:`959`]
    PORT = 'PORT', '<base>', 'Data Port', ('parameter setting',), 'mandatory to implement', ('RFC 959',)

    #: Data Channel Protection Level [:rfc:`4217`]
    PROT = 'PROT', 'PROT', 'Data Channel Protection Level', ('parameter setting',), 'optional', ('RFC 4217',)

    #: Print Directory [:rfc:`959`]
    PWD = 'PWD', '<base>', 'Print Directory', ('service execution',), 'optional', ('RFC 959',)

    #: Logout [:rfc:`959`]
    QUIT = 'QUIT', '<base>', 'Logout', ('access control',), 'mandatory to implement', ('RFC 959',)

    #: Reinitialize [:rfc:`959`]
    REIN = 'REIN', '<base>', 'Reinitialize', ('access control',), 'mandatory to implement', ('RFC 959',)

    #: Restart (for STREAM mode) [3][:rfc:`3659`]
    REST = 'REST', 'REST', 'Restart (for STREAM mode)', ('service execution', 'parameter setting'), 'mandatory to implement', ('RFC 3659',)

    #: Retrieve [:rfc:`959`]
    RETR = 'RETR', '<base>', 'Retrieve', ('service execution',), 'mandatory to implement', ('RFC 959',)

    #: Remove Directory [:rfc:`959`]
    RMD = 'RMD', '<base>', 'Remove Directory', ('service execution',), 'optional', ('RFC 959',)

    #: Rename From [:rfc:`959`]
    RNFR = 'RNFR', '<base>', 'Rename From', ('service execution', 'parameter setting'), 'mandatory to implement', ('RFC 959',)

    #: Rename From [:rfc:`959`]
    RNTO = 'RNTO', '<base>', 'Rename From', ('service execution',), 'mandatory to implement', ('RFC 959',)

    #: Site Parameters [:rfc:`959`][:rfc:`1123`]
    SITE = 'SITE', '<base>', 'Site Parameters', ('service execution',), 'mandatory to implement', ('RFC 959', 'RFC 1123')

    #: File Size [:rfc:`3659`]
    SIZE = 'SIZE', 'SIZE', 'File Size', ('service execution',), 'optional', ('RFC 3659',)

    #: Structure Mount [:rfc:`959`]
    SMNT = 'SMNT', '<base>', 'Structure Mount', ('access control',), 'optional', ('RFC 959',)

    #: Status [:rfc:`959`]
    STAT = 'STAT', '<base>', 'Status', ('service execution',), 'mandatory to implement', ('RFC 959',)

    #: Store [:rfc:`959`]
    STOR = 'STOR', '<base>', 'Store', ('service execution',), 'mandatory to implement', ('RFC 959',)

    #: Store Unique [:rfc:`959`][:rfc:`1123`]
    STOU = 'STOU', '<base>', 'Store Unique', ('access control',), 'optional', ('RFC 959', 'RFC 1123')

    #: File Structure [:rfc:`959`]
    STRU = 'STRU', '<base>', 'File Structure', ('parameter setting',), 'mandatory to implement', ('RFC 959',)

    #: System [:rfc:`959`]
    SYST = 'SYST', '<base>', 'System', ('service execution',), 'optional', ('RFC 959',)

    #: Representation Type [4][:rfc:`959`]
    TYPE = 'TYPE', '<base>', 'Representation Type', ('parameter setting',), 'mandatory to implement', ('RFC 959',)

    #: User Name [:rfc:`959`]
    USER = 'USER', '<base>', 'User Name', ('access control',), 'mandatory to implement', ('RFC 959',)

    #: None [:rfc:`775`][:rfc:`1123`]
    XCUP = 'XCUP', '<hist>', None, ('service execution',), 'historic', ('RFC 775', 'RFC 1123')

    #: None [:rfc:`775`][:rfc:`1123`]
    XCWD = 'XCWD', '<hist>', None, ('service execution',), 'historic', ('RFC 775', 'RFC 1123')

    #: None [:rfc:`775`][:rfc:`1123`]
    XMKD = 'XMKD', '<hist>', None, ('service execution',), 'historic', ('RFC 775', 'RFC 1123')

    #: None [:rfc:`775`][:rfc:`1123`]
    XPWD = 'XPWD', '<hist>', None, ('service execution',), 'historic', ('RFC 775', 'RFC 1123')

    #: None [:rfc:`775`][:rfc:`1123`]
    XRMD = 'XRMD', '<hist>', None, ('service execution',), 'historic', ('RFC 775', 'RFC 1123')

    #: Trivial Virtual File Store [:rfc:`3659`]
    TVFS = 'TVFS', 'TVFS', 'Trivial Virtual File Store', ('parameter setting',), 'optional', ('RFC 3659',)

    @staticmethod
    def get(key: 'str', default: 'Optional[str]' = None) -> 'Command':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if key not in Command._member_map_:  # pylint: disable=no-member
            extend_enum(Command, key.upper(), default if default is not None else key)
        return Command[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'str') -> 'Command':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        extend_enum(cls, value.upper(), value)
        return cls(value)
