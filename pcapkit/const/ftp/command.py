# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
# pylint: disable=line-too-long,consider-using-f-string
"""FTP Command
=================

.. module:: pcapkit.const.ftp.command

This module contains the constant enumeration for **FTP Command**,
which is automatically generated from :class:`pcapkit.vendor.ftp.command.Command`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum, IntFlag, StrEnum, auto, extend_enum

if TYPE_CHECKING:
    from typing import Optional, Type

__all__ = ['Command']


class FEATCode(StrEnum):
    """Keyword returned in FEAT response line for this command/extension,
    c.f., :rfc:`5797#secion-3`."""

    #: FTP standard commands [:rfc:`0959`].
    base = '<base>'
    #: Historic experimental commands [:rfc:`0775`][:rfc:`1639`].
    hist = '<hist>'
    #: FTP Security Extensions [:rfc:`2228`].
    secu = '<secu>'
    #: FTP Feature Negotiation [:rfc:`2389`].
    feat = '<feat>'
    #: FTP Extensions for NAT/IPv6 [:rfc:`2428`].
    nat6 = '<nat6>'

    def __repr__(self) -> 'str':
        return "<%s [%s]>" % (self.__class__.__name__, self._name_)

    @classmethod
    def _missing_(cls, value: 'str') -> 'FEATCode':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        return extend_enum(cls, value.upper(), value)


class CommandType(IntFlag):
    """Type of "kind" of command, based on :rfc:`959#section-4.1`."""

    undefined = 0

    #: Access control.
    A = auto()
    #: Parameter setting.
    P = auto()
    #: Service execution.
    S = auto()


class ConformanceRequirement(IntEnum):
    """Expectation for support in modern FTP implementations."""

    #: Mandatory to implement.
    M = auto()
    #: Optional.
    O = auto()
    #: Historic.
    H = auto()


class Command(StrEnum):
    """[Command] FTP Command"""

    if TYPE_CHECKING:
        #: Feature code. Keyword returned in FEAT response line for this command/extension,
        #: c.f., :rfc:`5797#secion-2.2`.
        feat: 'Optional[FEATCode]'
        #: Brief description of command / extension.
        desc: 'Optional[str]'
        #: Type of "kind" of command, based on :rfc:`959#section-4.1`.
        type: 'CommandType'
        #: Expectation for support in modern FTP implementations.
        conf: 'ConformanceRequirement'

    def __new__(cls, name: 'str', feat: 'Optional[FEATCode]' = None,
                desc: 'Optional[str]' = None, type: 'CommandType' = CommandType.undefined,
                conf: 'ConformanceRequirement' = ConformanceRequirement.O) -> 'Type[Command]':
        obj = str.__new__(cls, name)
        obj._value_ = name

        obj.feat = feat
        obj.desc = desc
        obj.type = type
        obj.conf = conf

        return obj

    def __repr__(self) -> 'str':
        return "<%s.%s: %s>" % (self.__class__.__name__, self._name_, self.desc)

    #: Abort [:rfc:`959`]
    ABOR: 'Command' = 'ABOR', FEATCode.base, 'Abort', CommandType.S, ConformanceRequirement.M

    #: Account [:rfc:`959`]
    ACCT: 'Command' = 'ACCT', FEATCode.base, 'Account', CommandType.A, ConformanceRequirement.M

    #: Authentication/Security Data [:rfc:`2228`][:rfc:`2773`][:rfc:`4217`]
    ADAT: 'Command' = 'ADAT', FEATCode.secu, 'Authentication/Security Data', CommandType.A, ConformanceRequirement.O

    #: FTP64 ALG status [:rfc:`6384`][Section 11]
    ALGS: 'Command' = 'ALGS', None, 'FTP64 ALG status', 0, ConformanceRequirement.O

    #: Allocate [:rfc:`959`]
    ALLO: 'Command' = 'ALLO', FEATCode.base, 'Allocate', CommandType.S, ConformanceRequirement.M

    #: Append (with create) [:rfc:`959`]
    APPE: 'Command' = 'APPE', FEATCode.base, 'Append (with create)', CommandType.S, ConformanceRequirement.M

    #: Authentication/Security Mechanism [2][:rfc:`2773`][:rfc:`4217`]
    AUTH: 'Command' = 'AUTH', FEATCode('AUTH'), 'Authentication/Security Mechanism', CommandType.A, ConformanceRequirement.O

    #: Clear Command Channel [:rfc:`2228`]
    CCC: 'Command' = 'CCC', FEATCode.secu, 'Clear Command Channel', CommandType.A, ConformanceRequirement.O

    #: Change to Parent Directory [:rfc:`959`]
    CDUP: 'Command' = 'CDUP', FEATCode.base, 'Change to Parent Directory', CommandType.A, ConformanceRequirement.O

    #: Confidentiality Protected Command [:rfc:`2228`]
    CONF: 'Command' = 'CONF', FEATCode.secu, 'Confidentiality Protected Command', CommandType.A, ConformanceRequirement.O

    #: Change Working Directory [:rfc:`959`]
    CWD: 'Command' = 'CWD', FEATCode.base, 'Change Working Directory', CommandType.A, ConformanceRequirement.M

    #: Delete File [:rfc:`959`]
    DELE: 'Command' = 'DELE', FEATCode.base, 'Delete File', CommandType.S, ConformanceRequirement.M

    #: Privacy Protected Command [:rfc:`2228`][:rfc:`2773`][:rfc:`4217`]
    ENC: 'Command' = 'ENC', FEATCode.secu, 'Privacy Protected Command', CommandType.A, ConformanceRequirement.O

    #: Extended Port [:rfc:`2428`]
    EPRT: 'Command' = 'EPRT', FEATCode.nat6, 'Extended Port', CommandType.P, ConformanceRequirement.O

    #: Extended Passive Mode [:rfc:`2428`]
    EPSV: 'Command' = 'EPSV', FEATCode.nat6, 'Extended Passive Mode', CommandType.P, ConformanceRequirement.O

    #: Feature Negotiation [:rfc:`2389`]
    FEAT: 'Command' = 'FEAT', FEATCode.feat, 'Feature Negotiation', CommandType.A, ConformanceRequirement.M

    #: Help [:rfc:`959`]
    HELP: 'Command' = 'HELP', FEATCode.base, 'Help', CommandType.S, ConformanceRequirement.M

    #: Hostname [:rfc:`7151`]
    HOST: 'Command' = 'HOST', FEATCode('HOST'), 'Hostname', CommandType.A, ConformanceRequirement.O

    #: Language (for Server Messages) [:rfc:`2640`]
    LANG: 'Command' = 'LANG', FEATCode('UTF8'), 'Language (for Server Messages)', CommandType.P, ConformanceRequirement.O

    #: List [:rfc:`959`][:rfc:`1123`]
    LIST: 'Command' = 'LIST', FEATCode.base, 'List', CommandType.S, ConformanceRequirement.M

    #: Data Port [:rfc:`1545`][:rfc:`1639`]
    LPRT: 'Command' = 'LPRT', FEATCode.hist, 'Data Port', CommandType.P, ConformanceRequirement.H

    #: Passive Mode [:rfc:`1545`][:rfc:`1639`]
    LPSV: 'Command' = 'LPSV', FEATCode.hist, 'Passive Mode', CommandType.P, ConformanceRequirement.H

    #: File Modification Time [:rfc:`3659`]
    MDTM: 'Command' = 'MDTM', FEATCode('MDTM'), 'File Modification Time', CommandType.S, ConformanceRequirement.O

    #: Integrity Protected Command [:rfc:`2228`][:rfc:`2773`][:rfc:`4217`]
    MIC: 'Command' = 'MIC', FEATCode.secu, 'Integrity Protected Command', CommandType.A, ConformanceRequirement.O

    #: Make Directory [:rfc:`959`]
    MKD: 'Command' = 'MKD', FEATCode.base, 'Make Directory', CommandType.S, ConformanceRequirement.O

    #: List Directory (for machine) [:rfc:`3659`]
    MLSD: 'Command' = 'MLSD', FEATCode('MLST'), 'List Directory (for machine)', CommandType.S, ConformanceRequirement.O

    #: List Single Object [:rfc:`3659`]
    MLST: 'Command' = 'MLST', FEATCode('MLST'), 'List Single Object', CommandType.S, ConformanceRequirement.O

    #: Transfer Mode [:rfc:`959`]
    MODE: 'Command' = 'MODE', FEATCode.base, 'Transfer Mode', CommandType.P, ConformanceRequirement.M

    #: Name List [:rfc:`959`][:rfc:`1123`]
    NLST: 'Command' = 'NLST', FEATCode.base, 'Name List', CommandType.S, ConformanceRequirement.M

    #: No-Op [:rfc:`959`]
    NOOP: 'Command' = 'NOOP', FEATCode.base, 'No-Op', CommandType.S, ConformanceRequirement.M

    #: Options [:rfc:`2389`]
    OPTS: 'Command' = 'OPTS', FEATCode.feat, 'Options', CommandType.P, ConformanceRequirement.M

    #: Password [:rfc:`959`]
    PASS: 'Command' = 'PASS', FEATCode.base, 'Password', CommandType.A, ConformanceRequirement.M

    #: Passive Mode [:rfc:`959`][:rfc:`1123`]
    PASV: 'Command' = 'PASV', FEATCode.base, 'Passive Mode', CommandType.P, ConformanceRequirement.M

    #: Protection Buffer Size [:rfc:`4217`]
    PBSZ: 'Command' = 'PBSZ', FEATCode('PBSZ'), 'Protection Buffer Size', CommandType.P, ConformanceRequirement.O

    #: Data Port [:rfc:`959`]
    PORT: 'Command' = 'PORT', FEATCode.base, 'Data Port', CommandType.P, ConformanceRequirement.M

    #: Data Channel Protection Level [:rfc:`4217`]
    PROT: 'Command' = 'PROT', FEATCode('PROT'), 'Data Channel Protection Level', CommandType.P, ConformanceRequirement.O

    #: Print Directory [:rfc:`959`]
    PWD: 'Command' = 'PWD', FEATCode.base, 'Print Directory', CommandType.S, ConformanceRequirement.O

    #: Logout [:rfc:`959`]
    QUIT: 'Command' = 'QUIT', FEATCode.base, 'Logout', CommandType.A, ConformanceRequirement.M

    #: Reinitialize [:rfc:`959`]
    REIN: 'Command' = 'REIN', FEATCode.base, 'Reinitialize', CommandType.A, ConformanceRequirement.M

    #: Restart (for STREAM mode) [3][:rfc:`3659`]
    REST: 'Command' = 'REST', FEATCode('REST'), 'Restart (for STREAM mode)', CommandType.S | CommandType.P, ConformanceRequirement.M

    #: Retrieve [:rfc:`959`]
    RETR: 'Command' = 'RETR', FEATCode.base, 'Retrieve', CommandType.S, ConformanceRequirement.M

    #: Remove Directory [:rfc:`959`]
    RMD: 'Command' = 'RMD', FEATCode.base, 'Remove Directory', CommandType.S, ConformanceRequirement.O

    #: Rename From [:rfc:`959`]
    RNFR: 'Command' = 'RNFR', FEATCode.base, 'Rename From', CommandType.S | CommandType.P, ConformanceRequirement.M

    #: Rename To [:rfc:`959`][RFC Errata 5748]
    RNTO: 'Command' = 'RNTO', FEATCode.base, 'Rename To', CommandType.S, ConformanceRequirement.M

    #: Site Parameters [:rfc:`959`][:rfc:`1123`]
    SITE: 'Command' = 'SITE', FEATCode.base, 'Site Parameters', CommandType.S, ConformanceRequirement.M

    #: File Size [:rfc:`3659`]
    SIZE: 'Command' = 'SIZE', FEATCode('SIZE'), 'File Size', CommandType.S, ConformanceRequirement.O

    #: Structure Mount [:rfc:`959`]
    SMNT: 'Command' = 'SMNT', FEATCode.base, 'Structure Mount', CommandType.A, ConformanceRequirement.O

    #: Status [:rfc:`959`]
    STAT: 'Command' = 'STAT', FEATCode.base, 'Status', CommandType.S, ConformanceRequirement.M

    #: Store [:rfc:`959`]
    STOR: 'Command' = 'STOR', FEATCode.base, 'Store', CommandType.S, ConformanceRequirement.M

    #: Store Unique [:rfc:`959`][:rfc:`1123`]
    STOU: 'Command' = 'STOU', FEATCode.base, 'Store Unique', CommandType.A, ConformanceRequirement.O

    #: File Structure [:rfc:`959`]
    STRU: 'Command' = 'STRU', FEATCode.base, 'File Structure', CommandType.P, ConformanceRequirement.M

    #: System [:rfc:`959`]
    SYST: 'Command' = 'SYST', FEATCode.base, 'System', CommandType.S, ConformanceRequirement.O

    #: Representation Type [4][:rfc:`959`]
    TYPE: 'Command' = 'TYPE', FEATCode.base, 'Representation Type', CommandType.P, ConformanceRequirement.M

    #: User Name [:rfc:`959`]
    USER: 'Command' = 'USER', FEATCode.base, 'User Name', CommandType.A, ConformanceRequirement.M

    #: None [:rfc:`775`][:rfc:`1123`]
    XCUP: 'Command' = 'XCUP', FEATCode.hist, None, CommandType.S, ConformanceRequirement.H

    #: None [:rfc:`775`][:rfc:`1123`]
    XCWD: 'Command' = 'XCWD', FEATCode.hist, None, CommandType.S, ConformanceRequirement.H

    #: None [:rfc:`775`][:rfc:`1123`]
    XMKD: 'Command' = 'XMKD', FEATCode.hist, None, CommandType.S, ConformanceRequirement.H

    #: None [:rfc:`775`][:rfc:`1123`]
    XPWD: 'Command' = 'XPWD', FEATCode.hist, None, CommandType.S, ConformanceRequirement.H

    #: None [:rfc:`775`][:rfc:`1123`]
    XRMD: 'Command' = 'XRMD', FEATCode.hist, None, CommandType.S, ConformanceRequirement.H

    #: Trivial Virtual File Store [:rfc:`3659`]
    TVFS: 'Command' = 'TVFS', FEATCode('TVFS'), 'Trivial Virtual File Store', CommandType.P, ConformanceRequirement.O

    @staticmethod
    def get(key: 'str', default: 'Optional[str]' = None) -> 'Command':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if key not in Command._member_map_:  # pylint: disable=no-member
            return extend_enum(Command, key.upper(), default if default is not None else key)
        return Command[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'str') -> 'Command':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        return extend_enum(cls, value.upper(), value)
