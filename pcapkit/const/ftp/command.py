# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
# pylint: disable=line-too-long
"""FTP Command
=================

.. module:: pcapkit.const.ftp.command

This module contains the constant enumeration for **FTP Command**,
which is automatically generated from :class:`pcapkit.vendor.ftp.command.Command`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum, IntFlag, StrEnum, auto

from pcapkit.corekit.enum import EnumRegistry

if TYPE_CHECKING:
    from typing import Optional, Type

__all__ = ['Command']


class FEATCode(EnumRegistry, StrEnum):
    """Keyword returned in FEAT response line for this command/extension,
    c.f., :rfc:`5797#secion-3`.

    .. note::

       Declares every FEAT keyword the IANA registry's own ``FEAT code``
       column names -- the 5 group markers below plus the per-command
       keywords generated after them (data-driven, not hand-picked; see
       :meth:`~pcapkit.vendor.ftp.command.Command.process`) -- rather than
       minting the per-command ones at import time as an incidental side
       effect of building :class:`Command`'s own rows. GitHub issue #860:
       that import-time mutation was the same defect shape #861 removed
       from :class:`~pcapkit.const.pcapng.filter_type.FilterType`, just not
       previously noticed here. ``_missing_`` still unmints for a keyword
       that turns up on the wire but names none of these -- the
       extendability the owner asked to keep, verbatim: *"If it is expected
       to be handled as our current approach in industry convention, then
       we keep it extendable as is."* No custom ``__new__`` here, so the
       base's generic :meth:`~pcapkit.corekit.enum.EnumRegistry.
       _unregistered_member` needs no override.

    """

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

    #: Authentication/Security Mechanism [2][:rfc:`2773`][:rfc:`4217`]
    AUTH = 'AUTH'

    #: Hostname [:rfc:`7151`]
    HOST = 'HOST'

    #: Language (for Server Messages) [:rfc:`2640`]
    UTF8 = 'UTF8'

    #: File Modification Time [:rfc:`3659`]
    MDTM = 'MDTM'

    #: List Directory (for machine) [:rfc:`3659`]
    MLST = 'MLST'

    #: Protection Buffer Size [:rfc:`4217`]
    PBSZ = 'PBSZ'

    #: Data Channel Protection Level [:rfc:`4217`]
    PROT = 'PROT'

    #: Restart (for STREAM mode) [3][:rfc:`3659`]
    REST = 'REST'

    #: File Size [:rfc:`3659`]
    SIZE = 'SIZE'

    #: Trivial Virtual File Store [:rfc:`3659`]
    TVFS = 'TVFS'

    def __repr__(self) -> 'str':
        return f'<{self.__class__.__name__} [{self._name_}]>'

    @classmethod
    def _missing_(cls, value: 'str') -> 'FEATCode':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not isinstance(value, str):
            raise ValueError(f'{value!r} is not a valid {cls.__name__}')
        return cls._unregistered_member(value, value.upper())


class CommandType(IntFlag):
    """Type of "kind" of command, based on :rfc:`959#section-4.1`."""

    undefined = 0

    #: Access control.
    A = auto()
    #: Parameter setting.
    P = auto()
    #: Service execution.
    S = auto()

    @classmethod
    def _missing_(cls, value: 'int') -> 'CommandType':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 0x07):
            raise ValueError(f'{value!r} is not a valid {cls.__name__}')
        return super()._missing_(value)


class ConformanceRequirement(IntEnum):
    """Expectation for support in modern FTP implementations."""

    #: Mandatory to implement.
    M = auto()
    #: Optional.
    O = auto()
    #: Historic.
    H = auto()


class Command(EnumRegistry, StrEnum):
    """[Command] FTP Command

    .. note::

       Neither ``_missing_`` nor ``get()`` mints any more, per the owner's
       ruling on GitHub issue #860: *"only IANA registered ones are legit
       values and we need register to properly create new entries. get will
       not have sufficient information to create new ones."* Concretely
       true here -- a bare wire command word carries no
       :attr:`feat`/:attr:`desc`/:attr:`type`/:attr:`conf`, so minting one
       used to register a permanent member with all four hollowed out to
       their defaults; :meth:`register` is the path that can actually supply
       them.

    """

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
        return f'<{self.__class__.__name__}.{self._name_}: {self.desc}>'

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
    AUTH: 'Command' = 'AUTH', FEATCode.AUTH, 'Authentication/Security Mechanism', CommandType.A, ConformanceRequirement.O

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
    HOST: 'Command' = 'HOST', FEATCode.HOST, 'Hostname', CommandType.A, ConformanceRequirement.O

    #: Language (for Server Messages) [:rfc:`2640`]
    LANG: 'Command' = 'LANG', FEATCode.UTF8, 'Language (for Server Messages)', CommandType.P, ConformanceRequirement.O

    #: List [:rfc:`959`][:rfc:`1123`]
    LIST: 'Command' = 'LIST', FEATCode.base, 'List', CommandType.S, ConformanceRequirement.M

    #: Data Port [:rfc:`1545`][:rfc:`1639`]
    LPRT: 'Command' = 'LPRT', FEATCode.hist, 'Data Port', CommandType.P, ConformanceRequirement.H

    #: Passive Mode [:rfc:`1545`][:rfc:`1639`]
    LPSV: 'Command' = 'LPSV', FEATCode.hist, 'Passive Mode', CommandType.P, ConformanceRequirement.H

    #: File Modification Time [:rfc:`3659`]
    MDTM: 'Command' = 'MDTM', FEATCode.MDTM, 'File Modification Time', CommandType.S, ConformanceRequirement.O

    #: Integrity Protected Command [:rfc:`2228`][:rfc:`2773`][:rfc:`4217`]
    MIC: 'Command' = 'MIC', FEATCode.secu, 'Integrity Protected Command', CommandType.A, ConformanceRequirement.O

    #: Make Directory [:rfc:`959`]
    MKD: 'Command' = 'MKD', FEATCode.base, 'Make Directory', CommandType.S, ConformanceRequirement.O

    #: List Directory (for machine) [:rfc:`3659`]
    MLSD: 'Command' = 'MLSD', FEATCode.MLST, 'List Directory (for machine)', CommandType.S, ConformanceRequirement.O

    #: List Single Object [:rfc:`3659`]
    MLST: 'Command' = 'MLST', FEATCode.MLST, 'List Single Object', CommandType.S, ConformanceRequirement.O

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
    PBSZ: 'Command' = 'PBSZ', FEATCode.PBSZ, 'Protection Buffer Size', CommandType.P, ConformanceRequirement.O

    #: Data Port [:rfc:`959`]
    PORT: 'Command' = 'PORT', FEATCode.base, 'Data Port', CommandType.P, ConformanceRequirement.M

    #: Data Channel Protection Level [:rfc:`4217`]
    PROT: 'Command' = 'PROT', FEATCode.PROT, 'Data Channel Protection Level', CommandType.P, ConformanceRequirement.O

    #: Print Directory [:rfc:`959`]
    PWD: 'Command' = 'PWD', FEATCode.base, 'Print Directory', CommandType.S, ConformanceRequirement.O

    #: Logout [:rfc:`959`]
    QUIT: 'Command' = 'QUIT', FEATCode.base, 'Logout', CommandType.A, ConformanceRequirement.M

    #: Reinitialize [:rfc:`959`]
    REIN: 'Command' = 'REIN', FEATCode.base, 'Reinitialize', CommandType.A, ConformanceRequirement.M

    #: Restart (for STREAM mode) [3][:rfc:`3659`]
    REST: 'Command' = 'REST', FEATCode.REST, 'Restart (for STREAM mode)', CommandType.S | CommandType.P, ConformanceRequirement.M

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
    SIZE: 'Command' = 'SIZE', FEATCode.SIZE, 'File Size', CommandType.S, ConformanceRequirement.O

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
    TVFS: 'Command' = 'TVFS', FEATCode.TVFS, 'Trivial Virtual File Store', CommandType.P, ConformanceRequirement.O

    @classmethod
    def _unregistered_member(cls, value: 'str', name: 'str') -> 'Command':
        """Build a member absent from this registry's own lookup tables.

        Leaves :attr:`feat`, :attr:`desc`, :attr:`type` and :attr:`conf` at
        the same defaults :meth:`__new__` itself would, rather than missing
        entirely -- :meth:`~pcapkit.corekit.enum.EnumRegistry.
        _unregistered_member` bypasses :meth:`__new__` (it calls
        :class:`str`'s directly), so those four attributes would otherwise
        be absent and :meth:`__repr__` (which reads :attr:`desc`) would
        raise on the result. There is no more specific value to reconstruct
        them from -- a bare wire command word carries none of the four,
        which is exactly the owner's reasoning for why ``get()``/
        ``_missing_`` must not mint one: :meth:`register` is the path that
        can actually supply them.

        Args:
            value: Value to get enum item -- the convention here, shared with
                :class:`~pcapkit.const.ftp.command.FEATCode` and
                :class:`~pcapkit.const.http.method.Method`, is the caller's
                own casing, unchanged: an unregistered member's *value* is
                exactly what was observed on the wire, matching how a
                *registered* member's own value is exactly what was
                declared, never reformatted. Only :attr:`name` -- the
                identifier, not the value -- is canonicalised.
            name: Bare label for the unregistered member -- here, the
                canonical upper-case form of ``value``, matching the name
                every *registered* member of this class is looked up by,
                since #860's open-vocabulary registries have no manufactured
                placeholder label to fall back to.

        """
        obj = super()._unregistered_member(value, name)
        obj.feat = None
        obj.desc = None
        obj.type = CommandType.undefined
        obj.conf = ConformanceRequirement.O
        return obj

    @staticmethod
    def get(key: 'str', default: 'Optional[str]' = None) -> 'Command':
        """Backport support for original codes.

        Args:
            key: Key to get enum item. Looked up case-insensitively, since
                member names are canonicalised to upper case on registration.
            default: Default value if not found.

        :meta private:
        """
        name = key.upper()
        if name not in Command._member_map_:  # type: ignore[misc]  # pylint: disable=no-member
            # NOTE: the value is ``default`` if the caller supplied one, or
            # else ``key`` exactly as given -- never ``name`` -- so an
            # unregistered member's value is the caller's own casing, the
            # same convention :meth:`_unregistered_member` documents and
            # :class:`~pcapkit.const.ftp.command.FEATCode` already followed
            # unchanged. Two calls naming the same command in different
            # case, e.g. ``get('xyzw')`` and ``get('XYZW')``, therefore build
            # results that are *not* equal -- each is exactly what its own
            # caller passed, which minting's ``_member_map_`` cache used to
            # paper over by returning the *first* casing seen for every
            # later call regardless of case. Losing that is the one
            # observable behaviour change in GitHub issue #860's conversion.
            return Command._unregistered_member(default if default is not None else key, name)
        return Command[name]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'str') -> 'Command':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item. Matched case-insensitively against
                the canonical upper-case member names.

        """
        if not isinstance(value, str):
            raise ValueError(f'{value!r} is not a valid {cls.__name__}')
        name = value.upper()
        if name in cls._member_map_:
            return cls._member_map_[name]  # type: ignore[return-value]
        return cls._unregistered_member(value, name)
