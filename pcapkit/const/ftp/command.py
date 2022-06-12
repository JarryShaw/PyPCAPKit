# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""FTP Command
=================

This module contains the constant enumeration for **FTP Command**,
which is automatically generated from :class:`pcapkit.vendor.ftp.command.Command`.

"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import Info

if TYPE_CHECKING:
    from typing import Optional

__all__ = ['Command']


class CommandType(Info):
    """FTP command type."""

    #: Name of command.
    name: 'str'
    #: Feature of command.
    feat: 'Optional[str]'
    #: Description of command.
    desc: 'Optional[str]'
    #: Type of command.
    type: 'Optional[tuple[str, ...]]'
    #: Conformance of command.
    conf: 'Optional[str]'
    #: Note of command.
    note: 'Optional[tuple[str, ...]]'

    if TYPE_CHECKING:
        def __init__(self, name: 'str', feat: 'Optional[str]', desc: 'Optional[str]', type: 'Optional[tuple[str, ...]]', conf: 'Optional[str]', note: 'Optional[tuple[str, ...]]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


class defaultInfo(Info[CommandType]):
    """Extended :class:`~pcapkit.corekit.infoclass.Info` with default values.

    Args:
        *args: Arbitrary positional arguments.
        **kwargs: Arbitrary keyword arguments.

    """

    def __getitem__(self, key: 'str') -> 'CommandType':
        """Missing keys as specified in :rfc:`3659`.

        Args:
            key: Key of missing command.

        """
        try:
            return super().__getitem__(key)
        except KeyError:
            return CommandType(name=key,
                               feat='TVFS',
                               desc='Trivial Virtual File Store',
                               type=('parameter setting',),
                               conf='optional',
                               note=('RFC 3659',))


#: FTP Command
Command = defaultInfo(
    # ABOR [:rfc:`959`]
    ABOR=CommandType(
        name='ABOR',
        feat='base',
        desc='Abort',
        type=('service execution',),
        conf='mandatory to implement',
        note=('RFC 959',),
    ),
    # ACCT [:rfc:`959`]
    ACCT=CommandType(
        name='ACCT',
        feat='base',
        desc='Account',
        type=('access control',),
        conf='mandatory to implement',
        note=('RFC 959',),
    ),
    # ADAT [:rfc:`2228`][:rfc:`2773`][:rfc:`4217`]
    ADAT=CommandType(
        name='ADAT',
        feat='secu',
        desc='Authentication/Security Data',
        type=('access control',),
        conf='optional',
        note=('RFC 2228', 'RFC 2773', 'RFC 4217'),
    ),
    # ALGS [:rfc:`6384`][Section 11]
    ALGS=CommandType(
        name='ALGS',
        feat=None,
        desc='FTP64 ALG status',
        type=None,
        conf='optional',
        note=('RFC 6384',),
    ),
    # ALLO [:rfc:`959`]
    ALLO=CommandType(
        name='ALLO',
        feat='base',
        desc='Allocate',
        type=('service execution',),
        conf='mandatory to implement',
        note=('RFC 959',),
    ),
    # APPE [:rfc:`959`]
    APPE=CommandType(
        name='APPE',
        feat='base',
        desc='Append (with create)',
        type=('service execution',),
        conf='mandatory to implement',
        note=('RFC 959',),
    ),
    # AUTH [2][:rfc:`2773`][:rfc:`4217`]
    AUTH=CommandType(
        name='AUTH',
        feat='AUTH',
        desc='Authentication/Security Mechanism',
        type=('access control',),
        conf='optional',
        note=('RFC 2773', 'RFC 4217'),
    ),
    # CCC [:rfc:`2228`]
    CCC=CommandType(
        name='CCC',
        feat='secu',
        desc='Clear Command Channel',
        type=('access control',),
        conf='optional',
        note=('RFC 2228',),
    ),
    # CDUP [:rfc:`959`]
    CDUP=CommandType(
        name='CDUP',
        feat='base',
        desc='Change to Parent Directory',
        type=('access control',),
        conf='optional',
        note=('RFC 959',),
    ),
    # CONF [:rfc:`2228`]
    CONF=CommandType(
        name='CONF',
        feat='secu',
        desc='Confidentiality Protected Command',
        type=('access control',),
        conf='optional',
        note=('RFC 2228',),
    ),
    # CWD [:rfc:`959`]
    CWD=CommandType(
        name='CWD',
        feat='base',
        desc='Change Working Directory',
        type=('access control',),
        conf='mandatory to implement',
        note=('RFC 959',),
    ),
    # DELE [:rfc:`959`]
    DELE=CommandType(
        name='DELE',
        feat='base',
        desc='Delete File',
        type=('service execution',),
        conf='mandatory to implement',
        note=('RFC 959',),
    ),
    # ENC [:rfc:`2228`][:rfc:`2773`][:rfc:`4217`]
    ENC=CommandType(
        name='ENC',
        feat='secu',
        desc='Privacy Protected Command',
        type=('access control',),
        conf='optional',
        note=('RFC 2228', 'RFC 2773', 'RFC 4217'),
    ),
    # EPRT [:rfc:`2428`]
    EPRT=CommandType(
        name='EPRT',
        feat='nat6',
        desc='Extended Port',
        type=('parameter setting',),
        conf='optional',
        note=('RFC 2428',),
    ),
    # EPSV [:rfc:`2428`]
    EPSV=CommandType(
        name='EPSV',
        feat='nat6',
        desc='Extended Passive Mode',
        type=('parameter setting',),
        conf='optional',
        note=('RFC 2428',),
    ),
    # FEAT [:rfc:`2389`]
    FEAT=CommandType(
        name='FEAT',
        feat='feat',
        desc='Feature Negotiation',
        type=('access control',),
        conf='mandatory to implement',
        note=('RFC 2389',),
    ),
    # HELP [:rfc:`959`]
    HELP=CommandType(
        name='HELP',
        feat='base',
        desc='Help',
        type=('service execution',),
        conf='mandatory to implement',
        note=('RFC 959',),
    ),
    # HOST [:rfc:`7151`]
    HOST=CommandType(
        name='HOST',
        feat='HOST',
        desc='Hostname',
        type=('access control',),
        conf='optional',
        note=('RFC 7151',),
    ),
    # LANG [:rfc:`2640`]
    LANG=CommandType(
        name='LANG',
        feat='UTF8',
        desc='Language (for Server Messages)',
        type=('parameter setting',),
        conf='optional',
        note=('RFC 2640',),
    ),
    # LIST [:rfc:`959`][:rfc:`1123`]
    LIST=CommandType(
        name='LIST',
        feat='base',
        desc='List',
        type=('service execution',),
        conf='mandatory to implement',
        note=('RFC 959', 'RFC 1123'),
    ),
    # LPRT [:rfc:`1545`][:rfc:`1639`]
    LPRT=CommandType(
        name='LPRT',
        feat='hist',
        desc='Data Port',
        type=('parameter setting',),
        conf='historic',
        note=('RFC 1545', 'RFC 1639'),
    ),
    # LPSV [:rfc:`1545`][:rfc:`1639`]
    LPSV=CommandType(
        name='LPSV',
        feat='hist',
        desc='Passive Mode',
        type=('parameter setting',),
        conf='historic',
        note=('RFC 1545', 'RFC 1639'),
    ),
    # MDTM [:rfc:`3659`]
    MDTM=CommandType(
        name='MDTM',
        feat='MDTM',
        desc='File Modification Time',
        type=('service execution',),
        conf='optional',
        note=('RFC 3659',),
    ),
    # MIC [:rfc:`2228`][:rfc:`2773`][:rfc:`4217`]
    MIC=CommandType(
        name='MIC',
        feat='secu',
        desc='Integrity Protected Command',
        type=('access control',),
        conf='optional',
        note=('RFC 2228', 'RFC 2773', 'RFC 4217'),
    ),
    # MKD [:rfc:`959`]
    MKD=CommandType(
        name='MKD',
        feat='base',
        desc='Make Directory',
        type=('service execution',),
        conf='optional',
        note=('RFC 959',),
    ),
    # MLSD [:rfc:`3659`]
    MLSD=CommandType(
        name='MLSD',
        feat='MLST',
        desc='List Directory (for machine)',
        type=('service execution',),
        conf='optional',
        note=('RFC 3659',),
    ),
    # MLST [:rfc:`3659`]
    MLST=CommandType(
        name='MLST',
        feat='MLST',
        desc='List Single Object',
        type=('service execution',),
        conf='optional',
        note=('RFC 3659',),
    ),
    # MODE [:rfc:`959`]
    MODE=CommandType(
        name='MODE',
        feat='base',
        desc='Transfer Mode',
        type=('parameter setting',),
        conf='mandatory to implement',
        note=('RFC 959',),
    ),
    # NLST [:rfc:`959`][:rfc:`1123`]
    NLST=CommandType(
        name='NLST',
        feat='base',
        desc='Name List',
        type=('service execution',),
        conf='mandatory to implement',
        note=('RFC 959', 'RFC 1123'),
    ),
    # NOOP [:rfc:`959`]
    NOOP=CommandType(
        name='NOOP',
        feat='base',
        desc='No-Op',
        type=('service execution',),
        conf='mandatory to implement',
        note=('RFC 959',),
    ),
    # OPTS [:rfc:`2389`]
    OPTS=CommandType(
        name='OPTS',
        feat='feat',
        desc='Options',
        type=('parameter setting',),
        conf='mandatory to implement',
        note=('RFC 2389',),
    ),
    # PASS [:rfc:`959`]
    PASS=CommandType(
        name='PASS',
        feat='base',
        desc='Password',
        type=('access control',),
        conf='mandatory to implement',
        note=('RFC 959',),
    ),
    # PASV [:rfc:`959`][:rfc:`1123`]
    PASV=CommandType(
        name='PASV',
        feat='base',
        desc='Passive Mode',
        type=('parameter setting',),
        conf='mandatory to implement',
        note=('RFC 959', 'RFC 1123'),
    ),
    # PBSZ [:rfc:`4217`]
    PBSZ=CommandType(
        name='PBSZ',
        feat='PBSZ',
        desc='Protection Buffer Size',
        type=('parameter setting',),
        conf='optional',
        note=('RFC 4217',),
    ),
    # PORT [:rfc:`959`]
    PORT=CommandType(
        name='PORT',
        feat='base',
        desc='Data Port',
        type=('parameter setting',),
        conf='mandatory to implement',
        note=('RFC 959',),
    ),
    # PROT [:rfc:`4217`]
    PROT=CommandType(
        name='PROT',
        feat='PROT',
        desc='Data Channel Protection Level',
        type=('parameter setting',),
        conf='optional',
        note=('RFC 4217',),
    ),
    # PWD [:rfc:`959`]
    PWD=CommandType(
        name='PWD',
        feat='base',
        desc='Print Directory',
        type=('service execution',),
        conf='optional',
        note=('RFC 959',),
    ),
    # QUIT [:rfc:`959`]
    QUIT=CommandType(
        name='QUIT',
        feat='base',
        desc='Logout',
        type=('access control',),
        conf='mandatory to implement',
        note=('RFC 959',),
    ),
    # REIN [:rfc:`959`]
    REIN=CommandType(
        name='REIN',
        feat='base',
        desc='Reinitialize',
        type=('access control',),
        conf='mandatory to implement',
        note=('RFC 959',),
    ),
    # REST [3][:rfc:`3659`]
    REST=CommandType(
        name='REST',
        feat='REST',
        desc='Restart (for STREAM mode)',
        type=('service execution', 'parameter setting'),
        conf='mandatory to implement',
        note=('RFC 3659',),
    ),
    # RETR [:rfc:`959`]
    RETR=CommandType(
        name='RETR',
        feat='base',
        desc='Retrieve',
        type=('service execution',),
        conf='mandatory to implement',
        note=('RFC 959',),
    ),
    # RMD [:rfc:`959`]
    RMD=CommandType(
        name='RMD',
        feat='base',
        desc='Remove Directory',
        type=('service execution',),
        conf='optional',
        note=('RFC 959',),
    ),
    # RNFR [:rfc:`959`]
    RNFR=CommandType(
        name='RNFR',
        feat='base',
        desc='Rename From',
        type=('service execution', 'parameter setting'),
        conf='mandatory to implement',
        note=('RFC 959',),
    ),
    # RNTO [:rfc:`959`]
    RNTO=CommandType(
        name='RNTO',
        feat='base',
        desc='Rename From',
        type=('service execution',),
        conf='mandatory to implement',
        note=('RFC 959',),
    ),
    # SITE [:rfc:`959`][:rfc:`1123`]
    SITE=CommandType(
        name='SITE',
        feat='base',
        desc='Site Parameters',
        type=('service execution',),
        conf='mandatory to implement',
        note=('RFC 959', 'RFC 1123'),
    ),
    # SIZE [:rfc:`3659`]
    SIZE=CommandType(
        name='SIZE',
        feat='SIZE',
        desc='File Size',
        type=('service execution',),
        conf='optional',
        note=('RFC 3659',),
    ),
    # SMNT [:rfc:`959`]
    SMNT=CommandType(
        name='SMNT',
        feat='base',
        desc='Structure Mount',
        type=('access control',),
        conf='optional',
        note=('RFC 959',),
    ),
    # STAT [:rfc:`959`]
    STAT=CommandType(
        name='STAT',
        feat='base',
        desc='Status',
        type=('service execution',),
        conf='mandatory to implement',
        note=('RFC 959',),
    ),
    # STOR [:rfc:`959`]
    STOR=CommandType(
        name='STOR',
        feat='base',
        desc='Store',
        type=('service execution',),
        conf='mandatory to implement',
        note=('RFC 959',),
    ),
    # STOU [:rfc:`959`][:rfc:`1123`]
    STOU=CommandType(
        name='STOU',
        feat='base',
        desc='Store Unique',
        type=('access control',),
        conf='optional',
        note=('RFC 959', 'RFC 1123'),
    ),
    # STRU [:rfc:`959`]
    STRU=CommandType(
        name='STRU',
        feat='base',
        desc='File Structure',
        type=('parameter setting',),
        conf='mandatory to implement',
        note=('RFC 959',),
    ),
    # SYST [:rfc:`959`]
    SYST=CommandType(
        name='SYST',
        feat='base',
        desc='System',
        type=('service execution',),
        conf='optional',
        note=('RFC 959',),
    ),
    # TYPE [4][:rfc:`959`]
    TYPE=CommandType(
        name='TYPE',
        feat='base',
        desc='Representation Type',
        type=('parameter setting',),
        conf='mandatory to implement',
        note=('RFC 959',),
    ),
    # USER [:rfc:`959`]
    USER=CommandType(
        name='USER',
        feat='base',
        desc='User Name',
        type=('access control',),
        conf='mandatory to implement',
        note=('RFC 959',),
    ),
    # XCUP [:rfc:`775`][:rfc:`1123`]
    XCUP=CommandType(
        name='XCUP',
        feat='hist',
        desc=None,
        type=('service execution',),
        conf='historic',
        note=('RFC 775', 'RFC 1123'),
    ),
    # XCWD [:rfc:`775`][:rfc:`1123`]
    XCWD=CommandType(
        name='XCWD',
        feat='hist',
        desc=None,
        type=('service execution',),
        conf='historic',
        note=('RFC 775', 'RFC 1123'),
    ),
    # XMKD [:rfc:`775`][:rfc:`1123`]
    XMKD=CommandType(
        name='XMKD',
        feat='hist',
        desc=None,
        type=('service execution',),
        conf='historic',
        note=('RFC 775', 'RFC 1123'),
    ),
    # XPWD [:rfc:`775`][:rfc:`1123`]
    XPWD=CommandType(
        name='XPWD',
        feat='hist',
        desc=None,
        type=('service execution',),
        conf='historic',
        note=('RFC 775', 'RFC 1123'),
    ),
    # XRMD [:rfc:`775`][:rfc:`1123`]
    XRMD=CommandType(
        name='XRMD',
        feat='hist',
        desc=None,
        type=('service execution',),
        conf='historic',
        note=('RFC 775', 'RFC 1123'),
    ),
)
