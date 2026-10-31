# -*- coding: utf-8 -*-
# pylint: disable=unused-import, unused-wildcard-import
"""Vendor Crawlers
=====================

.. module:: pcapkit.vendor

This module contains all web crawlers of :mod:`pcapkit`, which
automatically generate the :mod:`pcapkit.const` module's constant
enumerations.

The crawlers need the ``vendor`` extra, ``pip install "pypcapkit[vendor]"``.

.. versionchanged:: 1.5.0

   Without ``requests`` or ``beautifulsoup4``, which the crawlers import at
   module scope, importing this package succeeds and imports no crawler.
   Reading any name in its ``__all__``, or
   :class:`~pcapkit.vendor.default.Vendor`, then raises
   :exc:`ModuleNotFoundError` naming the missing packages and the extra to
   install, and :program:`pcapkit-vendor` exits with that message on one line
   (:issue:`1850`). Importing a crawler module directly, such as
   :mod:`pcapkit.vendor.reg`, still raises the missing package's own
   :exc:`ModuleNotFoundError`. Before, importing this package raised it.

"""
import typing

from pcapkit.utilities.compat import ModuleNotFoundError  # pylint: disable=redefined-builtin
from pcapkit.utilities.exceptions import stacklevel
from pcapkit.utilities.warnings import VendorWarning, warn

#: list[str]: Distributions of the ``vendor`` extra whose modules the crawlers
#: import at module scope, and which cannot be imported here. While it is not
#: empty no crawler is imported: :func:`__getattr__` raises for their names,
#: and :func:`pcapkit.vendor.__main__.main` exits (:issue:`1850`). :mod:`pcapkit`
#: has already put the conda package's :file:`pcapkit/_extern` on
#: :data:`sys.path` by then, so a package vendored there counts as installed.
_MISSING = []  # type: list[str]

try:
    import requests
except ModuleNotFoundError:
    _MISSING.append('requests')

try:
    import bs4
except ModuleNotFoundError:
    _MISSING.append('beautifulsoup4')

# The ``[socks]`` and ``[html5lib]`` extras of those packages are needed only at
# run time, by a crawler that goes through a SOCKS proxy or parses HTML, so
# their absence stays a warning.
try:
    import socks
except ModuleNotFoundError:
    warn("dependency package 'requests[socks]' not found",
         VendorWarning, stacklevel=stacklevel())

try:
    import html5lib
except ModuleNotFoundError:
    warn("dependency package 'beautifulsoup4[html5lib]' not found",
         VendorWarning, stacklevel=stacklevel())


def _missing_message() -> 'str':
    """Why no crawler was imported, naming the extra to install.

    Returns:
        The packages in :data:`_MISSING` and the extra that installs them, on
        one line, or an empty string if :data:`_MISSING` is empty.

    """
    if not _MISSING:
        return ''
    return (f"missing dependencies: {', '.join(_MISSING)}; "
            'install the vendor extra: pip install "pypcapkit[vendor]"')


if _MISSING:
    def __getattr__(name: 'str') -> 'typing.NoReturn':
        """Raise for a crawler, or for its base class, which were not imported.

        :pep:`562` calls this only for a name missing from this module's
        globals, so it is defined only while :data:`_MISSING` is not empty.

        Raises:
            ModuleNotFoundError: If ``name`` is in ``__all__``, or is
                ``Vendor``, naming the missing packages and the extra.
            AttributeError: For any other name, as without this hook.

        """
        if name == 'Vendor' or name in __all__:
            raise ModuleNotFoundError(f'cannot import {name!r} from {__name__!r}: {_missing_message()}')
        raise AttributeError(f'module {__name__!r} has no attribute {name!r}')
else:
    # base crawler
    from pcapkit.vendor.default import Vendor

    # IANA registration
    from pcapkit.vendor.reg import *

    # Miscellaneous
    from pcapkit.vendor.pcapng import *

    # per protocol
    from pcapkit.vendor.arp import *
    from pcapkit.vendor.esp import *
    from pcapkit.vendor.ftp import *
    from pcapkit.vendor.hip import *
    from pcapkit.vendor.http import *
    from pcapkit.vendor.igmp import *
    from pcapkit.vendor.ipv4 import *
    from pcapkit.vendor.ipv6 import *
    from pcapkit.vendor.ipx import *
    from pcapkit.vendor.l2tp import *
    from pcapkit.vendor.linux import *
    from pcapkit.vendor.mh import *
    from pcapkit.vendor.ngap import *
    from pcapkit.vendor.ospf import *
    from pcapkit.vendor.sctp import *
    from pcapkit.vendor.sslv2 import *
    from pcapkit.vendor.tcp import *
    from pcapkit.vendor.vlan import *

# Crawlers only. This list is also the default target list of
# :mod:`pcapkit.vendor.__main__`, which runs every name in it, so the base
# class ``Vendor`` and the warning machinery imported above stay out of it --
# see ``DELIBERATE_NON_EXPORTS`` in :file:`tests/project/test_public_api.py`.
__all__ = [
    # Protocol Registration
    'EtherType', 'LinkType', 'TransType', 'AppType',
    'AppType_TCP', 'AppType_UDP', 'AppType_SCTP', 'AppType_DCCP',
    # ARP
    'ARP_Hardware', 'ARP_Operation',
    # ESP
    'ESP_Cipher', 'ESP_Integrity',
    # FTP
    'FTP_Command', 'FTP_ReturnCode',
    # HIP
    'HIP_Certificate', 'HIP_Cipher', 'HIP_DITypes', 'HIP_ECDSACurve', 'HIP_ECDSALowCurve',
    'HIP_ESPTransformSuite', 'HIP_Group', 'HIP_HIAlgorithm', 'HIP_HITSuite', 'HIP_NATTraversal',
    'HIP_NotifyMessage', 'HIP_Packet', 'HIP_Parameter', 'HIP_Registration', 'HIP_RegistrationFailure',
    'HIP_Suite', 'HIP_Transport', 'HIP_EdDSACurve',
    # HTTP
    'HTTP_ErrorCode', 'HTTP_Frame', 'HTTP_Method', 'HTTP_Setting', 'HTTP_StatusCode',
    # IGMP
    'IGMP_Type',
    # IPv4
    'IPv4_ClassificationLevel', 'IPv4_OptionClass', 'IPv4_OptionNumber', 'IPv4_ProtectionAuthority',
    'IPv4_QSFunction', 'IPv4_RouterAlert', 'IPv4_ToSDelay', 'IPv4_ToSECN', 'IPv4_ToSPrecedence',
    'IPv4_ToSReliability', 'IPv4_ToSThroughput', 'IPv4_TSFlag',
    # IPv6
    'IPv6_ExtensionHeader', 'IPv6_Option', 'IPv6_QSFunction', 'IPv6_RouterAlert', 'IPv6_Routing',
    'IPv6_SeedID', 'IPv6_SMFDPDMode', 'IPv6_TaggerID', 'IPv6_OptionAction',
    # IPX
    'IPX_Packet', 'IPX_Socket',
    # L2TP
    'L2TP_Type',
    # Linux
    'Linux_ARPHRD',
    # MH
    'MH_Packet', 'MH_Option', 'MH_DNSStatusCode', 'MH_ACKStatusCode',
    'MH_MNIDSubtype', 'MH_StatusCode', 'MH_EnumeratingAlgorithm',
    'MH_AuthSubtype', 'MH_HandoffType', 'MH_AccessType',
    'MH_BindingUpdateFlag', 'MH_BindingACKFlag', 'MH_DSMIPv6HomeAddress',
    'MH_BindingRevocation', 'MH_RevocationTrigger', 'MH_RevocationStatusCode',
    'MH_HomeAddressReply', 'MH_DHCPSupportMode', 'MH_HandoverInitiateFlag',
    'MH_HandoverACKFlag', 'MH_HandoverInitiateStatus', 'MH_HandoverACKStatus',
    'MH_FlowIDStatus', 'MH_FlowIDSuboption', 'MH_TrafficSelector',
    'MH_MNGroupID', 'MH_DSMIP6TLSPacket', 'MH_ANISuboption', 'MH_OperatorID',
    'MH_UpdateNotificationReason', 'MH_UpdateNotificationACKStatus',
    'MH_FlowBindingType', 'MH_FlowBindingIndicationTrigger',
    'MH_FlowBindingACKStatus', 'MH_FlowBindingAction', 'MH_QoSAttribute',
    'MH_LMAControlledMAGSuboption', 'MH_LLACode', 'MH_CGAType',
    'MH_CGAExtension', 'MH_CGASec', 'MH_BindingError',
    # NGAP
    'NGAP_ProcedureCode', 'NGAP_ProtocolIE',
    # OSPF
    'OSPF_Authentication', 'OSPF_Packet',
    # SCTP
    'SCTP_Chunk', 'SCTP_Parameter', 'SCTP_CauseCode',
    'SCTP_PayloadProtocolIdentifier',
    # SSLv2
    'SSLv2_HandshakeType', 'SSLv2_Version',
    # TCP
    'TCP_Checksum', 'TCP_Option', 'TCP_MPTCPOption', 'TCP_Flags',
    # VLAN
    'VLAN_PriorityLevel',
    # PCAPNG
    'PCAPNG_BlockType', 'PCAPNG_OptionType', 'PCAPNG_HashAlgorithm',
    'PCAPNG_VerdictType', 'PCAPNG_RecordType', 'PCAPNG_SecretsType',
    'PCAPNG_FilterType', 'PCAPNG_TLSKeyLabel',
]
