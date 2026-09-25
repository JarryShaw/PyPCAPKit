# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Application Layer Protocol Numbers
========================================

.. module:: pcapkit.const.reg.apptype.apptype

This module contains the constant enumeration for **Application Layer Protocol Numbers**,
which is automatically generated from :class:`pcapkit.vendor.reg.apptype.apptype.AppType`.

"""
from typing import TYPE_CHECKING

from aenum import IntFlag, StrEnum, auto, extend_enum

from pcapkit.utilities.compat import show_flag_values

__all__ = ['TransportProtocol', 'AppType']

if TYPE_CHECKING:
    from typing import Any, Optional, Type

    from pcapkit.corekit.multidict import MultiDict


class TransportProtocol(IntFlag):
    """Transport layer protocol."""

    undefined = 0

    #: Transmission Control Protocol.
    tcp = auto()
    #: User Datagram Protocol.
    udp = auto()
    #: Stream Control Transmission Protocol.
    sctp = auto()
    #: Datagram Congestion Control Protocol.
    dccp = auto()

    @staticmethod
    def get(key: 'int | str') -> 'TransportProtocol':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.

        :meta private:
        """
        if isinstance(key, int):
            return TransportProtocol(key)
        if key.lower() in TransportProtocol.__members__:
            return TransportProtocol[key.lower()]  # type: ignore[misc]
        max_val = max(TransportProtocol.__members__.values())
        return extend_enum(TransportProtocol, key.lower(), max_val * 2)

    @classmethod
    def _missing_(cls, value: 'int') -> 'TransportProtocol':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        Raises:
            ValueError: If ``value`` sets a bit no member declares.

        Note:
            This is what makes an unrecognised transport protocol *rejected*
            rather than accepted -- GitHub issue #647's fix for this registry.
            :mod:`aenum` on its own is permissive here and composes whatever bits
            it is handed: measured on aenum 3.1.17 with this method removed,
            ``TransportProtocol(-1)`` returns ``tcp|udp|sctp|dccp``, which is
            #647's recorded defect for this class verbatim, and
            ``TransportProtocol(16)`` returns a member whose ``name`` is
            :obj:`None`. Declared bits still compose, since a service assigned to
            several transport protocols is the ordinary case rather than the
            exception.

        """
        if not (isinstance(value, int) and 0 <= value <= max(cls.__members__.values()) * 2 - 1):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return super()._missing_(value)


class AppType(StrEnum):
    """[AppType] Application Layer Protocol Numbers

    This is the transport-agnostic base of the per-transport registries in
    :mod:`pcapkit.const.reg.apptype`, and it declares **no members of its own**.
    IANA keys every assignment on a ``(service, port, transport)`` triple, so a
    service belongs to the registry of the transport protocol that carries it --
    :class:`~pcapkit.const.reg.apptype.tcp.TCP`,
    :class:`~pcapkit.const.reg.apptype.udp.UDP`,
    :class:`~pcapkit.const.reg.apptype.sctp.SCTP` or
    :class:`~pcapkit.const.reg.apptype.dccp.DCCP`. Being memberless is also what
    makes it subclassable at all, since :mod:`aenum` refuses to extend an
    enumeration that already has members.

    Note:
        The rows below are the registry entries whose **transport protocol column
        is empty**. A blank transport is not an assignment to anything, so there
        is no registry they could be members of and they are documented here
        instead. Most are historic service or IP-protocol names with no port
        either; the rest are IANA's own reserved, unassigned and withdrawn
        markers.

    .. list-table:: Service names assigned no transport protocol
       :header-rows: 1
       :widths: 25 10 65

       * - Service Name
         - Port
         - Description
       * - ``reserved``
         - 51
         - [N/A] Reserved
       * - ``unassigned``
         - 81
         - [N/A] Unassigned
       * - ``unassigned``
         - 100
         - [N/A] Unassigned
       * - ``unassigned``
         - 114
         - [N/A] unassigned
       * - ``unassigned``
         - 258
         - [N/A] Unassigned
       * - ``unassigned``
         - 285
         - [N/A] Unassigned
       * - ``unassigned``
         - 703
         - [N/A] Unassigned
       * - ``unassigned``
         - 708
         - [N/A] Unassigned
       * - ``unassigned``
         - 743
         - [N/A] Unassigned
       * - ``unassigned``
         - 766
         - [N/A] Unassigned
       * - ``unassigned``
         - 768
         - [N/A] Unassigned
       * - ``unassigned``
         - 786
         - [N/A] Unassigned
       * - ``unassigned``
         - 787
         - [N/A] Unassigned
       * - ``unassigned``
         - 1009
         - [N/A] Unassigned
       * - ``deprecated``
         - 1028
         - [N/A] Deprecated
       * - ``reserved``
         - 1030
         - [N/A] Reserved
       * - ``reserved``
         - 1031
         - [N/A] Reserved
       * - ``reserved``
         - 1032
         - [N/A] Reserved
       * - ``reserved_iana``
         - 1109
         - [N/A] Reserved - IANA
       * - ``unassigned``
         - 1491
         - [N/A] Unassigned
       * - ``decomissioned_port_04_14_00_ms``
         - 1783
         - [N/A] Decomissioned Port 04/14/00, ms
       * - ``removed``
         - 659
         - [N/A] Removed
       * - ``removed``
         - 2682
         - [N/A] Removed
       * - ``possibly_assigned``
         - 2825
         - [N/A] (unassigned) Possibly assigned
       * - ``de_registered``
         - 585
         - [N/A] De-registered
       * - ``unassigned``
         - 2925
         - [N/A] Unassigned (FRP-Released 12/7/00)
       * - ``unassigned``
         - 3092
         - [N/A] Unassigned
       * - ``unassigned``
         - 3126
         - [N/A] Unassigned
       * - ``removed``
         - 3404
         - [N/A] Removed
       * - ``unassigned``
         - 3546
         - [N/A] Unassigned
       * - ``unassigned``
         - 3694
         - [N/A] Unassigned
       * - ``unassigned``
         - 3994
         - [N/A] Unassigned
       * - ``unassigned``
         - 4048
         - [N/A] Unassigned
       * - ``unassigned``
         - 4144
         - [N/A] Unassigned
       * - ``unassigned``
         - 4196
         - [N/A] Unassigned
       * - ``unassigned``
         - 4198
         - [N/A] Unassigned
       * - ``unassigned``
         - 4315
         - [N/A] Unassigned
       * - ``unassigned``
         - 4318
         - [N/A] Unassigned
       * - ``reserved``
         - 4324
         - [N/A] Reserved
       * - ``unassigned``
         - 4367
         - [N/A] Unassigned
       * - ``unassigned``
         - 4424
         - [N/A] Unassigned
       * - ``unassigned``
         - 4459
         - [N/A] Unassigned
       * - ``unassigned``
         - 4501
         - [N/A] Unassigned
       * - ``unassigned``
         - 4983
         - [N/A] Unassigned
       * - ``unassigned``
         - 5113
         - [N/A] Unassigned
       * - ``unassigned``
         - 5244
         - [N/A] Unassigned
       * - ``unassigned``
         - 5311
         - [N/A] Unassigned
       * - ``unassigned``
         - 5444
         - [N/A] Unassigned
       * - ``unassigned``
         - 5749
         - [N/A] Unassigned
       * - ``unassigned``
         - 5756
         - [N/A] Unassigned
       * - ``unassigned``
         - 6067
         - [N/A] Unassigned
       * - ``unassigned``
         - 6319
         - [N/A] Unassigned
       * - ``unassigned``
         - 6323
         - [N/A] Unassigned
       * - ``boe-cms``
         - 6400
         - [N/A] Business Objects CMS contact port
       * - ``boe-was``
         - 6401
         - [N/A] boe-was
       * - ``boe-eventsrv``
         - 6402
         - [N/A] boe-eventsrv
       * - ``boe-cachesvr``
         - 6403
         - [N/A] boe-cachesvr
       * - ``boe-filesvr``
         - 6404
         - [N/A] Business Objects Enterprise internal server
       * - ``boe-pagesvr``
         - 6405
         - [N/A] Business Objects Enterprise internal server
       * - ``boe-processsvr``
         - 6406
         - [N/A] Business Objects Enterprise internal server
       * - ``boe-resssvr1``
         - 6407
         - [N/A] Business Objects Enterprise internal server
       * - ``boe-resssvr2``
         - 6408
         - [N/A] Business Objects Enterprise internal server
       * - ``boe-resssvr3``
         - 6409
         - [N/A] Business Objects Enterprise internal server
       * - ``boe-resssvr4``
         - 6410
         - [N/A] Business Objects Enterprise internal server
       * - ``unassigned``
         - 6441
         - [N/A] Unassigned
       * - ``unassigned``
         - 6504
         - [N/A] Unassigned
       * - ``unassigned``
         - 6557
         - [N/A] Unassigned
       * - ``reserved``
         - 6567
         - [N/A] Reserved
       * - ``unassigned``
         - 6588
         - [N/A] Unassigned
       * - ``unassigned``
         - 6630
         - [N/A] Unassigned
       * - ``unassigned``
         - 6631
         - [N/A] Unassigned
       * - ``unassigned``
         - 6654
         - [N/A] Unassigned
       * - ``unassigned``
         - 6698
         - [N/A] Unassigned
       * - ``unassigned``
         - 6700
         - [N/A] Unassigned
       * - ``unassigned``
         - 7122
         - [N/A] Unassigned
       * - ``unassigned``
         - 7396
         - [N/A] Unassigned
       * - ``unassigned``
         - 7472
         - [N/A] Unassigned
       * - ``unassigned``
         - 7625
         - [N/A] Unassigned
       * - ``de_registered``
         - 3403
         - [N/A] De-registered
       * - ``unassigned``
         - 7632
         - [N/A] Unassigned
       * - ``unassigned``
         - 7688
         - [N/A] Unassigned
       * - ``unassigned``
         - 7776
         - [N/A] Unassigned
       * - ``unassigned``
         - 7780
         - [N/A] Unassigned
       * - ``unassigned``
         - 7785
         - [N/A] Unassigned
       * - ``unassigned``
         - 7788
         - [N/A] Unassigned
       * - ``unassigned``
         - 7879
         - [N/A] Unassigned
       * - ``reserved``
         - 8010
         - [N/A] Reserved
       * - ``unassigned``
         - 8018
         - [N/A] Unassigned
       * - ``unassigned``
         - 8024
         - [N/A] Unassigned
       * - ``unassigned``
         - 8085
         - [N/A] Unassigned
       * - ``unassigned``
         - 8089
         - [N/A] Unassigned
       * - ``unassigned``
         - 8193
         - [N/A] Unassigned
       * - ``unassigned``
         - 8281
         - [N/A] Unassigned
       * - ``unassigned``
         - 8449
         - [N/A] Unassigned
       * - ``unassigned``
         - 8667
         - [N/A] Unassigned
       * - ``unassigned``
         - 8687
         - [N/A] Unassigned
       * - ``unassigned``
         - 8806
         - [N/A] Unassigned
       * - ``unassigned``
         - 8882
         - [N/A] Unassigned
       * - ``unassigned``
         - 8909
         - [N/A] Unassigned
       * - ``de_commissioned_port``
         - 9006
         - [N/A] De-Commissioned Port
       * - ``unassigned``
         - 9311
         - [N/A] Unassigned
       * - ``unassigned``
         - 9613
         - [N/A] Unassigned
       * - ``unassigned``
         - 9615
         - [N/A] Unassigned
       * - ``unassigned``
         - 9910
         - [N/A] Unassigned
       * - ``unassigned``
         - 9980
         - [N/A] Unassigned
       * - ``unassigned``
         - 10112
         - [N/A] Unassigned
       * - ``unassigned``
         - 11107
         - [N/A] Unassigned
       * - ``unassigned``
         - 12011
         - [N/A] Unassigned
       * - ``unassigned``
         - 12301
         - [N/A] Unassigned
       * - ``unassigned``
         - 13723
         - [N/A] Unassigned
       * - ``unassigned``
         - 13784
         - [N/A] Unassigned
       * - ``unassigned``
         - 14144
         - [N/A] Unassigned
       * - ``unassigned``
         - 15001
         - [N/A] Unassigned
       * - ``unassigned``
         - 18259
         - [N/A] Unassigned
       * - ``unassigned``
         - 19789
         - [N/A] Unassigned
       * - ``unassigned``
         - 20004
         - [N/A] Unassigned
       * - ``unassigned``
         - 22334
         - [N/A] Unassigned
       * - ``unassigned``
         - 24679
         - [N/A] Unassigned
       * - ``unassigned``
         - 24727
         - [N/A] Unassigned
       * - ``de_registered``
         - 26264
         - [N/A] De-registered
       * - ``unassigned``
         - 26488
         - [N/A] Unassigned
       * - ``unassigned``
         - 33332
         - [N/A] Unassigned
       * - ``unassigned``
         - 47807
         - [N/A] Unassigned
       * - ``reserved``
         - 49151
         - [N/A] Reserved [:rfc:`6335`]
       * - ``argus``
         - N/A
         - [N/A] ARGUS Protocol
       * - ``arp``
         - N/A
         - [N/A] Address Resolution Protocol
       * - ``bbn-rcc-mon``
         - N/A
         - [N/A] BBN RCC Monitoring
       * - ``bootp``
         - N/A
         - [N/A] Bootstrap Protocol
       * - ``br-sat-mon``
         - N/A
         - [N/A] Backroom SATNET Monitoring
       * - ``cftp``
         - N/A
         - [N/A] CFTP
       * - ``chaos``
         - N/A
         - [N/A] CHAOS Protocol
       * - ``clock``
         - N/A
         - [N/A] DCNET Time Server Protocol
       * - ``cmot``
         - N/A
         - [N/A] Common Mgmnt Info Ser and Prot over TCP/IP
       * - ``cookie-jar``
         - N/A
         - [N/A] Authentication Scheme
       * - ``dcn-meas``
         - N/A
         - [N/A] DCN Measurement Subsystems Protocol
       * - ``dgp``
         - N/A
         - [N/A] Dissimilar Gateway Protocol
       * - ``dmf-mail``
         - N/A
         - [N/A] Digest Message Format for Mail
       * - ``egp``
         - N/A
         - [N/A] Exterior Gateway Protocol
       * - ``ehf-mail``
         - N/A
         - [N/A] Encoding Header Field for Mail
       * - ``emcon``
         - N/A
         - [N/A] Emission Control Protocol
       * - ``fconfig``
         - N/A
         - [N/A] Fujitsu Config Protocol
       * - ``ggp``
         - N/A
         - [N/A] Gateway Gateway Protocol
       * - ``hmp``
         - N/A
         - [N/A] Host Monitoring Protocol
       * - ``host2-ns``
         - N/A
         - [N/A] Host2 Name Server
       * - ``icmp``
         - N/A
         - [N/A] Internet Control Message Protocol
       * - ``igmp``
         - N/A
         - [N/A] Internet Group Management Protocol
       * - ``igp``
         - N/A
         - [N/A] Interior Gateway Protocol
       * - ``imap2``
         - N/A
         - [N/A] Interim Mail Access Protocol version 2
       * - ``ip``
         - N/A
         - [N/A] Internet Protocol
       * - ``ipcu``
         - N/A
         - [N/A] Internet Packet Core Utility
       * - ``ippc``
         - N/A
         - [N/A] Internet Pluribus Packet Core
       * - ``ip-arc``
         - N/A
         - [N/A] Internet Protocol on ARCNET
       * - ``ip-arpa``
         - N/A
         - [N/A] Internet Protocol on ARPANET
       * - ``ip-cmprs``
         - N/A
         - [N/A] Compressing TCP/IP Headers
       * - ``ip-dc``
         - N/A
         - [N/A] Internet Protocol on DC Networks
       * - ``ip-dvmrp``
         - N/A
         - [N/A] Distance Vector Multicast Routing Protocol
       * - ``ip-e``
         - N/A
         - [N/A] Internet Protocol on Ethernet Networks
       * - ``ip-ee``
         - N/A
         - [N/A] Internet Protocol on Exp. Ethernet Nets
       * - ``ip-fddi``
         - N/A
         - [N/A] Transmission of IP over FDDI
       * - ``ip-hc``
         - N/A
         - [N/A] Internet Protocol on Hyperchannnel
       * - ``ip-ieee``
         - N/A
         - [N/A] Internet Protocol on IEEE 802
       * - ``ip-ipx``
         - N/A
         - [N/A] Transmission of 802.2 over IPX Networks
       * - ``ip-mtu``
         - N/A
         - [N/A] IP MTU Discovery Options
       * - ``ip-netbios``
         - N/A
         - [N/A] Internet Protocol over NetBIOS Networks
       * - ``ip-slip``
         - N/A
         - [N/A] Transmission of IP over Serial Lines
       * - ``ip-wb``
         - N/A
         - [N/A] Internet Protocol on Wideband Network
       * - ``ip-x25``
         - N/A
         - [N/A] Internet Protocol on X.25 Networks
       * - ``irtp``
         - N/A
         - [N/A] Internet Reliable Transaction Protocol
       * - ``iso-tp4``
         - N/A
         - [N/A] ISO Transport Protocol Class 4
       * - ``larp``
         - N/A
         - [N/A] Locus Address Resoultion Protocol
       * - ``leaf-1``
         - N/A
         - [N/A] Leaf-1 Protocol
       * - ``leaf-2``
         - N/A
         - [N/A] Leaf-2 Protocol
       * - ``loc-srv``
         - N/A
         - [N/A] Location Service
       * - ``mail``
         - N/A
         - [N/A] Format of Electronic Mail Messages
       * - ``merit-inp``
         - N/A
         - [N/A] MERIT Internodal Protocol
       * - ``mib``
         - N/A
         - [N/A] Management Information Base
       * - ``mihcs``
         - N/A
         - [N/A] MIH Command Services [:rfc:`5679`]
       * - ``mihes``
         - N/A
         - [N/A] MIH Event Services [:rfc:`5679`]
       * - ``mihis``
         - N/A
         - [N/A] MIH Information Services [:rfc:`5679`]
       * - ``mfe-nsp``
         - N/A
         - [N/A] MFE Network Services Protocol
       * - ``mit-subnet``
         - N/A
         - [N/A] MIT Subnet Support
       * - ``mux``
         - N/A
         - [N/A] Multiplexing Protocol
       * - ``netblt``
         - N/A
         - [N/A] Bulk Data Transfer Protocol
       * - ``neted``
         - N/A
         - [N/A] Network Standard Text Editor
       * - ``netrjs``
         - N/A
         - [N/A] Remote Job Service
       * - ``netconf-beep``
         - N/A
         - [N/A] NETCONF over BEEP [:rfc:`4744`][:rfc:`9900`]
       * - ``netconfsoapbeep``
         - N/A
         - [N/A] NETCONF for SOAP over BEEP [:rfc:`4743`][:rfc:`9900`]
       * - ``netconfsoaphttp``
         - N/A
         - [N/A] NETCONF for SOAP over HTTPS [:rfc:`4743`][:rfc:`9900`]
       * - ``nfile``
         - N/A
         - [N/A] A File Access Protocol
       * - ``nvp-ii``
         - N/A
         - [N/A] Network Voice Protocol
       * - ``ospf``
         - N/A
         - [N/A] Open Shortest Path First Interior GW Protocol
       * - ``pcmail``
         - N/A
         - [N/A] Pcmail Transport Protocol
       * - ``ppp``
         - N/A
         - [N/A] Point-to-Point Protocol
       * - ``prm``
         - N/A
         - [N/A] Packet Radio Measurement
       * - ``pup``
         - N/A
         - [N/A] PUP Protocol
       * - ``quote``
         - N/A
         - [N/A] Quote of the Day Protocol
       * - ``rarp``
         - N/A
         - [N/A] A Reverse Address Resolution Protocol
       * - ``ratp``
         - N/A
         - [N/A] Reliable Asynchronous Transfer Protocol
       * - ``rdp``
         - N/A
         - [N/A] Reliable Data Protocol; [N/A] Windows Remote Desktop Protocol
       * - ``rip``
         - N/A
         - [N/A] Routing Information Protocol
       * - ``rvd``
         - N/A
         - [N/A] Remote Virtual Disk Protocol
       * - ``sat-expak``
         - N/A
         - [N/A] Satnet and Backroom EXPAK
       * - ``sat-mon``
         - N/A
         - [N/A] SATNET Monitoring
       * - ``smi``
         - N/A
         - [N/A] Structure of Management Information
       * - ``stp``
         - N/A
         - [N/A] Stream Protocol
       * - ``sun-rpc``
         - N/A
         - [N/A] SUN Remote Procedure Call
       * - ``tcp``
         - N/A
         - [N/A] Transmission Control Protocol
       * - ``tcp-aco``
         - N/A
         - [N/A] TCP Alternate Checksum Option
       * - ``thinwire``
         - N/A
         - [N/A] Thinwire Protocol
       * - ``tp-tcp``
         - N/A
         - [N/A] ISO Transport Service on top of the TCP
       * - ``trunk-1``
         - N/A
         - [N/A] Trunk-1 Protocol
       * - ``trunk-2``
         - N/A
         - [N/A] Trunk-2 Protocol
       * - ``ucl``
         - N/A
         - [N/A] University College London Protocol
       * - ``udp``
         - N/A
         - [N/A] User Datagram Protocol
       * - ``users``
         - N/A
         - [N/A] Active Users Protocol
       * - ``via-ftp``
         - N/A
         - [N/A] VIA Systems-File Transfer Protocol
       * - ``visa``
         - N/A
         - [N/A] VISA Protocol
       * - ``vmtp``
         - N/A
         - [N/A] Versatile Message Transaction Protocol
       * - ``wb-expak``
         - N/A
         - [N/A] Wideband EXPAK
       * - ``wb-mon``
         - N/A
         - [N/A] Wideband Monitoring
       * - ``xnet``
         - N/A
         - [N/A] Cross Net Debugger
       * - ``xns-idp``
         - N/A
         - [N/A] Xerox NS IDP
       * - ``1password``
         - N/A
         - [N/A] 1Password Password Manager data sharing and synchronization
           protocol
       * - ``a-d-sync``
         - N/A
         - [N/A] Altos Design Synchronization protocol
       * - ``abi-instrument``
         - N/A
         - [N/A] Applied Biosystems Universal Instrument Framework
       * - ``accessdata-f2d``
         - N/A
         - [N/A] FTK2 Database Discovery Service
       * - ``accessdata-f2w``
         - N/A
         - [N/A] FTK2 Backend Processing Agent Service
       * - ``accessone``
         - N/A
         - [N/A] Strix Systems 5S/AccessOne protocol
       * - ``accountedge``
         - N/A
         - [N/A] MYOB AccountEdge
       * - ``acrobatsrv``
         - N/A
         - [N/A] Adobe Acrobat
       * - ``actionitems``
         - N/A
         - [N/A] ActionItems
       * - ``activeraid``
         - N/A
         - [N/A] Active Storage Proprietary Device Management Protocol
       * - ``activeraid-ssl``
         - N/A
         - [N/A] Encrypted transport of Active Storage Proprietary Device
           Management Protocol
       * - ``addressbook``
         - N/A
         - [N/A] Address-O-Matic
       * - ``adnodes``
         - N/A
         - [N/A] difusi Cloud based plug & play network synchronization
           protocol, content pool database discovery, and cloudOS SAaS
           discovery protocol.
       * - ``adobe-vc``
         - N/A
         - [N/A] Adobe Version Cue
       * - ``adisk``
         - N/A
         - [N/A] Automatic Disk Discovery
       * - ``adpro-setup``
         - N/A
         - [N/A] ADPRO Security Device Setup
       * - ``aecoretech``
         - N/A
         - [N/A] Apple Application Engineering Services
       * - ``aeroflex``
         - N/A
         - [N/A] Aeroflex instrumentation and software
       * - ``airport``
         - N/A
         - [N/A] AirPort Base Station
       * - ``airprojector``
         - N/A
         - [N/A] AirProjector
       * - ``airsharing``
         - N/A
         - [N/A] Air Sharing
       * - ``airsharingpro``
         - N/A
         - [N/A] Air Sharing Pro
       * - ``amiphd-p2p``
         - N/A
         - [N/A] P2PTapWar Sample Application from "iPhone SDK Development"
           Book
       * - ``ams-htm``
         - N/A
         - [N/A] Proprietary protocol for Accu-Med HTM
       * - ``animolmd``
         - N/A
         - [N/A] Animo License Manager
       * - ``animobserver``
         - N/A
         - [N/A] Animo Batch Server
       * - ``anquetsync``
         - N/A
         - [N/A] Anquet map synchronization between desktop and handheld
           devices
       * - ``appelezvous``
         - N/A
         - [N/A] Appelezvous
       * - ``apple-ausend``
         - N/A
         - [N/A] Apple Audio Units
       * - ``applerdbg``
         - N/A
         - [N/A] Apple Remote Debug Services (OpenGL Profiler)
       * - ``appletv``
         - N/A
         - [N/A] Apple TV
       * - ``appletv-itunes``
         - N/A
         - [N/A] Apple TV discovery of iTunes
       * - ``appletv-pair``
         - N/A
         - [N/A] Apple TV Pairing
       * - ``aquamon``
         - N/A
         - [N/A] AquaMon
       * - ``aroundsound``
         - N/A
         - [N/A] AroundSound's information sharing protocol
       * - ``astralite``
         - N/A
         - [N/A] Astralite
       * - ``async``
         - N/A
         - [N/A] address-o-sync
       * - ``atlassianapp``
         - N/A
         - [N/A] Atlassian Application (JIRA, Confluence, Fisheye, Crucible,
           Crowd, Bamboo) discovery service
       * - ``av``
         - N/A
         - [N/A] Allen Vanguard Hardware Service
       * - ``axis-video``
         - N/A
         - [N/A] Axis Video Cameras
       * - ``b3d-convince``
         - N/A
         - [N/A] 3M Unitek Digital Orthodontic System
       * - ``babyphone``
         - N/A
         - [N/A] BabyPhone
       * - ``bdsk``
         - N/A
         - [N/A] BibDesk Sharing
       * - ``beacon``
         - N/A
         - [N/A] Beacon Remote Service
       * - ``beamer``
         - N/A
         - [N/A] Beamer Data Sharing Protocol
       * - ``beatpack``
         - N/A
         - [N/A] BeatPack Synchronization Server for BeatMaker
       * - ``beep``
         - N/A
         - [N/A] Xgrid Technology Preview
       * - ``bender``
         - N/A
         - [N/A] Bender Communication Protocol
       * - ``bfagent``
         - N/A
         - [N/A] BuildForge Agent
       * - ``bigbangchess``
         - N/A
         - [N/A] Big Bang Chess
       * - ``bigbangmancala``
         - N/A
         - [N/A] Big Bang Mancala
       * - ``bittorrent``
         - N/A
         - [N/A] BitTorrent Zeroconf Peer Discovery Protocol
       * - ``blackbook``
         - N/A
         - [N/A] Little Black Book Information Exchange Protocol
       * - ``bookworm``
         - N/A
         - [N/A] Bookworm Client Discovery
       * - ``bousg``
         - N/A
         - [N/A] Bag Of Unusual Strategy Games
       * - ``bri``
         - N/A
         - [N/A] RFID Reader Basic Reader Interface
       * - ``bsqdea``
         - N/A
         - [N/A] Backup Simplicity
       * - ``caltalk``
         - N/A
         - [N/A] CalTalk
       * - ``cardsend``
         - N/A
         - [N/A] Card Send Protocol
       * - ``cctv``
         - N/A
         - [N/A] IP and Closed-Circuit Television for Securitiy applications
       * - ``cheat``
         - N/A
         - [N/A] The Cheat
       * - ``chess``
         - N/A
         - [N/A] Project Gridlock
       * - ``chfts``
         - N/A
         - [N/A] Fluid Theme Server
       * - ``chili``
         - N/A
         - [N/A] The CHILI Radiology System
       * - ``cip4discovery``
         - N/A
         - [N/A] Discovery of JDF (CIP4 Job Definition Format) enabled devices
       * - ``clipboard``
         - N/A
         - [N/A] Clipboard Sharing
       * - ``clscts``
         - N/A
         - [N/A] Oracle CLS Cluster Topology Service
       * - ``collection``
         - N/A
         - [N/A] Published Collection Object
       * - ``com-ocs-es-mcc``
         - N/A
         - [N/A] ElectraStar media centre control protocol
       * - ``contactserver``
         - N/A
         - [N/A] Now Contact
       * - ``corroboree``
         - N/A
         - [N/A] Corroboree Server
       * - ``cpnotebook2``
         - N/A
         - [N/A] NoteBook 2
       * - ``cw-codetap``
         - N/A
         - [N/A] CodeWarrior HTI Xscale PowerTAP
       * - ``cw-dpitap``
         - N/A
         - [N/A] CodeWarrior HTI DPI PowerTAP
       * - ``cw-oncetap``
         - N/A
         - [N/A] CodeWarrior HTI OnCE PowerTAP
       * - ``cw-powertap``
         - N/A
         - [N/A] CodeWarrior HTI COP PowerTAP
       * - ``cytv``
         - N/A
         - [N/A] CyTV - Network streaming for Elgato EyeTV
       * - ``dacp``
         - N/A
         - [N/A] Digital Audio Control Protocol (iTunes)
       * - ``dancepartner``
         - N/A
         - [N/A] Dance partner application for iPhone
       * - ``dataturbine``
         - N/A
         - [N/A] Open Source DataTurbine Streaming Data Middleware
       * - ``device-info``
         - N/A
         - [N/A] Device Info
       * - ``dictation``
         - N/A
         - [N/A] Use of a dictation service by a hand-held device
       * - ``difi``
         - N/A
         - [N/A] EyeHome
       * - ``disconnect``
         - N/A
         - [N/A] DisConnect Peer to Peer Game Protocol
       * - ``dist-opencl``
         - N/A
         - [N/A] Distributed OpenCL discovery protocol
       * - ``ditrios``
         - N/A
         - [N/A] Ditrios SOA Framework Protocol
       * - ``divelogsync``
         - N/A
         - [N/A] Dive Log Data Sharing and Synchronization Protocol
       * - ``dns-sd``
         - N/A
         - [N/A] DNS Service Discovery
       * - ``dop``
         - N/A
         - [N/A] Roar (Death of Productivity)
       * - ``dropcopy``
         - N/A
         - [N/A] DropCopy
       * - ``dsgsync``
         - N/A
         - [N/A] Datacolor SpyderGallery Desktop Sync Protocol
       * - ``dsl-sync``
         - N/A
         - [N/A] Data Synchronization Protocol for Discovery Software products
       * - ``dtrmtdesktop``
         - N/A
         - [N/A] Desktop Transporter Remote Desktop Protocol
       * - ``dxtgsync``
         - N/A
         - [N/A] Documents To Go Desktop Sync Protocol
       * - ``ea-dttx-poker``
         - N/A
         - [N/A] Protocol for EA Downtown Texas Hold 'em
       * - ``earphoria``
         - N/A
         - [N/A] Earphoria
       * - ``eb-amuzi``
         - N/A
         - [N/A] Amuzi peer-to-peer session synchronization protocol
       * - ``ebms``
         - N/A
         - [N/A] ebXML Messaging
       * - ``ecms``
         - N/A
         - [N/A] Northrup Grumman/Mission Systems/ESL Data Flow Protocol
       * - ``ebreg``
         - N/A
         - [N/A] ebXML Registry
       * - ``ecbyesfsgksc``
         - N/A
         - [N/A] Net Monitor Anti-Piracy Service
       * - ``egistix``
         - N/A
         - [N/A] Egistix Auto-Discovery
       * - ``eheap``
         - N/A
         - [N/A] Interactive Room Software Infrastructure (Event Sharing)
       * - ``embrace``
         - N/A
         - [N/A] DataEnvoy
       * - ``ep``
         - N/A
         - [N/A] Endpoint Protocol (EP) for use in Home Automation systems
       * - ``eucalyptus``
         - N/A
         - [N/A] Eucalyptus Discovery
       * - ``eventserver``
         - N/A
         - [N/A] Now Up-to-Date
       * - ``evs-notif``
         - N/A
         - [N/A] EVS Notification Center Protocol
       * - ``ewalletsync``
         - N/A
         - [N/A] Synchronization Protocol for Ilium Software's eWallet
       * - ``example``
         - N/A
         - [N/A] Example Service Type
       * - ``exb``
         - N/A
         - [N/A] Exbiblio Cascading Service Protocol
       * - ``extensissn``
         - N/A
         - [N/A] Extensis Serial Number
       * - ``eyetvsn``
         - N/A
         - [N/A] EyeTV Sharing
       * - ``facespan``
         - N/A
         - [N/A] FaceSpan
       * - ``faxstfx``
         - N/A
         - [N/A] FAXstf
       * - ``feed-sharing``
         - N/A
         - [N/A] NetNewsWire 2.0
       * - ``firetask``
         - N/A
         - [N/A] Firetask task sharing and synchronization protocol
       * - ``fish``
         - N/A
         - [N/A] Fish
       * - ``fix``
         - N/A
         - [N/A] Financial Information Exchange (FIX) Protocol
       * - ``fjork``
         - N/A
         - [N/A] Fjork
       * - ``fmserver-admin``
         - N/A
         - [N/A] FileMaker Server Administration Communication Service
       * - ``fontagentnode``
         - N/A
         - [N/A] FontAgent Pro
       * - ``foxtrot-serv``
         - N/A
         - [N/A] FoxTrot Search Server Discovery Service
       * - ``foxtrot-start``
         - N/A
         - [N/A] FoxTrot Professional Search Discovery Service
       * - ``frameforge-lic``
         - N/A
         - [N/A] FrameForge License
       * - ``freehand``
         - N/A
         - [N/A] FreeHand MusicPad Pro Interface Protocol
       * - ``frog``
         - N/A
         - [N/A] Frog Navigation Systems
       * - ``ftpcroco``
         - N/A
         - [N/A] Crocodile FTP Server
       * - ``garagepad``
         - N/A
         - [N/A] Entrackment Client Service
       * - ``gforce-ssmp``
         - N/A
         - [N/A] G-Force Control via SoundSpectrum's SSMP TCP Protocol
       * - ``glasspad``
         - N/A
         - [N/A] GlassPad Data Exchange Protocol
       * - ``glasspadserver``
         - N/A
         - [N/A] GlassPadServer Data Exchange Protocol
       * - ``glrdrvmon``
         - N/A
         - [N/A] OpenGL Driver Monitor
       * - ``gpnp``
         - N/A
         - [N/A] Grid Plug and Play
       * - ``grillezvous``
         - N/A
         - [N/A] Roxio ToastAnywhere(tm) Recorder Sharing
       * - ``growl``
         - N/A
         - [N/A] Growl
       * - ``guid``
         - N/A
         - [N/A] Special service type for resolving by GUID (Globally Unique
           Identifier)
       * - ``h323``
         - N/A
         - [N/A] H.323 Real-time audio, video and data communication call setup
           protocol
       * - ``help``
         - N/A
         - [N/A] HELP command [:rfc:`1078`]
       * - ``hg``
         - N/A
         - [N/A] Mercurial web-based repository access
       * - ``hinz``
         - N/A
         - [N/A] HINZMobil Synchronization protocol
       * - ``hmcp``
         - N/A
         - [N/A] Home Media Control Protocol
       * - ``home-sharing``
         - N/A
         - [N/A] iTunes Home Sharing
       * - ``homeauto``
         - N/A
         - [N/A] iDo Technology Home Automation Protocol
       * - ``hotwayd``
         - N/A
         - [N/A] Hotwayd
       * - ``howdy``
         - N/A
         - [N/A] Howdy messaging and notification protocol
       * - ``hpr-bldlnx``
         - N/A
         - [N/A] HP Remote Build System for Linux-based Systems
       * - ``hpr-bldwin``
         - N/A
         - [N/A] HP Remote Build System for Microsoft Windows Systems
       * - ``hpr-db``
         - N/A
         - [N/A] Identifies systems that house databases for the Remote Build
           System and Remote Test System
       * - ``hpr-rep``
         - N/A
         - [N/A] HP Remote Repository for Build and Test Results
       * - ``hpr-toollnx``
         - N/A
         - [N/A] HP Remote System that houses compilers and tools for Linux-
           based Systems
       * - ``hpr-toolwin``
         - N/A
         - [N/A] HP Remote System that houses compilers and tools for Microsoft
           Windows Systems
       * - ``hpr-tstlnx``
         - N/A
         - [N/A] HP Remote Test System for Linux-based Systems
       * - ``hpr-tstwin``
         - N/A
         - [N/A] HP Remote Test System for Microsoft Windows Systems
       * - ``hs-off``
         - N/A
         - [N/A] Hobbyist Software Off Discovery
       * - ``htsp``
         - N/A
         - [N/A] Home Tv Streaming Protocol
       * - ``hyperstream``
         - N/A
         - [N/A] Atempo HyperStream deduplication server
       * - ``iad1``
         - N/A
         - [N/A] BBN IAD
       * - ``iad2``
         - N/A
         - [N/A] BBN IAD
       * - ``iad3``
         - N/A
         - [N/A] BBN IAD
       * - ``ibiz``
         - N/A
         - [N/A] iBiz Server
       * - ``ica-networking``
         - N/A
         - [N/A] Image Capture Networking
       * - ``ican``
         - N/A
         - [N/A] Northrup Grumman/TASC/ICAN Protocol
       * - ``ichalkboard``
         - N/A
         - [N/A] iChalk
       * - ``ichat``
         - N/A
         - [N/A] iChat 1.0
       * - ``ici``
         - N/A
         - [N/A] ICI
       * - ``iconquer``
         - N/A
         - [N/A] iConquer
       * - ``idata``
         - N/A
         - [N/A] Generic Data Acquisition and Control Protocol
       * - ``idcws``
         - N/A
         - [N/A] Intermec Device Configuration Web Services
       * - ``idsync``
         - N/A
         - [N/A] SplashID Synchronization Service
       * - ``iffl``
         - N/A
         - [N/A] iFFL Bonjour service for communication between client and
           server applications.
       * - ``ifolder``
         - N/A
         - [N/A] Published iFolder
       * - ``ihouse``
         - N/A
         - [N/A] Idle Hands iHouse Protocol
       * - ``ii-drills``
         - N/A
         - [N/A] Instant Interactive Drills
       * - ``ii-konane``
         - N/A
         - [N/A] Instant Interactive Konane
       * - ``ilynx``
         - N/A
         - [N/A] iLynX
       * - ``imidi``
         - N/A
         - [N/A] iMidi
       * - ``indigo-dvr``
         - N/A
         - [N/A] Indigo Security Digital Video Recorders
       * - ``inova-ontrack``
         - N/A
         - [N/A] Inova Solutions OnTrack Display Protocol
       * - ``ipbroadcaster``
         - N/A
         - [N/A] IP Broadcaster
       * - ``ipspeaker``
         - N/A
         - [N/A] IP Speaker Control Protocol
       * - ``irelay``
         - N/A
         - [N/A] iRelay application discovery service
       * - ``irmc``
         - N/A
         - [N/A] Intego Remote Management Console
       * - ``isparx``
         - N/A
         - [N/A] iSparx
       * - ``ispq-vc``
         - N/A
         - [N/A] iSpQ VideoChat
       * - ``ishare``
         - N/A
         - [N/A] iShare
       * - ``isticky``
         - N/A
         - [N/A] iSticky
       * - ``istorm``
         - N/A
         - [N/A] iStorm
       * - ``itis-device``
         - N/A
         - [N/A] IT-IS International Ltd. Device
       * - ``itsrc``
         - N/A
         - [N/A] iTunes Socket Remote Control
       * - ``ivef``
         - N/A
         - [N/A] Inter VTS Exchange Format
       * - ``iwork``
         - N/A
         - [N/A] iWork Server
       * - ``jcan``
         - N/A
         - [N/A] Northrup Grumman/TASC/JCAN Protocol
       * - ``jeditx``
         - N/A
         - [N/A] Jedit X
       * - ``jini``
         - N/A
         - [N/A] Jini Service Discovery
       * - ``jtag``
         - N/A
         - [N/A] Proprietary
       * - ``ktp``
         - N/A
         - [N/A] Kabira Transaction Platform
       * - ``la-maint``
         - N/A
         - [N/A] IMP Logical Address Maintenance
       * - ``lan2p``
         - N/A
         - [N/A] Lan2P Peer-to-Peer Network Protocol
       * - ``lapse``
         - N/A
         - [N/A] Gawker
       * - ``leaf``
         - N/A
         - [N/A] Lua Embedded Application Framework
       * - ``lexicon``
         - N/A
         - [N/A] Lexicon Vocabulary Sharing
       * - ``liaison``
         - N/A
         - [N/A] Liaison
       * - ``library``
         - N/A
         - [N/A] Delicious Library 2 Collection Data Sharing Protocol
       * - ``libratone``
         - N/A
         - [N/A] Protocol for setup and control of Libratone products
       * - ``licor``
         - N/A
         - [N/A] LI-COR Biosciences instrument discovery
       * - ``llrp-secure``
         - N/A
         - [N/A] RFID reader Low Level Reader Protocol over SSL/TLS
       * - ``lobby``
         - N/A
         - [N/A] Gobby
       * - ``lonbridge``
         - N/A
         - [N/A] Echelon LonBridge Server
       * - ``lontalk``
         - N/A
         - [N/A] LonTalk over IP (ANSI 852)
       * - ``lonworks``
         - N/A
         - [N/A] Echelon LNS Remote Client
       * - ``lsys-appserver``
         - N/A
         - [N/A] Linksys One Application Server API
       * - ``lsys-camera``
         - N/A
         - [N/A] Linksys One Camera API
       * - ``lsys-ezcfg``
         - N/A
         - [N/A] LinkSys EZ Configuration
       * - ``lsys-oamp``
         - N/A
         - [N/A] LinkSys Operations, Administration, Management, and
           Provisioning
       * - ``lux-dtp``
         - N/A
         - [N/A] Lux Solis Data Transport Protocol
       * - ``lxi``
         - N/A
         - [N/A] LXI
       * - ``lyrics``
         - N/A
         - [N/A] iPod Lyrics Service
       * - ``macfoh``
         - N/A
         - [N/A] MacFOH
       * - ``macfoh-admin``
         - N/A
         - [N/A] MacFOH admin services
       * - ``macfoh-db``
         - N/A
         - [N/A] MacFOH database
       * - ``macfoh-remote``
         - N/A
         - [N/A] MacFOH Remote
       * - ``macminder``
         - N/A
         - [N/A] Mac Minder
       * - ``maestro``
         - N/A
         - [N/A] Maestro Music Sharing Service
       * - ``magicdice``
         - N/A
         - [N/A] Magic Dice Game Protocol
       * - ``mandos``
         - N/A
         - [N/A] Mandos Password Server
       * - ``matrix``
         - N/A
         - [N/A] MATRIX Remote AV Switching
       * - ``mbconsumer``
         - N/A
         - [N/A] MediaBroker++ Consumer
       * - ``mbproducer``
         - N/A
         - [N/A] MediaBroker++ Producer
       * - ``mbserver``
         - N/A
         - [N/A] MediaBroker++ Server
       * - ``mconnect``
         - N/A
         - [N/A] ClairMail Connect
       * - ``mcrcp``
         - N/A
         - [N/A] MediaCentral
       * - ``mediaboard1``
         - N/A
         - [N/A] MediaBoardONE Asset and Information Manager data sharing and
           synchronization protocol
       * - ``mesamis``
         - N/A
         - [N/A] Mes Amis
       * - ``mi-raysat``
         - N/A
         - [N/A] Mental Ray for Maya
       * - ``modolansrv``
         - N/A
         - [N/A] modo LAN Services
       * - ``moneysync``
         - N/A
         - [N/A] SplashMoney Synchronization Service
       * - ``moneyworks``
         - N/A
         - [N/A] MoneyWorks Gold and MoneyWorks Datacentre network service
       * - ``moodring``
         - N/A
         - [N/A] Bonjour Mood Ring tutorial program
       * - ``mother``
         - N/A
         - [N/A] Mother script server protocol
       * - ``movieslate``
         - N/A
         - [N/A] MovieSlate digital clapperboard
       * - ``mp3sushi``
         - N/A
         - [N/A] MP3 Sushi
       * - ``mqtt``
         - N/A
         - [N/A] IBM MQ Telemetry Transport Broker
       * - ``mslingshot``
         - N/A
         - [N/A] Martian SlingShot
       * - ``mumble``
         - N/A
         - [N/A] Mumble VoIP communication protocol
       * - ``musicmachine``
         - N/A
         - [N/A] Protocol for a distributed music playing service
       * - ``mysync``
         - N/A
         - [N/A] MySync Protocol
       * - ``mttp``
         - N/A
         - [N/A] MenuTunes Sharing
       * - ``mxim-art2``
         - N/A
         - [N/A] Maxim Integrated Products Automated Roadtest Mk II
       * - ``mxim-ice``
         - N/A
         - [N/A] Maxim Integrated Products In-circuit Emulator
       * - ``mxs``
         - N/A
         - [N/A] MatrixStore
       * - ``ncbroadcast``
         - N/A
         - [N/A] Network Clipboard Broadcasts
       * - ``ncdirect``
         - N/A
         - [N/A] Network Clipboard Direct Transfers
       * - ``ncsyncserver``
         - N/A
         - [N/A] Network Clipboard Sync Server
       * - ``netrestore``
         - N/A
         - [N/A] NetRestore
       * - ``ntlx-arch``
         - N/A
         - [N/A] American Dynamics Intellex Archive Management Service
       * - ``ntlx-ent``
         - N/A
         - [N/A] American Dynamics Intellex Enterprise Management Service
       * - ``ntlx-video``
         - N/A
         - [N/A] American Dynamics Intellex Video Service
       * - ``obf``
         - N/A
         - [N/A] Observations Framework
       * - ``objective``
         - N/A
         - [N/A] Means for clients to locate servers in an Objective
           (http://www.objective.com) instance.
       * - ``oce``
         - N/A
         - [N/A] Oce Common Exchange Protocol
       * - ``od-master``
         - N/A
         - [N/A] OpenDirectory Master
       * - ``odabsharing``
         - N/A
         - [N/A] OD4Contact
       * - ``odisk``
         - N/A
         - [N/A] Optical Disk Sharing
       * - ``officetime-sync``
         - N/A
         - [N/A] OfficeTime Synchronization Protocol
       * - ``ofocus-conf``
         - N/A
         - [N/A] OmniFocus setting configuration
       * - ``ofocus-sync``
         - N/A
         - [N/A] OmniFocus document synchronization
       * - ``oma-bcast-sg``
         - N/A
         - [N/A] OMA BCAST Service Guide Discovery Service
       * - ``omni-bookmark``
         - N/A
         - [N/A] OmniWeb
       * - ``omni-live``
         - N/A
         - [N/A] Service for remote control of Omnisphere virtual instrument
       * - ``openbase``
         - N/A
         - [N/A] OpenBase SQL
       * - ``oprofile``
         - N/A
         - [N/A] oprofile server protocol
       * - ``ovready``
         - N/A
         - [N/A] ObjectVideo OV Ready Protocol
       * - ``owhttpd``
         - N/A
         - [N/A] OWFS (1-wire file system) web server
       * - ``parentcontrol``
         - N/A
         - [N/A] Remote Parental Controls
       * - ``passwordwallet``
         - N/A
         - [N/A] PasswordWallet Data Synchronization Protocol
       * - ``pcast``
         - N/A
         - [N/A] Mac OS X Podcast Producer Server
       * - ``pgpkey-hkp``
         - N/A
         - [N/A] Horowitz Key Protocol (HKP)
       * - ``pgpkey-http``
         - N/A
         - [N/A] PGP Keyserver using HTTP/1.1
       * - ``pgpkey-https``
         - N/A
         - [N/A] PGP Keyserver using HTTPS
       * - ``pgpkey-ldap``
         - N/A
         - [N/A] PGP Keyserver using LDAP
       * - ``pgpkey-mailto``
         - N/A
         - [N/A] PGP Key submission using SMTP
       * - ``photoparata``
         - N/A
         - [N/A] Photo Parata Event Photography Software
       * - ``pictua``
         - N/A
         - [N/A] Pictua Intercommunication Protocol
       * - ``piesync``
         - N/A
         - [N/A] pieSync Computer to Computer Synchronization
       * - ``piu``
         - N/A
         - [N/A] Pedestal Interface Unit by RPM-PSI
       * - ``pkixrep``
         - N/A
         - [N/A] Public Key Infrastructure Repository Locator Service
           [:rfc:`4386`]
       * - ``poch``
         - N/A
         - [N/A] Parallel OperatiOn and Control Heuristic (Pooch)
       * - ``pokeeye``
         - N/A
         - [N/A] Communication channel for "Poke Eye" Elgato EyeTV remote
           controller
       * - ``powereasy-erp``
         - N/A
         - [N/A] PowerEasy ERP
       * - ``powereasy-pos``
         - N/A
         - [N/A] PowerEasy Point of Sale
       * - ``pplayer-ctrl``
         - N/A
         - [N/A] Piano Player Remote Control
       * - ``presence``
         - N/A
         - [N/A] Peer-to-peer messaging / Link-Local Messaging
       * - ``print-caps``
         - N/A
         - [N/A] Retrieve a description of a device's print capabilities
       * - ``profilemac``
         - N/A
         - [N/A] Profile for Mac medical practice management software
       * - ``prolog``
         - N/A
         - [N/A] Prolog
       * - ``protonet``
         - N/A
         - [N/A] Protonet node and service discovery protocol
       * - ``psia``
         - N/A
         - [N/A] Physical Security Interoperability Alliance Protocol
       * - ``ptnetprosrv2``
         - N/A
         - [N/A] PTNetPro Service
       * - ``ptp-req``
         - N/A
         - [N/A] PTP Initiation Request Protocol
       * - ``puzzle``
         - N/A
         - [N/A] Protocol used for puzzle games
       * - ``qbox``
         - N/A
         - [N/A] QBox Appliance Locator
       * - ``qttp``
         - N/A
         - [N/A] QuickTime Transfer Protocol
       * - ``quinn``
         - N/A
         - [N/A] Quinn Game Server
       * - ``rakket``
         - N/A
         - [N/A] Rakket Client Protocol
       * - ``radicle-node``
         - N/A
         - [N/A] Radicle peer to peer network
       * - ``radiotag``
         - N/A
         - [N/A] RadioTAG: Event tagging for radio services
       * - ``radiovis``
         - N/A
         - [N/A] RadioVIS: Visualisation for radio services
       * - ``radioepg``
         - N/A
         - [N/A] RadioEPG: Electronic Programme Guide for radio services
       * - ``raop``
         - N/A
         - [N/A] Remote Audio Output Protocol (AirTunes)
       * - ``rbr``
         - N/A
         - [N/A] RBR Instrument Communication
       * - ``rce``
         - N/A
         - [N/A] PowerCard
       * - ``realplayfavs``
         - N/A
         - [N/A] RealPlayer Shared Favorites
       * - ``remote``
         - N/A
         - [N/A] Remote Device Control Protocol
       * - ``remoteburn``
         - N/A
         - [N/A] LaCie Remote Burn
       * - ``renderpipe``
         - N/A
         - [N/A] ARTvps RenderDrive/PURE Renderer Protocol
       * - ``rendezvouspong``
         - N/A
         - [N/A] RendezvousPong
       * - ``renkara-sync``
         - N/A
         - [N/A] Renkara synchronization protocol
       * - ``resol-vbus``
         - N/A
         - [N/A] RESOL VBus
       * - ``retrospect``
         - N/A
         - [N/A] Retrospect backup and restore service
       * - ``rfbc``
         - N/A
         - [N/A] Remote Frame Buffer Client (Used by VNC viewers in listen-
           mode)
       * - ``rfid``
         - N/A
         - [N/A] RFID Reader Mach1(tm) Protocol
       * - ``riousbprint``
         - N/A
         - [N/A] Remote I/O USB Printer Protocol
       * - ``roku-rcp``
         - N/A
         - [N/A] Roku Control Protocol
       * - ``rql``
         - N/A
         - [N/A] RemoteQuickLaunch
       * - ``rr-disc``
         - N/A
         - [N/A] Robot Raconteur discovery
       * - ``rsmp-server``
         - N/A
         - [N/A] Remote System Management Protocol (Server Instance)
       * - ``rubygems``
         - N/A
         - [N/A] RubyGems GemServer
       * - ``safarimenu``
         - N/A
         - [N/A] Safari Menu
       * - ``sallingbridge``
         - N/A
         - [N/A] Salling Clicker Sharing
       * - ``sallingclicker``
         - N/A
         - [N/A] Salling Clicker Service
       * - ``salutafugijms``
         - N/A
         - [N/A] Salutafugi Peer-To-Peer Java Message Service Implementation
       * - ``sandvox``
         - N/A
         - [N/A] Sandvox
       * - ``sc-golf``
         - N/A
         - [N/A] StrawberryCat Golf Protocol
       * - ``scanner``
         - N/A
         - [N/A] Bonjour Scanning
       * - ``schick``
         - N/A
         - [N/A] Schick
       * - ``scone``
         - N/A
         - [N/A] Scone
       * - ``scpi-raw``
         - N/A
         - [N/A] IEEE 488.2 (SCPI) Socket
       * - ``scpi-telnet``
         - N/A
         - [N/A] IEEE 488.2 (SCPI) Telnet
       * - ``sdsharing``
         - N/A
         - [N/A] Speed Download
       * - ``see``
         - N/A
         - [N/A] SubEthaEdit 2
       * - ``seecard``
         - N/A
         - [N/A] seeCard
       * - ``senteo-http``
         - N/A
         - [N/A] Senteo Assessment Software Protocol
       * - ``sentillion-vlc``
         - N/A
         - [N/A] Sentillion Vault System
       * - ``sentillion-vlt``
         - N/A
         - [N/A] Sentillion Vault Systems Cluster
       * - ``sepvsync``
         - N/A
         - [N/A] SEPV Application Data Synchronization Protocol
       * - ``serendipd``
         - N/A
         - [N/A] serendiPd Shared Patches for Pure Data
       * - ``servereye``
         - N/A
         - [N/A] ServerEye AgentContainer Communication Protocol
       * - ``servermgr``
         - N/A
         - [N/A] Mac OS X Server Admin
       * - ``services``
         - N/A
         - [N/A] DNS Service Discovery
       * - ``sessionfs``
         - N/A
         - [N/A] Session File Sharing
       * - ``sftp-ssh``
         - N/A
         - [N/A] Secure File Transfer Protocol over SSH
       * - ``sge-exec``
         - N/A
         - [N/A] Sun Grid Engine (Execution Host)
       * - ``sge-qmaster``
         - N/A
         - [N/A] Sun Grid Engine (Master)
       * - ``shifter``
         - N/A
         - [N/A] Window Shifter server protocol
       * - ``shipsgm``
         - N/A
         - [N/A] Swift Office Ships
       * - ``shipsinvit``
         - N/A
         - [N/A] Swift Office Ships
       * - ``shoppersync``
         - N/A
         - [N/A] SplashShopper Synchronization Service
       * - ``shoutcast``
         - N/A
         - [N/A] Nicecast
       * - ``simmon``
         - N/A
         - [N/A] Medical simulation patient monitor syncronisation protocol
       * - ``simusoftpong``
         - N/A
         - [N/A] simusoftpong iPhone game protocol
       * - ``sipuri``
         - N/A
         - [N/A] Session Initiation Protocol Uniform Resource Identifier
       * - ``sironaxray``
         - N/A
         - [N/A] Sirona Xray Protocol
       * - ``skype``
         - N/A
         - [N/A] Skype
       * - ``slimcli``
         - N/A
         - [N/A] SliMP3 Server Command-Line Interface
       * - ``slimhttp``
         - N/A
         - [N/A] SliMP3 Server Web Interface
       * - ``smartenergy``
         - N/A
         - [N/A] Smart Energy Profile
       * - ``smb``
         - N/A
         - [N/A] Server Message Block over TCP/IP
       * - ``sms``
         - N/A
         - [N/A] Short Text Message Sending and Delivery Status Service
       * - ``smsync``
         - N/A
         - [N/A] Syncellence file synchronization protocol
       * - ``soap``
         - N/A
         - [N/A] Simple Object Access Protocol
       * - ``socketcloud``
         - N/A
         - [N/A] Socketcloud distributed application framework
       * - ``souschef``
         - N/A
         - [N/A] SousChef Recipe Sharing Protocol
       * - ``sox``
         - N/A
         - [N/A] Simple Object eXchange
       * - ``sparechange``
         - N/A
         - [N/A] SpareChange data sharing protocol
       * - ``sparql``
         - N/A
         - [N/A] SPARQL Protocol and RDF Query Language
       * - ``spearcat``
         - N/A
         - [N/A] sPearCat Host Discovery
       * - ``spincrisis``
         - N/A
         - [N/A] Spin Crisis
       * - ``spl-itunes``
         - N/A
         - [N/A] launchTunes
       * - ``spr-itunes``
         - N/A
         - [N/A] netTunes
       * - ``splashsync``
         - N/A
         - [N/A] SplashData Synchronization Service
       * - ``ssscreenshare``
         - N/A
         - [N/A] Screen Sharing
       * - ``strateges``
         - N/A
         - [N/A] Strateges
       * - ``stanza``
         - N/A
         - [N/A] Lexcycle Stanza service for discovering shared books
       * - ``stickynotes``
         - N/A
         - [N/A] Sticky Notes
       * - ``supple``
         - N/A
         - [N/A] Supple Service protocol
       * - ``surveillus``
         - N/A
         - [N/A] Surveillus Networks Discovery Protocol
       * - ``svn``
         - N/A
         - [N/A] Subversion
       * - ``swcards``
         - N/A
         - [N/A] Signwave Card Sharing Protocol
       * - ``switcher``
         - N/A
         - [N/A] Wireless home control remote control protocol
       * - ``swordfish``
         - N/A
         - [N/A] Swordfish Protocol for Input/Output
       * - ``swyp``
         - N/A
         - [N/A] Framework for transferring any file from any app, to any app
           on any device: simply with a swÿp.
       * - ``sxqdea``
         - N/A
         - [N/A] Synchronize! Pro X
       * - ``sybase-tds``
         - N/A
         - [N/A] Sybase Server
       * - ``syncopation``
         - N/A
         - [N/A] Syncopation Synchronization Protocol by Sonzea
       * - ``syncqdea``
         - N/A
         - [N/A] Synchronize! X Plus 2.0
       * - ``synergy``
         - N/A
         - [N/A] Synergy Peer Discovery
       * - ``synksharing``
         - N/A
         - [N/A] SynkSharing synchronization protocol
       * - ``taccounting``
         - N/A
         - [N/A] Data Transmission and Synchronization
       * - ``tango``
         - N/A
         - [N/A] Tango Remote Control Protocol
       * - ``tapinoma-ecs``
         - N/A
         - [N/A] Tapinoma Easycontact receiver
       * - ``taskcoachsync``
         - N/A
         - [N/A] Task Coach Two-way Synchronization Protocol for iPhone
       * - ``tbricks``
         - N/A
         - [N/A] tbricks internal protocol
       * - ``tcode``
         - N/A
         - [N/A] Time Code
       * - ``tcu``
         - N/A
         - [N/A] Tracking Control Unit by RPM-PSI
       * - ``te-faxserver``
         - N/A
         - [N/A] TE-SYSTEMS GmbH Fax Server Daemon
       * - ``teamlist``
         - N/A
         - [N/A] ARTIS Team Task
       * - ``tera-fsmgr``
         - N/A
         - [N/A] Terascala Filesystem Manager Protocol
       * - ``tera-mp``
         - N/A
         - [N/A] Terascala Maintenance Protocol
       * - ``tf-redeye``
         - N/A
         - [N/A] ThinkFlood RedEye IR bridge
       * - ``thumbwrestling``
         - N/A
         - [N/A] tinkerbuilt Thumb Wrestling game
       * - ``ticonnectmgr``
         - N/A
         - [N/A] TI Connect Manager Discovery Service
       * - ``tinavigator``
         - N/A
         - [N/A] TI Navigator Hub 1.0 Discovery Service
       * - ``tivo-hme``
         - N/A
         - [N/A] TiVo Home Media Engine Protocol
       * - ``tivo-music``
         - N/A
         - [N/A] TiVo Music Protocol
       * - ``tivo-photos``
         - N/A
         - [N/A] TiVo Photos Protocol
       * - ``tivo-remote``
         - N/A
         - [N/A] TiVo Remote Protocol
       * - ``tivo-videos``
         - N/A
         - [N/A] TiVo Videos Protocol
       * - ``todogwa``
         - N/A
         - [N/A] 2Do Sync Helper Tool for Mac OS X and PCs
       * - ``tomboy``
         - N/A
         - [N/A] Tomboy
       * - ``toothpicserver``
         - N/A
         - [N/A] ToothPics Dental Office Support Server
       * - ``touch-able``
         - N/A
         - [N/A] iPhone and iPod touch Remote Controllable
       * - ``touch-remote``
         - N/A
         - [N/A] iPhone and iPod touch Remote Pairing
       * - ``tri-vis-client``
         - N/A
         - [N/A] triCerat Simplify Visibility Client
       * - ``tri-vis-server``
         - N/A
         - [N/A] triCerat Simplify Visibility Server
       * - ``tryst``
         - N/A
         - [N/A] Tryst
       * - ``tt4inarow``
         - N/A
         - [N/A] Trivial Technology's 4 in a Row
       * - ``ttcheckers``
         - N/A
         - [N/A] Trivial Technology's Checkers
       * - ``ttp4daemon``
         - N/A
         - [N/A] TechTool Pro 4 Anti-Piracy Service
       * - ``tunage``
         - N/A
         - [N/A] Tunage Media Control Service
       * - ``tuneranger``
         - N/A
         - [N/A] TuneRanger
       * - ``ubertragen``
         - N/A
         - [N/A] Ubertragen
       * - ``uddi``
         - N/A
         - [N/A] Universal Description, Discovery and Integration
       * - ``uddi-inq``
         - N/A
         - [N/A] Universal Description, Discovery and Integration Inquiry
       * - ``uddi-pub``
         - N/A
         - [N/A] Universal Description, Discovery and Integration Publishing
       * - ``uddi-sub``
         - N/A
         - [N/A] Universal Description, Discovery and Integration Subscription
       * - ``uddi-sec``
         - N/A
         - [N/A] Universal Description, Discovery and Integration Security
       * - ``upnp``
         - N/A
         - [N/A] Universal Plug and Play
       * - ``urlbookmark``
         - N/A
         - [N/A] URL Advertising
       * - ``uswi``
         - N/A
         - [N/A] Universal Switching Corporation products
       * - ``utest``
         - N/A
         - [N/A] uTest
       * - ``uwsgi``
         - N/A
         - [N/A] Unbit Web Server Gateway Interface
       * - ``ve-decoder``
         - N/A
         - [N/A] American Dynamics VideoEdge Decoder Control Service
       * - ``ve-encoder``
         - N/A
         - [N/A] American Dynamics VideoEdge Encoder Control Service
       * - ``ve-recorder``
         - N/A
         - [N/A] American Dynamics VideoEdge Recorder Control Service
       * - ``virtualdj``
         - N/A
         - [N/A] VirtualDJ Remote Control protocol
       * - ``visel``
         - N/A
         - [N/A] visel Q-System services
       * - ``vos``
         - N/A
         - [N/A] Virtual Object System (using VOP/TCP)
       * - ``vue4rendercow``
         - N/A
         - [N/A] VueProRenderCow
       * - ``vxi-11``
         - N/A
         - [N/A] VXI-11 TCP/IP Instrument Protocol
       * - ``walkietalkie``
         - N/A
         - [N/A] Walkie Talkie
       * - ``we-jell``
         - N/A
         - [N/A] Proprietary collaborative messaging protocol
       * - ``webdav``
         - N/A
         - [N/A] World Wide Web Distributed Authoring and Versioning (WebDAV)
       * - ``webdavs``
         - N/A
         - [N/A] WebDAV over SSL/TLS
       * - ``webissync``
         - N/A
         - [N/A] WebIS Sync Protocol
       * - ``wedraw``
         - N/A
         - [N/A] weDraw document sharing protocol
       * - ``whamb``
         - N/A
         - [N/A] Whamb
       * - ``whistler``
         - N/A
         - [N/A] Honeywell Video Systems
       * - ``witap``
         - N/A
         - [N/A] WiTap Sample Game Protocol
       * - ``witapvoice``
         - N/A
         - [N/A] witapvoice
       * - ``wkgrpsvr``
         - N/A
         - [N/A] Workgroup Server Discovery
       * - ``workstation``
         - N/A
         - [N/A] Workgroup Manager
       * - ``wormhole``
         - N/A
         - [N/A] Roku Cascade Wormhole Protocol
       * - ``workgroup``
         - N/A
         - [N/A] Novell collaboration workgroup
       * - ``writietalkie``
         - N/A
         - [N/A] Writie Talkie Data Sharing
       * - ``ws``
         - N/A
         - [N/A] Web Services
       * - ``wtc-heleos``
         - N/A
         - [N/A] Wyatt Technology Corporation HELEOS
       * - ``wtc-qels``
         - N/A
         - [N/A] Wyatt Technology Corporation QELS
       * - ``wtc-rex``
         - N/A
         - [N/A] Wyatt Technology Corporation Optilab rEX
       * - ``wtc-viscostar``
         - N/A
         - [N/A] Wyatt Technology Corporation ViscoStar
       * - ``wtc-wpr``
         - N/A
         - [N/A] Wyatt Technology Corporation DynaPro Plate Reader
       * - ``wwdcpic``
         - N/A
         - [N/A] PictureSharing sample code
       * - ``x-on``
         - N/A
         - [N/A] x-on services synchronisation protocol
       * - ``xcodedistcc``
         - N/A
         - [N/A] Xcode Distributed Compiler
       * - ``xgate-rmi``
         - N/A
         - [N/A] xGate Remote Management Interface
       * - ``xmp``
         - N/A
         - [N/A] Xperientia Mobile Protocol
       * - ``xsanclient``
         - N/A
         - [N/A] Xsan Client
       * - ``xsanserver``
         - N/A
         - [N/A] Xsan Server
       * - ``xsansystem``
         - N/A
         - [N/A] Xsan System
       * - ``xtimelicence``
         - N/A
         - [N/A] xTime License
       * - ``xtshapro``
         - N/A
         - [N/A] xTime Project
       * - ``xul-http``
         - N/A
         - [N/A] XUL (XML User Interface Language) transported over HTTP

    """

    if TYPE_CHECKING:
        #: Service name.
        svc: 'str'
        #: Port number.
        port: 'int'
        #: Transport protocol.
        proto: 'TransportProtocol'

    #: Transport protocol whose assignments this registry holds. The base
    #: registry holds none, so it names none.
    __transport__: 'TransportProtocol' = TransportProtocol.undefined

    #: Members of this registry, keyed on port number -- a
    #: :class:`~pcapkit.corekit.multidict.MultiDict` because IANA genuinely
    #: assigns several services to one port, and a plain mapping would keep only
    #: the last of them.
    #:
    #: Declared here as :obj:`None` and overridden in each subclass: a mutable
    #: class attribute declared on this class would be *shared* by all four
    #: subclasses, so they would collide with each other exactly as the ports of
    #: one transport used to collide inside the old flat registry.
    __registry__: 'Optional[MultiDict[int, AppType]]' = None

    #: Registry class owning each transport protocol, i.e. what
    #: :meth:`get` delegates to when called on this class rather than on one of
    #: them. Populated by :mod:`pcapkit.const.reg.apptype` once all four have
    #: been imported, since this module cannot import its own subclasses.
    __registries__: 'dict[TransportProtocol, Type[AppType]]' = {}

    #: Canonical service per port, for the ports carrying more than one. The base
    #: registry has no members and so no collisions.
    __canonical__: 'dict[int, str]' = {}

    def __new__(cls, value: 'int', name: 'str' = '<null>',
                proto: 'TransportProtocol' = TransportProtocol.undefined) -> 'Type[AppType]':
        temp = '%s [%d - %s]' % (name, value, proto.name)

        obj = str.__new__(cls, temp)
        obj._value_ = temp

        obj.svc = name
        obj.port = value
        obj.proto = proto

        # NOTE: the value is the formatted string above rather than the port, so
        # two services on one port stay two canonical members instead of one
        # member and an alias -- an alias would answer to the other's name.
        if cls.__registry__ is None:
            raise ValueError('%s holds no members; they belong to its per-transport '
                             'subclasses' % cls.__name__)
        cls.__registry__.add(value, obj)

        return obj

    def __repr__(self) -> 'str':
        return "<%s.%s: %d [%s]>" % (self.__class__.__name__, self.svc, self.port, self.proto.name)

    def __str__(self) -> 'str':
        return '%s [%d - %s]' % (self.svc, self.port, self.proto.name)

    def __int__(self) -> 'int':
        return self.port

    def __lt__(self, other: 'AppType') -> 'bool':
        return self.port < other

    def __gt__(self, other: 'AppType') -> 'bool':
        return self.port > other

    def __le__(self, other: 'AppType') -> 'bool':
        return self.port <= other

    def __ge__(self, other: 'AppType') -> 'bool':
        return self.port >= other

    def __eq__(self, other: 'Any') -> 'bool':
        return self.port == other

    def __ne__(self, other: 'Any') -> 'bool':
        return self.port != other

    def __hash__(self) -> 'int':
        return hash(self.port)

    @classmethod
    def _dispatch(cls, key: 'int', proto: 'TransportProtocol | str') -> 'Type[AppType]':
        """The registry that owns ``proto``, or ``cls`` where it is one already.

        Args:
            key: Port number the caller is looking up, validated here so that
                every entry point rejects a non-port identically.
            proto: Transport protocol, as a flag or its name.

        Returns:
            The registry class to search.

        Raises:
            ValueError: If ``key`` is not a port number, or if ``cls`` holds no
                members and ``proto`` names no registry to delegate to.

        """
        # NOTE: this registry resolves ports, not service names. The old string
        # branch tested ``key in __members_proto__``, which is keyed by transport
        # protocol, so a name never matched and the miss path minted a brand-new
        # member with port -1 -- GitHub issue #734's silent junk. Rejecting a
        # non-port outright is the honest answer, and it has to happen before the
        # miss path, which formats ``key`` with ``%d``.
        if not isinstance(key, int):
            raise ValueError('%r is not a valid port number for %s' % (key, cls.__name__))
        if cls.__registry__ is not None:
            return cls

        if isinstance(proto, str):
            proto = TransportProtocol.get(proto.lower())
        for namespace in show_flag_values(proto):
            subclass = cls.__registries__.get(TransportProtocol(namespace))
            if subclass is not None:
                return subclass
        raise ValueError('%r names no transport protocol registry of %s'
                         % (proto, cls.__name__))

    @classmethod
    def get(cls, key: 'int', *,
            proto: 'TransportProtocol | str' = TransportProtocol.undefined) -> 'AppType':
        """Backport support for original codes.

        Args:
            key: Port number to look up.
            proto: Transport protocol carrying ``key``. Selects the registry to
                search when called on :class:`AppType` itself, which holds no
                members; ignored when called on one of those registries, each of
                which already knows its own transport.

        Returns:
            The **canonical** service for ``key``. IANA assigns several services
            to some ports -- ``80`` carries ``http``, ``www`` and ``www-http`` --
            and names no precedence among them, so :data:`__canonical__` supplies
            the one the rest of the world answers with. The others remain real,
            named members and are reached through :meth:`get_all`.

        Raises:
            ValueError: If called on a class that holds no members, i.e. on
                :class:`AppType` itself, with a ``proto`` naming no registry to
                delegate to. Also for a ``key`` that is not a port number, since
                this registry resolves ports and not service names -- including
                one outside ``0..65535``, whose rejection by :meth:`_missing_` this
                method propagates rather than minting over, so that ``get`` is
                never more permissive than ``AppType(...)``.

        :meta private:
        """
        owner = cls._dispatch(key, proto)

        matched = owner.__registry__.getlist(key)  # type: ignore[union-attr]
        if matched:
            canonical = owner.__canonical__.get(key)
            if canonical is not None:
                for member in matched:
                    if member.svc == canonical:
                        return member
            # NOTE: IANA's oldest row, for a port whose collision postdates
            # :data:`__canonical__` -- including one :func:`~aenum.extend_enum`
            # created, which must not displace what the registry already
            # answered with.
            return matched[0]

        # NOTE: :meth:`_missing_` answers :obj:`None` for a port it holds no row
        # for, which is what minting is for, and *raises* for a value that is not a
        # port at all. Catching that rejection was GitHub issue #758's defect: it
        # minted ``PORT_999999_tcp`` and ``PORT_-1_tcp``, the latter a name no
        # attribute access can reach, and left ``get`` more permissive than
        # ``AppType(...)``, which has always raised here. The rejection now
        # propagates, so both entry points answer an out-of-range port identically.
        ret = owner._missing_(key)
        if ret is None:
            ret = extend_enum(owner, 'PORT_%d_%s' % (key, owner.__transport__.name),
                              key, 'unknown', owner.__transport__)
        return ret

    @classmethod
    def get_all(cls, key: 'int', *,
                proto: 'TransportProtocol | str' = TransportProtocol.undefined) -> 'tuple[AppType, ...]':
        """Every service IANA assigns to a port, canonical first.

        :meth:`get` answers with one member because that is what a port lookup
        means everywhere else -- :func:`socket.getservbyport` returns a single
        name -- but IANA really did register all three services on TCP/80, and
        discarding two of them would be inventing a registry it does not have.
        This is how the rest are reached.

        Args:
            key: Port number to look up.
            proto: Transport protocol carrying ``key``, as for :meth:`get`.

        Returns:
            The canonical member followed by its aliases, in registry row order.
            Never empty: a port with no assignment goes through :meth:`get`, so it
            is minted rather than answered with an empty result.

        Raises:
            ValueError: As :meth:`get`.

        """
        owner = cls._dispatch(key, proto)

        canonical = owner.get(key)
        matched = owner.__registry__.getlist(key)  # type: ignore[union-attr]
        return (canonical, *(member for member in matched if member is not canonical))

    @classmethod
    def _missing_(cls, value: 'int') -> 'Optional[AppType]':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        # NOTE: extending this class would give it a member, and aenum then
        # refuses to subclass it -- permanently, for every registry not yet
        # imported. The spans below belong to whichever registry was asked, never
        # to this one.
        if cls.__registry__ is None:
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        # NOTE: most spans are IANA's unassigned and reserved markers, which name
        # no transport protocol and so answer every registry. A span that does name
        # one tests ``cls.__transport__`` and answers that registry alone --
        # GitHub issue #760, where source order decided instead and a UDP lookup in
        # 6000-6063 came back carrying ``tcp``. A registry a named span excludes
        # falls through to a mint, which is what IANA assigning it nothing means.
        if 225 <= value <= 241:
            #: [N/A] Reserved [:rfc:`1060`]
            return extend_enum(cls, 'reserved_%d' % value, value, 'reserved', TransportProtocol.undefined)
        if 249 <= value <= 255:
            #: [N/A] Reserved [:rfc:`1060`]
            return extend_enum(cls, 'reserved_%d' % value, value, 'reserved', TransportProtocol.undefined)
        if 272 <= value <= 279:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 288 <= value <= 299:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 301 <= value <= 307:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 325 <= value <= 332:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 334 <= value <= 343:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 717 <= value <= 728:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 732 <= value <= 740:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 745 <= value <= 746:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 755 <= value <= 757:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 778 <= value <= 779:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 781 <= value <= 785:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 788 <= value <= 799:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 803 <= value <= 809:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 811 <= value <= 827:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 834 <= value <= 846:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 849 <= value <= 852:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 855 <= value <= 859:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 863 <= value <= 872:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 874 <= value <= 885:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 889 <= value <= 899:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 904 <= value <= 909:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 916 <= value <= 952:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 954 <= value <= 988:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 1002 <= value <= 1007:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 1011 <= value <= 1020:
            #: [N/A] Reserved
            return extend_enum(cls, 'reserved_%d' % value, value, 'reserved', TransportProtocol.undefined)
        if 2194 <= value <= 2196:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 3322 <= value <= 3325:
            #: [N/A] Active Networks
            return extend_enum(cls, 'active_net_%d' % value, value, 'active-net', TransportProtocol.undefined)
        if 3367 <= value <= 3371:
            #: [N/A] Satellite Video Data Link
            return extend_enum(cls, 'satvid_datalnk_%d' % value, value, 'satvid-datalnk', TransportProtocol.undefined)
        if 4200 <= value <= 4299:
            #: [N/A] VRML Multi User Systems
            return extend_enum(cls, 'vrml_multi_use_%d' % value, value, 'vrml-multi-use', TransportProtocol.undefined)
        if 4337 <= value <= 4339:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 4363 <= value <= 4365:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 4380 <= value <= 4388:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 4397 <= value <= 4399:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 4434 <= value <= 4440:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 4461 <= value <= 4479:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 4481 <= value <= 4483:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 4489 <= value <= 4499:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 4504 <= value <= 4533:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 4539 <= value <= 4544:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 4560 <= value <= 4562:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 4564 <= value <= 4565:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 4571 <= value <= 4572:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 4574 <= value <= 4589:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 4607 <= value <= 4620:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 4622 <= value <= 4645:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 4647 <= value <= 4657:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 4693 <= value <= 4699:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 4705 <= value <= 4710:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 4712 <= value <= 4724:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 4734 <= value <= 4736:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 4748 <= value <= 4748:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 4757 <= value <= 4773:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 4775 <= value <= 4783:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 4795 <= value <= 4799:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 4805 <= value <= 4826:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 4828 <= value <= 4836:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 4852 <= value <= 4866:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 4872 <= value <= 4875:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 4886 <= value <= 4887:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 4890 <= value <= 4893:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 4895 <= value <= 4898:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 4903 <= value <= 4911:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 4916 <= value <= 4935:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 4938 <= value <= 4939:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 4943 <= value <= 4948:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 4954 <= value <= 4968:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 4972 <= value <= 4979:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 4981 <= value <= 4982:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 4992 <= value <= 4998:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5016 <= value <= 5019:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5035 <= value <= 5041:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5076 <= value <= 5077:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5088 <= value <= 5089:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5095 <= value <= 5098:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5108 <= value <= 5110:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5118 <= value <= 5119:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5121 <= value <= 5132:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5138 <= value <= 5144:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5147 <= value <= 5149:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5158 <= value <= 5160:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5169 <= value <= 5171:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5173 <= value <= 5189:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5198 <= value <= 5199:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5204 <= value <= 5208:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5210 <= value <= 5214:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5216 <= value <= 5220:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5238 <= value <= 5241:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5255 <= value <= 5263:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5266 <= value <= 5268:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5273 <= value <= 5279:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5283 <= value <= 5297:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5322 <= value <= 5342:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5345 <= value <= 5348:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5365 <= value <= 5396:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5438 <= value <= 5442:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5446 <= value <= 5449:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5451 <= value <= 5452:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5457 <= value <= 5460:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5466 <= value <= 5469:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5476 <= value <= 5499:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5508 <= value <= 5539:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5541 <= value <= 5542:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5544 <= value <= 5549:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5551 <= value <= 5552:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5558 <= value <= 5564:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5570 <= value <= 5572:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5576 <= value <= 5578:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5587 <= value <= 5596:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5606 <= value <= 5617:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5619 <= value <= 5626:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5640 <= value <= 5645:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5647 <= value <= 5665:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5667 <= value <= 5669:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5685 <= value <= 5686:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5690 <= value <= 5692:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5694 <= value <= 5695:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5697 <= value <= 5699:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5701 <= value <= 5704:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5706 <= value <= 5712:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5731 <= value <= 5740:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5751 <= value <= 5754:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5758 <= value <= 5765:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5772 <= value <= 5776:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5778 <= value <= 5779:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5788 <= value <= 5792:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5795 <= value <= 5797:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5799 <= value <= 5812:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5815 <= value <= 5819:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5821 <= value <= 5840:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5843 <= value <= 5858:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5860 <= value <= 5862:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5864 <= value <= 5867:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5869 <= value <= 5882:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5884 <= value <= 5899:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5901 <= value <= 5902:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5915 <= value <= 5962:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5964 <= value <= 5967:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5970 <= value <= 5983:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 5995 <= value <= 5998:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6000 <= value <= 6063 and cls.__transport__ is TransportProtocol.tcp:
            #: [TCP] X Window System
            return extend_enum(cls, 'x11_%d' % value, value, 'x11', TransportProtocol.tcp)
        if 6000 <= value <= 6063 and cls.__transport__ is TransportProtocol.udp:
            #: [UDP] X Window System
            return extend_enum(cls, 'x11_%d' % value, value, 'x11', TransportProtocol.udp)
        if 6078 <= value <= 6079:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6089 <= value <= 6098:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6119 <= value <= 6120:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6125 <= value <= 6129:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6131 <= value <= 6132:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6134 <= value <= 6139:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6150 <= value <= 6158:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6164 <= value <= 6199:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6202 <= value <= 6208:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6210 <= value <= 6221:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6223 <= value <= 6240:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6245 <= value <= 6250:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6254 <= value <= 6266:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6270 <= value <= 6299:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6302 <= value <= 6305:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6307 <= value <= 6314:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6327 <= value <= 6342:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6345 <= value <= 6345:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6348 <= value <= 6349:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6351 <= value <= 6354:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6356 <= value <= 6359:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6361 <= value <= 6362:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6364 <= value <= 6369:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6371 <= value <= 6378:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6380 <= value <= 6381:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6383 <= value <= 6388:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6391 <= value <= 6399:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6411 <= value <= 6416:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6422 <= value <= 6431:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6433 <= value <= 6439:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6447 <= value <= 6454:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6457 <= value <= 6463:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6465 <= value <= 6470:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6472 <= value <= 6479:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6490 <= value <= 6499:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6512 <= value <= 6512:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6516 <= value <= 6542:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6545 <= value <= 6546:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6552 <= value <= 6555:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6559 <= value <= 6565:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6569 <= value <= 6578:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6584 <= value <= 6587:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6589 <= value <= 6599:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6603 <= value <= 6609:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6611 <= value <= 6618:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6637 <= value <= 6639:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6641 <= value <= 6652:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6658 <= value <= 6664:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6665 <= value <= 6669 and cls.__transport__ is TransportProtocol.tcp:
            #: [TCP] IRCU
            return extend_enum(cls, 'ircu_%d' % value, value, 'ircu', TransportProtocol.tcp)
        if 6665 <= value <= 6669 and cls.__transport__ is TransportProtocol.udp:
            #: [UDP] Reserved
            return extend_enum(cls, 'reserved_%d' % value, value, 'reserved', TransportProtocol.udp)
        if 6674 <= value <= 6677:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6680 <= value <= 6686:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6691 <= value <= 6695:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6707 <= value <= 6713:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6717 <= value <= 6766:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6772 <= value <= 6776:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6779 <= value <= 6783:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6792 <= value <= 6800:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6802 <= value <= 6816:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6818 <= value <= 6830:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6832 <= value <= 6840:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6843 <= value <= 6849:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6851 <= value <= 6867:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6869 <= value <= 6887:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6889 <= value <= 6899:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6902 <= value <= 6923:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6925 <= value <= 6934:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6937 <= value <= 6945:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6947 <= value <= 6950:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6952 <= value <= 6960:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6967 <= value <= 6968:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6971 <= value <= 6979:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 6981 <= value <= 6996:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7027 <= value <= 7029:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7032 <= value <= 7039:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7041 <= value <= 7069:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7074 <= value <= 7079:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7081 <= value <= 7087:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7089 <= value <= 7094:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7096 <= value <= 7098:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7102 <= value <= 7106:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7108 <= value <= 7116:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7118 <= value <= 7120:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7124 <= value <= 7127:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7130 <= value <= 7160:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7175 <= value <= 7180:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7182 <= value <= 7199:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7203 <= value <= 7214:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7217 <= value <= 7226:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7230 <= value <= 7233:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7238 <= value <= 7243:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7245 <= value <= 7261:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7263 <= value <= 7271:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7284 <= value <= 7299:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7300 <= value <= 7359:
            #: [N/A] The Swiss Exchange
            return extend_enum(cls, 'swx_%d' % value, value, 'swx', TransportProtocol.undefined)
        if 7360 <= value <= 7364:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7366 <= value <= 7390:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7398 <= value <= 7399:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7403 <= value <= 7409:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7412 <= value <= 7419:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7422 <= value <= 7425:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7432 <= value <= 7436:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7438 <= value <= 7442:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7444 <= value <= 7470:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7475 <= value <= 7477:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7479 <= value <= 7490:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7492 <= value <= 7499:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7502 <= value <= 7507:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7512 <= value <= 7541:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7552 <= value <= 7559:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7561 <= value <= 7562:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7564 <= value <= 7565:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7567 <= value <= 7568:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7571 <= value <= 7573:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7576 <= value <= 7587:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7589 <= value <= 7605:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7607 <= value <= 7623:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7634 <= value <= 7647:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7649 <= value <= 7662:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7664 <= value <= 7667:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7669 <= value <= 7671:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7678 <= value <= 7679:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7681 <= value <= 7682:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7684 <= value <= 7686:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7691 <= value <= 7696:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7698 <= value <= 7699:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7702 <= value <= 7706:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7709 <= value <= 7719:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7721 <= value <= 7723:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7729 <= value <= 7733:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7735 <= value <= 7737:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7739 <= value <= 7740:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7745 <= value <= 7746:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7748 <= value <= 7776:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7782 <= value <= 7783:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7790 <= value <= 7793:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7795 <= value <= 7796:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7803 <= value <= 7809:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7811 <= value <= 7844:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7848 <= value <= 7868:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7873 <= value <= 7877:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7881 <= value <= 7886:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7888 <= value <= 7899:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7904 <= value <= 7912:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7914 <= value <= 7931:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7934 <= value <= 7961:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7963 <= value <= 7966:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7968 <= value <= 7978:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 7983 <= value <= 7997:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8011 <= value <= 8014:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8028 <= value <= 8031:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8035 <= value <= 8039:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8045 <= value <= 8050:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8062 <= value <= 8065:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8068 <= value <= 8069:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8071 <= value <= 8073:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8075 <= value <= 8076:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8078 <= value <= 8079:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8092 <= value <= 8096:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8098 <= value <= 8099:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8103 <= value <= 8110:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8112 <= value <= 8114:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8119 <= value <= 8120:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8123 <= value <= 8127:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8133 <= value <= 8139:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8141 <= value <= 8147:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8150 <= value <= 8152:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8154 <= value <= 8159:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8163 <= value <= 8180:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8185 <= value <= 8189:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8196 <= value <= 8198:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8203 <= value <= 8203:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8209 <= value <= 8210:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8212 <= value <= 8229:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8233 <= value <= 8242:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8244 <= value <= 8265:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8267 <= value <= 8269:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8271 <= value <= 8275:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8277 <= value <= 8279:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8283 <= value <= 8291:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8295 <= value <= 8299:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8302 <= value <= 8312:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8314 <= value <= 8319:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8323 <= value <= 8350:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8352 <= value <= 8375:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8381 <= value <= 8382:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8385 <= value <= 8399:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8406 <= value <= 8414:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8418 <= value <= 8422:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8424 <= value <= 8431:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8434 <= value <= 8441:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8446 <= value <= 8447:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8451 <= value <= 8456:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8458 <= value <= 8469:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8475 <= value <= 8499:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8504 <= value <= 8553:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8556 <= value <= 8566:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8568 <= value <= 8599:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8601 <= value <= 8608:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8616 <= value <= 8664:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8669 <= value <= 8674:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8676 <= value <= 8685:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8689 <= value <= 8698:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8700 <= value <= 8709:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8712 <= value <= 8731:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8734 <= value <= 8749:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8751 <= value <= 8762:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8771 <= value <= 8777:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8779 <= value <= 8785:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8788 <= value <= 8792:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8794 <= value <= 8799:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8801 <= value <= 8803:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8810 <= value <= 8872:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8874 <= value <= 8879:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8884 <= value <= 8887:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8895 <= value <= 8898:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8902 <= value <= 8907:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8914 <= value <= 8936:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8938 <= value <= 8952:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8955 <= value <= 8979:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8982 <= value <= 8988:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 8992 <= value <= 8996:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9003 <= value <= 9004:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9012 <= value <= 9019:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9027 <= value <= 9049:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9052 <= value <= 9059:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9061 <= value <= 9079:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9094 <= value <= 9099:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9108 <= value <= 9110:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9112 <= value <= 9118:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9120 <= value <= 9121:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9124 <= value <= 9130:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9132 <= value <= 9159:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9165 <= value <= 9182:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9184 <= value <= 9190:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9192 <= value <= 9199:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9218 <= value <= 9221:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9223 <= value <= 9254:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9256 <= value <= 9276:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9288 <= value <= 9291:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9296 <= value <= 9299:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9301 <= value <= 9305:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9307 <= value <= 9309:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9313 <= value <= 9317:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9319 <= value <= 9320:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9322 <= value <= 9338:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9341 <= value <= 9342:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9347 <= value <= 9373:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9375 <= value <= 9379:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9381 <= value <= 9386:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9391 <= value <= 9395:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9398 <= value <= 9399:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9403 <= value <= 9417:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9419 <= value <= 9442:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9446 <= value <= 9449:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9451 <= value <= 9499:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9501 <= value <= 9521:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9523 <= value <= 9534:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9537 <= value <= 9554:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9556 <= value <= 9558:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9560 <= value <= 9591:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9601 <= value <= 9611:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9619 <= value <= 9627:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9633 <= value <= 9639:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9641 <= value <= 9665:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9669 <= value <= 9693:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9696 <= value <= 9699:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9701 <= value <= 9746:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9748 <= value <= 9749:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9751 <= value <= 9752:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9754 <= value <= 9761:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9763 <= value <= 9799:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9803 <= value <= 9874:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9879 <= value <= 9887:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9890 <= value <= 9897:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9904 <= value <= 9908:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9912 <= value <= 9924:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9926 <= value <= 9949:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9957 <= value <= 9965:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9967 <= value <= 9977:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9982 <= value <= 9985:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 9989 <= value <= 9989:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 10011 <= value <= 10019:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 10021 <= value <= 10022:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 10024 <= value <= 10049:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 10052 <= value <= 10054:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 10056 <= value <= 10079:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 10082 <= value <= 10099:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 10105 <= value <= 10106:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 10108 <= value <= 10109:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 10118 <= value <= 10124:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 10126 <= value <= 10127:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 10130 <= value <= 10159:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 10163 <= value <= 10199:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 10202 <= value <= 10251:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 10254 <= value <= 10259:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 10262 <= value <= 10287:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 10289 <= value <= 10320:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 10322 <= value <= 10438:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 10440 <= value <= 10442:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 10444 <= value <= 10499:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 10501 <= value <= 10539:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 10545 <= value <= 10547:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 10549 <= value <= 10630:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 10632 <= value <= 10799:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 10801 <= value <= 10804:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 10806 <= value <= 10808:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 10811 <= value <= 10859:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 10861 <= value <= 10879:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 10881 <= value <= 10932:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 10934 <= value <= 10989:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 10991 <= value <= 10999:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 11002 <= value <= 11094:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 11096 <= value <= 11102:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 11113 <= value <= 11160:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 11166 <= value <= 11170:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 11176 <= value <= 11200:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 11203 <= value <= 11207:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 11209 <= value <= 11210:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 11212 <= value <= 11234:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 11236 <= value <= 11318:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 11322 <= value <= 11366:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 11368 <= value <= 11370:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 11372 <= value <= 11429:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 11431 <= value <= 11433:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 11435 <= value <= 11488:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 11490 <= value <= 11599:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 11601 <= value <= 11622:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 11624 <= value <= 11719:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 11721 <= value <= 11722:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 11724 <= value <= 11750:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 11752 <= value <= 11795:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 11797 <= value <= 11875:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 11878 <= value <= 11966:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 11968 <= value <= 11970:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 11972 <= value <= 11996:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 12014 <= value <= 12108:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 12110 <= value <= 12120:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 12122 <= value <= 12167:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 12169 <= value <= 12171:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 12173 <= value <= 12299:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 12303 <= value <= 12320:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 12323 <= value <= 12344:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 12346 <= value <= 12545:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 12547 <= value <= 12752:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 12754 <= value <= 12864:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 12866 <= value <= 13159:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 13161 <= value <= 13215:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 13219 <= value <= 13222:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 13225 <= value <= 13399:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 13401 <= value <= 13719:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 13725 <= value <= 13781:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 13787 <= value <= 13817:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 13824 <= value <= 13831:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 13833 <= value <= 13893:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 13895 <= value <= 13928:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 13931 <= value <= 13999:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 14003 <= value <= 14032:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 14035 <= value <= 14140:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 14146 <= value <= 14148:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 14151 <= value <= 14153:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 14155 <= value <= 14249:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 14251 <= value <= 14413:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 14415 <= value <= 14499:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 14501 <= value <= 14935:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 14938 <= value <= 14999:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 15003 <= value <= 15117:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 15119 <= value <= 15344:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 15346 <= value <= 15362:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 15364 <= value <= 15554:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 15556 <= value <= 15659:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 15661 <= value <= 15739:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 15741 <= value <= 15997:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 16004 <= value <= 16019:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 16022 <= value <= 16160:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 16163 <= value <= 16308:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 16312 <= value <= 16359:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 16362 <= value <= 16366:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 16369 <= value <= 16383:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 16386 <= value <= 16618:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 16620 <= value <= 16664:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 16667 <= value <= 16788:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 16790 <= value <= 16899:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 16901 <= value <= 16949:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 16951 <= value <= 16990:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 16996 <= value <= 17006:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 17008 <= value <= 17009:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 17011 <= value <= 17183:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 17186 <= value <= 17218:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 17226 <= value <= 17233:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 17236 <= value <= 17499:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 17501 <= value <= 17554:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 17556 <= value <= 17728:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 17730 <= value <= 17753:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 17757 <= value <= 17776:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 17778 <= value <= 17999:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 18001 <= value <= 18103:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 18105 <= value <= 18135:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 18137 <= value <= 18180:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 18188 <= value <= 18240:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 18244 <= value <= 18258:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 18260 <= value <= 18261:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 18263 <= value <= 18462:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 18464 <= value <= 18515:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 18517 <= value <= 18633:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 18636 <= value <= 18667:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 18669 <= value <= 18768:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 18770 <= value <= 18880:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 18882 <= value <= 18887:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 18889 <= value <= 18999:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 19001 <= value <= 19006:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 19008 <= value <= 19019:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 19021 <= value <= 19190:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 19192 <= value <= 19193:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 19195 <= value <= 19219:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 19221 <= value <= 19282:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 19284 <= value <= 19314:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 19316 <= value <= 19397:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 19399 <= value <= 19409:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 19413 <= value <= 19538:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 19542 <= value <= 19787:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 19791 <= value <= 19997:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 20006 <= value <= 20011:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 20015 <= value <= 20033:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 20035 <= value <= 20045:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 20047 <= value <= 20047:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 20050 <= value <= 20056:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 20058 <= value <= 20166:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 20168 <= value <= 20201:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 20203 <= value <= 20221:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 20223 <= value <= 20479:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 20481 <= value <= 20669:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 20671 <= value <= 20809:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 20811 <= value <= 20998:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 21001 <= value <= 21009:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 21011 <= value <= 21211:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 21214 <= value <= 21220:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 21222 <= value <= 21336:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 21338 <= value <= 21552:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 21555 <= value <= 21589:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 21591 <= value <= 21799:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 21802 <= value <= 21844:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 21850 <= value <= 21999:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 22006 <= value <= 22124:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 22126 <= value <= 22127:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 22129 <= value <= 22221:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 22223 <= value <= 22272:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 22274 <= value <= 22304:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 22306 <= value <= 22332:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 22336 <= value <= 22342:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 22344 <= value <= 22346:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 22348 <= value <= 22349:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 22352 <= value <= 22536:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 22538 <= value <= 22554:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 22556 <= value <= 22762:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 22764 <= value <= 22799:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 22801 <= value <= 22950:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 22952 <= value <= 22999:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 23006 <= value <= 23052:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 23054 <= value <= 23271:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 23273 <= value <= 23293:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 23295 <= value <= 23332:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 23334 <= value <= 23399:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 23403 <= value <= 23455:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 23458 <= value <= 23545:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 23547 <= value <= 23999:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 24007 <= value <= 24241:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 24243 <= value <= 24248:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 24250 <= value <= 24320:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 24324 <= value <= 24385:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 24387 <= value <= 24464:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 24466 <= value <= 24553:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 24555 <= value <= 24576:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 24578 <= value <= 24600:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 24602 <= value <= 24665:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 24667 <= value <= 24675:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 24681 <= value <= 24726:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 24728 <= value <= 24753:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 24755 <= value <= 24849:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 24851 <= value <= 24921:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 24923 <= value <= 24999:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 25010 <= value <= 25099:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 25101 <= value <= 25470:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 25472 <= value <= 25575:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 25577 <= value <= 25603:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 25605 <= value <= 25792:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 25794 <= value <= 25899:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 25904 <= value <= 25953:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 25956 <= value <= 25999:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 26001 <= value <= 26132:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 26134 <= value <= 26207:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 26209 <= value <= 26256:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 26258 <= value <= 26259:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 26265 <= value <= 26485:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 26490 <= value <= 26999:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 27000 <= value <= 27009:
            #: [N/A] FLEX LM (1-10)
            return extend_enum(cls, 'flex_lm_%d' % value, value, 'flex-lm', TransportProtocol.undefined)
        if 27011 <= value <= 27015:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 27018 <= value <= 27344:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 27346 <= value <= 27441:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 27443 <= value <= 27503:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 27505 <= value <= 27781:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 27783 <= value <= 27875:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 27877 <= value <= 27998:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 28002 <= value <= 28009:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 28011 <= value <= 28079:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 28081 <= value <= 28118:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 28120 <= value <= 28199:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 28201 <= value <= 28239:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 28241 <= value <= 28588:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 28590 <= value <= 28999:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 29001 <= value <= 29117:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 29119 <= value <= 29166:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 29170 <= value <= 29998:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 30005 <= value <= 30099:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 30101 <= value <= 30259:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 30261 <= value <= 30399:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 30401 <= value <= 30831:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 30833 <= value <= 30938:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 30940 <= value <= 30998:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 31000 <= value <= 31015:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 31017 <= value <= 31019:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 31021 <= value <= 31028:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 31030 <= value <= 31336:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 31338 <= value <= 31399:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 31401 <= value <= 31415:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 31417 <= value <= 31456:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 31458 <= value <= 31619:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 31621 <= value <= 31684:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 31686 <= value <= 31764:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 31766 <= value <= 31947:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 31950 <= value <= 32033:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 32035 <= value <= 32248:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 32250 <= value <= 32399:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 32401 <= value <= 32482:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 32484 <= value <= 32634:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 32637 <= value <= 32766:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 32778 <= value <= 32800:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 32802 <= value <= 32810:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 32812 <= value <= 32895:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 32897 <= value <= 32999:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 33001 <= value <= 33059:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 33061 <= value <= 33122:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 33124 <= value <= 33330:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 33335 <= value <= 33433:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 33436 <= value <= 33655:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 33657 <= value <= 33889:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 33891 <= value <= 34248:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 34250 <= value <= 34377:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 34380 <= value <= 34566:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 34568 <= value <= 34961:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 34967 <= value <= 34979:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 34981 <= value <= 34999:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 35007 <= value <= 35099:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 35101 <= value <= 35353:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 35358 <= value <= 36000:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 36002 <= value <= 36410:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 36413 <= value <= 36421:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 36425 <= value <= 36442:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 36445 <= value <= 36461:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 36463 <= value <= 36523:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 36525 <= value <= 36601:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 36603 <= value <= 36699:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 36701 <= value <= 36864:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 36866 <= value <= 37471:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 37473 <= value <= 37474:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 37476 <= value <= 37482:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 37484 <= value <= 37600:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 37602 <= value <= 37653:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 37655 <= value <= 37999:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 38003 <= value <= 38200:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 38204 <= value <= 38411:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 38413 <= value <= 38421:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 38423 <= value <= 38461:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 38463 <= value <= 38471:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 38473 <= value <= 38637:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 38639 <= value <= 38799:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 38801 <= value <= 38864:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 38866 <= value <= 39062:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 39064 <= value <= 39680:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 39682 <= value <= 39999:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 40001 <= value <= 40022:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 40024 <= value <= 40403:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 40405 <= value <= 40840:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 40844 <= value <= 40852:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 40854 <= value <= 41110:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 41112 <= value <= 41120:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 41122 <= value <= 41229:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 41231 <= value <= 41793:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 41798 <= value <= 42507:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 42511 <= value <= 42998:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 43001 <= value <= 43187:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 43192 <= value <= 43209:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 43211 <= value <= 43437:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 43442 <= value <= 44122:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 44124 <= value <= 44320:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 44324 <= value <= 44443:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 44446 <= value <= 44543:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 44545 <= value <= 44552:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 44554 <= value <= 44599:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 44601 <= value <= 44817:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 44819 <= value <= 44899:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 44901 <= value <= 44999:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 45003 <= value <= 45044:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 45046 <= value <= 45053:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 45055 <= value <= 45184:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 45186 <= value <= 45513:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 45515 <= value <= 45677:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 45679 <= value <= 45823:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 45826 <= value <= 45965:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 45967 <= value <= 46335:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 46337 <= value <= 46997:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 47002 <= value <= 47099:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 47101 <= value <= 47556:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 47558 <= value <= 47623:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 47625 <= value <= 47805:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 47810 <= value <= 47999:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 48006 <= value <= 48047:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 48051 <= value <= 48127:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 48130 <= value <= 48555:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 48557 <= value <= 48618:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 48620 <= value <= 48652:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 48654 <= value <= 48999:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        if 49002 <= value <= 49149:
            #: [N/A] Unassigned
            return extend_enum(cls, 'unassigned_%d' % value, value, 'unassigned', TransportProtocol.undefined)
        return super()._missing_(value)
