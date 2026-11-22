# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""PPP DLL Protocol Numbers
==============================

.. module:: pcapkit.const.ppp.protocol

This module contains the constant enumeration for **PPP DLL Protocol Numbers**,
which is automatically generated from :class:`pcapkit.vendor.ppp.protocol.Protocol`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['Protocol']


class Protocol(EnumRegistry, IntEnum):
    """[Protocol] PPP DLL Protocol Numbers"""

    #: Protocol class(es) owning the ``__proto__`` dispatch registry keyed by
    #: this enumeration, read by
    #: :func:`~pcapkit.foundation.registry.protocols.protocol.register_protocol_code`
    #: to resolve a bare member of it into its destination(s). The classes are
    #: named as lazy :class:`~pcapkit.corekit.module.ModuleDescriptor`
    #: references rather than imported, because :mod:`pcapkit.const` sits below
    #: :mod:`pcapkit.protocols` and importing one from here would be circular.
    __proto_dest__ = (
        ModuleDescriptor('pcapkit.protocols.link.ppp.protocol', 'PPP'),
    )

    #: Padding Protocol [:rfc:`1661`]
    Padding_Protocol = 0x0001

    #: ROHC small-CID [:rfc:`3095`]
    ROHC_small_CID = 0x0003

    #: ROHC large-CID [:rfc:`3095`]
    ROHC_large_CID = 0x0005

    #: Internet Protocol version 4 [:rfc:`1332`]
    Internet_Protocol_version_4 = 0x0021

    #: OSI Network Layer [:rfc:`1377`]
    OSI_Network_Layer = 0x0023

    #: Xerox NS IDP [:rfc:`1764`]
    Xerox_NS_IDP = 0x0025

    #: DECnet Phase IV [:rfc:`1762`]
    DECnet_Phase_IV = 0x0027

    #: Appletalk [:rfc:`1378`]
    Appletalk = 0x0029

    #: Novell IPX [:rfc:`1552`]
    Novell_IPX = 0x002B

    #: Van Jacobson Compressed TCP/IP [:rfc:`1332`]
    Van_Jacobson_Compressed_TCP_IP = 0x002D

    #: Van Jacobson Uncompressed TCP/IP [:rfc:`1332`]
    Van_Jacobson_Uncompressed_TCP_IP = 0x002F

    #: Bridging PDU [:rfc:`3518`]
    Bridging_PDU = 0x0031

    #: Stream Protocol (ST-II)
    Stream_Protocol = 0x0033

    #: Banyan Vines [:rfc:`1763`]
    Banyan_Vines = 0x0035

    #: Unassigned
    Unassigned_0x0037 = 0x0037

    #: AppleTalk EDDP
    AppleTalk_EDDP = 0x0039

    #: AppleTalk SmartBuffered
    AppleTalk_SmartBuffered = 0x003B

    #: Multi-Link [:rfc:`1990`]
    Multi_Link = 0x003D

    #: NETBIOS Framing [:rfc:`2097`]
    NETBIOS_Framing = 0x003F

    #: Cisco Systems
    Cisco_Systems = 0x0041

    #: Ascom Timeplex
    Ascom_Timeplex_0x0043 = 0x0043

    #: Fujitsu Link Backup and Load Balancing (LBLB)
    Fujitsu_Link_Backup_and_Load_Balancing = 0x0045

    #: DCA Remote Lan
    DCA_Remote_Lan = 0x0047

    #: Serial Data Transport Protocol (PPP-SDTP) [:rfc:`1963`]
    Serial_Data_Transport_Protocol = 0x0049

    #: SNA over 802.2 [:rfc:`2043`]
    SNA_over_802_2 = 0x004B

    #: SNA [:rfc:`2043`]
    SNA = 0x004D

    #: IPv6 Header Compression
    IPv6_Header_Compression = 0x004F

    #: KNX Bridging Data [ianp knxunix knx co]
    KNX_Bridging_Data = 0x0051

    #: Encryption [:rfc:`1968`]
    Encryption = 0x0053

    #: Individual Link Encryption [:rfc:`1968`]
    Individual_Link_Encryption = 0x0055

    #: Internet Protocol version 6 [:rfc:`5072`]
    Internet_Protocol_version_6 = 0x0057

    #: PPP Muxing [:rfc:`3153`]
    PPP_Muxing = 0x0059

    #: Vendor-Specific Network Protocol (VSNP) [:rfc:`3772`]
    Vendor_Specific_Network_Protocol = 0x005B

    #: TRILL Network Protocol (TNP) [:rfc:`6361`]
    TRILL_Network_Protocol = 0x005D

    #: RTP IPHC Full Header [:rfc:`3544`]
    RTP_IPHC_Full_Header = 0x0061

    #: RTP IPHC Compressed TCP [:rfc:`3544`]
    RTP_IPHC_Compressed_TCP = 0x0063

    #: RTP IPHC Compressed Non TCP [:rfc:`3544`]
    RTP_IPHC_Compressed_Non_TCP = 0x0065

    #: RTP IPHC Compressed UDP 8 [:rfc:`3544`]
    RTP_IPHC_Compressed_UDP_8 = 0x0067

    #: RTP IPHC Compressed RTP 8 [:rfc:`3544`]
    RTP_IPHC_Compressed_RTP_8 = 0x0069

    #: Stampede Bridging
    Stampede_Bridging = 0x006F

    #: Reserved [Karl Fox]
    Reserved_0x0071 = 0x0071

    #: MP+ Protocol [:rfc:`1934`]
    MP_Protocol = 0x0073

    #: Reserved (Control Escape) [:rfc:`1661`]
    Reserved_0x007D = 0x007D

    #: Reserved (compression inefficient) [:rfc:`1662`]
    Reserved_0x007F = 0x007F

    #: Unassigned
    Unassigned_0x0081 = 0x0081

    #: Unassigned
    Unassigned_0x0083 = 0x0083

    #: NTCITS IPI [Alan Ungar]
    NTCITS_IPI = 0x00C1

    #: Reserved (PPP NLPID) [:rfc:`1661`]
    Reserved_0x00CF = 0x00CF

    #: Single link compression in multilink [:rfc:`1962`]
    Single_link_compression_in_multilink = 0x00FB

    #: Compressed datagram [:rfc:`1962`]
    Compressed_datagram = 0x00FD

    #: Reserved (compression inefficient) [:rfc:`1661`]
    Reserved_0x00FF = 0x00FF

    #: 802.1d Hello Packets [:rfc:`3518`]
    Protocol_802_1d_Hello_Packets = 0x0201

    #: IBM Source Routing BPDU [:rfc:`3518`]
    IBM_Source_Routing_BPDU = 0x0203

    #: DEC LANBridge100 Spanning Tree [:rfc:`3518`]
    DEC_LANBridge100_Spanning_Tree = 0x0205

    #: Cisco Discovery Protocol [Arun Sastry]
    Cisco_Discovery_Protocol = 0x0207

    #: Netcs Twin Routing [Oliver Korfmacher]
    Netcs_Twin_Routing_0x0209 = 0x0209

    #: STP - Scheduled Transfer Protocol [Ben Segal]
    STP_Scheduled_Transfer_Protocol = 0x020B

    #: EDP - Extreme Discovery Protocol [Don Grosser]
    EDP_Extreme_Discovery_Protocol = 0x020D

    #: Optical Supervisory Channel Protocol (OSCP) [Sharat C Prasad]
    Optical_Supervisory_Channel_Protocol_0x0211 = 0x0211

    #: Optical Supervisory Channel Protocol (OSCP) [Sharat C Prasad]
    Optical_Supervisory_Channel_Protocol_0x0213 = 0x0213

    #: Luxcom
    Luxcom = 0x0231

    #: Sigma Network Systems
    Sigma_Network_Systems = 0x0233

    #: Apple Client Server Protocol [Howard Ridenour]
    Apple_Client_Server_Protocol = 0x0235

    #: MPLS Unicast [:rfc:`3032`]
    MPLS_Unicast = 0x0281

    #: MPLS Multicast [:rfc:`3032`]
    MPLS_Multicast = 0x0283

    #: IEEE p1284.4 standard - data packets [Brian Batchelder]
    IEEE_p1284_4_standard_data_packets = 0x0285

    #: ETSI TETRA Network Protocol Type 1 [Seppo Nieminen]
    ETSI_TETRA_Network_Protocol_Type_1 = 0x0287

    #: Multichannel Flow Treatment Protocol [Pete McCann]
    Multichannel_Flow_Treatment_Protocol_0x0289 = 0x0289

    #: RTP IPHC Compressed TCP No Delta [:rfc:`3544`]
    RTP_IPHC_Compressed_TCP_No_Delta = 0x2063

    #: RTP IPHC Context State [:rfc:`3544`]
    RTP_IPHC_Context_State = 0x2065

    #: RTP IPHC Compressed UDP 16 [:rfc:`3544`]
    RTP_IPHC_Compressed_UDP_16 = 0x2067

    #: RTP IPHC Compressed RTP 16 [:rfc:`3544`]
    RTP_IPHC_Compressed_RTP_16 = 0x2069

    #: Cray Communications Control Protocol [Erling B Stage]
    Cray_Communications_Control_Protocol = 0x4001

    #: CDPD Mobile Network Registration Protocol [Frank Quick]
    CDPD_Mobile_Network_Registration_Protocol = 0x4003

    #: Expand accelerator protocol [Ilan Rachmani]
    Expand_accelerator_protocol = 0x4005

    #: ODSICP NCP [K Arvind]
    ODSICP_NCP = 0x4007

    #: DOCSIS DLL [Jason Gaedtke]
    DOCSIS_DLL = 0x4009

    #: Cetacean Network Detection Protocol [Curtis A Siller Jr]
    Cetacean_Network_Detection_Protocol = 0x400B

    #: Stacker LZS [:rfc:`1974`]
    Stacker_LZS = 0x4021

    #: RefTek Protocol [Robert Banfill]
    RefTek_Protocol = 0x4023

    #: Fibre Channel [Murali Rajagopal]
    Fibre_Channel = 0x4025

    #: OpenDOF [Bryant Eastham]
    OpenDOF = 0x4027

    #: Vendor-Specific Protocol (VSP) [:rfc:`3772`]
    Vendor_Specific_Protocol = 0x405B

    #: TRILL Link State Protocol (TLSP) [:rfc:`6361`]
    TRILL_Link_State_Protocol = 0x405D

    #: Internet Protocol Control Protocol [:rfc:`1332`]
    Internet_Protocol_Control_Protocol = 0x8021

    #: OSI Network Layer Control Protocol [:rfc:`1377`]
    OSI_Network_Layer_Control_Protocol = 0x8023

    #: Xerox NS IDP Control Protocol [:rfc:`1764`]
    Xerox_NS_IDP_Control_Protocol = 0x8025

    #: DECnet Phase IV Control Protocol [:rfc:`1762`]
    DECnet_Phase_IV_Control_Protocol = 0x8027

    #: Appletalk Control Protocol [:rfc:`1378`]
    Appletalk_Control_Protocol = 0x8029

    #: Novell IPX Control Protocol [:rfc:`1552`]
    Novell_IPX_Control_Protocol = 0x802B

    #: Reserved
    Reserved_0x802D = 0x802D

    #: Reserved
    Reserved_0x802F = 0x802F

    #: Bridging NCP [:rfc:`3518`]
    Bridging_NCP = 0x8031

    #: Stream Protocol Control Protocol
    Stream_Protocol_Control_Protocol = 0x8033

    #: Banyan Vines Control Protocol [:rfc:`1763`]
    Banyan_Vines_Control_Protocol = 0x8035

    #: Unassigned
    Unassigned_0x8037 = 0x8037

    #: Reserved
    Reserved_0x8039 = 0x8039

    #: Reserved
    Reserved_0x803B = 0x803B

    #: Multi-Link Control Protocol [:rfc:`1990`]
    Multi_Link_Control_Protocol = 0x803D

    #: NETBIOS Framing Control Protocol [:rfc:`2097`]
    NETBIOS_Framing_Control_Protocol = 0x803F

    #: Cisco Systems Control Protocol
    Cisco_Systems_Control_Protocol = 0x8041

    #: Ascom Timeplex
    Ascom_Timeplex_0x8043 = 0x8043

    #: Fujitsu LBLB Control Protocol
    Fujitsu_LBLB_Control_Protocol = 0x8045

    #: DCA Remote Lan Network Control Protocol (RLNCP)
    DCA_Remote_Lan_Network_Control_Protocol = 0x8047

    #: Serial Data Control Protocol (PPP-SDCP) [:rfc:`1963`]
    Serial_Data_Control_Protocol = 0x8049

    #: SNA over 802.2 Control Protocol [:rfc:`2043`]
    SNA_over_802_2_Control_Protocol = 0x804B

    #: SNA Control Protocol [:rfc:`2043`]
    SNA_Control_Protocol = 0x804D

    #: IP6 Header Compression Control Protocol
    IP6_Header_Compression_Control_Protocol = 0x804F

    #: KNX Bridging Control Protocol [ianp knxunix knx co]
    KNX_Bridging_Control_Protocol = 0x8051

    #: Encryption Control Protocol [:rfc:`1968`]
    Encryption_Control_Protocol = 0x8053

    #: Individual Link Encryption Control Protocol [:rfc:`1968`]
    Individual_Link_Encryption_Control_Protocol = 0x8055

    #: IPv6 Control Protocol [:rfc:`5072`]
    IPv6_Control_Protocol = 0x8057

    #: PPP Muxing Control Protocol [:rfc:`3153`]
    PPP_Muxing_Control_Protocol = 0x8059

    #: Vendor-Specific Network Control Protocol (VSNCP) [:rfc:`3772`]
    Vendor_Specific_Network_Control_Protocol = 0x805B

    #: TRILL Network Control Protocol (TNCP) [:rfc:`6361`]
    TRILL_Network_Control_Protocol = 0x805D

    #: Stampede Bridging Control Protocol
    Stampede_Bridging_Control_Protocol = 0x806F

    #: MP+ Control Protocol [:rfc:`1934`]
    MP_Control_Protocol = 0x8073

    #: Reserved [Karl Fox]
    Reserved_0x8071 = 0x8071

    #: Not Used - reserved [:rfc:`1661`]
    Not_Used_reserved_0x807D = 0x807D

    #: Unassigned
    Unassigned_0x8081 = 0x8081

    #: Unassigned
    Unassigned_0x8083 = 0x8083

    #: NTCITS IPI Control Protocol [Alan Ungar]
    NTCITS_IPI_Control_Protocol = 0x80C1

    #: Not Used - reserved [:rfc:`1661`]
    Not_Used_reserved_0x80CF = 0x80CF

    #: single link compression in multilink control [:rfc:`1962`]
    single_link_compression_in_multilink_control = 0x80FB

    #: Compression Control Protocol [:rfc:`1962`]
    Compression_Control_Protocol = 0x80FD

    #: Not Used - reserved [:rfc:`1661`]
    Not_Used_reserved_0x80FF = 0x80FF

    #: Cisco Discovery Protocol Control [Arun Sastry]
    Cisco_Discovery_Protocol_Control = 0x8207

    #: Netcs Twin Routing [Oliver Korfmacher]
    Netcs_Twin_Routing_0x8209 = 0x8209

    #: STP - Control Protocol [Ben Segal]
    STP_Control_Protocol = 0x820B

    #: EDPCP - Extreme Discovery Protocol Ctrl Prtcl [Don Grosser]
    EDPCP_Extreme_Discovery_Protocol_Ctrl_Prtcl = 0x820D

    #: Apple Client Server Protocol Control [Howard Ridenour]
    Apple_Client_Server_Protocol_Control = 0x8235

    #: MPLSCP [:rfc:`3032`]
    MPLSCP = 0x8281

    #: IEEE p1284.4 standard - Protocol Control [Brian Batchelder]
    IEEE_p1284_4_standard_Protocol_Control = 0x8285

    #: ETSI TETRA TNP1 Control Protocol [Seppo Nieminen]
    ETSI_TETRA_TNP1_Control_Protocol = 0x8287

    #: Multichannel Flow Treatment Protocol [Pete McCann]
    Multichannel_Flow_Treatment_Protocol_0x8289 = 0x8289

    #: Link Control Protocol [:rfc:`1661`]
    Link_Control_Protocol = 0xC021

    #: Password Authentication Protocol [:rfc:`1661`]
    Password_Authentication_Protocol = 0xC023

    #: Link Quality Report [:rfc:`1661`]
    Link_Quality_Report = 0xC025

    #: Shiva Password Authentication Protocol
    Shiva_Password_Authentication_Protocol = 0xC027

    #: CallBack Control Protocol (CBCP)
    CallBack_Control_Protocol = 0xC029

    #: BACP Bandwidth Allocation Control Protocol [:rfc:`2125`]
    BACP_Bandwidth_Allocation_Control_Protocol = 0xC02B

    #: BAP [:rfc:`2125`]
    BAP = 0xC02D

    #: Vendor-Specific Authentication Protocol (VSAP) [:rfc:`3772`]
    Vendor_Specific_Authentication_Protocol = 0xC05B

    #: Container Control Protocol [Ken funk com]
    Container_Control_Protocol = 0xC081

    #: Challenge Handshake Authentication Protocol [:rfc:`1661`]
    Challenge_Handshake_Authentication_Protocol = 0xC223

    #: RSA Authentication Protocol [Badari Narayana]
    RSA_Authentication_Protocol = 0xC225

    #: Extensible Authentication Protocol [:rfc:`3748`]
    Extensible_Authentication_Protocol = 0xC227

    #: Mitsubishi Security Info Exch Ptcl (SIEP) [Shoichiro Seno]
    Mitsubishi_Security_Info_Exch_Ptcl = 0xC229

    #: Stampede Bridging Authorization Protocol
    Stampede_Bridging_Authorization_Protocol = 0xC26F

    #: Proprietary Authentication Protocol [Ken funk com]
    Proprietary_Authentication_Protocol_0xC281 = 0xC281

    #: Proprietary Authentication Protocol [Wayne Tackabury]
    Proprietary_Authentication_Protocol_0xC283 = 0xC283

    #: Proprietary Node ID Authentication Protocol [Ken funk com]
    Proprietary_Node_ID_Authentication_Protocol = 0xC481

    @classmethod
    def _validate_value(cls, value: 'Any') -> 'None':
        """Reject ``value`` unless it passes the range check :meth:`_missing_` makes.

        Overrides :meth:`~pcapkit.corekit.enum.EnumLookup._validate_value`
        with that check and the message it raises, so
        :meth:`~pcapkit.corekit.enum.EnumRegistry.register` refuses exactly the
        values :meth:`~pcapkit.corekit.enum.EnumLookup.get` refuses, in the
        same words (:issue:`1816`).

        Args:
            value: Value about to be looked up or minted.

        Raises:
            EnumValueError: If ``value`` fails that check. A
                :exc:`ValueError`, so an ``except ValueError`` caller is
                unaffected.

        """
        if not (isinstance(value, int) and 0x0000 <= value <= 0xFFFF):
            raise EnumValueError('%r is not a valid %s' % (value, cls.__name__))

    @classmethod
    def _missing_(cls, value: 'int') -> 'Protocol':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0x0000 <= value <= 0xFFFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 0x0007 <= value <= 0x001F:
            #: Reserved (transparency inefficient) [:rfc:`1661`]
            return cls._unregistered_member(value, 'Reserved')
        if 0x028B <= value <= 0x1EFF:
            #: Reserved for compression inefficient
            return cls._unregistered_member(value, 'Reserved_for_compression_inefficient')
        if 0x8001 <= value <= 0x801F:
            #: Not Used - reserved [:rfc:`1661`]
            return cls._unregistered_member(value, 'Not_Used_reserved')
        return super()._missing_(value)
