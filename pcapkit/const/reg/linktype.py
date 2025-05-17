# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Link-Layer Header Type Values
===================================

.. module:: pcapkit.const.reg.linktype

This module contains the constant enumeration for **Link-Layer Header Type Values**,
which is automatically generated from :class:`pcapkit.vendor.reg.linktype.LinkType`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['LinkType']


class LinkType(IntEnum):
    """[LinkType] Link-Layer Header Type Values"""

    #: [``DLT_NULL``] BSD loopback encapsulation.
    NULL = 0

    #: [``DLT_EN10MB``] IEEE 802.3 Ethernet (10Mb, 100Mb, 1000Mb, and up); the 10MB
    #: in the DLT\_ name is historical.
    ETHERNET = 1

    #: [``DLT_EN3MB``] Experimental Ethernet (3Mb).
    EXP_ETHERNET = 2

    #: [``DLT_AX25``] AX.25 layer 2 packets,
    AX25 = 3

    #: [``DLT_PRONET``] Reserved for Proteon ProNET Token Ring.
    PRONET = 4

    #: [``DLT_CHAOS``] Reserved for MIT Chaosnet.
    CHAOS = 5

    #: [``DLT_IEEE802``] IEEE 802.5 Token Ring; the IEEE802, without \_5, in the
    #: DLT\_ name is historical.
    IEEE802_5 = 6

    #: [``DLT_ARCNET``] Reserved for ARCNET Data Packets with BSD encapsulation.
    ARCNET_BSD = 7

    #: [``DLT_SLIP``] SLIP, with a header giving packet direction
    SLIP = 8

    #: [``DLT_PPP``] PPP.
    PPP = 9

    #: [``DLT_FDDI``] FDDI, as specified by ANSI INCITS 239-1994.
    FDDI = 10

    #: [``DLT_REDBACK_SMARTEDGE``] Redback SmartEdge 400/800.
    REDBACK_SMARTEDGE = 32

    #: [``DLT_PPP_SERIAL``] PPP in HDLC-like framing.
    PPP_HDLC = 50

    #: [``DLT_PPP_ETHER``] PPPoE session packets.
    PPP_ETHER = 51

    #: [``DLT_SYMANTEC_FIREWALL``] Symantec Enterprise (ex-Axent Raptor) firewall.
    SYMANTEC_FIREWALL = 99

    #: [``DLT_ATM_RFC1483``] LLC/SNAP-encapsulated ATM
    ATM_RFC1483 = 100

    #: [``DLT_RAW``] Raw IP; the packet begins with an IPv4 or IPv6 header, with
    #: the version field of the header indicating whether it's an IPv4 or IPv6
    #: header.
    RAW = 101

    #: [``DLT_C_HDLC``] Cisco PPP with HDLC framing.
    C_HDLC = 104

    #: [``DLT_IEEE802_11``] IEEE 802.11 wireless LAN.
    IEEE802_11 = 105

    #: [``DLT_ATM_CLIP``] Linux Classical IP over ATM.
    ATM_CLIP = 106

    #: [``DLT_FRELAY``] Frame Relay LAPF.
    FRELAY = 107

    #: [``DLT_LOOP``] OpenBSD loopback encapsulation.
    LOOP = 108

    #: [``DLT_ENC``] Encapsulated packets for IPsec.
    ENC = 109

    #: [``DLT_HDLC``] Cisco HDLC.
    NETBSD_HDLC = 112

    #: [``DLT_LINUX_SLL``] Linux "cooked" capture encapsulation.
    LINUX_SLL = 113

    #: [``DLT_LTALK``] Apple LocalTalk packets.
    LTALK = 114

    #: [``DLT_ECONET``] Acorn Econet.
    ECONET = 115

    #: [``DLT_IPFILTER``] OpenBSD ipfilter.
    IPFILTER = 116

    #: [``DLT_PFLOG``] OpenBSD pflog; the link-layer header contains a struct
    #: pfloghdr structure, as defined by the host on that the file was saved. (This
    #: differs from operating system to operating system and release to release;
    #: there is nothing in the file to indicate what the layout of that structure
    #: is.)
    PFLOG = 117

    #: [``DLT_CISCO_IOS``] Cisco internal use.
    CISCO_IOS = 118

    #: [``DLT_PRISM_HEADER``] Prism monitor mode information, followed by an 802.11
    #: frame.
    IEEE802_11_PRISM = 119

    #: [``DLT_AIRONET_HEADER``] Reserved for Aironet 802.11 cards, with an Aironet
    #: link-layer header.
    AIRONET_HEADER = 120

    #: [``DLT_IP_OVER_FC``] IP and ATM over Fibre Channel.
    IP_OVER_FC = 122

    #: [``DLT_SUNATM``] ATM traffic captured from a SunATM device.
    SUNATM = 123

    #: [``DLT_RIO``] RapidIO.
    RIO = 124

    #: [``DLT_PCI_EXP``] PCI Express.
    PCI_EXP = 125

    #: [``DLT_AURORA``] Xilinx Aurora.
    AURORA = 126

    #: [``DLT_IEEE802_11_RADIO``] Radiotap link-layer information followed by an
    #: 802.11 header.
    IEEE802_11_RADIOTAP = 127

    #: [``DLT_TZSP``] Tazmen Sniffer Protocol (TZSP) is a generic encapsulation for
    #: any other link type, which includes a means to include meta-information with
    #: the packet, e.g. signal strength and channel for 802.11 packets.
    TZSP = 128

    #: [``DLT_ARCNET_LINUX``] ARCnet Data Packets with Linux encapsulation.
    ARCNET_LINUX = 129

    #: [``DLT_JUNIPER_MLPPP``] Juniper Networks private data link type.
    JUNIPER_MLPPP = 130

    #: [``DLT_JUNIPER_MLFR``] Juniper Networks private data link type.
    JUNIPER_MLFR = 131

    #: [``DLT_JUNIPER_ES``] Juniper Networks private data link type.
    JUNIPER_ES = 132

    #: [``DLT_JUNIPER_GGSN``] Juniper Networks private data link type.
    JUNIPER_GGSN = 133

    #: [``DLT_JUNIPER_MFR``] Juniper Networks private data link type.
    JUNIPER_MFR = 134

    #: [``DLT_JUNIPER_ATM2``] Juniper Networks private data link type.
    JUNIPER_ATM2 = 135

    #: [``DLT_JUNIPER_SERVICES``] Juniper Networks private data link type.
    JUNIPER_SERVICES = 136

    #: [``DLT_JUNIPER_ATM1``] Juniper Networks private data link type.
    JUNIPER_ATM1 = 137

    #: [``DLT_APPLE_IP_OVER_IEEE1394``] Apple IP-over-IEEE 1394 cooked header.
    APPLE_IP_OVER_IEEE1394 = 138

    #: [``DLT_MTP2_WITH_PHDR``] SS7 MTP2 packets, with a pseudo-header.
    MTP2_WITH_PHDR = 139

    #: [``DLT_MTP2``] SS7 MTP2 packets.
    MTP2 = 140

    #: [``DLT_MTP3``] SS7 MTP3 packets.
    MTP3 = 141

    #: [``DLT_SCCP``] SS7 SCCP packets.
    SCCP = 142

    #: [``DLT_DOCSIS``] DOCSIS MAC frames, as described by the DOCSIS 4.0 MAC and
    #: Upper Layer Protocols Interface Specification or earlier specifications for
    #: MAC frames.
    DOCSIS = 143

    #: [``DLT_LINUX_IRDA``] Linux-IrDA packets
    LINUX_IRDA = 144

    #: [``DLT_IBM_SP``] IBM SP switch.
    IBM_SP = 145

    #: [``DLT_IBM_SN``] IBM Next Federation switch.
    IBM_SN = 146

    #: [``DLT_USER0``] Reserved for private use; see above.
    USER0 = 147

    #: [``DLT_USER1``] Reserved for private use; see above.
    USER1 = 148

    #: [``DLT_USER2``] Reserved for private use; see above.
    USER2 = 149

    #: [``DLT_USER3``] Reserved for private use; see above.
    USER3 = 150

    #: [``DLT_USER4``] Reserved for private use; see above.
    USER4 = 151

    #: [``DLT_USER5``] Reserved for private use; see above.
    USER5 = 152

    #: [``DLT_USER6``] Reserved for private use; see above.
    USER6 = 153

    #: [``DLT_USER7``] Reserved for private use; see above.
    USER7 = 154

    #: [``DLT_USER8``] Reserved for private use; see above.
    USER8 = 155

    #: [``DLT_USER9``] Reserved for private use; see above.
    USER9 = 156

    #: [``DLT_USER10``] Reserved for private use; see above.
    USER10 = 157

    #: [``DLT_USER11``] Reserved for private use; see above.
    USER11 = 158

    #: [``DLT_USER12``] Reserved for private use; see above.
    USER12 = 159

    #: [``DLT_USER13``] Reserved for private use; see above.
    USER13 = 160

    #: [``DLT_USER14``] Reserved for private use; see above.
    USER14 = 161

    #: [``DLT_USER15``] Reserved for private use; see above.
    USER15 = 162

    #: [``DLT_IEEE802_11_RADIO_AVS``] AVS monitor mode information followed by an
    #: 802.11 header.
    IEEE802_11_AVS = 163

    #: [``DLT_JUNIPER_MONITOR``] Juniper Networks private data link type.
    JUNIPER_MONITOR = 164

    #: [``DLT_BACNET_MS_TP``] BACnet MS/TP frames.
    BACNET_MS_TP = 165

    #: [``DLT_PPP_PPPD``] PPP preceded by a direction octet and an HDLC-like
    #: control field.
    PPP_PPPD = 166

    #: [``DLT_JUNIPER_PPPOE``] Juniper Networks private data link type.
    JUNIPER_PPPOE = 167

    #: [``DLT_JUNIPER_PPPOE_ATM``] Juniper Networks private data link type.
    JUNIPER_PPPOE_ATM = 168

    #: [``DLT_GPRS_LLC``] General Packet Radio Service Logical Link Control, as
    #: defined by 3GPP TS 04.64.
    GPRS_LLC = 169

    #: [``DLT_GPF_T``] Transparent-mapped generic framing procedure, as specified
    #: by ITU-T Recommendation G.7041/Y.1303.
    GPF_T = 170

    #: [``DLT_GPF_F``] Frame-mapped generic framing procedure, as specified by
    #: ITU-T Recommendation G.7041/Y.1303.
    GPF_F = 171

    #: [``DLT_GCOM_T1E1``] Gcom's T1/E1 line monitoring equipment.
    GCOM_T1E1 = 172

    #: [``DLT_GCOM_SERIAL``] Gcom's T1/E1 line monitoring equipment.
    GCOM_SERIAL = 173

    #: [``DLT_JUNIPER_PIC_PEER``] Juniper Networks private data link type.
    JUNIPER_PIC_PEER = 174

    #: [``DLT_ERF_ETH``] Endace ERF records of type TYPE\_ETH.
    ERF_ETH = 175

    #: [``DLT_ERF_POS``] Endace ERF records of type TYPE\_POS\_HDLC.
    ERF_POS = 176

    #: [``DLT_LINUX_LAPD``] Linux vISDN LAPD frames
    LINUX_LAPD = 177

    #: [``DLT_JUNIPER_ETHER``] Juniper Networks private data link type. Ethernet
    #: frames prepended with meta-information.
    JUNIPER_ETHER = 178

    #: [``DLT_JUNIPER_PPP``] Juniper Networks private data link type. PPP frames
    #: prepended with meta-information.
    JUNIPER_PPP = 179

    #: [``DLT_JUNIPER_FRELAY``] Juniper Networks private data link type. Frame
    #: Relay frames prepended with meta-information.
    JUNIPER_FRELAY = 180

    #: [``DLT_JUNIPER_CHDLC``] Juniper Networks private data link type. C-HDLC
    #: frames prepended with meta-information.
    JUNIPER_CHDLC = 181

    #: [``DLT_MFR``] FRF.16.1 Multi-Link Frame Relay frames.
    MFR = 182

    #: [``DLT_JUNIPER_VP``] Juniper Networks private data link type.
    JUNIPER_VP = 183

    #: [``DLT_A429``] ARINC 429 frames. Every frame contains a 32-bit A429 word, in
    #: little-endian format.
    A429 = 184

    #: [``DLT_A653_ICM``] ARINC 653 interpartition communication messages. Please
    #: refer to the A653-1 standard for more information.
    A653_ICM = 185

    #: [``DLT_USB_FREEBSD``] USB with FreeBSD header.
    USB_FREEBSD = 186

    #: [``DLT_BLUETOOTH_HCI_H4``] Bluetooth HCI UART Transport Layer packets.
    BLUETOOTH_HCI_H4 = 187

    #: [``DLT_IEEE802_16_MAC_CPS``] IEEE 802.16 MAC Common Part Sublayer.
    IEEE802_16_MAC_CPS = 188

    #: [``DLT_USB_LINUX``] USB packets, beginning with a Linux USB header.
    USB_LINUX = 189

    #: [``DLT_CAN20B``] Controller Area Network (CAN) v. 2.0B.
    CAN20B = 190

    #: [``DLT_IEEE802_15_4_LINUX``] IEEE 802.15.4, with address fields padded, as
    #: is done by Linux drivers.
    IEEE802_15_4_LINUX = 191

    #: [``DLT_PPI``] Per-Packet Information header preceding packet data.
    PPI = 192

    #: [``DLT_IEEE802_16_MAC_CPS_RADIO``] IEEE 802.16 MAC Common Part Sublayer plus
    #: radiotap header.
    IEEE802_16_MAC_CPS_RADIO = 193

    #: [``DLT_JUNIPER_ISM``] Juniper Networks private data link type.
    JUNIPER_ISM = 194

    #: [``DLT_IEEE802_15_4_WITHFCS``] IEEE 802.15.4 packets with FCS.
    IEEE802_15_4_WITHFCS = 195

    #: [``DLT_SITA``] Various link-layer types, with a pseudo-header, for SITA.
    SITA = 196

    #: [``DLT_ERF``] Endace ERF records.
    ERF = 197

    #: [``DLT_RAIF1``] Special header prepended to Ethernet packets when capturing
    #: from a u10 Networks board.
    RAIF1 = 198

    #: [``DLT_IPMB_KONTRON``] IPMB packet for IPMI, beginning with a 2-byte header,
    #: followed by the I2C slave address, followed by the netFn and LUN, etc…
    IPMB_KONTRON = 199

    #: [``DLT_JUNIPER_ST``] Juniper Networks private data link type.
    JUNIPER_ST = 200

    #: [``DLT_BLUETOOTH_HCI_H4_WITH_PHDR``] Bluetooth HCI UART Transport Layer
    #: packets with a direction pseudo-header.
    BLUETOOTH_HCI_H4_WITH_PHDR = 201

    #: [``DLT_AX25_KISS``] KISS frames between a host and an AX.25 TNC.
    AX25_KISS = 202

    #: [``DLT_LAPD``] Q.921 LAPD frames.
    LAPD = 203

    #: [``DLT_PPP_WITH_DIR``] PPP, with a direction header.
    PPP_WITH_DIR = 204

    #: [``DLT_C_HDLC_WITH_DIR``] Cisco PPP with HDLC framing, with a direction
    #: header.
    C_HDLC_WITH_DIR = 205

    #: [``DLT_FRELAY_WITH_DIR``] Frame Relay LAPF, with a direction header.
    FRELAY_WITH_DIR = 206

    #: [``DLT_LAPB_WITH_DIR``] X.25 LAPB, with a direction header.
    LAPB_WITH_DIR = 207

    #: [``DLT_IPMB_LINUX``] Legacy names (do not use) for Linux I2C below.
    IPMB_LINUX = 209

    #: [``DLT_I2C_LINUX``] Linux I2C packets.
    I2C_LINUX = 209

    #: [``DLT_FLEXRAY``] FlexRay automotive bus frames or symbols, preceded by a
    #: pseudo-header
    FLEXRAY = 210

    #: [``DLT_MOST``] Media Oriented Systems Transport (MOST) bus for multimedia
    #: transport.
    MOST = 211

    #: [``DLT_LIN``] Local Interconnect Network (LIN) automotive bus, with a
    #: metadata header
    LIN = 212

    #: [``DLT_X2E_SERIAL``] X2E-private data link type used for serial line
    #: capture.
    X2E_SERIAL = 213

    #: [``DLT_X2E_XORAYA``] X2E-private data link type used for the Xoraya data
    #: logger family.
    X2E_XORAYA = 214

    #: [``DLT_IEEE802_15_4_NONASK_PHY``] IEEE 802.15.4 packets with PHY header.
    IEEE802_15_4_NONASK_PHY = 215

    #: [``DLT_LINUX_EVDEV``] Linux evdev events from /dev/input/eventN devices.
    LINUX_EVDEV = 216

    #: [``DLT_GSMTAP_UM``] GSM Um interface, preceded by a "gsmtap" header.
    GSMTAP_UM = 217

    #: [``DLT_GSMTAP_ABIS``] GSM Abis interface, preceded by a "gsmtap" header.
    GSMTAP_ABIS = 218

    #: [``DLT_MPLS``] MPLS, with an MPLS label as the link-layer header.
    MPLS = 219

    #: [``DLT_USB_LINUX_MMAPPED``] USB packets, beginning with an extended Linux
    #: USB header.
    USB_LINUX_MMAPPED = 220

    #: [``DLT_DECT``] DECT packets, with a pseudo-header.
    DECT = 221

    #: [``DLT_AOS``] AOS Space Data Link Protocol.
    AOS = 222

    #: [``DLT_WIHART``] WirelessHART (Highway Addressable Remote Transducer) from
    #: the HART Communication Foundation (IEC/PAS 62591).
    WIHART = 223

    #: [``DLT_FC_2``] Fibre Channel FC-2 frames.
    FC_2 = 224

    #: [``DLT_FC_2_WITH_FRAME_DELIMS``] Fibre Channel FC-2 frames with SOF and EOF.
    FC_2_WITH_FRAME_DELIMS = 225

    #: [``DLT_IPNET``] Solaris ipnet
    IPNET = 226

    #: [``DLT_CAN_SOCKETCAN``] Controller Area Network (CAN) frames, with a
    #: metadata header.
    CAN_SOCKETCAN = 227

    #: [``DLT_IPV4``] Raw IPv4; the packet begins with an IPv4 header.
    IPV4 = 228

    #: [``DLT_IPV6``] Raw IPv6; the packet begins with an IPv6 header.
    IPV6 = 229

    #: [``DLT_IEEE802_15_4_NOFCS``] IEEE 802.15.4 packets without FCS.
    IEEE802_15_4_NOFCS = 230

    #: [``DLT_DBUS``] Raw D-Bus messages.
    DBUS = 231

    #: [``DLT_JUNIPER_VS``] Juniper Networks private data link type.
    JUNIPER_VS = 232

    #: [``DLT_JUNIPER_SRX_E2E``] Juniper Networks private data link type.
    JUNIPER_SRX_E2E = 233

    #: [``DLT_JUNIPER_FIBRECHANNEL``] Juniper Networks private data link type.
    JUNIPER_FIBRECHANNEL = 234

    #: [``DLT_DVB_CI``] DVB-CI messages, with a pseudo-header.
    DVB_CI = 235

    #: [``DLT_MUX27010``] Variant of 3GPP TS 27.010 multiplexing protocol.
    MUX27010 = 236

    #: [``DLT_STANAG_5066_D_PDU``] STANAG 5066 D\_PDUs.
    STANAG_5066_D_PDU = 237

    #: [``DLT_JUNIPER_ATM_CEMIC``] Juniper Networks private data link type.
    JUNIPER_ATM_CEMIC = 238

    #: [``DLT_NFLOG``] Linux netlink NETLINK NFLOG socket log messages.
    NFLOG = 239

    #: [``DLT_NETANALYZER``] Ethernet frames with Hilscher netANALYZER pseudo-
    #: header.
    NETANALYZER = 240

    #: [``DLT_NETANALYZER_TRANSPARENT``] Ethernet frames with netANALYZER pseudo-
    #: header, preamble and SFD, preceded by a Hilscher.
    NETANALYZER_TRANSPARENT = 241

    #: [``DLT_IPOIB``] IP-over-InfiniBand.
    IPOIB = 242

    #: [``DLT_MPEG_2_TS``] MPEG-2 Transport Stream transport packets.
    MPEG_2_TS = 243

    #: [``DLT_NG40``] Frames from ng4T GmbH's ng40 protocol tester.
    NG40 = 244

    #: [``DLT_NFC_LLCP``] NFC Logical Link Control Protocol frames, with a pseudo-
    #: header.
    NFC_LLCP = 245

    #: Packet filter state syncing.
    PFSYNC = 246

    #: [``DLT_INFINIBAND``] InfiniBand data packets.
    INFINIBAND = 247

    #: [``DLT_SCTP``] SCTP packets, as defined by RFC 4960, with no lower-level
    #: protocols such as IPv4 or IPv6.
    SCTP = 248

    #: [``DLT_USBPCAP``] USB packets, beginning with a USBPcap header.
    USBPCAP = 249

    #: [``DLT_RTAC_SERIAL``] Serial-line packets from the Schweitzer Engineering
    #: Laboratories "RTAC" product.
    RTAC_SERIAL = 250

    #: [``DLT_BLUETOOTH_LE_LL``] Bluetooth Low Energy link-layer packets.
    BLUETOOTH_LE_LL = 251

    #: [``DLT_WIRESHARK_UPPER_PDU``] Upper-protocol layer PDU saves from Wireshark;
    #: the actual contents are determined by two tags, one or more of which is
    #: stored with each packet.
    WIRESHARK_UPPER_PDU = 252

    #: [``DLT_NETLINK``] Linux Netlink capture encapsulation.
    NETLINK = 253

    #: [``DLT_BLUETOOTH_LINUX_MONITOR``] Bluetooth Linux Monitor.
    BLUETOOTH_LINUX_MONITOR = 254

    #: [``DLT_BLUETOOTH_BREDR_BB``] Bluetooth Basic Rate and Enhanced Data Rate
    #: baseband packets.
    BLUETOOTH_BREDR_BB = 255

    #: [``DLT_BLUETOOTH_LE_LL_WITH_PHDR``] Bluetooth Low Energy link-layer packets,
    #: with a pseudo-header.
    BLUETOOTH_LE_LL_WITH_PHDR = 256

    #: [``DLT_PROFIBUS_DL``] PROFIBUS data link layer packets.
    PROFIBUS_DL = 257

    #: [``DLT_PKTAP``] Apple PKTAP capture encapsulation.
    PKTAP = 258

    #: [``DLT_EPON``] Ethernet-over-passive-optical-network packets, including
    #: preamble octets.
    EPON = 259

    #: [``DLT_IPMI_HPM_2``] IPMI HPM.2 trace packets.
    IPMI_HPM_2 = 260

    #: [``DLT_ZWAVE_R1_R2``] Z-Wave RF profile R1 and R2 packets.
    ZWAVE_R1_R2 = 261

    #: [``DLT_ZWAVE_R3``] Z-Wave RF profile R3 packets.
    ZWAVE_R3 = 262

    #: [``DLT_WATTSTOPPER_DLM``] WattStopper Digital Lighting Management (DLM) and
    #: Legrand Nitoo Open protocol packets.
    WATTSTOPPER_DLM = 263

    #: [``DLT_ISO_14443``] Messages between ISO 14443 contactless smartcards
    #: (Proximity Integrated Circuit Card, PICC) and card readers (Proximity
    #: Coupling Device, PCD), with the message format specified by the PCAP format
    #: for ISO14443 specification.
    ISO_14443 = 264

    #: [``DLT_RDS``] IEC 62106 Radio data system (RDS) groups.
    RDS = 265

    #: [``DLT_USB_DARWIN``] USB packets captured on a Darwin-based operating system
    #: (macOS, etc.).
    USB_DARWIN = 266

    #: [``DLT_OPENFLOW``] OpenFlow messages with an additional 12-octet header, as
    #: used in OpenBSD switch interface monitoring.
    OPENFLOW = 267

    #: [``DLT_SDLC``] SNA SDLC packets
    SDLC = 268

    #: [``DLT_TI_LLN_SNIFFER``] TI LLN sniffer frames.
    TI_LLN_SNIFFER = 269

    #: [``DLT_LORATAP``] LoRaWan packets with a LoRaTap pseudo-header.
    LORATAP = 270

    #: [``DLT_VSOCK``] Protocol for communication between host and guest machines
    #: in VMware and KVM hypervisors.
    VSOCK = 271

    #: [``DLT_NORDIC_BLE``] Messages to and from a Nordic Semiconductor nRF Sniffer
    #: for Bluetooth LE packets.
    NORDIC_BLE = 272

    #: [``DLT_DOCSIS31_XRA31``] DOCSIS packets and bursts, preceded by a pseudo-
    #: header giving metadata about the packet.
    DOCSIS31_XRA31 = 273

    #: [``DLT_ETHERNET_MPACKET``] IEEE 802.3 mPackets.
    ETHERNET_MPACKET = 274

    #: [``DLT_DISPLAYPORT_AUX``] DisplayPort AUX channel monitoring messages.
    DISPLAYPORT_AUX = 275

    #: [``DLT_LINUX_SLL2``] Linux "cooked" capture encapsulation v2.
    LINUX_SLL2 = 276

    #: [``DLT_SERCOS_MONITOR``] Sercos Monitor.
    SERCOS_MONITOR = 277

    #: [``DLT_OPENVIZSLA``] OpenVizsla FPGA-based USB sniffer frames.
    OPENVIZSLA = 278

    #: [``DLT_EBHSCR``] Elektrobit High Speed Capture and Replay (EBHSCR) format.
    EBHSCR = 279

    #: [``DLT_VPP_DISPATCH``] Records in traces from the http://fd.io VPP graph
    #: dispatch tracer, in the the graph dispatcher trace format.
    VPP_DISPATCH = 280

    #: [``DLT_DSA_TAG_BRCM``] Ethernet frames, with a Broadcom switch tag inserted.
    DSA_TAG_BRCM = 281

    #: [``DLT_DSA_TAG_BRCM_PREPEND``] Ethernet frames, with a Broadcom switch tag
    #: prepended.
    DSA_TAG_BRCM_PREPEND = 282

    #: [``DLT_IEEE802_15_4_TAP``] IEEE 802.15.4 packets, with a pseudo-header
    #: containing TLVs with metadata preceding the 802.15.4 header.
    IEEE802_15_4_TAP = 283

    #: [``DLT_DSA_TAG_DSA``] Ethernet frames, with a Marvell DSA switch tag
    #: inserted.
    DSA_TAG_DSA = 284

    #: [``DLT_DSA_TAG_EDSA``] Ethernet frames, with a Marvell EDSA switch tag
    #: inserted.
    DSA_TAG_EDSA = 285

    #: [``DLT_ELEE``] Reserved for ELEE lawful intercept protocol.
    ELEE = 286

    #: [``DLT_Z_WAVE_SERIAL``] Serial frames transmitted between a host and a
    #: Z-Wave chip over an RS-232 or USB serial connection, as described in section
    #: 5 of the Z-Wave Serial API Host Application Programming Guide.
    Z_WAVE_SERIAL = 287

    #: [``DLT_USB_2_0``] USB 2.0, 1.1, or 1.0 packets.
    USB_2_0 = 288

    #: [``DLT_ATSC_ALP``] ATSC Link-Layer Protocol frames.
    ATSC_ALP = 289

    #: [``DLT_ETW``] Event Tracing for Windows messages.
    ETW = 290

    #: [``DLT_NETANALYZER_NG``] Reserved for Hilscher Gesellschaft fuer
    #: Systemautomation mbH netANALYZER NG hardware and software.
    NETANALYZER_NG = 291

    #: [``DLT_ZBOSS_NCP``] ZBOSS NCP Serial Protocol, with a pseudo-header.
    ZBOSS_NCP = 292

    #: [``DLT_USB_2_0_LOW_SPEED``] Low-Speed USB 2.0, 1.1, or 1.0 packets..
    USB_2_0_LOW_SPEED = 293

    #: [``DLT_USB_2_0_FULL_SPEED``] Full-Speed USB 2.0, 1.1, or 1.0 packets.
    USB_2_0_FULL_SPEED = 294

    #: [``DLT_USB_2_0_HIGH_SPEED``] High-Speed USB 2.0 packets.
    USB_2_0_HIGH_SPEED = 295

    #: [``DLT_AUERSWALD_LOG``] Auerswald Logger Protocol packets.
    AUERSWALD_LOG = 296

    #: [``DLT_ZWAVE_TAP``] Z-Wave packets, with a metadata header.
    ZWAVE_TAP = 297

    #: [``DLT_SILABS_DEBUG_CHANNEL``] Silicon Labs debug channel protocol, as
    #: described in the specification.
    SILABS_DEBUG_CHANNEL = 298

    #: [``DLT_FIRA_UCI``] Ultra-wideband (UWB) controller interface protocol (UCI).
    FIRA_UCI = 299

    #: [``DLT_MDB``] MDB (Multi-Drop Bus) messages, with a pseudo-header.
    MDB = 300

    #: [``DLT_DECT_NR``] DECT-2020 New Radio (NR) MAC layer.
    DECT_NR = 301

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'LinkType':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return LinkType(key)
        if key not in LinkType._member_map_:  # pylint: disable=no-member
            return extend_enum(LinkType, key, default)
        return LinkType[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'LinkType':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0x00000000 <= value <= 0xFFFFFFFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return extend_enum(cls, 'Unassigned_%d' % value, value)
