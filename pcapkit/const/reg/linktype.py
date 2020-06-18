# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Link-Layer Header Type Values"""

from aenum import IntEnum, extend_enum

__all__ = ['LinkType']


class LinkType(IntEnum):
    """[LinkType] Link-Layer Header Type Values"""

    #: ``DLT_NULL``
    NULL = 0

    #: ``DLT_EN10MB``
    ETHERNET = 1

    #: ``DLT_AX25``
    AX25 = 3

    #: ``DLT_IEEE802``
    IEEE802_5 = 6

    #: ``DLT_ARCNET``
    ARCNET_BSD = 7

    #: ``DLT_SLIP``
    SLIP = 8

    #: ``DLT_PPP``
    PPP = 9

    #: ``DLT_FDDI``
    FDDI = 10

    #: ``DLT_PPP_SERIAL``
    PPP_HDLC = 50

    #: ``DLT_PPP_ETHER``
    PPP_ETHER = 51

    #: ``DLT_ATM_RFC1483``
    ATM_RFC1483 = 100

    #: ``DLT_RAW``
    RAW = 101

    #: ``DLT_C_HDLC``
    C_HDLC = 104

    #: ``DLT_IEEE802_11``
    IEEE802_11 = 105

    #: ``DLT_FRELAY``
    FRELAY = 107

    #: ``DLT_LOOP``
    LOOP = 108

    #: ``DLT_LINUX_SLL``
    LINUX_SLL = 113

    #: ``DLT_LTALK``
    LTALK = 114

    #: ``DLT_PFLOG``
    PFLOG = 117

    #: ``DLT_PRISM_HEADER``
    IEEE802_11_PRISM = 119

    #: ``DLT_IP_OVER_FC``
    IP_OVER_FC = 122

    #: ``DLT_SUNATM``
    SUNATM = 123

    #: ``DLT_IEEE802_11_RADIO``
    IEEE802_11_RADIOTAP = 127

    #: ``DLT_ARCNET_LINUX``
    ARCNET_LINUX = 129

    #: ``DLT_APPLE_IP_OVER_IEEE1394``
    APPLE_IP_OVER_IEEE1394 = 138

    #: ``DLT_MTP2_WITH_PHDR``
    MTP2_WITH_PHDR = 139

    #: ``DLT_MTP2``
    MTP2 = 140

    #: ``DLT_MTP3``
    MTP3 = 141

    #: ``DLT_SCCP``
    SCCP = 142

    #: ``DLT_DOCSIS``
    DOCSIS = 143

    #: ``DLT_LINUX_IRDA``
    LINUX_IRDA = 144

    #: ``DLT_USER_0``
    USER_0 = 147

    #: ``DLT_USER_1``
    USER_1 = 148

    #: ``DLT_USER_2``
    USER_2 = 149

    #: ``DLT_USER_3``
    USER_3 = 150

    #: ``DLT_USER_4``
    USER_4 = 151

    #: ``DLT_USER_5``
    USER_5 = 152

    #: ``DLT_USER_6``
    USER_6 = 153

    #: ``DLT_USER_7``
    USER_7 = 154

    #: ``DLT_USER_8``
    USER_8 = 155

    #: ``DLT_USER_9``
    USER_9 = 156

    #: ``DLT_USER_10``
    USER_10 = 157

    #: ``DLT_USER_11``
    USER_11 = 158

    #: ``DLT_USER_12``
    USER_12 = 159

    #: ``DLT_USER_13``
    USER_13 = 160

    #: ``DLT_USER_14``
    USER_14 = 161

    #: ``DLT_USER_15``
    USER_15 = 162

    #: ``DLT_IEEE802_11_RADIO_AVS``
    IEEE802_11_AVS = 163

    #: ``DLT_BACNET_MS_TP``
    BACNET_MS_TP = 165

    #: ``DLT_PPP_PPPD``
    PPP_PPPD = 166

    #: ``DLT_GPRS_LLC``
    GPRS_LLC = 169

    #: ``DLT_GPF_T``
    GPF_T = 170

    #: ``DLT_GPF_F``
    GPF_F = 171

    #: ``DLT_LINUX_LAPD``
    LINUX_LAPD = 177

    #: ``DLT_MFR``
    MFR = 182

    #: ``DLT_BLUETOOTH_HCI_H4``
    BLUETOOTH_HCI_H4 = 187

    #: ``DLT_USB_LINUX``
    USB_LINUX = 189

    #: ``DLT_PPI``
    PPI = 192

    #: ``DLT_IEEE802_15_4_WITHFCS``
    IEEE802_15_4_WITHFCS = 195

    #: ``DLT_SITA``
    SITA = 196

    #: ``DLT_ERF``
    ERF = 197

    #: ``DLT_BLUETOOTH_HCI_H4_WITH_PHDR``
    BLUETOOTH_HCI_H4_WITH_PHDR = 201

    #: ``DLT_AX25_KISS``
    AX25_KISS = 202

    #: ``DLT_LAPD``
    LAPD = 203

    #: ``DLT_PPP_WITH_DIR``
    PPP_WITH_DIR = 204

    #: ``DLT_C_HDLC_WITH_DIR``
    C_HDLC_WITH_DIR = 205

    #: ``DLT_FRELAY_WITH_DIR``
    FRELAY_WITH_DIR = 206

    #: ``DLT_LAPB_WITH_DIR``
    LAPB_WITH_DIR = 207

    #: ``DLT_IPMB_LINUX``
    IPMB_LINUX = 209

    #: ``DLT_IEEE802_15_4_NONASK_PHY``
    IEEE802_15_4_NONASK_PHY = 215

    #: ``DLT_USB_LINUX_MMAPPED``
    USB_LINUX_MMAPPED = 220

    #: ``DLT_FC_2``
    FC_2 = 224

    #: ``DLT_FC_2_WITH_FRAME_DELIMS``
    FC_2_WITH_FRAME_DELIMS = 225

    #: ``DLT_IPNET``
    IPNET = 226

    #: ``DLT_CAN_SOCKETCAN``
    CAN_SOCKETCAN = 227

    #: ``DLT_IPV4``
    IPV4 = 228

    #: ``DLT_IPV6``
    IPV6 = 229

    #: ``DLT_IEEE802_15_4_NOFCS``
    IEEE802_15_4_NOFCS = 230

    #: ``DLT_DBUS``
    DBUS = 231

    #: ``DLT_DVB_CI``
    DVB_CI = 235

    #: ``DLT_MUX27010``
    MUX27010 = 236

    #: ``DLT_STANAG_5066_D_PDU``
    STANAG_5066_D_PDU = 237

    #: ``DLT_NFLOG``
    NFLOG = 239

    #: ``DLT_NETANALYZER``
    NETANALYZER = 240

    #: ``DLT_NETANALYZER_TRANSPARENT``
    NETANALYZER_TRANSPARENT = 241

    #: ``DLT_IPOIB``
    IPOIB = 242

    #: ``DLT_MPEG_2_TS``
    MPEG_2_TS = 243

    #: ``DLT_NG40``
    NG40 = 244

    #: ``DLT_NFC_LLCP``
    NFC_LLCP = 245

    #: ``DLT_INFINIBAND``
    INFINIBAND = 247

    #: ``DLT_SCTP``
    SCTP = 248

    #: ``DLT_USBPCAP``
    USBPCAP = 249

    #: ``DLT_RTAC_SERIAL``
    RTAC_SERIAL = 250

    #: ``DLT_BLUETOOTH_LE_LL``
    BLUETOOTH_LE_LL = 251

    #: ``DLT_NETLINK``
    NETLINK = 253

    #: ``DLT_BLUETOOTH_LINUX_MONITOR``
    BLUETOOTH_LINUX_MONITOR = 254

    #: ``DLT_BLUETOOTH_BREDR_BB``
    BLUETOOTH_BREDR_BB = 255

    #: ``DLT_BLUETOOTH_LE_LL_WITH_PHDR``
    BLUETOOTH_LE_LL_WITH_PHDR = 256

    #: ``DLT_PROFIBUS_DL``
    PROFIBUS_DL = 257

    #: ``DLT_PKTAP``
    PKTAP = 258

    #: ``DLT_EPON``
    EPON = 259

    #: ``DLT_IPMI_HPM_2``
    IPMI_HPM_2 = 260

    #: ``DLT_ZWAVE_R1_R2``
    ZWAVE_R1_R2 = 261

    #: ``DLT_ZWAVE_R3``
    ZWAVE_R3 = 262

    #: ``DLT_WATTSTOPPER_DLM``
    WATTSTOPPER_DLM = 263

    #: ``DLT_ISO_14443``
    ISO_14443 = 264

    #: ``DLT_RDS``
    RDS = 265

    #: ``DLT_USB_DARWIN``
    USB_DARWIN = 266

    #: ``DLT_SDLC``
    SDLC = 268

    #: ``DLT_LORATAP``
    LORATAP = 270

    #: ``DLT_VSOCK``
    VSOCK = 271

    #: ``DLT_NORDIC_BLE``
    NORDIC_BLE = 272

    #: ``DLT_DOCSIS31_XRA31``
    DOCSIS31_XRA31 = 273

    #: ``DLT_ETHERNET_MPACKET``
    ETHERNET_MPACKET = 274

    #: ``DLT_DISPLAYPORT_AUX``
    DISPLAYPORT_AUX = 275

    #: ``DLT_LINUX_SLL2``
    LINUX_SLL2 = 276

    #: ``DLT_OPENVIZSLA``
    OPENVIZSLA = 278

    #: ``DLT_EBHSCR``
    EBHSCR = 279

    #: ``DLT_VPP_DISPATCH``
    VPP_DISPATCH = 280

    #: ``DLT_DSA_TAG_BRCM``
    DSA_TAG_BRCM = 281

    #: ``DLT_DSA_TAG_BRCM_PREPEND``
    DSA_TAG_BRCM_PREPEND = 282

    #: ``DLT_IEEE802_15_4_TAP``
    IEEE802_15_4_TAP = 283

    #: ``DLT_DSA_TAG_DSA``
    DSA_TAG_DSA = 284

    #: ``DLT_DSA_TAG_EDSA``
    DSA_TAG_EDSA = 285

    #: ``DLT_ELEE``
    ELEE = 286

    #: ``DLT_Z_WAVE_SERIAL``
    Z_WAVE_SERIAL = 287

    #: ``DLT_USB_2_0``
    USB_2_0 = 288

    #: ``DLT_ATSC_ALP``
    ATSC_ALP = 289

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return LinkType(key)
        if key not in LinkType._member_map_:  # pylint: disable=no-member
            extend_enum(LinkType, key, default)
        return LinkType[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0x00000000 <= value <= 0xFFFFFFFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned_%d' % value, value)
        return cls(value)
