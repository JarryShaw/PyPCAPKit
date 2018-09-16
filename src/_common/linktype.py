# -*- coding: utf-8 -*-


from aenum import IntEnum, extend_enum


class LinkType(IntEnum):
    """Enumeration class for LinkType."""
    _ignore_ = 'LinkType _'
    LinkType = vars()

    # Link-Layer Header Type Values
    LinkType['NULL'] = 0                                                        # DLT_NULL
    LinkType['ETHERNET'] = 1                                                    # DLT_EN10MB
    LinkType['AX25'] = 3                                                        # DLT_AX25
    LinkType['IEEE802_5'] = 6                                                   # DLT_IEEE802
    LinkType['ARCNET_BSD'] = 7                                                  # DLT_ARCNET
    LinkType['SLIP'] = 8                                                        # DLT_SLIP
    LinkType['PPP'] = 9                                                         # DLT_PPP
    LinkType['FDDI'] = 10                                                       # DLT_FDDI
    LinkType['PPP_HDLC'] = 50                                                   # DLT_PPP_SERIAL
    LinkType['PPP_ETHER'] = 51                                                  # DLT_PPP_ETHER
    LinkType['ATM_RFC1483'] = 100                                               # DLT_ATM_RFC1483
    LinkType['RAW'] = 101                                                       # DLT_RAW
    LinkType['C_HDLC'] = 104                                                    # DLT_C_HDLC
    LinkType['IEEE802_11'] = 105                                                # DLT_IEEE802_11
    LinkType['FRELAY'] = 107                                                    # DLT_FRELAY
    LinkType['LOOP'] = 108                                                      # DLT_LOOP
    LinkType['LINUX_SLL'] = 113                                                 # DLT_LINUX_SLL
    LinkType['LTALK'] = 114                                                     # DLT_LTALK
    LinkType['PFLOG'] = 117                                                     # DLT_PFLOG
    LinkType['IEEE802_11_PRISM'] = 119                                          # DLT_PRISM_HEADER
    LinkType['IP_OVER_FC'] = 122                                                # DLT_IP_OVER_FC
    LinkType['SUNATM'] = 123                                                    # DLT_SUNATM
    LinkType['IEEE802_11_RADIOTAP'] = 127                                       # DLT_IEEE802_11_RADIO
    LinkType['ARCNET_LINUX'] = 129                                              # DLT_ARCNET_LINUX
    LinkType['APPLE_IP_OVER_IEEE1394'] = 138                                    # DLT_APPLE_IP_OVER_IEEE1394
    LinkType['MTP2_WITH_PHDR'] = 139                                            # DLT_MTP2_WITH_PHDR
    LinkType['MTP2'] = 140                                                      # DLT_MTP2
    LinkType['MTP3'] = 141                                                      # DLT_MTP3
    LinkType['SCCP'] = 142                                                      # DLT_SCCP
    LinkType['DOCSIS'] = 143                                                    # DLT_DOCSIS
    LinkType['LINUX_IRDA'] = 144                                                # DLT_LINUX_IRDA
    LinkType['USER0'] = 147                                                     # DLT_USER{code-start}
    LinkType['USER1'] = 148                                                     # DLT_USER{code-start}
    LinkType['USER2'] = 149                                                     # DLT_USER{code-start}
    LinkType['USER3'] = 150                                                     # DLT_USER{code-start}
    LinkType['USER4'] = 151                                                     # DLT_USER{code-start}
    LinkType['USER5'] = 152                                                     # DLT_USER{code-start}
    LinkType['USER6'] = 153                                                     # DLT_USER{code-start}
    LinkType['USER7'] = 154                                                     # DLT_USER{code-start}
    LinkType['USER8'] = 155                                                     # DLT_USER{code-start}
    LinkType['USER9'] = 156                                                     # DLT_USER{code-start}
    LinkType['USER10'] = 157                                                    # DLT_USER{code-start}
    LinkType['USER11'] = 158                                                    # DLT_USER{code-start}
    LinkType['USER12'] = 159                                                    # DLT_USER{code-start}
    LinkType['USER13'] = 160                                                    # DLT_USER{code-start}
    LinkType['USER14'] = 161                                                    # DLT_USER{code-start}
    LinkType['USER15'] = 162                                                    # DLT_USER{code-start}
    LinkType['IEEE802_11_AVS'] = 163                                            # DLT_IEEE802_11_RADIO_AVS
    LinkType['BACNET_MS_TP'] = 165                                              # DLT_BACNET_MS_TP
    LinkType['PPP_PPPD'] = 166                                                  # DLT_PPP_PPPD
    LinkType['GPRS_LLC'] = 169                                                  # DLT_GPRS_LLC
    LinkType['GPF_T'] = 170                                                     # DLT_GPF_T
    LinkType['GPF_F'] = 171                                                     # DLT_GPF_F
    LinkType['LINUX_LAPD'] = 177                                                # DLT_LINUX_LAPD
    LinkType['BLUETOOTH_HCI_H4'] = 187                                          # DLT_BLUETOOTH_HCI_H4
    LinkType['USB_LINUX'] = 189                                                 # DLT_USB_LINUX
    LinkType['PPI'] = 192                                                       # DLT_PPI
    LinkType['IEEE802_15_4_WITHFCS'] = 195                                      # DLT_IEEE802_15_4_WITHFCS
    LinkType['SITA'] = 196                                                      # DLT_SITA
    LinkType['ERF'] = 197                                                       # DLT_ERF
    LinkType['BLUETOOTH_HCI_H4_WITH_PHDR'] = 201                                # DLT_BLUETOOTH_HCI_H4_WITH_PHDR
    LinkType['AX25_KISS'] = 202                                                 # DLT_AX25_KISS
    LinkType['LAPD'] = 203                                                      # DLT_LAPD
    LinkType['PPP_WITH_DIR'] = 204                                              # DLT_PPP_WITH_DIR
    LinkType['C_HDLC_WITH_DIR'] = 205                                           # DLT_C_HDLC_WITH_DIR
    LinkType['FRELAY_WITH_DIR'] = 206                                           # DLT_FRELAY_WITH_DIR
    LinkType['IPMB_LINUX'] = 209                                                # DLT_IPMB_LINUX
    LinkType['IEEE802_15_4_NONASK_PHY'] = 215                                   # DLT_IEEE802_15_4_NONASK_PHY
    LinkType['USB_LINUX_MMAPPED'] = 220                                         # DLT_USB_LINUX_MMAPPED
    LinkType['FC_2'] = 224                                                      # DLT_FC_2
    LinkType['FC_2_WITH_FRAME_DELIMS'] = 225                                    # DLT_FC_2_WITH_FRAME_DELIMS
    LinkType['IPNET'] = 226                                                     # DLT_IPNET
    LinkType['CAN_SOCKETCAN'] = 227                                             # DLT_CAN_SOCKETCAN
    LinkType['IPV4'] = 228                                                      # DLT_IPV4
    LinkType['IPV6'] = 229                                                      # DLT_IPV6
    LinkType['IEEE802_15_4_NOFCS'] = 230                                        # DLT_IEEE802_15_4_NOFCS
    LinkType['DBUS'] = 231                                                      # DLT_DBUS
    LinkType['DVB_CI'] = 235                                                    # DLT_DVB_CI
    LinkType['MUX27010'] = 236                                                  # DLT_MUX27010
    LinkType['STANAG_5066_D_PDU'] = 237                                         # DLT_STANAG_5066_D_PDU
    LinkType['NFLOG'] = 239                                                     # DLT_NFLOG
    LinkType['NETANALYZER'] = 240                                               # DLT_NETANALYZER
    LinkType['NETANALYZER_TRANSPARENT'] = 241                                   # DLT_NETANALYZER_TRANSPARENT
    LinkType['IPOIB'] = 242                                                     # DLT_IPOIB
    LinkType['MPEG_2_TS'] = 243                                                 # DLT_MPEG_2_TS
    LinkType['NG40'] = 244                                                      # DLT_NG40
    LinkType['NFC_LLCP'] = 245                                                  # DLT_NFC_LLCP
    LinkType['INFINIBAND'] = 247                                                # DLT_INFINIBAND
    LinkType['SCTP'] = 248                                                      # DLT_SCTP
    LinkType['USBPCAP'] = 249                                                   # DLT_USBPCAP
    LinkType['RTAC_SERIAL'] = 250                                               # DLT_RTAC_SERIAL
    LinkType['BLUETOOTH_LE_LL'] = 251                                           # DLT_BLUETOOTH_LE_LL
    LinkType['NETLINK'] = 253                                                   # DLT_NETLINK
    LinkType['BLUETOOTH_LINUX_MONITOR'] = 254                                   # DLT_BLUETOOTH_LINUX_MONITOR
    LinkType['BLUETOOTH_BREDR_BB'] = 255                                        # DLT_BLUETOOTH_BREDR_BB
    LinkType['BLUETOOTH_LE_LL_WITH_PHDR'] = 256                                 # DLT_BLUETOOTH_LE_LL_WITH_PHDR
    LinkType['PROFIBUS_DL'] = 257                                               # DLT_PROFIBUS_DL
    LinkType['PKTAP'] = 258                                                     # DLT_PKTAP
    LinkType['EPON'] = 259                                                      # DLT_EPON
    LinkType['IPMI_HPM_2'] = 260                                                # DLT_IPMI_HPM_2
    LinkType['ZWAVE_R1_R2'] = 261                                               # DLT_ZWAVE_R1_R2
    LinkType['ZWAVE_R3'] = 262                                                  # DLT_ZWAVE_R3
    LinkType['WATTSTOPPER_DLM'] = 263                                           # DLT_WATTSTOPPER_DLM
    LinkType['ISO_14443'] = 264                                                 # DLT_ISO_14443
    LinkType['RDS'] = 265                                                       # DLT_RDS
    LinkType['USB_DARWIN'] = 266                                                # DLT_USB_DARWIN
    LinkType['SDLC'] = 268                                                      # DLT_SDLC
    LinkType['LORATAP'] = 270                                                   # DLT_LORATAP
    LinkType['VSOCK'] = 271                                                     # DLT_VSOCK
    LinkType['NORDIC_BLE'] = 272                                                # DLT_NORDIC_BLE
    LinkType['DOCSIS31_XRA31'] = 273                                            # DLT_DOCSIS31_XRA31
    LinkType['ETHERNET_MPACKET'] = 274                                          # DLT_ETHERNET_MPACKET
    LinkType['DISPLAYPORT_AUX'] = 275                                           # DLT_DISPLAYPORT_AUX
    LinkType['LINUX_SLL2'] = 276                                                # DLT_LINUX_SLL2
    LinkType['OPENVIZSLA'] = 278                                                # DLT_OPENVIZSLA

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return LinkType(key)
        if key not in LinkType._member_map_:
            extend_enum(LinkType, key, default)
        return LinkType[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 0xFFFF_FFFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned [%d]' % value, value)
        return cls(value)
