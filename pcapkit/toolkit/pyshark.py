# -*- coding: utf-8 -*-
"""PyShark Tools
===================

:mod:`pcapkit.toolkit.pyshark` contains the adapters for the `PyShark`_ engine.
The reassembly and flow tracing adapters return the data their
:mod:`pcapkit.foundation` counterpart consumes, or :data:`None` if the frame
cannot be used for it.

.. _PyShark: https://kiminewt.github.io/pyshark

.. note::

   Due to the lack of functionality of `PyShark`_, some
   functions of :mod:`pcapkit` may not be available with
   the `PyShark`_ engine.

"""
import decimal
import ipaddress
from typing import TYPE_CHECKING, NamedTuple

from pcapkit.const.reg.ethertype import EtherType as Enum_EtherType
from pcapkit.const.reg.linktype import LinkType as Enum_LinkType
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.foundation.traceflow.data.tcp import Packet as TF_TCP_Packet
from pcapkit.protocols.link.loopback import family_byteorder
from pcapkit.toolkit.pypcapfile import (IP_TUNNELS, IPV4_EXTENSION_HEADERS, IPV4_HEADER_LEN,
                                        TCP_MIN_HEADER_LEN, VLAN_TAG_LEN, VLAN_TAGS,
                                        _default_accepts, _upper_layer)
from pcapkit.utilities.exceptions import MissingKeyError, ProtocolError

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv6Address
    from typing import Any, Callable, Optional

    from pyshark.packet.packet import Packet

__all__ = ['packet2dict', 'tcp_traceflow', 'Captured', 'ENCAP_TYPE_TO_LINKTYPE', 'FILTER_NAME_TO_LINKTYPE']

#: ``frame.encap_type`` -- Wireshark's internal ``WTAP_ENCAP_*`` number, which :mod:`pyshark`
#: exposes as ``packet.frame_info.encap_type`` -- to the matching
#: :class:`~pcapkit.const.reg.linktype.LinkType` member. This is :func:`tcp_traceflow`'s primary
#: link-type source; ``FILTER_NAME_TO_LINKTYPE`` below is only its fallback.
#:
#: A ``WTAP_ENCAP_*`` number is **not** a DLT: it is 25 where the DLT is 113, 15 where it is 0, and
#: 2 where it is 6, so it needs this table rather than a cast. What it does do is distinguish
#: encapsulations that the PDML root layer's *filter* name cannot, which is the whole reason this
#: table exists: ``sll`` is both ``LINUX_SLL`` (113) and ``LINUX_SLL2`` (276), ``null`` is both
#: ``NULL`` (0) and ``LOOP`` (108), ``raw`` is ``RAW`` (101), ``IPV4`` (228) and ``IPV6`` (229),
#: ``ppp`` is ``PPP`` (9) and ``PPP_WITH_DIR`` (204), ``lapd`` is ``LAPD`` (203) and
#: ``LINUX_LAPD`` (177). ``frame.encap_type`` separates every one of those pairs.
#:
#: Every entry was measured, not transcribed, with ``editcap``/``tshark`` 4.6.9::
#:
#:     editcap -F pcap -T <encap> examples/captures/in.pcap out.pcap
#:     # value := the ``network`` field at offset 20 of out.pcap's pcap file header
#:     # key   := the ``frame.encap_type`` that ``tshark -r out.pcap -c 1 -T pdml`` then reports
#:
#: so each pair is one round trip through Wireshark's own ``wiretap/pcap-common.c``, in the read
#: direction :mod:`pyshark` actually exercises. The trailing comment on each line names the
#: ``editcap -T`` encapsulation that produced it.
#:
#: What the sweep does **not** cover, since that bounds this table: of the 226 encapsulations
#: ``editcap -T`` accepts, 157 could be written as pcap from the Ethernet source above and the
#: other 69 refused the rewrite, so they are untested. Those 157 yielded 153 distinct
#: ``frame.encap_type`` keys, with no key mapping to two DLTs and no DLT reading back as two keys.
#: 152 of them are below; ``frame.encap_type`` 32 (``editcap -T hhdlc``, DLT 121) is left out
#: because :class:`LinkType` has no member for 121. An encapsulation absent from this table raises
#: rather than resolving to a near-miss DLT.
#:
#: In the read direction, one key can come from several DLTs. Measured with ``tshark`` 4.6.9 over
#: every PCAP-NG link type from 0 to 65535 (bar 144 and 177, under which it rejected the test
#: frame), ``frame.encap_type`` 7 is read from DLTs 12, 14 and 101, 4 from 9 and 50, 10 from 11
#: and 100, 11 from 16, 18, 19 and 106, 28 from 104 and 112, and 38 from 13 and 109; each other
#: key of this table from one DLT. So where :func:`tcp_traceflow` reads a frame as the default
#: engine does, it takes the link type from the capture file rather than from this table
#: (:issue:`1625`).
ENCAP_TYPE_TO_LINKTYPE = {
    1: Enum_LinkType.ETHERNET,                     # ether
    2: Enum_LinkType.IEEE802_5,                    # tr
    3: Enum_LinkType.SLIP,                         # slip
    4: Enum_LinkType.PPP,                          # ppp
    6: Enum_LinkType.FDDI,                         # fddi,fddi-nettl,fddi-swapped
    7: Enum_LinkType.RAW,                          # rawip
    8: Enum_LinkType.ARCNET_BSD,                   # arcnet
    9: Enum_LinkType.ARCNET_LINUX,                 # arcnet_linux
    10: Enum_LinkType.ATM_RFC1483,                 # atm-rfc1483
    11: Enum_LinkType.ATM_CLIP,                    # linux-atm-clip
    13: Enum_LinkType.SUNATM,                      # atm-pdus
    15: Enum_LinkType.NULL,                        # null
    18: Enum_LinkType.IP_OVER_FC,                  # ip-over-fc
    19: Enum_LinkType.PPP_WITH_DIR,                # ppp-with-direction
    20: Enum_LinkType.IEEE802_11,                  # ieee-802-11,ieee-802-11-radio
    21: Enum_LinkType.IEEE802_11_PRISM,            # ieee-802-11-prism
    23: Enum_LinkType.IEEE802_11_RADIOTAP,         # ieee-802-11-radiotap
    24: Enum_LinkType.IEEE802_11_AVS,              # ieee-802-11-avs
    25: Enum_LinkType.LINUX_SLL,                   # linux-sll
    26: Enum_LinkType.FRELAY,                      # frelay,frelay-with-direction
    28: Enum_LinkType.C_HDLC,                      # chdlc
    29: Enum_LinkType.CISCO_IOS,                   # ios
    30: Enum_LinkType.LTALK,                       # ltalk
    33: Enum_LinkType.DOCSIS,                      # docsis
    36: Enum_LinkType.SDLC,                        # sdlc
    37: Enum_LinkType.TZSP,                        # tzsp
    38: Enum_LinkType.ENC,                         # enc
    39: Enum_LinkType.PFLOG,                       # pflog
    41: Enum_LinkType.BLUETOOTH_HCI_H4,            # bluetooth-h4
    42: Enum_LinkType.MTP2,                        # mtp2
    43: Enum_LinkType.MTP3,                        # mtp3
    44: Enum_LinkType.LINUX_IRDA,                  # irda
    45: Enum_LinkType.USER0,                       # user0
    46: Enum_LinkType.USER1,                       # user1
    47: Enum_LinkType.USER2,                       # user2
    48: Enum_LinkType.USER3,                       # user3
    49: Enum_LinkType.USER4,                       # user4
    50: Enum_LinkType.USER5,                       # user5
    51: Enum_LinkType.USER6,                       # user6
    52: Enum_LinkType.USER7,                       # user7
    53: Enum_LinkType.USER8,                       # user8
    54: Enum_LinkType.USER9,                       # user9
    55: Enum_LinkType.USER10,                      # user10
    56: Enum_LinkType.USER11,                      # user11
    57: Enum_LinkType.USER12,                      # user12
    58: Enum_LinkType.USER13,                      # user13
    59: Enum_LinkType.USER14,                      # user14
    60: Enum_LinkType.USER15,                      # user15
    61: Enum_LinkType.SYMANTEC_FIREWALL,           # symantec
    62: Enum_LinkType.APPLE_IP_OVER_IEEE1394,      # ap1394
    63: Enum_LinkType.BACNET_MS_TP,                # bacnet-ms-tp
    66: Enum_LinkType.GPRS_LLC,                    # gprs-llc
    67: Enum_LinkType.JUNIPER_ATM1,                # juniper-atm1
    68: Enum_LinkType.JUNIPER_ATM2,                # juniper-atm2
    69: Enum_LinkType.REDBACK_SMARTEDGE,           # redback
    75: Enum_LinkType.MTP2_WITH_PHDR,              # mtp2-with-phdr
    76: Enum_LinkType.JUNIPER_PPPOE,               # juniper-pppoe
    77: Enum_LinkType.GCOM_T1E1,                   # gcom-tie1
    78: Enum_LinkType.GCOM_SERIAL,                 # gcom-serial
    81: Enum_LinkType.JUNIPER_MLPPP,               # juniper-mlppp
    82: Enum_LinkType.JUNIPER_MLFR,                # juniper-mlfr
    83: Enum_LinkType.JUNIPER_ETHER,               # juniper-ether
    84: Enum_LinkType.JUNIPER_PPP,                 # juniper-ppp
    85: Enum_LinkType.JUNIPER_FRELAY,              # juniper-frelay
    86: Enum_LinkType.JUNIPER_CHDLC,               # juniper-chdlc
    87: Enum_LinkType.JUNIPER_GGSN,                # juniper-ggsn
    88: Enum_LinkType.LINUX_LAPD,                  # linux-lapd
    91: Enum_LinkType.JUNIPER_VP,                  # juniper-vp
    92: Enum_LinkType.USB_FREEBSD,                 # usb-freebsd
    93: Enum_LinkType.IEEE802_16_MAC_CPS,          # ieee-802-16-mac-cps
    95: Enum_LinkType.USB_LINUX,                   # usb-linux
    97: Enum_LinkType.PPI,                         # ppi
    98: Enum_LinkType.ERF,                         # erf
    99: Enum_LinkType.BLUETOOTH_HCI_H4_WITH_PHDR,  # bluetooth-h4-linux
    100: Enum_LinkType.SITA,                       # sita-wan
    101: Enum_LinkType.SCCP,                       # sccp
    103: Enum_LinkType.IPMB_KONTRON,               # ipmb-kontron
    104: Enum_LinkType.IEEE802_15_4_WITHFCS,       # wpan
    105: Enum_LinkType.X2E_XORAYA,                 # x2e-xoraya
    106: Enum_LinkType.FLEXRAY,                    # flexray
    107: Enum_LinkType.LIN,                        # lin
    108: Enum_LinkType.MOST,                       # most
    109: Enum_LinkType.CAN20B,                     # can20b
    111: Enum_LinkType.X2E_SERIAL,                 # x2e-serial
    112: Enum_LinkType.I2C_LINUX,                  # i2c-linux
    113: Enum_LinkType.IEEE802_15_4_NONASK_PHY,    # wpan-nonask-phy
    115: Enum_LinkType.USB_LINUX_MMAPPED,          # usb-linux-mmap
    121: Enum_LinkType.FC_2,                       # fc2
    122: Enum_LinkType.FC_2_WITH_FRAME_DELIMS,     # fc2sof
    124: Enum_LinkType.IPNET,                      # ipnet
    125: Enum_LinkType.CAN_SOCKETCAN,              # socketcan
    127: Enum_LinkType.IEEE802_15_4_NOFCS,         # wpan-nofcs
    129: Enum_LinkType.IPV4,                       # rawip4
    130: Enum_LinkType.IPV6,                       # rawip6
    131: Enum_LinkType.LAPD,                       # lapd
    132: Enum_LinkType.DVB_CI,                     # dvbci
    133: Enum_LinkType.MUX27010,                   # mux27010
    135: Enum_LinkType.NETANALYZER,                # netanalyzer
    136: Enum_LinkType.NETANALYZER_TRANSPARENT,    # netanalyzer-transparent
    138: Enum_LinkType.MPEG_2_TS,                  # mp2ts
    139: Enum_LinkType.PPP_ETHER,                  # pppoes
    140: Enum_LinkType.NFC_LLCP,                   # nfc-llcp
    141: Enum_LinkType.NFLOG,                      # nflog
    146: Enum_LinkType.DBUS,                       # dbus
    147: Enum_LinkType.AX25_KISS,                  # ax25-kiss
    148: Enum_LinkType.AX25,                       # ax25
    149: Enum_LinkType.SCTP,                       # sctp
    151: Enum_LinkType.JUNIPER_SERVICES,           # juniper-svcs
    152: Enum_LinkType.USBPCAP,                    # usb-usbpcap
    153: Enum_LinkType.RTAC_SERIAL,                # rtac-serial
    154: Enum_LinkType.BLUETOOTH_LE_LL,            # bluetooth-le-ll
    155: Enum_LinkType.WIRESHARK_UPPER_PDU,        # wireshark-upper-pdu
    157: Enum_LinkType.STANAG_5066_D_PDU,          # s5066-dpdu
    158: Enum_LinkType.NETLINK,                    # netlink
    159: Enum_LinkType.BLUETOOTH_LINUX_MONITOR,    # bluetooth-linux-monitor
    160: Enum_LinkType.BLUETOOTH_BREDR_BB,         # bluetooth-bredr-bb-rf
    161: Enum_LinkType.BLUETOOTH_LE_LL_WITH_PHDR,  # bluetooth-le-ll-rf
    171: Enum_LinkType.PKTAP,                      # pktap
    172: Enum_LinkType.EPON,                       # epon
    173: Enum_LinkType.IPMI_HPM_2,                 # ipmi-trace
    174: Enum_LinkType.LOOP,                       # loop
    177: Enum_LinkType.ISO_14443,                  # iso14443
    178: Enum_LinkType.GPF_T,                      # gfp-t
    179: Enum_LinkType.GPF_F,                      # gfp-f
    180: Enum_LinkType.IPOIB,                      # ip-ib
    181: Enum_LinkType.A429,                       # juniper-vn
    182: Enum_LinkType.USB_DARWIN,                 # usb-darwin
    183: Enum_LinkType.LORATAP,                    # loratap
    184: Enum_LinkType.EXP_ETHERNET,               # xeth
    185: Enum_LinkType.VSOCK,                      # vsock
    186: Enum_LinkType.NORDIC_BLE,                 # nordic_ble
    197: Enum_LinkType.JUNIPER_ST,                 # juniper-st
    198: Enum_LinkType.ETHERNET_MPACKET,           # ether-mpacket
    199: Enum_LinkType.DOCSIS31_XRA31,             # docsis31_xra31
    200: Enum_LinkType.DISPLAYPORT_AUX,            # dpauxmon
    204: Enum_LinkType.EBHSCR,                     # ebhscr
    205: Enum_LinkType.VPP_DISPATCH,               # vpp
    206: Enum_LinkType.IEEE802_15_4_TAP,           # wpan-tap
    208: Enum_LinkType.USB_2_0,                    # usb-20
    210: Enum_LinkType.LINUX_SLL2,                 # linux-sll2
    211: Enum_LinkType.Z_WAVE_SERIAL,              # zwave-serial
    212: Enum_LinkType.ETW,                        # etw
    214: Enum_LinkType.ZBOSS_NCP,                  # zbncp
    215: Enum_LinkType.USB_2_0_LOW_SPEED,          # usb-20-low
    216: Enum_LinkType.USB_2_0_FULL_SPEED,         # usb-20-full
    217: Enum_LinkType.USB_2_0_HIGH_SPEED,         # usb-20-high
    219: Enum_LinkType.AUERSWALD_LOG,              # auerlog
    220: Enum_LinkType.ATSC_ALP,                   # alp
    221: Enum_LinkType.FIRA_UCI,                   # fira-uci
    222: Enum_LinkType.SILABS_DEBUG_CHANNEL,       # silabs-dch
    223: Enum_LinkType.MDB,                        # mdb
    225: Enum_LinkType.DECT_NR,                    # dect_nr
}  # type: dict[int, Enum_LinkType]

#: Wireshark display-filter name -> :class:`~pcapkit.const.reg.linktype.LinkType` member, used by
#: :func:`tcp_traceflow` **only** when the frame layer carries no ``frame.encap_type`` field for
#: ``ENCAP_TYPE_TO_LINKTYPE`` above to key on -- every capture measured for that table did carry
#: one, so this is a defensive path rather than the usual one. PyShark takes the name verbatim from
#: the PDML
#: ``<proto name=...>`` attribute, which is Wireshark's own dissector *filter* name -- the third
#: argument to ``proto_register_protocol()`` in the relevant ``epan/dissectors/packet-*.c`` -- and
#: that vocabulary is not :class:`LinkType`'s: Ethernet's filter name is ``eth``, never
#: ``ETHERNET``.
#:
#: Every entry comes from the same sweep as ``ENCAP_TYPE_TO_LINKTYPE`` above: the root ``<proto
#: name=...>`` of ``tshark -r out.pcap -c 1 -T pdml`` against the DLT in ``out.pcap``'s own file
#: header. The trailing comment on each line names the ``editcap -T`` encapsulation that produced
#: it, so an entry can be re-checked, or corrected when upstream moves, by rerunning that one
#: rewrite. Names are listed even where they already spell their :class:`LinkType` member
#: (``docsis``, ``fddi``, ``pflog``, ...): there is deliberately **no** fallback onto a like-named
#: member, because upper-casing the name is exactly what would answer 101 for a ``rawip6`` capture
#: and 0 for a ``DLT_LOOP`` one -- valid DLTs, wrong ones, and silent (:issue:`843`).
#:
#: Three classes of name are absent, all three measured rather than assumed:
#:
#: * **Ambiguous** -- one name, several DLTs, and the PDML node does not say which arrived. These
#:   cannot be mapped at any size: ``user_dlt`` (16 DLTs), ``bluetooth`` (6), ``usb`` (5),
#:   ``usbll`` (4), ``raw`` (3), and ``arcnet``, ``gfp``, ``i2c``, ``lapd``, ``mtp2``,
#:   ``netanalyzer``, ``null``, ``ppp``, ``sll``, ``wlan``, ``wpan`` (2 each).
#: * **Pseudo-protocols** -- ``fake-field-wrapper``, which :mod:`pyshark` reports as ``data`` and
#:   which was the root for 29 of the swept encapsulations (no dissector), and ``_ws.malformed``,
#:   the root for the one capture ``tshark`` could not parse. Neither names a link type.
#: * **Unswept** -- the 69 encapsulations ``editcap -T`` would not write as pcap from an Ethernet
#:   source. No evidence either way was gathered for them.
#:
#: Two caveats on what "unambiguous" means here. It means unambiguous *within* the 157 swept
#: encapsulations: one of the 69 unswept could still root at the same name (``ether-nettl`` and
#: ``tr-nettl`` are the obvious candidates, for ``eth`` and ``tr``). And five of the entries name a
#: *payload* dissector that happened to be the outermost PDML node for exactly one encapsulation
#: -- ``llc``, ``sctp``, ``pppoes``, ``fpp`` and ``irlap`` -- rather than a link-layer dissector
#: registered against a ``WTAP_ENCAP_*``. Both are why this table is the fallback and
#: ``frame.encap_type`` is the primary key; ``eth`` and ``tr`` additionally check out against
#: Wireshark's own registrations (``packet-eth.c`` on ``WTAP_ENCAP_ETHERNET``, ``packet-tr.c`` on
#: ``WTAP_ENCAP_TOKEN_RING``).
FILTER_NAME_TO_LINKTYPE = {
    'alp': Enum_LinkType.ATSC_ALP,                             # alp
    'ap1394': Enum_LinkType.APPLE_IP_OVER_IEEE1394,            # ap1394
    'atm': Enum_LinkType.SUNATM,                               # atm-pdus
    'ax25': Enum_LinkType.AX25,                                # ax25
    'ax25_kiss': Enum_LinkType.AX25_KISS,                      # ax25-kiss
    'can': Enum_LinkType.CAN_SOCKETCAN,                        # socketcan
    'chdlc': Enum_LinkType.C_HDLC,                             # chdlc
    'clip': Enum_LinkType.ATM_CLIP,                            # linux-atm-clip
    'dbus': Enum_LinkType.DBUS,                                # dbus
    'dect_nr': Enum_LinkType.DECT_NR,                          # dect_nr
    'docsis': Enum_LinkType.DOCSIS,                            # docsis
    'dpauxmon': Enum_LinkType.DISPLAYPORT_AUX,                 # dpauxmon
    'ebhscr': Enum_LinkType.EBHSCR,                            # ebhscr
    'enc': Enum_LinkType.ENC,                                  # enc
    'epon': Enum_LinkType.EPON,                                # epon
    'erf': Enum_LinkType.ERF,                                  # erf
    'eth': Enum_LinkType.ETHERNET,                             # ether
    'exported_pdu': Enum_LinkType.WIRESHARK_UPPER_PDU,         # wireshark-upper-pdu
    'fc': Enum_LinkType.FC_2,                                  # fc2
    'fcsof': Enum_LinkType.FC_2_WITH_FRAME_DELIMS,             # fc2sof
    'fddi': Enum_LinkType.FDDI,                                # fddi,fddi-nettl,fddi-swapped
    'flexray': Enum_LinkType.FLEXRAY,                          # flexray
    'fpp': Enum_LinkType.ETHERNET_MPACKET,                     # ether-mpacket
    'fr': Enum_LinkType.FRELAY,                                # frelay,frelay-with-direction
    'ipfc': Enum_LinkType.IP_OVER_FC,                          # ip-over-fc
    'ipmi.trace': Enum_LinkType.IPMI_HPM_2,                    # ipmi-trace
    'ipnet': Enum_LinkType.IPNET,                              # ipnet
    'ipoib': Enum_LinkType.IPOIB,                              # ip-ib
    'irlap': Enum_LinkType.LINUX_IRDA,                         # irda
    'lin': Enum_LinkType.LIN,                                  # lin
    'llap': Enum_LinkType.LTALK,                               # ltalk
    'llc': Enum_LinkType.ATM_RFC1483,                          # atm-rfc1483
    'llcgprs': Enum_LinkType.GPRS_LLC,                         # gprs-llc
    'loratap': Enum_LinkType.LORATAP,                          # loratap
    'mstp': Enum_LinkType.BACNET_MS_TP,                        # bacnet-ms-tp
    'mtp3': Enum_LinkType.MTP3,                                # mtp3
    'mux27010': Enum_LinkType.MUX27010,                        # mux27010
    'nflog': Enum_LinkType.NFLOG,                              # nflog
    'nordic_ble': Enum_LinkType.NORDIC_BLE,                    # nordic_ble
    'pflog': Enum_LinkType.PFLOG,                              # pflog
    'pktap': Enum_LinkType.PKTAP,                              # pktap
    'ppi': Enum_LinkType.PPI,                                  # ppi
    'pppoes': Enum_LinkType.PPP_ETHER,                         # pppoes
    'radiotap': Enum_LinkType.IEEE802_11_RADIOTAP,             # ieee-802-11-radiotap
    'redback': Enum_LinkType.REDBACK_SMARTEDGE,                # redback
    'rtacser': Enum_LinkType.RTAC_SERIAL,                      # rtac-serial
    'sccp': Enum_LinkType.SCCP,                                # sccp
    'sctp': Enum_LinkType.SCTP,                                # sctp
    'sdlc': Enum_LinkType.SDLC,                                # sdlc
    'silabs-dch': Enum_LinkType.SILABS_DEBUG_CHANNEL,          # silabs-dch
    'sita': Enum_LinkType.SITA,                                # sita-wan
    'tr': Enum_LinkType.IEEE802_5,                             # tr
    'tzsp': Enum_LinkType.TZSP,                                # tzsp
    'uci': Enum_LinkType.FIRA_UCI,                             # fira-uci
    'vpp': Enum_LinkType.VPP_DISPATCH,                         # vpp
    'vsock': Enum_LinkType.VSOCK,                              # vsock
    'wpan-nonask-phy': Enum_LinkType.IEEE802_15_4_NONASK_PHY,  # wpan-nonask-phy
    'xra': Enum_LinkType.DOCSIS31_XRA31,                       # docsis31_xra31
}  # type: dict[str, Enum_LinkType]

#: PyShark's text for a boolean field -> its value. tshark 4.x spells one ``'True'``/``'False'``
#: (measured for ``tcp.flags_syn``, ``tcp.flags_fin`` and ``tcp.flags_reset`` with PyShark 0.6
#: on tshark 4.6.9); ``'1'``/``'0'`` is the spelling this module first parsed (#1514).
_BOOLEAN_FIELD = {'1': True, '0': False, 'True': True, 'False': False}  # type: dict[str, bool]

#: IPv4 protocol numbers that make :func:`tcp_traceflow` read a frame from its
#: captured octets though tshark dissects no TCP segment in it (see
#: :func:`_extension_header_carrier`): the AH and IPv6 extension headers. The
#: default engine reads past those of the
#: :data:`~pcapkit.toolkit.pypcapfile.IPV4_EXTENSION_HEADERS` by rules of its
#: own, and past Shim6 not at all, as its parser refuses IPv4; tshark dissects
#: the TCP behind any of them by its own rules.
OCTETS_PROTOCOLS = IPV4_EXTENSION_HEADERS | {Enum_TransType.Shim6}

#: tshark display filter matching every frame :func:`tcp_traceflow` asks the
#: captured octets of: one tshark dissects TCP in (see :func:`_traces`), or one
#: with an IPv4 header whose protocol is one of the :data:`OCTETS_PROTOCOLS`.
#: It matches every ``tcp`` layer and ``ip.proto`` field of a frame, so it
#: matches all of those frames and maybe others. The members are joined with
#: ``||`` rather than written as a set, as tshark 4.6.9 refuses a set whose
#: members are separated by spaces only.
OCTETS_FILTER = ' || '.join(['tcp', *(f'ip.proto == {int(protocol)}' for protocol in sorted(OCTETS_PROTOCOLS))])

#: Length of an Ethernet header: two MAC addresses and the EtherType.
ETHERNET_HEADER_LEN = 14

#: Length of a BSD loopback header: the address family.
LOOPBACK_HEADER_LEN = 4

#: EtherTypes of the IP layers the default engine dissects over Ethernet, each
#: mapped to its IP version (see :attr:`Link.__proto__
#: <pcapkit.protocols.link.link.Link.__proto__>`).
ETHERTYPE_IP_VERSIONS = {
    Enum_EtherType.Internet_Protocol_version_4: 4,
    Enum_EtherType.Internet_Protocol_version_6: 6,
}  # type: dict[int, int]

#: Address families of the IP layers the default engine dissects over BSD
#: loopback, each mapped to its IP version (see :attr:`Loopback.__proto__
#: <pcapkit.protocols.link.loopback.Loopback.__proto__>`).
LOOPBACK_IP_VERSIONS = {2: 4, 24: 6, 28: 6, 30: 6}  # type: dict[int, int]


class Captured(NamedTuple):
    """A frame as the default engine reads it from the capture file (:issue:`1625`)."""

    #: Link type the default engine dissects the frame by: the PCAP file's, or
    #: that of the PCAP-NG interface the frame was captured on.
    linktype: 'int'
    #: The frame's captured octets.
    octets: 'bytes'


class _Segment(NamedTuple):
    """The fields of a TCP segment that a flow tracing record takes from it."""

    #: Source address of the IP layer carrying the segment.
    src: 'IPv4Address | IPv6Address'
    #: Destination address of that IP layer.
    dst: 'IPv4Address | IPv6Address'
    #: TCP source port.
    srcport: 'int'
    #: TCP destination port.
    dstport: 'int'
    #: TCP sequence number, as on the wire.
    seq: 'int'
    #: TCP acknowledgement number, as on the wire.
    ack: 'int'
    #: TCP synchronise (SYN) flag.
    syn: 'bool'
    #: TCP finish (FIN) flag.
    fin: 'bool'
    #: TCP reset (RST) flag.
    rst: 'bool'


def _parse_flag(value: 'Any', name: 'str') -> 'bool':
    """Parse a boolean PyShark field, such as ``tcp.flags_syn``.

    Args:
        value: The field as PyShark reports it, a ``LayerFieldsContainer``
            (a :obj:`str` subclass).
        name: The field's name, for the error message.

    Returns:
        The flag's value.

    Raises:
        ProtocolError: If ``value`` is not a :obj:`str` spelling ``'1'``,
            ``'0'``, ``'True'`` or ``'False'``.

    """
    if isinstance(value, str):
        flag = _BOOLEAN_FIELD.get(str(value))
        if flag is not None:
            return flag
    raise ProtocolError(f'invalid PyShark boolean field {name}: {value!r}')


def _parse_epoch(value: 'Any') -> 'float':
    """Parse PyShark's ``frame.time_epoch``, such as ``'1500000000.000638000'``.

    Args:
        value: The field as PyShark reports it, decimal text.

    Returns:
        The timestamp, as the same :obj:`float` the default engine reports.

    Note:
        The default engine computes the epoch as a :class:`~decimal.Decimal`
        and hands the tracer ``float()`` of it (:mod:`pcapkit.toolkit.pcap`).
        This takes the same route, so both are the double nearest the same
        decimal value: identical, not merely close.

    Raises:
        ProtocolError: If ``value`` is not decimal text.

    """
    try:
        return float(decimal.Decimal(str(value)))
    except decimal.InvalidOperation:
        raise ProtocolError(f'invalid PyShark frame.time_epoch: {value!r}') from None


def _absolute(tcp: 'Any', name: 'str') -> 'int':
    """Read the absolute TCP sequence or acknowledgement number.

    Args:
        tcp: PyShark TCP layer.
        name: ``'seq'`` or ``'ack'``.

    Returns:
        ``tcp.<name>_raw``, the number on the wire, or ``tcp.<name>`` where
        tshark does not report the former.

    Note:
        tshark's ``tcp.seq`` and ``tcp.ack`` are *relative* to the flow's first
        number by default (``0`` where the wire says ``832175175``).
        ``tcp.seq_raw`` and ``tcp.ack_raw`` exist from Wireshark 3.2: they are
        absent from 3.0.0's ``epan/dissectors/packet-tcp.c`` and present in
        3.2.0's and 4.2.2's. On an older tshark the fallback is relative unless
        its ``tcp.relative_sequence_numbers`` preference is off.

    """
    value = getattr(tcp, f'{name}_raw', None)
    if value is None:
        value = getattr(tcp, name)
    return int(value)


def _frame_layer(packet: 'Packet') -> 'Any':
    """Find the ``frame`` layer of a PyShark packet.

    Args:
        packet: PyShark packet.

    Returns:
        The layer named ``frame``, or :data:`None` if the record has none.

    Note:
        PyShark takes the second PDML ``<proto>`` as ``frame_info``. On a packet
        with a comment that is ``pkt_comment``, and the frame layer is
        ``layers[0]`` (measured on ``test.pcapng`` frames 1 and 6 with tshark
        4.6.9), so the layer is looked up by name, as the engine does (#1531).

    """
    for layer in (packet.frame_info, *packet.layers):
        if layer.layer_name == 'frame':
            return layer
    return None


def packet2dict(packet: 'Packet') -> 'dict[str, Any]':
    """Convert PyShark packet into :obj:`dict`.

    Args:
        packet: PyShark packet.

    Returns:
        A :obj:`dict` mapping of packet data: the ``frame`` layer's fields at
        the top level, and each later layer nested in the one before it. A
        packet comment, which PyShark reports as ``frame_info`` in place of the
        frame layer, is kept under its own ``PKT_COMMENT`` key. A record with
        no ``frame`` layer keeps PyShark's ``frame_info`` at the top level.

    """
    dict_ = {}  # type: dict[str, Any]
    frame = _frame_layer(packet)
    if frame is None:
        frame = packet.frame_info
    for field in frame.field_names:
        dict_[field] = getattr(frame, field)
    if packet.frame_info is not frame:
        note = packet.frame_info
        dict_[note.layer_name.upper()] = {field: getattr(note, field) for field in note.field_names}

    tempdict = dict_
    for layer in packet.layers:
        if layer is frame:
            continue
        tempdict[layer.layer_name.upper()] = {}
        tempdict = tempdict[layer.layer_name.upper()]
        for field in layer.field_names:
            tempdict[field] = getattr(layer, field)

    return dict_


def _carrier(packet: 'Packet') -> 'tuple[Any, Any]':
    """Fetch the TCP layer of a PyShark packet and the IP layer that carries it.

    Args:
        packet: PyShark packet.

    Returns:
        The ``ip`` or ``ipv6`` layer nearest above the packet's first ``tcp``
        layer, and that TCP layer; :data:`None` for either the packet lacks.

    Note:
        The nearest is the innermost IP layer of an IP-in-IP tunnel
        (:rfc:`2003`, :rfc:`2473`, :rfc:`4213`), whose addresses are the TCP
        endpoints', as for the default engine
        (:func:`pcapkit.toolkit.pcap.tcp_segment`). ``packet.ip`` is the first
        ``ip`` layer instead, which is the tunnel's (:issue:`1581`).

    """
    ip = None  # type: Any
    for layer in packet.layers:
        name = layer.layer_name.lower()
        if name == 'tcp':
            return ip, layer
        if name in ('ip', 'ipv6'):
            ip = layer
    return ip, None


def _has_fixed_header(tcp: 'Any') -> 'bool':
    """Whether tshark dissected the whole fixed TCP header of a PyShark TCP layer.

    Args:
        tcp: PyShark TCP layer.

    Returns:
        Whether the layer carries ``tcp.urgent_pointer``.

    Note:
        The default engine traces a segment only if its 20-octet fixed header
        (:rfc:`9293#section-3.1`) was captured and its Data Offset is at least
        5 (:func:`pcapkit.toolkit.pcap.tcp_segment`). tshark omits fields in
        both other cases, measured with tshark 4.6.9 (:issue:`1611`):

        * a Data Offset below 5 stops the dissection at ``tcp.hdr_len``, so
          ``tcp.ack`` and the ``tcp.flags`` fields are absent;
        * a header cut at octet *k* keeps the fields that fit: no TCP layer
          below 4, the ports only below 14, and no ``tcp.urgent_pointer``
          below 20.

        ``tcp.urgent_pointer`` covers octets 18 and 19, the last of the fixed
        header. ``dissect_tcp`` in :file:`epan/dissectors/packet-tcp.c` adds
        it unconditionally once the Data Offset check passes, in 2.6.0, 3.0.0
        and 4.6.0, after every field :func:`tcp_traceflow` reads.

    """
    return 'urgent_pointer' in tcp.field_names


def _from_layers(packet: 'Packet') -> 'Optional[_Segment]':
    """Read the TCP segment of a PyShark packet from tshark's dissection of it.

    Args:
        packet: PyShark packet.

    Returns:
        The packet's first TCP layer, if it has a whole fixed header (see
        :func:`_has_fixed_header`), keyed by the IP layer that carries it -- in
        an IP-in-IP tunnel, the innermost (see :func:`_carrier`); else
        :data:`None`.

    Raises:
        ProtocolError: If a TCP flag field is not a boolean tshark spelling.

    """
    ip, tcp = _carrier(packet)
    if ip is None or tcp is None or not _has_fixed_header(tcp):
        return None
    return _Segment(
        src=ipaddress.ip_address(ip.src),
        dst=ipaddress.ip_address(ip.dst),
        srcport=int(tcp.srcport),
        dstport=int(tcp.dstport),
        seq=_absolute(tcp, 'seq'),
        ack=_absolute(tcp, 'ack'),
        syn=_parse_flag(tcp.flags_syn, 'tcp.flags_syn'),
        fin=_parse_flag(tcp.flags_fin, 'tcp.flags_fin'),
        rst=_parse_flag(tcp.flags_reset, 'tcp.flags_reset'),
    )


def _traces(packet: 'Packet') -> 'bool':
    """Whether tshark's dissection of a PyShark packet has a TCP segment to trace.

    Args:
        packet: PyShark packet.

    Returns:
        Whether :func:`_from_layers` finds a segment in it, its flags unread.

    """
    ip, tcp = _carrier(packet)
    return ip is not None and tcp is not None and _has_fixed_header(tcp)


def _extension_header_carrier(packet: 'Packet') -> 'Any':
    """Find the IPv4 layer of a PyShark packet whose protocol names an AH or IPv6 extension header.

    Args:
        packet: PyShark packet.

    Returns:
        The first ``ip`` layer above the packet's first ``tcp`` layer, or of a
        packet with none, whose ``ip.proto`` is one of the
        :data:`OCTETS_PROTOCOLS`; else :data:`None`.

    """
    for layer in packet.layers:
        name = layer.layer_name.lower()
        if name == 'tcp':
            break
        if name == 'ip':
            try:
                protocol = int(str(getattr(layer, 'proto', '')))
            except ValueError:
                continue
            if protocol in OCTETS_PROTOCOLS:
                return layer
    return None


def _link_type(packet: 'Packet', frame: 'Any') -> 'Enum_LinkType':
    """Resolve the link type of a PyShark packet's frame.

    Args:
        packet: PyShark packet.
        frame: Its ``frame`` layer (see :func:`_frame_layer`).

    Returns:
        The link type ``frame.encap_type`` names, through
        :data:`ENCAP_TYPE_TO_LINKTYPE`, or the PDML root layer's filter name,
        through :data:`FILTER_NAME_TO_LINKTYPE`, where the frame layer has no
        such field.

    Raises:
        MissingKeyError: If the link type cannot be resolved.

    """
    # NOTE: the link type is keyed on ``frame.encap_type`` -- Wireshark's
    # internal ``WTAP_ENCAP_*`` number -- through
    # ``ENCAP_TYPE_TO_LINKTYPE`` (module level, above), and only on the
    # PDML root layer's *filter* name when the frame layer has no such
    # field. That name cannot do the job on its own: one filter name
    # serves several DLTs, so keying on it would answer ``RAW`` (101) for a
    # ``rawip6`` capture and ``NULL`` (0) for a ``DLT_LOOP`` one -- valid
    # DLTs, wrong ones, and silent (#843). ``frame.encap_type``
    # distinguishes them; see that table's comment for the measurements.
    #
    # PyShark reports every field as ``LayerFieldsContainer``, a ``str``
    # subclass, so the number arrives as text and needs ``int()``; and a
    # field the frame layer does not carry raises ``AttributeError`` out
    # of ``pyshark.packet.layers.base.BaseLayer.__getattr__``, which is
    # what the ``getattr`` default absorbs here.
    #
    # Neither path substitutes a DLT on a miss. A lookup raises on an
    # unresolvable key rather than minting one (#775), and
    # NULL and RAW are genuine DLTs -- BSD loopback and raw IP framing,
    # respectively -- each meant to go with its own handler protocol
    # class, so neither is an honest stand-in for "unknown link type".
    # The bare ``KeyError``/``ValueError`` is re-raised as
    # :exc:`~pcapkit.utilities.exceptions.MissingKeyError` -- this
    # package's own house exception for a lookup miss -- rather than
    # letting it escape the public :func:`tcp_traceflow`.
    #
    # The root layer is the first layer that is not the frame layer.
    encap_type = getattr(frame, 'encap_type', None)
    if encap_type is None:
        name = [layer for layer in packet.layers if layer is not frame][0].layer_name
        try:
            return FILTER_NAME_TO_LINKTYPE[name.lower()]
        except KeyError:
            raise MissingKeyError(name) from None
    try:
        return ENCAP_TYPE_TO_LINKTYPE[int(encap_type)]
    except (KeyError, ValueError):
        raise MissingKeyError('frame.encap_type=%s' % encap_type) from None


def _network_start(linktype: 'int', octets: 'bytes') -> 'Optional[tuple[int, int]]':
    """Find the outermost IP layer the default engine dissects in a frame, from its octets.

    Args:
        linktype: The link type the default engine dissects the frame by, the
            capture file's (see :class:`Captured`).
        octets: The frame's captured octets.

    Returns:
        The layer's IP version and where its header starts in ``octets``, or
        :data:`None` if the default engine dissects no IP layer right after
        the link layer.

    Note:
        The default engine dissects a frame by its link type
        (:attr:`Frame.__proto__ <pcapkit.protocols.misc.pcap.frame.Frame.__proto__>`).
        That is the capture file's, not the one tshark's ``frame.encap_type``
        names (see :func:`_link_type`): tshark reads link types 12 and 14, raw
        IP on some BSDs, as it reads ``RAW`` (101), and the default engine
        leaves them raw.
        Over Ethernet, it reads the EtherTypes in :data:`ETHERTYPE_IP_VERSIONS`
        after the 14-octet header and every one of the
        :data:`~pcapkit.toolkit.pypcapfile.VLAN_TAGS` behind it; over BSD
        loopback (``NULL`` and ``LOOP``), the address families in
        :data:`LOOPBACK_IP_VERSIONS` after the 4-octet family, in the byte
        order :func:`~pcapkit.protocols.link.loopback.family_byteorder` gives.
        ``IPV4`` and ``IPV6`` frames are IP, and a ``RAW`` one is the IP
        version its first octet gives, 4 or 6. It leaves every other link type,
        EtherType and family raw, and a frame cut short of its link header.

    """
    if linktype == Enum_LinkType.ETHERNET:
        if len(octets) < ETHERNET_HEADER_LEN:
            return None
        ethertype, start = int.from_bytes(octets[12:14], 'big'), ETHERNET_HEADER_LEN
        while ethertype in VLAN_TAGS:
            if len(octets) < start + VLAN_TAG_LEN:
                return None
            ethertype, start = int.from_bytes(octets[start + 2:start + 4], 'big'), start + VLAN_TAG_LEN
        version = ETHERTYPE_IP_VERSIONS.get(ethertype)
    elif linktype in (Enum_LinkType.NULL, Enum_LinkType.LOOP):
        if len(octets) < LOOPBACK_HEADER_LEN:
            return None
        family, start = octets[:LOOPBACK_HEADER_LEN], LOOPBACK_HEADER_LEN
        version = LOOPBACK_IP_VERSIONS.get(int.from_bytes(family, family_byteorder(family, linktype)))
    elif linktype == Enum_LinkType.RAW:
        if not octets:
            return None
        version, start = octets[0] >> 4, 0
    elif linktype in (Enum_LinkType.IPV4, Enum_LinkType.IPV6):
        version, start = (4 if linktype == Enum_LinkType.IPV4 else 6), 0
    else:
        return None
    if version is None or version not in (4, 6):
        return None
    return version, start


def _network(packet: 'Packet', captured: 'Captured') -> 'Optional[tuple[int, bytes]]':
    """Find the outermost IP packet the default engine dissects in a PyShark packet's frame.

    Args:
        packet: PyShark packet.
        captured: The frame, as the default engine reads it from the capture file.

    Returns:
        The packet's IP version and its octets on, to the end of the frame, as
        :func:`_network_start` finds it by the frame's link type, if tshark
        dissected it too: the packet's first ``ip`` or ``ipv6`` layer is of that
        version, and tshark reports its version field there, the layer's source
        address in the header's Source Address field, and its destination
        address in the octets where tshark reports that field (see below).
        Else :data:`None`: the default engine dissects no IP packet right after
        the link layer, or tshark dissected none there, e.g. as it reads an
        IPv6 packet over link type ``IPV4`` (228) as IPv6, or dissected that
        layer out of other octets, e.g. another frame's.

    Note:
        The destination address is matched where tshark reports it, not in
        the header's Destination Address field: with an LSRR or SSRR option
        whose route is not yet used up (:rfc:`791#section-3.1`), tshark
        reports the route's last address as ``ip.dst``, at its place in the
        option, and the header's as ``ip.cur_rt``, measured with tshark 4.6.9.
        The default engine keys the segment by the header's, as the octets do.

    """
    linktype, octets = captured
    found = _network_start(linktype, octets)
    if found is None:
        return None
    version, start = found

    name = 'ip' if version == 4 else 'ipv6'
    ip = next((layer for layer in packet.layers if layer.layer_name.lower() in ('ip', 'ipv6')), None)
    if ip is None or ip.layer_name.lower() != name:
        return None
    try:
        position, target = int(ip.version.pos), int(ip.dst.pos)
        source, destination = bytes.fromhex(str(ip.src.raw_value)), bytes.fromhex(str(ip.dst.raw_value))
    except (AttributeError, TypeError, ValueError):
        return None
    size = 4 if version == 4 else 16
    where = start + (12 if version == 4 else 8)  # the source address
    if (position != start or len(source) != size or len(destination) != size
            or octets[where:where + size] != source
            or target < start or octets[target:target + size] != destination):
        return None
    return version, octets[start:]


def _from_octets(version: 'int', data: 'bytes') -> 'Optional[_Segment]':
    """Read the TCP segment the default engine reads in an IP packet, from its octets.

    Args:
        version: IP version of the header ``data`` starts with, ``4`` or ``6``.
        data: Raw octets from the IP header on, to the end of the frame.

    Returns:
        The segment, keyed by the IP layer that carries it -- in an IP-in-IP
        tunnel, the innermost -- or :data:`None` if the default engine reads no
        TCP segment there. Only IPv4 and IPv6 in IP (the
        :data:`~pcapkit.toolkit.pypcapfile.IP_TUNNELS`) are followed: no other
        tunnel, such as GRE or VXLAN, as the default engine dissects none.

        Every IPv4 header on the way must have options the default engine's
        IPv4 parser accepts (see
        :func:`~pcapkit.toolkit.pypcapfile._default_accepts`), and each IP
        packet is followed past its headers by
        :func:`~pcapkit.toolkit.pypcapfile._upper_layer`: an AH or IPv6
        extension header in IPv4 by the default engine's own parser, and the
        extension headers of IPv6, up to
        :data:`~pcapkit.protocols.internet.internet.EXTENSION_HEADER_LIMIT` of
        them in a row; none in a later fragment. A TCP header must be at least
        :data:`~pcapkit.toolkit.pypcapfile.TCP_MIN_HEADER_LEN` octets long, as
        its Data Offset gives it, with that many captured.

        Behind an AH or IPv6 extension header in IPv4, the default engine reads
        TCP only as its TCP parser does, so the whole of that header must be
        there, with options the parser accepts. Directly over IP, it reads a
        header the parser rejects out of the raw octets left behind
        (:func:`pcapkit.toolkit.pcap.tcp_segment`), the rule
        :func:`_has_fixed_header` applies to tshark's own dissection.

    Note:
        These are the rules the pypcapfile, dpkt and scapy engines apply to
        the same octets (:func:`pcapkit.toolkit.pypcapfile._transport`,
        :issue:`1606`).

    """
    while True:
        if version == 4 and len(data) >= IPV4_HEADER_LEN:
            ihl = (data[0] & 0x0F) * 4
            if IPV4_HEADER_LEN < ihl <= len(data) and not _default_accepts('IPv4', data[:ihl]):
                return None
        upper = _upper_layer(version, data)
        if upper is None:
            return None
        if upper[0] not in IP_TUNNELS:
            break
        version, data = IP_TUNNELS[upper[0]], upper[1]

    protocol, segment = upper
    if protocol != Enum_TransType.TCP or len(segment) < TCP_MIN_HEADER_LEN:
        return None
    header = (segment[12] >> 4) * 4  # the Data Offset, in octets
    if header < TCP_MIN_HEADER_LEN:
        return None
    if version == 4 and data[9] != Enum_TransType.TCP and (header > len(segment) or (
            header > TCP_MIN_HEADER_LEN and not _default_accepts('TCP', segment[:header]))):
        return None

    src, dst = (data[12:16], data[16:20]) if version == 4 else (data[8:24], data[24:40])
    flags = segment[13]
    return _Segment(
        src=ipaddress.ip_address(src),
        dst=ipaddress.ip_address(dst),
        srcport=int.from_bytes(segment[0:2], 'big'),
        dstport=int.from_bytes(segment[2:4], 'big'),
        seq=int.from_bytes(segment[4:8], 'big'),
        ack=int.from_bytes(segment[8:12], 'big'),
        syn=bool(flags & 0x02),
        fin=bool(flags & 0x01),
        rst=bool(flags & 0x04),
    )


def _segment(packet: 'Packet', captured: 'Optional[Callable[[Packet], Optional[Captured]]]') -> 'Optional[_Segment]':
    """Read the TCP segment of a PyShark packet that the default engine reads.

    Args:
        packet: PyShark packet.
        captured: Fetches a frame as the default engine reads it from the
            capture file, or :data:`None` where it cannot be had (see
            :func:`tcp_traceflow`).

    Returns:
        If tshark's dissection has a segment (see :func:`_traces`), or an IPv4
        layer whose protocol names an AH or IPv6 extension header (see
        :func:`_extension_header_carrier`), the segment read from the octets of
        the frame's outermost IP packet on (see :func:`_network` and
        :func:`_from_octets`), or :data:`None` where the default engine
        dissects no IP packet after the frame's link layer or tshark dissects
        none there. Otherwise, or where the frame cannot be had, the segment of
        tshark's dissection (see :func:`_from_layers`). :data:`None` if there
        is none.

    Raises:
        ProtocolError: If a TCP flag field of tshark's dissection is not a
            boolean tshark spelling.

    Note:
        tshark dissects TCP inside encapsulations the default engine leaves
        raw: link types 12 and 14, which it reads as raw IP (101), Linux SLL,
        an EtherType such as MPLS or PPPoE, 802.3 LLC/SNAP, Cisco ISL, and
        tunnels such as GRE, VXLAN and L2TP (:issue:`1639`). And it dissects
        an AH or IPv6 extension header in IPv4 and what its Next Header names
        by rules of its own, and nothing past a Mobility (135) or HIP (139)
        header, whose payload it leaves out of the PDML that PyShark reads.
        The default engine dispatches IPv4's protocol through the registry
        IPv6 uses, reads TCP behind such a header only if its TCP parser
        accepts it, and none behind Shim6 (140), whose parser refuses IPv4
        (:issue:`1625`). Reading the frame from its link layer on, as the
        default engine does, stops where it stops: at a link type, EtherType or
        tunnel it does not dissect, or past
        :data:`~pcapkit.protocols.internet.internet.EXTENSION_HEADER_LIMIT`
        extension headers in a row of an IPv6 packet.

    """
    if captured is not None and (_traces(packet) or _extension_header_carrier(packet) is not None):
        frame = captured(packet)
        if frame is not None:
            network = _network(packet, frame)
            return None if network is None else _from_octets(*network)
    return _from_layers(packet)


def tcp_traceflow(packet: 'Packet', *, count: 'int' = -1,
                  captured: 'Optional[Callable[[Packet], Optional[Captured]]]' = None) -> 'TF_TCP_Packet | None':
    """Trace packet flow for TCP.

    Args:
        packet: PyShark packet.
        count: Packet index. If not provided, default to ``-1``. The engine
            passes its own frame count, not tshark's ``frame.number``, which
            also numbers records that are not packets (#1515).
        captured: Fetches a frame as the default engine reads it from the
            capture file, given its packet: its link type there and its
            captured octets, neither of which the PDML carries; or
            :data:`None` where it cannot. It is called only for a packet
            :data:`OCTETS_FILTER` matches. The engine passes
            :meth:`PyShark._captured
            <pcapkit.foundation.engines.pyshark.PyShark._captured>`; without
            it, or where it returns :data:`None`, a packet is read as tshark
            dissects it.

    Returns:
        Data for TCP flow tracing.

        * If the ``packet`` can be used for TCP flow tracing. A packet can be reassembled
          if it contains TCP layer with a whole fixed header (see
          :func:`_has_fixed_header`), keyed by the IP layer that carries it -- in an
          IP-in-IP tunnel, the innermost (see :func:`_carrier`). Where
          ``captured`` has the frame, it is instead the TCP the default engine
          reads in the frame's octets, by the frame's link type in the capture
          file, and none where the default engine reads none: behind a link
          type, EtherType or tunnel it does not dissect (see :func:`_segment`).
        * If the ``packet`` can be reassembled, then the :obj:`dict` mapping of data for TCP
          flow tracing (:term:`trace.tcp.packet`) will be returned; otherwise, returns :data:`None`.

    Raises:
        MissingKeyError: If the frame's link type cannot be resolved.
        ProtocolError: If the packet has no ``frame`` layer, a TCP flag field is
            not a boolean tshark spelling, or ``frame.time_epoch`` is not decimal
            text.

    See Also:
        :class:`pcapkit.foundation.traceflow.tcp.TCP`

    """
    segment = _segment(packet, captured)
    if segment is not None:

        # NOTE: the frame layer is found by name, not taken as ``frame_info``,
        # which is ``pkt_comment`` on a commented packet; ``_link_type`` says
        # how the link type is keyed on it.
        frame = _frame_layer(packet)
        if frame is None:
            raise ProtocolError(f'PyShark packet {packet.number} has no frame layer')
        protocol = _link_type(packet, frame)

        # A Simple Packet Block carries no timestamp, so tshark reports no
        # ``frame.time_epoch`` for it; the PDML ``geninfo`` timestamp PyShark
        # keeps as ``sniff_timestamp`` is then ``'0.000000000'``, which is what
        # the default engine reports (measured on ``test.pcapng`` frame 4).
        epoch = getattr(frame, 'time_epoch', None)
        if epoch is None:
            epoch = packet.sniff_timestamp

        data = TF_TCP_Packet(  # type: ignore[type-var]
            protocol=protocol,                                                   # data link type
            index=count,                                                         # frame number
            frame=packet2dict(packet),                                           # extracted packet
            syn=segment.syn,                                                     # TCP synchronise (SYN) flag
            fin=segment.fin,                                                     # TCP finish (FIN) flag
            rst=segment.rst,                                                     # TCP reset (RST) flag
            src=segment.src,                                                     # source IP
            dst=segment.dst,                                                     # destination IP
            srcport=segment.srcport,                                             # TCP source port
            dstport=segment.dstport,                                             # TCP destination port
            timestamp=_parse_epoch(epoch),                                       # timestamp
            seq=segment.seq,                                                     # TCP sequence number
            ack=segment.ack,                                                     # TCP acknowledgement number
            # NOTE: PyShark reports dissected *fields*, not the octets behind
            # them, so there is no header or payload to hand over -- which is
            # the same reason this module carries no ``tcp_reassembly`` at all.
            # The octets ``_segment`` reads are missing wherever the frame
            # cannot be had, so are not handed over either.
            # ``Extractor`` refuses ``trace_analyse=True`` on this engine, so
            # nothing reads these two.
            header=b'',                                                          # unavailable
            payload=bytearray(),                                                 # unavailable
        )
        return data
    return None
