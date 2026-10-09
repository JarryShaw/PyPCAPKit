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
from typing import TYPE_CHECKING, cast

from pcapkit.const.reg.linktype import LinkType as Enum_LinkType
from pcapkit.foundation.traceflow.data.tcp import Packet as TF_TCP_Packet
from pcapkit.utilities.exceptions import MissingKeyError, ProtocolError

if TYPE_CHECKING:
    from typing import Any

    from pyshark.packet.packet import Packet

__all__ = ['packet2dict', 'tcp_traceflow', 'ENCAP_TYPE_TO_LINKTYPE', 'FILTER_NAME_TO_LINKTYPE']

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


def tcp_traceflow(packet: 'Packet', *, count: 'int' = -1) -> 'TF_TCP_Packet | None':
    """Trace packet flow for TCP.

    Args:
        packet: PyShark packet.
        count: Packet index. If not provided, default to ``-1``. The engine
            passes its own frame count, not tshark's ``frame.number``, which
            also numbers records that are not packets (#1515).

    Returns:
        Data for TCP flow tracing.

        * If the ``packet`` can be used for TCP flow tracing. A packet can be reassembled
          if it contains TCP layer.
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
    if 'IP' in packet:
        ip = cast('Packet', packet.ip)
    elif 'IPv6' in packet:
        ip = cast('Packet', packet.ipv6)
    else:
        return None

    if 'TCP' in packet:
        tcp = cast('Packet', packet.tcp)

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
        # letting it escape this public function.
        #
        # The frame layer is found by name, not taken as ``frame_info``, which
        # is ``pkt_comment`` on a commented packet; the root layer is then the
        # first layer that is not the frame layer.
        frame = _frame_layer(packet)
        if frame is None:
            raise ProtocolError(f'PyShark packet {packet.number} has no frame layer')
        encap_type = getattr(frame, 'encap_type', None)
        if encap_type is None:
            name = [layer for layer in packet.layers if layer is not frame][0].layer_name
            try:
                protocol = FILTER_NAME_TO_LINKTYPE[name.lower()]
            except KeyError:
                raise MissingKeyError(name) from None
        else:
            try:
                protocol = ENCAP_TYPE_TO_LINKTYPE[int(encap_type)]
            except (KeyError, ValueError):
                raise MissingKeyError('frame.encap_type=%s' % encap_type) from None

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
            syn=_parse_flag(tcp.flags_syn, 'tcp.flags_syn'),                     # TCP synchronise (SYN) flag
            fin=_parse_flag(tcp.flags_fin, 'tcp.flags_fin'),                     # TCP finish (FIN) flag
            rst=_parse_flag(tcp.flags_reset, 'tcp.flags_reset'),                 # TCP reset (RST) flag
            src=ipaddress.ip_address(ip.src),                                    # source IP
            dst=ipaddress.ip_address(ip.dst),                                    # destination IP
            srcport=int(tcp.srcport),                                            # TCP source port
            dstport=int(tcp.dstport),                                            # TCP destination port
            timestamp=_parse_epoch(epoch),                                       # timestamp
            seq=_absolute(tcp, 'seq'),                                           # TCP sequence number
            ack=_absolute(tcp, 'ack'),                                           # TCP acknowledgement number
            # NOTE: PyShark reports dissected *fields*, not the octets behind
            # them, so there is no header or payload to hand over -- which is
            # the same reason this module carries no ``tcp_reassembly`` at all.
            # ``Extractor`` refuses ``trace_analyse=True`` on this engine, so
            # nothing reads these two.
            header=b'',                                                          # unavailable
            payload=bytearray(),                                                 # unavailable
        )
        return data
    return None
