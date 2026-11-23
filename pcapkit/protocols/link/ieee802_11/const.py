# -*- coding: utf-8 -*-
"""constants for IEEE 802.11 MAC headers

.. versionadded:: 1.7.0

"""
from typing import TYPE_CHECKING

from pcapkit.const.ieee802_11.control_subtype import ControlSubtype as Enum_ControlSubtype
from pcapkit.const.ieee802_11.data_subtype import DataSubtype as Enum_DataSubtype
from pcapkit.const.ieee802_11.extension_subtype import ExtensionSubtype as Enum_ExtensionSubtype
from pcapkit.const.ieee802_11.management_subtype import ManagementSubtype as Enum_ManagementSubtype
from pcapkit.const.ieee802_11.type import Type as Enum_Type

if TYPE_CHECKING:
    from typing import Type

    from pcapkit.protocols.link.ieee802_11.protocol import Subtype

__all__ = ['SUBTYPE', 'CONTROL_WITH_ADDR2']

#: Subtype registry of each frame type (IEEE Std 802.11-2020, Table 9-1).
SUBTYPE = {
    Enum_Type.Management: Enum_ManagementSubtype,
    Enum_Type.Control: Enum_ControlSubtype,
    Enum_Type.Data: Enum_DataSubtype,
    Enum_Type.Extension: Enum_ExtensionSubtype,
}  # type: dict[int, Type[Subtype]]

#: Control frame subtypes whose MAC header carries a TA (or BSSID) as
#: Address 2 after the RA; IEEE Std 802.11-2020 §9.3.1, *Control frames*, and
#: IEEE Std 802.11ax-2021 for ``Trigger``. CTS and Ack carry the RA alone. A
#: Control Frame Extension frame takes the six octets after the RA as Address 2,
#: as the Linux kernel's ``ieee80211_hdrlen()`` reads it; in a DMG DTS
#: (extension 6) they are NAV-SA rather than a TA, and NAV-DA stays in the body.
CONTROL_WITH_ADDR2 = frozenset({
    Enum_ControlSubtype.Trigger,
    Enum_ControlSubtype.TACK,
    Enum_ControlSubtype.Beamforming_Report_Poll,
    Enum_ControlSubtype.VHT_HE_NDP_Announcement,
    Enum_ControlSubtype.Control_Frame_Extension,
    Enum_ControlSubtype.Block_Ack_Request,
    Enum_ControlSubtype.Block_Ack,
    Enum_ControlSubtype.PS_Poll,
    Enum_ControlSubtype.RTS,
    Enum_ControlSubtype.CF_End,
    Enum_ControlSubtype.CF_End_CF_ACK,
})
