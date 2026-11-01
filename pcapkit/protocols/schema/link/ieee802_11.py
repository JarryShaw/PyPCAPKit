# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for IEEE 802.11 MAC headers

Which fields a MAC header carries is decided by its Frame Control field, so
:func:`layout` reads that field once and every optional field of
:class:`IEEE802_11` is a :class:`~pcapkit.corekit.fields.misc.ConditionalField`
on its answer. Every multi-octet numeric field is little-endian, as IEEE Std
802.11-2020 §9.2.2, *Conventions*, has it.

"""

from typing import TYPE_CHECKING, NamedTuple

from pcapkit.const.ieee802_11.control_subtype import ControlSubtype as Enum_ControlSubtype
from pcapkit.const.ieee802_11.type import Type as Enum_Type
from pcapkit.corekit.fields.misc import ConditionalField, PayloadField
from pcapkit.corekit.fields.numbers import UInt16Field, UInt32Field
from pcapkit.corekit.fields.strings import BytesField
from pcapkit.protocols.schema.schema import Schema, schema_final

__all__ = ['IEEE802_11']

if TYPE_CHECKING:
    from typing import Any, Optional

    from pcapkit.protocols.protocol import ProtocolBase

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


class Layout(NamedTuple):
    """Fields a MAC header carries after Frame Control, Duration/ID and Address 1."""

    #: Address 2.
    addr2: 'bool'
    #: Address 3.
    addr3: 'bool'
    #: Sequence Control.
    seq_ctrl: 'bool'
    #: Address 4.
    addr4: 'bool'
    #: QoS Control.
    qos_control: 'bool'
    #: HT Control.
    ht_control: 'bool'


def layout(frame_control: 'int') -> 'Layout':
    """Decide which fields a protocol version 0 MAC header carries.

    * A Management frame carries Address 2, Address 3 and Sequence Control
      whatever its subtype, and HT Control when +HTC/Order is set (IEEE Std
      802.11-2020 §9.3.3, *Management frames*; §9.2.4.1.10, *+HTC/Order
      subfield*).
    * A Data frame carries the same three, Address 4 when To DS and From DS are
      both set, QoS Control when the QoS bit (B7) of its subtype is set, and HT
      Control when that bit and +HTC/Order are both set (§9.3.2, *Data frames*).
    * A Control frame carries Address 2 for the subtypes in
      :data:`CONTROL_WITH_ADDR2`, and Address 1 alone for CTS and Ack (§9.3.1,
      *Control frames*).
    * Every other frame -- a reserved Control subtype, a Control Wrapper, whose
      octets after Address 1 are Carried Frame Control and HT Control, and
      every Extension frame -- is read as the minimal frame format that §9.2.3,
      *General frame format*, makes present in every frame, reserved types and
      subtypes included: Frame Control, Duration/ID and Address 1. What follows
      stays in the frame body.

    This departs from the Linux kernel's ``ieee80211_hdrlen()`` deliberately: a
    Control Wrapper and the reserved Control subtypes 0 and 1 read 10 octets
    where it gives 16, and an Extension frame reads 10 where it gives 4.

    Args:
        frame_control: Frame Control field, as the little-endian integer read
            off the wire.

    Returns:
        The fields present after Address 1.

    """
    type_ = (frame_control >> 2) & 0b11
    subtype = (frame_control >> 4) & 0b1111
    to_ds = (frame_control >> 8) & 0b1
    from_ds = (frame_control >> 9) & 0b1
    order = (frame_control >> 15) & 0b1

    if type_ == Enum_Type.Management:
        return Layout(True, True, True, False, False, bool(order))
    if type_ == Enum_Type.Data:
        qos = bool(subtype & 0b1000)
        return Layout(True, True, True, bool(to_ds and from_ds), qos, qos and bool(order))
    if type_ == Enum_Type.Control and subtype in CONTROL_WITH_ADDR2:
        return Layout(True, False, False, False, False, False)
    return Layout(False, False, False, False, False, False)


@schema_final
class IEEE802_11(Schema):
    """Header schema for an IEEE 802.11 MAC header (IEEE Std 802.11-2020 §9.2)."""

    #: Frame Control.
    frame_control: 'int' = UInt16Field(byteorder='little')
    #: Duration/ID.
    duration_id: 'int' = UInt16Field(byteorder='little')
    #: Address 1.
    addr1: 'bytes' = BytesField(length=6)
    #: Address 2, where :func:`layout` says so.
    addr2: 'Optional[bytes]' = ConditionalField(
        BytesField(length=6),
        lambda packet: layout(packet['frame_control']).addr2,
    )
    #: Address 3, where :func:`layout` says so.
    addr3: 'Optional[bytes]' = ConditionalField(
        BytesField(length=6),
        lambda packet: layout(packet['frame_control']).addr3,
    )
    #: Sequence Control, where :func:`layout` says so.
    seq_ctrl: 'Optional[int]' = ConditionalField(
        UInt16Field(byteorder='little'),
        lambda packet: layout(packet['frame_control']).seq_ctrl,
    )
    #: Address 4, where :func:`layout` says so.
    addr4: 'Optional[bytes]' = ConditionalField(
        BytesField(length=6),
        lambda packet: layout(packet['frame_control']).addr4,
    )
    #: QoS Control, where :func:`layout` says so.
    qos_control: 'Optional[int]' = ConditionalField(
        UInt16Field(byteorder='little'),
        lambda packet: layout(packet['frame_control']).qos_control,
    )
    #: HT Control, where :func:`layout` says so.
    ht_control: 'Optional[int]' = ConditionalField(
        UInt32Field(byteorder='little'),
        lambda packet: layout(packet['frame_control']).ht_control,
    )
    #: Frame body, and the FCS where one was captured.
    payload: 'bytes' = PayloadField(length=lambda pkt: pkt['__length__'])

    if TYPE_CHECKING:
        def __init__(self, frame_control: 'int', duration_id: 'int', addr1: 'bytes',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
                     addr2: 'Optional[bytes]', addr3: 'Optional[bytes]',  # pylint: disable=unused-argument
                     seq_ctrl: 'Optional[int]', addr4: 'Optional[bytes]',  # pylint: disable=unused-argument
                     qos_control: 'Optional[int]', ht_control: 'Optional[int]',  # pylint: disable=unused-argument
                     payload: 'bytes | ProtocolBase | Schema | dict[str, Any]') -> 'None': ...  # pylint: disable=unused-argument
