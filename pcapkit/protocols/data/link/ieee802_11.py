# -*- coding: utf-8 -*-
"""data models for IEEE 802.11 MAC headers"""

# NOTE: ``Optional`` is imported at run time so that ``from_dict`` can resolve the
# nested annotations below and rebuild them as their own classes.
from typing import TYPE_CHECKING, Optional  # pylint: disable=unused-import

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data.data import Data
from pcapkit.protocols.data.protocol import Protocol

if TYPE_CHECKING:
    from typing_extensions import Literal

    from pcapkit.const.ieee802_11.control_subtype import ControlSubtype
    from pcapkit.const.ieee802_11.data_subtype import DataSubtype
    from pcapkit.const.ieee802_11.extension_subtype import ExtensionSubtype
    from pcapkit.const.ieee802_11.management_subtype import ManagementSubtype
    from pcapkit.const.ieee802_11.type import Type

__all__ = [
    'IEEE802_11',
    'FrameControl', 'SequenceControl', 'QoSControl', 'HTControl',
]


@info_final
class FrameControl(Data):
    """Data model for the Frame Control field (IEEE Std 802.11-2020 §9.2.4.1).

    Two frames lay out B8-B15 differently, and the flags they replace are
    :obj:`None` there: a Control Frame Extension frame carries
    :attr:`control_frame_extension` in B8-B11, and an S1G Beacon carries
    :attr:`s1g_beacon_flags` in all of B8-B15.

    """

    #: Protocol Version.
    version: 'int'
    #: Type.
    type: 'Type'
    #: Subtype, from the registry :attr:`type` selects.
    subtype: 'ManagementSubtype | ControlSubtype | DataSubtype | ExtensionSubtype'
    #: To DS.
    to_ds: 'Optional[bool]'
    #: From DS.
    from_ds: 'Optional[bool]'
    #: More Fragments.
    more_fragments: 'Optional[bool]'
    #: Retry.
    retry: 'Optional[bool]'
    #: Control Frame Extension (B8-B11) of a Control Frame Extension frame;
    #: :obj:`None` in any other frame.
    control_frame_extension: 'Optional[int]'
    #: Power Management.
    power_management: 'Optional[bool]'
    #: More Data.
    more_data: 'Optional[bool]'
    #: Protected Frame.
    protected: 'Optional[bool]'
    #: +HTC/Order.
    order: 'Optional[bool]'
    #: B8-B15 of an S1G Beacon, kept whole -- Next TBTT Present, Compressed SSID
    #: Present, ANO Present, BSS BW, Security and AP PM, as Wireshark's
    #: ``packet-ieee80211.c`` names them; :obj:`None` in any other frame.
    s1g_beacon_flags: 'Optional[int]'

    if TYPE_CHECKING:
        def __init__(self, version: 'int', type: 'Type',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin
                     subtype: 'ManagementSubtype | ControlSubtype | DataSubtype | ExtensionSubtype',  # pylint: disable=unused-argument
                     to_ds: 'Optional[bool]', from_ds: 'Optional[bool]',  # pylint: disable=unused-argument
                     more_fragments: 'Optional[bool]', retry: 'Optional[bool]',  # pylint: disable=unused-argument
                     control_frame_extension: 'Optional[int]', power_management: 'Optional[bool]',  # pylint: disable=unused-argument
                     more_data: 'Optional[bool]', protected: 'Optional[bool]',  # pylint: disable=unused-argument
                     order: 'Optional[bool]', s1g_beacon_flags: 'Optional[int]') -> 'None': ...  # pylint: disable=unused-argument


@info_final
class SequenceControl(Data):
    """Data model for the Sequence Control field (IEEE Std 802.11-2020 §9.2.4.4)."""

    #: Fragment Number.
    fragment_number: 'int'
    #: Sequence Number.
    sequence_number: 'int'

    if TYPE_CHECKING:
        def __init__(self, fragment_number: 'int', sequence_number: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class QoSControl(Data):
    """Data model for the QoS Control field (IEEE Std 802.11-2020 §9.2.4.5).

    Only the subfields every QoS Data subtype places alike are decoded. What
    bits 8-15 carry depends on the subtype and on the kind of station that
    sent the frame, which the MAC header does not say, so they are kept
    whole as :attr:`bits_8_15`.

    """

    #: TID (bits 0-3).
    tid: 'int'
    #: EOSP (bit 4). In a frame a non-AP station sends, the same bit says
    #: whether :attr:`bits_8_15` is TXOP Duration Requested or Queue Size.
    eosp: 'bool'
    #: Ack Policy Indicator (bits 5-6).
    ack_policy: 'int'
    #: A-MSDU Present (bit 7); reserved in the subtypes that carry no data.
    amsdu_present: 'bool'
    #: Bits 8-15, which are TXOP Limit, TXOP Duration Requested, Queue Size,
    #: AP PS Buffer State, or the mesh subfields, by subtype and sender.
    bits_8_15: 'int'

    if TYPE_CHECKING:
        def __init__(self, tid: 'int', eosp: 'bool', ack_policy: 'int',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
                     amsdu_present: 'bool', bits_8_15: 'int') -> 'None': ...  # pylint: disable=unused-argument


@info_final
class HTControl(Data):
    """Data model for the HT Control field (IEEE Std 802.11-2020 §9.2.4.6).

    Its first bits name the variant the rest of the field takes; the
    variants' own subfields are not decoded.

    """

    #: The variant, ``'HT'`` when bit 0 is clear, ``'VHT'`` when bit 0 is set
    #: and bit 1 clear, and ``'HE'`` when both are set (IEEE Std 802.11ax-2021).
    variant: 'Literal["HT", "VHT", "HE"]'
    #: The whole field, as the little-endian integer read off the wire.
    value: 'int'

    if TYPE_CHECKING:
        def __init__(self, variant: 'Literal["HT", "VHT", "HE"]', value: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class IEEE802_11(Protocol):
    """Data model for an IEEE 802.11 MAC header (IEEE Std 802.11-2020 §9.2).

    A field the header does not carry is :obj:`None`; see
    :func:`~pcapkit.protocols.schema.link.ieee802_11.layout`.

    """

    #: Frame Control.
    frame_control: 'FrameControl'
    #: Duration/ID; the AID in a PS-Poll frame.
    duration_id: 'int'
    #: Address 1.
    addr1: 'str'
    #: Address 2.
    addr2: 'Optional[str]'
    #: Address 3.
    addr3: 'Optional[str]'
    #: Sequence Control.
    seq_ctrl: 'Optional[SequenceControl]'
    #: Address 4.
    addr4: 'Optional[str]'
    #: QoS Control.
    qos_control: 'Optional[QoSControl]'
    #: HT Control.
    ht_control: 'Optional[HTControl]'

    if TYPE_CHECKING:
        def __init__(self, frame_control: 'FrameControl', duration_id: 'int', addr1: 'str',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
                     addr2: 'Optional[str]', addr3: 'Optional[str]',  # pylint: disable=unused-argument
                     seq_ctrl: 'Optional[SequenceControl]', addr4: 'Optional[str]',  # pylint: disable=unused-argument
                     qos_control: 'Optional[QoSControl]',  # pylint: disable=unused-argument
                     ht_control: 'Optional[HTControl]') -> 'None': ...  # pylint: disable=unused-argument
