# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for IEEE 802.11 radiotap headers"""

from typing import TYPE_CHECKING

from pcapkit.const.radiotap.ampdu_flags import AMPDUFlags as Enum_AMPDUFlags
from pcapkit.const.radiotap.channel_flags import ChannelFlags as Enum_ChannelFlags
from pcapkit.const.radiotap.eht_known import EHTKnown as Enum_EHTKnown
from pcapkit.const.radiotap.field_type import FieldType as Enum_FieldType
from pcapkit.const.radiotap.flags import Flags as Enum_Flags
from pcapkit.const.radiotap.he_data1_known import HEData1Known as Enum_HEData1Known
from pcapkit.const.radiotap.he_data2_known import HEData2Known as Enum_HEData2Known
from pcapkit.const.radiotap.he_mu_flags1_known import HEMUFlags1Known as Enum_HEMUFlags1Known
from pcapkit.const.radiotap.he_mu_flags2_known import HEMUFlags2Known as Enum_HEMUFlags2Known
from pcapkit.const.radiotap.he_mu_other_user_known import \
    HEMUOtherUserKnown as Enum_HEMUOtherUserKnown
from pcapkit.const.radiotap.lsig_data1 import LSIGData1 as Enum_LSIGData1
from pcapkit.const.radiotap.mcs_known import MCSKnown as Enum_MCSKnown
from pcapkit.const.radiotap.rx_flags import RXFlags as Enum_RXFlags
from pcapkit.const.radiotap.s1g_known import S1GKnown as Enum_S1GKnown
from pcapkit.const.radiotap.timestamp_flags import TimestampFlags as Enum_TimestampFlags
from pcapkit.const.radiotap.tx_flags import TXFlags as Enum_TXFlags
from pcapkit.const.radiotap.usig_common_known import USIGCommonKnown as Enum_USIGCommonKnown
from pcapkit.const.radiotap.vht_coding import VHTCoding as Enum_VHTCoding
from pcapkit.const.radiotap.vht_flags import VHTFlags as Enum_VHTFlags
from pcapkit.const.radiotap.vht_known import VHTKnown as Enum_VHTKnown
from pcapkit.corekit.fields.collections import ListField
from pcapkit.corekit.fields.misc import PayloadField
from pcapkit.corekit.fields.numbers import (BitmapField, EnumField, Int8Field, UInt8Field,
                                            UInt16Field, UInt32Field, UInt64Field)
from pcapkit.corekit.fields.strings import BytesField
from pcapkit.protocols.schema import EnumSchema, Schema, schema_final

__all__ = [
    'Radiotap',

    'RadiotapField', 'Unknown',
    'TSFT', 'Flags', 'Rate', 'Channel', 'FHSS', 'AntennaSignal', 'AntennaNoise',
    'LockQuality', 'TXAttenuation', 'DBTXAttenuation', 'DBmTXPower', 'Antenna',
    'DBAntennaSignal', 'DBAntennaNoise', 'RXFlags', 'TXFlags', 'RTSRetries', 'DataRetries',
    'MCS', 'AMPDUStatus',
    'VHT', 'Timestamp', 'HE', 'HEMU', 'HEMUOtherUser', 'ZeroLengthPSDU', 'LSIG',
    'VendorNamespace', 'S1G', 'USIG', 'EHT',
    'TLV', 'VendorTLV',
]

if TYPE_CHECKING:
    from typing import Any, ClassVar

    from pcapkit.protocols.protocol import ProtocolBase



@schema_final
class Radiotap(Schema):
    """Header schema for an IEEE 802.11 radiotap header.

    Only the fixed 8-octet start -- ``it_version``, ``it_pad``, ``it_len``
    and the first ``it_present`` word -- is given its own field, all
    little-endian per radiotap.org. Everything that follows -- any extended
    present-flags words, the optional-field region they select, and the
    802.11 MAC frame behind it -- is captured together as :attr:`payload`,
    since where one ends and the next begins is only known once the
    present-flags chain itself has been walked; see :meth:`Radiotap.read
    <pcapkit.protocols.link.radiotap.protocol.Radiotap.read>`. Each field in the
    region is a :class:`RadiotapField` of its own.

    """

    #: Header revision.
    it_version: 'int' = UInt8Field()
    #: Padding octet.
    it_pad: 'int' = UInt8Field()
    #: Total header length, including this fixed start.
    it_len: 'int' = UInt16Field(byteorder='little')
    #: First present-flags word.
    it_present: 'int' = UInt32Field(byteorder='little')
    #: Everything after the fixed start -- see the class docstring.
    payload: 'bytes' = PayloadField()

    if TYPE_CHECKING:
        def __init__(self, it_version: 'int', it_pad: 'int', it_len: 'int',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
                     it_present: 'int',  # pylint: disable=unused-argument
                     payload: 'bytes | ProtocolBase | Schema') -> 'None': ...  # pylint: disable=unused-argument


class RadiotapField(EnumSchema[Enum_FieldType]):
    """Header schema for a radiotap field, little-endian on the wire.

    A subclass registered with a field type is the layout of that type's field,
    as its page on radiotap.org gives it: its subfields are the schema's fields,
    its size their total, and its alignment :attr:`__align__`. A field a
    presence bit selects has a fixed size.

    """

    __default__ = lambda: Unknown
    __additional__ = ['__align__']
    __excluded__ = ['__align__']

    #: Alignment of the field, in octets counted from the start of the header.
    __align__: 'ClassVar[int]' = 1


@schema_final
class Unknown(RadiotapField):
    """Header schema for an octet run a field type does not decode, kept whole."""

    #: The octets, to the end of the field-data region.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['__length__'])

    if TYPE_CHECKING:
        def __init__(self, data: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@schema_final
class TSFT(RadiotapField, code=Enum_FieldType.TSFT):
    """Header schema for the TSFT field, bit 0."""

    __align__ = 8

    #: Time Synchronization Function timer, in microseconds.
    mactime: 'int' = UInt64Field(byteorder='little')

    if TYPE_CHECKING:
        def __init__(self, mactime: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@schema_final
class Flags(RadiotapField, code=Enum_FieldType.Flags):
    """Header schema for the Flags field, bit 1."""

    #: Properties of the frame.
    flags: 'Enum_Flags' = EnumField(length=1, namespace=Enum_Flags)

    if TYPE_CHECKING:
        def __init__(self, flags: 'Enum_Flags | int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@schema_final
class Rate(RadiotapField, code=Enum_FieldType.Rate):
    """Header schema for the Rate field, bit 2."""

    #: TX/RX data rate, in 500 kbps.
    rate: 'int' = UInt8Field()

    if TYPE_CHECKING:
        def __init__(self, rate: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@schema_final
class Channel(RadiotapField, code=Enum_FieldType.Channel):
    """Header schema for the Channel field, bit 3."""

    __align__ = 2

    #: TX/RX frequency, in MHz.
    frequency: 'int' = UInt16Field(byteorder='little')
    #: Channel flags.
    flags: 'Enum_ChannelFlags' = EnumField(length=2, byteorder='little', namespace=Enum_ChannelFlags)

    if TYPE_CHECKING:
        def __init__(self, frequency: 'int', flags: 'Enum_ChannelFlags | int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@schema_final
class FHSS(RadiotapField, code=Enum_FieldType.FHSS):
    """Header schema for the FHSS field, bit 4.

    Its page names no alignment; the Linux kernel, Wireshark and
    radiotap-library align it to 2.

    """

    __align__ = 2

    #: Hop set.
    hop_set: 'int' = UInt8Field()
    #: Hop pattern.
    hop_pattern: 'int' = UInt8Field()

    if TYPE_CHECKING:
        def __init__(self, hop_set: 'int', hop_pattern: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@schema_final
class AntennaSignal(RadiotapField, code=Enum_FieldType.Antenna_signal):
    """Header schema for the Antenna signal field, bit 5."""

    #: RF signal power at the antenna, in dBm.
    signal: 'int' = Int8Field()

    if TYPE_CHECKING:
        def __init__(self, signal: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@schema_final
class AntennaNoise(RadiotapField, code=Enum_FieldType.Antenna_noise):
    """Header schema for the Antenna noise field, bit 6."""

    #: RF noise power at the antenna, in dBm.
    noise: 'int' = Int8Field()

    if TYPE_CHECKING:
        def __init__(self, noise: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@schema_final
class LockQuality(RadiotapField, code=Enum_FieldType.Lock_quality):
    """Header schema for the Lock quality field, bit 7."""

    __align__ = 2

    #: Quality of Barker code lock.
    quality: 'int' = UInt16Field(byteorder='little')

    if TYPE_CHECKING:
        def __init__(self, quality: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@schema_final
class TXAttenuation(RadiotapField, code=Enum_FieldType.TX_attenuation):
    """Header schema for the TX attenuation field, bit 8."""

    __align__ = 2

    #: Transmit power below the maximum, unitless.
    attenuation: 'int' = UInt16Field(byteorder='little')

    if TYPE_CHECKING:
        def __init__(self, attenuation: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@schema_final
class DBTXAttenuation(RadiotapField, code=Enum_FieldType.dB_TX_attenuation):
    """Header schema for the dB TX attenuation field, bit 9."""

    __align__ = 2

    #: Transmit power below the maximum, in dB.
    attenuation: 'int' = UInt16Field(byteorder='little')

    if TYPE_CHECKING:
        def __init__(self, attenuation: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@schema_final
class DBmTXPower(RadiotapField, code=Enum_FieldType.dBm_TX_power):
    """Header schema for the dBm TX power field, bit 10."""

    #: Transmit power, in dBm.
    power: 'int' = Int8Field()

    if TYPE_CHECKING:
        def __init__(self, power: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@schema_final
class Antenna(RadiotapField, code=Enum_FieldType.Antenna):
    """Header schema for the Antenna field, bit 11."""

    #: Antenna index.
    antenna: 'int' = UInt8Field()

    if TYPE_CHECKING:
        def __init__(self, antenna: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@schema_final
class DBAntennaSignal(RadiotapField, code=Enum_FieldType.dB_antenna_signal):
    """Header schema for the dB antenna signal field, bit 12."""

    #: RF signal power at the antenna, in dB from an arbitrary reference.
    signal: 'int' = UInt8Field()

    if TYPE_CHECKING:
        def __init__(self, signal: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@schema_final
class DBAntennaNoise(RadiotapField, code=Enum_FieldType.dB_antenna_noise):
    """Header schema for the dB antenna noise field, bit 13."""

    #: RF noise power at the antenna, in dB from an arbitrary reference.
    noise: 'int' = UInt8Field()

    if TYPE_CHECKING:
        def __init__(self, noise: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@schema_final
class RXFlags(RadiotapField, code=Enum_FieldType.RX_flags):
    """Header schema for the RX flags field, bit 14."""

    __align__ = 2

    #: Properties of the received frame.
    flags: 'Enum_RXFlags' = EnumField(length=2, byteorder='little', namespace=Enum_RXFlags)

    if TYPE_CHECKING:
        def __init__(self, flags: 'Enum_RXFlags | int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@schema_final
class TXFlags(RadiotapField, code=Enum_FieldType.TX_flags):
    """Header schema for the TX flags field, bit 15."""

    __align__ = 2

    #: Properties of the transmitted frame.
    flags: 'Enum_TXFlags' = EnumField(length=2, byteorder='little', namespace=Enum_TXFlags)

    if TYPE_CHECKING:
        def __init__(self, flags: 'Enum_TXFlags | int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@schema_final
class RTSRetries(RadiotapField, code=Enum_FieldType.RTS_retries):
    """Header schema for the RTS retries field, bit 16, from radiotap.org's unofficial fields."""

    #: RTS retries.
    retries: 'int' = UInt8Field()

    if TYPE_CHECKING:
        def __init__(self, retries: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@schema_final
class DataRetries(RadiotapField, code=Enum_FieldType.data_retries):
    """Header schema for the data retries field, bit 17, from radiotap.org's unofficial fields."""

    #: Data retries.
    retries: 'int' = UInt8Field()

    if TYPE_CHECKING:
        def __init__(self, retries: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@schema_final
class MCS(RadiotapField, code=Enum_FieldType.MCS):
    """Header schema for the MCS field, bit 19."""

    #: Which of :attr:`flags` and :attr:`mcs` are known.
    known: 'Enum_MCSKnown' = EnumField(length=1, namespace=Enum_MCSKnown)
    #: Bandwidth, guard interval, HT format, FEC type, STBC streams and the
    #: low bit of the extension spatial streams.
    flags: 'dict[str, Any]' = BitmapField(length=1, namespace={
        'bandwidth': (0, 2),
        'guard_interval': (2, 1),
        'ht_format': (3, 1),
        'fec_type': (4, 1),
        'stbc_streams': (5, 2),
        'ness_bit0': (7, 1),
    })
    #: MCS rate index.
    mcs: 'int' = UInt8Field()

    if TYPE_CHECKING:
        def __init__(self, known: 'Enum_MCSKnown | int', flags: 'dict[str, Any]', mcs: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@schema_final
class AMPDUStatus(RadiotapField, code=Enum_FieldType.A_MPDU_status):
    """Header schema for the A-MPDU status field, bit 20."""

    __align__ = 4

    #: Reference number of the A-MPDU.
    reference: 'int' = UInt32Field(byteorder='little')
    #: Flags.
    flags: 'Enum_AMPDUFlags' = EnumField(length=2, byteorder='little', namespace=Enum_AMPDUFlags)
    #: A-MPDU subframe delimiter CRC.
    delimiter_crc: 'int' = UInt8Field()
    #: Reserved.
    reserved: 'int' = UInt8Field()

    if TYPE_CHECKING:
        def __init__(self, reference: 'int', flags: 'Enum_AMPDUFlags | int', delimiter_crc: 'int',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
                     reserved: 'int') -> 'None': ...  # pylint: disable=unused-argument


@schema_final
class VHT(RadiotapField, code=Enum_FieldType.VHT):
    """Header schema for the VHT field, bit 21."""

    __align__ = 2

    #: Which of the subfields are known.
    known: 'Enum_VHTKnown' = EnumField(length=2, byteorder='little', namespace=Enum_VHTKnown)
    #: Flags.
    flags: 'Enum_VHTFlags' = EnumField(length=1, namespace=Enum_VHTFlags)
    #: Bandwidth.
    bandwidth: 'int' = UInt8Field()
    #: MCS and NSS of each of the four users.
    mcs_nss: 'list[int]' = ListField(length=4, item_type=UInt8Field())
    #: FEC coding of each user.
    coding: 'Enum_VHTCoding' = EnumField(length=1, namespace=Enum_VHTCoding)
    #: Group ID.
    group_id: 'int' = UInt8Field()
    #: Partial AID.
    partial_aid: 'int' = UInt16Field(byteorder='little')

    if TYPE_CHECKING:
        def __init__(self, known: 'Enum_VHTKnown | int', flags: 'Enum_VHTFlags | int', bandwidth: 'int',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
                     mcs_nss: 'list[int] | tuple[int, ...]', coding: 'Enum_VHTCoding | int',  # pylint: disable=unused-argument
                     group_id: 'int', partial_aid: 'int') -> 'None': ...  # pylint: disable=unused-argument


@schema_final
class Timestamp(RadiotapField, code=Enum_FieldType.timestamp):
    """Header schema for the timestamp field, bit 22."""

    __align__ = 8

    #: Timestamp.
    timestamp: 'int' = UInt64Field(byteorder='little')
    #: Accuracy, in nanoseconds.
    accuracy: 'int' = UInt16Field(byteorder='little')
    #: Unit and sampling position.
    unit_position: 'int' = UInt8Field()
    #: Flags.
    flags: 'Enum_TimestampFlags' = EnumField(length=1, namespace=Enum_TimestampFlags)

    if TYPE_CHECKING:
        def __init__(self, timestamp: 'int', accuracy: 'int', unit_position: 'int',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
                     flags: 'Enum_TimestampFlags | int') -> 'None': ...  # pylint: disable=unused-argument


@schema_final
class HE(RadiotapField, code=Enum_FieldType.HE):
    """Header schema for the HE field, bit 23."""

    __align__ = 2

    #: PPDU format, and which other subfields are known.
    data1: 'dict[str, Any]' = BitmapField(length=2, byteorder='little', namespace={
        'ppdu_format': (0, 2),
    }, remainder='known', flags=Enum_HEData1Known)
    #: RU allocation offset, primary or secondary 80 MHz, and which other
    #: subfields are known.
    data2: 'dict[str, Any]' = BitmapField(length=2, byteorder='little', namespace={
        'ru_offset': (8, 6),
        'pri_sec_80mhz': (15, 1),
    }, remainder='known', flags=Enum_HEData2Known)
    #: Third data word.
    data3: 'int' = UInt16Field(byteorder='little')
    #: Fourth data word.
    data4: 'int' = UInt16Field(byteorder='little')
    #: Fifth data word.
    data5: 'int' = UInt16Field(byteorder='little')
    #: Sixth data word.
    data6: 'int' = UInt16Field(byteorder='little')

    if TYPE_CHECKING:
        def __init__(self, data1: 'dict[str, Any]', data2: 'dict[str, Any]', data3: 'int', data4: 'int', data5: 'int',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
                     data6: 'int') -> 'None': ...  # pylint: disable=unused-argument


@schema_final
class HEMU(RadiotapField, code=Enum_FieldType.HE_MU):
    """Header schema for the HE-MU field, bit 24."""

    __align__ = 2

    #: SIG-B MCS and DCM, the channel 1 center 26-tone RU, and which subfields
    #: are known.
    flags1: 'dict[str, Any]' = BitmapField(length=2, byteorder='little', namespace={
        'sig_b_mcs': (0, 4),
        'sig_b_dcm': (5, 1),
        'ch1_center_26_tone_ru': (13, 1),
    }, remainder='known', flags=Enum_HEMUFlags1Known)
    #: Bandwidth, SIG-B compression, SIG-B symbols or MU-MIMO users, preamble
    #: puncturing, the channel 2 center 26-tone RU, and which are known.
    flags2: 'dict[str, Any]' = BitmapField(length=2, byteorder='little', namespace={
        'bandwidth': (0, 2),
        'sig_b_compression': (3, 1),
        'sig_b_symbols_users': (4, 4),
        'preamble_puncturing': (8, 2),
        'ch2_center_26_tone_ru': (11, 1),
    }, remainder='known', flags=Enum_HEMUFlags2Known)
    #: RU allocation of channel 1.
    ru_channel1: 'list[int]' = ListField(length=4, item_type=UInt8Field())
    #: RU allocation of channel 2.
    ru_channel2: 'list[int]' = ListField(length=4, item_type=UInt8Field())

    if TYPE_CHECKING:
        def __init__(self, flags1: 'dict[str, Any]', flags2: 'dict[str, Any]',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
                     ru_channel1: 'list[int] | tuple[int, ...]',  # pylint: disable=unused-argument
                     ru_channel2: 'list[int] | tuple[int, ...]') -> 'None': ...  # pylint: disable=unused-argument


@schema_final
class HEMUOtherUser(RadiotapField, code=Enum_FieldType.HE_MU_other_user):
    """Header schema for the HE-MU-other-user field, bit 25."""

    __align__ = 2

    #: First per-user word.
    per_user_1: 'int' = UInt16Field(byteorder='little')
    #: Second per-user word.
    per_user_2: 'int' = UInt16Field(byteorder='little')
    #: Position of the user.
    per_user_position: 'int' = UInt8Field()
    #: Which of the per-user subfields are known.
    per_user_known: 'Enum_HEMUOtherUserKnown' = EnumField(length=1, namespace=Enum_HEMUOtherUserKnown)

    if TYPE_CHECKING:
        def __init__(self, per_user_1: 'int', per_user_2: 'int', per_user_position: 'int',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
                     per_user_known: 'Enum_HEMUOtherUserKnown | int') -> 'None': ...  # pylint: disable=unused-argument


@schema_final
class ZeroLengthPSDU(RadiotapField, code=Enum_FieldType.FieldType_0_length_PSDU):
    """Header schema for the 0-length-PSDU field, bit 26."""

    #: Why no PSDU was captured.
    psdu_type: 'int' = UInt8Field()

    if TYPE_CHECKING:
        def __init__(self, psdu_type: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@schema_final
class LSIG(RadiotapField, code=Enum_FieldType.L_SIG):
    """Header schema for the L-SIG field, bit 27."""

    __align__ = 2

    #: Which of the subfields of :attr:`data2` are known.
    data1: 'Enum_LSIGData1' = EnumField(length=2, byteorder='little', namespace=Enum_LSIGData1)
    #: Rate and length.
    data2: 'int' = UInt16Field(byteorder='little')

    if TYPE_CHECKING:
        def __init__(self, data1: 'Enum_LSIGData1 | int', data2: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@schema_final
class VendorNamespace(RadiotapField):
    """Header schema for the Vendor Namespace field, bit 30.

    The vendor data it gives the length of follows it, and is not a subfield of
    its own; nor is the schema registered, since a vendor namespace TLV is a
    :class:`VendorTLV` instead.

    """

    __align__ = 2

    #: OUI of the vendor.
    oui: 'bytes' = BytesField(length=3)
    #: Sub-namespace of the vendor's.
    sub_namespace: 'int' = UInt8Field()
    #: Octets of vendor data that follow.
    skip_length: 'int' = UInt16Field(byteorder='little')

    if TYPE_CHECKING:
        def __init__(self, oui: 'bytes', sub_namespace: 'int', skip_length: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@schema_final
class S1G(RadiotapField, code=Enum_FieldType.S1G):
    """Header schema for the S1G field, type 32, which only a TLV carries."""

    __align__ = 2

    #: Which of the subfields are known.
    known: 'Enum_S1GKnown' = EnumField(length=2, byteorder='little', namespace=Enum_S1GKnown)
    #: First data word.
    data1: 'int' = UInt16Field(byteorder='little')
    #: Second data word.
    data2: 'int' = UInt16Field(byteorder='little')

    if TYPE_CHECKING:
        def __init__(self, known: 'Enum_S1GKnown | int', data1: 'int', data2: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@schema_final
class USIG(RadiotapField, code=Enum_FieldType.U_SIG):
    """Header schema for the U-SIG field, type 33, which only a TLV carries."""

    __align__ = 4

    #: PHY version, bandwidth, UL/DL, BSS color and TXOP, and which are known.
    common: 'dict[str, Any]' = BitmapField(length=4, byteorder='little', namespace={
        'phy_version': (12, 3),
        'bandwidth': (15, 3),
        'ul_dl': (18, 1),
        'bss_color': (19, 6),
        'txop': (25, 7),
    }, remainder='known', flags=Enum_USIGCommonKnown)
    #: Value of the U-SIG bits.
    value: 'int' = UInt32Field(byteorder='little')
    #: Which of :attr:`value`'s bits are known.
    mask: 'int' = UInt32Field(byteorder='little')

    if TYPE_CHECKING:
        def __init__(self, common: 'dict[str, Any]', value: 'int', mask: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@schema_final
class EHT(RadiotapField, code=Enum_FieldType.EHT):
    """Header schema for the EHT field, type 34, which only a TLV carries."""

    __align__ = 4

    #: Which of the subfields are known.
    known: 'Enum_EHTKnown' = EnumField(length=4, byteorder='little', namespace=Enum_EHTKnown)
    #: The data words, nine of them.
    data: 'list[int]' = ListField(length=36, item_type=UInt32Field(byteorder='little'))
    #: One word per user, to the end of the field.
    user_info: 'list[int]' = ListField(length=lambda pkt: pkt['__length__'],
                                       item_type=UInt32Field(byteorder='little'))

    if TYPE_CHECKING:
        def __init__(self, known: 'Enum_EHTKnown | int', data: 'list[int] | tuple[int, ...]',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
                     user_info: 'list[int] | tuple[int, ...]') -> 'None': ...  # pylint: disable=unused-argument


@schema_final
class TLV(RadiotapField):
    """Header schema for the type and length opening a TLV item, bit 28.

    The item's data follows, then padding to its
    :attr:`~RadiotapField.__align__`, which the TLV list is aligned to as well.
    The schema is not registered, since a TLV item is no field of a type of its
    own.

    """

    __align__ = 4

    #: Type of the item, a field type.
    type: 'Enum_FieldType' = EnumField(length=2, byteorder='little', namespace=Enum_FieldType)
    #: Octets of the item's data.
    length: 'int' = UInt16Field(byteorder='little')

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_FieldType | int', length: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin


@schema_final
class VendorTLV(Schema):
    """Header schema for the vendor header opening the data of a vendor namespace TLV item.

    The vendor data follows, to the end of the item.

    """

    #: OUI of the vendor.
    oui: 'bytes' = BytesField(length=3)
    #: Sub-namespace of the vendor's.
    subtype: 'int' = UInt8Field()
    #: Vendor type of the data.
    presence_type: 'int' = UInt16Field(byteorder='little')
    #: Reserved.
    reserved: 'int' = UInt16Field(byteorder='little')

    if TYPE_CHECKING:
        def __init__(self, oui: 'bytes', subtype: 'int', presence_type: 'int',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
                     reserved: 'int') -> 'None': ...  # pylint: disable=unused-argument
