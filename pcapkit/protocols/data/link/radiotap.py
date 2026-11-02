# -*- coding: utf-8 -*-
"""data models for IEEE 802.11 radiotap headers"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data.data import Data
from pcapkit.protocols.data.protocol import Protocol

if TYPE_CHECKING:
    from pcapkit.const.radiotap.ampdu_flags import AMPDUFlags
    from pcapkit.const.radiotap.channel_flags import ChannelFlags
    from pcapkit.const.radiotap.eht_known import EHTKnown
    from pcapkit.const.radiotap.field_type import FieldType
    from pcapkit.const.radiotap.flags import Flags as Radiotap_Flags
    from pcapkit.const.radiotap.he_data1_known import HEData1Known
    from pcapkit.const.radiotap.he_data2_known import HEData2Known
    from pcapkit.const.radiotap.he_mu_flags1_known import HEMUFlags1Known
    from pcapkit.const.radiotap.he_mu_flags2_known import HEMUFlags2Known
    from pcapkit.const.radiotap.he_mu_other_user_known import HEMUOtherUserKnown
    from pcapkit.const.radiotap.lsig_data1 import LSIGData1
    from pcapkit.const.radiotap.mcs_known import MCSKnown
    from pcapkit.const.radiotap.rx_flags import RXFlags as Radiotap_RXFlags
    from pcapkit.const.radiotap.s1g_known import S1GKnown
    from pcapkit.const.radiotap.timestamp_flags import TimestampFlags
    from pcapkit.const.radiotap.tx_flags import TXFlags as Radiotap_TXFlags
    from pcapkit.const.radiotap.usig_common_known import USIGCommonKnown
    from pcapkit.const.radiotap.vht_coding import VHTCoding
    from pcapkit.const.radiotap.vht_flags import VHTFlags
    from pcapkit.const.radiotap.vht_known import VHTKnown
    from pcapkit.corekit.infoclass import OrderedMultiInfo
    from pcapkit.corekit.multidict import OrderedMultiDict

__all__ = [
    'Radiotap',

    'RadiotapField', 'Unknown',
    'TSFT', 'Flags', 'Rate', 'Channel', 'FHSS', 'AntennaSignal', 'AntennaNoise',
    'LockQuality', 'TXAttenuation', 'DBTXAttenuation', 'DBmTXPower', 'Antenna',
    'DBAntennaSignal', 'DBAntennaNoise', 'RXFlags', 'TXFlags', 'RTSRetries', 'DataRetries',
    'MCS', 'MCSFlags', 'AMPDUStatus',
    'VHT', 'Timestamp', 'HE', 'HEData1', 'HEData2', 'HEMU', 'HEMUFlags1', 'HEMUFlags2', 'HEMUOtherUser',
    'ZeroLengthPSDU', 'LSIG',
    'TLVFields', 'RadiotapNamespace', 'VendorNamespace', 'S1G', 'USIG', 'USIGCommon', 'EHT',
    'TLV', 'VendorTLV',
]


class RadiotapField(Data):
    """Data model for a radiotap field.

    Each field's subfields are named as its own page on radiotap.org names
    them, and each is the little-endian integer read off the wire. A bitmap
    radiotap.org defines bit by bit is a member of its flag registry under
    :mod:`pcapkit.const.radiotap`, which keeps the bits it does not name; any
    other bitmap stays the integer.

    """

    #: The presence bit that selects the field, or its TLV type.
    type: 'FieldType'


@info_final
class Unknown(RadiotapField):
    """Data model for an octet run a field type does not decode.

    It is the field of a presence bit no field is defined for, or of a field
    that does not fit in what the header holds, and it holds every octet
    from the end of the field before it to the end of the field-data region,
    since what follows cannot be located without knowing its size.

    """

    #: The octets, kept whole.
    data: 'bytes'
    #: The reason the walk stopped here, that the field type has no layout or
    #: that the field runs past the field-data region. :meth:`Radiotap.make
    #: <pcapkit.protocols.link.radiotap.Radiotap.make>` does not read it.
    reason: 'str'

    if TYPE_CHECKING:
        def __init__(self, type: 'FieldType', data: 'bytes', reason: 'str') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin


@info_final
class TSFT(RadiotapField):
    """Data model for the TSFT field, bit 0."""

    #: The MAC's 64-bit Time Synchronization Function timer, in microseconds,
    #: when the first bit of the MPDU arrived.
    mactime: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'FieldType', mactime: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin


@info_final
class Flags(RadiotapField):
    """Data model for the Flags field, bit 1."""

    #: Properties of the frame.
    flags: 'Radiotap_Flags'

    if TYPE_CHECKING:
        def __init__(self, type: 'FieldType', flags: 'Radiotap_Flags') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin


@info_final
class Rate(RadiotapField):
    """Data model for the Rate field, bit 2."""

    #: TX/RX data rate, in units of 500 kbps.
    rate: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'FieldType', rate: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin


@info_final
class Channel(RadiotapField):
    """Data model for the Channel field, bit 3."""

    #: TX/RX frequency, in MHz.
    frequency: 'int'
    #: Channel flags.
    flags: 'ChannelFlags'

    if TYPE_CHECKING:
        def __init__(self, type: 'FieldType', frequency: 'int', flags: 'ChannelFlags') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin


@info_final
class FHSS(RadiotapField):
    """Data model for the FHSS field, bit 4."""

    #: Hop set of a frequency-hopping radio.
    hop_set: 'int'
    #: Hop pattern of a frequency-hopping radio.
    hop_pattern: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'FieldType', hop_set: 'int', hop_pattern: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin


@info_final
class AntennaSignal(RadiotapField):
    """Data model for the Antenna signal field, bit 5."""

    #: RF signal power at the antenna, in dBm.
    signal: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'FieldType', signal: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin


@info_final
class AntennaNoise(RadiotapField):
    """Data model for the Antenna noise field, bit 6."""

    #: RF noise power at the antenna, in dBm.
    noise: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'FieldType', noise: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin


@info_final
class LockQuality(RadiotapField):
    """Data model for the Lock quality field, bit 7."""

    #: Quality of Barker code lock, unitless.
    quality: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'FieldType', quality: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin


@info_final
class TXAttenuation(RadiotapField):
    """Data model for the TX attenuation field, bit 8."""

    #: Distance from the maximum transmit power, unitless; ``0`` is maximum power.
    attenuation: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'FieldType', attenuation: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin


@info_final
class DBTXAttenuation(RadiotapField):
    """Data model for the dB TX attenuation field, bit 9."""

    #: Distance from the maximum transmit power, in dB; ``0`` is maximum power.
    attenuation: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'FieldType', attenuation: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin


@info_final
class DBmTXPower(RadiotapField):
    """Data model for the dBm TX power field, bit 10."""

    #: Transmit power at the antenna port, in dBm.
    power: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'FieldType', power: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin


@info_final
class Antenna(RadiotapField):
    """Data model for the Antenna field, bit 11."""

    #: Index of the RX/TX antenna, from ``0``.
    antenna: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'FieldType', antenna: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin


@info_final
class DBAntennaSignal(RadiotapField):
    """Data model for the dB antenna signal field, bit 12."""

    #: RF signal power at the antenna, in dB from an arbitrary reference.
    signal: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'FieldType', signal: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin


@info_final
class DBAntennaNoise(RadiotapField):
    """Data model for the dB antenna noise field, bit 13."""

    #: RF noise power at the antenna, in dB from an arbitrary reference.
    noise: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'FieldType', noise: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin


@info_final
class RXFlags(RadiotapField):
    """Data model for the RX flags field, bit 14."""

    #: Properties of the received frame.
    flags: 'Radiotap_RXFlags'

    if TYPE_CHECKING:
        def __init__(self, type: 'FieldType', flags: 'Radiotap_RXFlags') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin


@info_final
class TXFlags(RadiotapField):
    """Data model for the TX flags field, bit 15."""

    #: Properties of the transmitted frame.
    flags: 'Radiotap_TXFlags'

    if TYPE_CHECKING:
        def __init__(self, type: 'FieldType', flags: 'Radiotap_TXFlags') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin


@info_final
class RTSRetries(RadiotapField):
    """Data model for the RTS retries field, bit 16, which radiotap.org lists as unofficial."""

    #: RTS retries the transmitted frame used.
    retries: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'FieldType', retries: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin


@info_final
class DataRetries(RadiotapField):
    """Data model for the data retries field, bit 17, which radiotap.org lists as unofficial."""

    #: Data retries the transmitted frame used.
    retries: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'FieldType', retries: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin


@info_final
class MCSFlags(Data):
    """Data model for the MCS field's ``flags``, each a value subfield.

    .. versionadded:: 1.6.0

    """

    #: Bandwidth, ``0`` for 20, ``1`` for 40, ``2`` for 20L and ``3`` for 20U.
    bandwidth: 'int'
    #: Guard interval, ``0`` for long and ``1`` for short.
    guard_interval: 'int'
    #: HT format, ``0`` for mixed and ``1`` for greenfield.
    ht_format: 'int'
    #: FEC type, ``0`` for BCC and ``1`` for LDPC.
    fec_type: 'int'
    #: Number of STBC streams.
    stbc_streams: 'int'
    #: Bit 0, the least significant, of the number of extension spatial streams.
    ness_bit0: 'int'

    if TYPE_CHECKING:
        def __init__(self, bandwidth: 'int', guard_interval: 'int', ht_format: 'int', fec_type: 'int',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
                     stbc_streams: 'int', ness_bit0: 'int') -> 'None': ...  # pylint: disable=unused-argument


@info_final
class MCS(RadiotapField):
    """Data model for the MCS field, bit 19."""

    #: Which of :attr:`flags` and :attr:`mcs` are known.
    known: 'MCSKnown'
    #: Bandwidth, guard interval, HT format, FEC type, STBC and Ness.
    flags: 'MCSFlags'
    #: MCS rate index, as in IEEE Std 802.11n-2009.
    mcs: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'FieldType', known: 'MCSKnown', flags: 'MCSFlags', mcs: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin


@info_final
class AMPDUStatus(RadiotapField):
    """Data model for the A-MPDU status field, bit 20."""

    #: Reference number, the same for every subframe of an A-MPDU.
    reference: 'int'
    #: A-MPDU flags.
    flags: 'AMPDUFlags'
    #: Delimiter CRC value.
    delimiter_crc: 'int'
    #: Reserved.
    reserved: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'FieldType', reference: 'int', flags: 'AMPDUFlags',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin
                     delimiter_crc: 'int', reserved: 'int') -> 'None': ...  # pylint: disable=unused-argument


@info_final
class VHT(RadiotapField):
    """Data model for the VHT field, bit 21."""

    #: Which of the subfields below are known.
    known: 'VHTKnown'
    #: STBC, TXOP_PS_NOT_ALLOWED, guard interval, LDPC extra OFDM symbol and
    #: beamformed.
    flags: 'VHTFlags'
    #: Bandwidth.
    bandwidth: 'int'
    #: MCS and NSS of each of the four users.
    mcs_nss: 'tuple[int, int, int, int]'
    #: Coding of each user.
    coding: 'VHTCoding'
    #: Group ID.
    group_id: 'int'
    #: Partial AID.
    partial_aid: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'FieldType', known: 'VHTKnown', flags: 'VHTFlags', bandwidth: 'int',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin
                     mcs_nss: 'tuple[int, int, int, int]', coding: 'VHTCoding', group_id: 'int',  # pylint: disable=unused-argument
                     partial_aid: 'int') -> 'None': ...  # pylint: disable=unused-argument


@info_final
class Timestamp(RadiotapField):
    """Data model for the timestamp field, bit 22."""

    #: The timestamp, in the unit :attr:`unit_position` names.
    timestamp: 'int'
    #: Expected accuracy of :attr:`timestamp`, in the same unit.
    accuracy: 'int'
    #: Unit (bits 0-3) and sampling position (bits 4-7).
    unit_position: 'int'
    #: Timestamp flags.
    flags: 'TimestampFlags'

    if TYPE_CHECKING:
        def __init__(self, type: 'FieldType', timestamp: 'int', accuracy: 'int',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin
                     unit_position: 'int', flags: 'TimestampFlags') -> 'None': ...  # pylint: disable=unused-argument


@info_final
class HEData1(Data):
    """Data model for the HE field's ``data1``, a value subfield and known bits.

    .. versionadded:: 1.6.0

    """

    #: HE PPDU format, ``0`` for HE_SU, ``1`` for HE_EXT_SU, ``2`` for HE_MU and
    #: ``3`` for HE_TRIG.
    ppdu_format: 'int'
    #: Which of the other subfields are known.
    known: 'HEData1Known'

    if TYPE_CHECKING:
        def __init__(self, ppdu_format: 'int', known: 'HEData1Known') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class HEData2(Data):
    """Data model for the HE field's ``data2``, value subfields and known bits.

    .. versionadded:: 1.6.0

    """

    #: RU allocation offset, within the 80 MHz channel.
    ru_offset: 'int'
    #: The 80 MHz channel, ``0`` for the primary and ``1`` for the secondary.
    pri_sec_80mhz: 'int'
    #: Which of the other subfields are known.
    known: 'HEData2Known'

    if TYPE_CHECKING:
        def __init__(self, ru_offset: 'int', pri_sec_80mhz: 'int', known: 'HEData2Known') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class HE(RadiotapField):
    """Data model for the HE field, bit 23, mostly the common part of HE-SIG-A."""

    #: PPDU format and which of the subfields are known.
    data1: 'HEData1'
    #: RU allocation offset, the 80 MHz channel, and which subfields are known.
    data2: 'HEData2'
    #: BSS color, beam change, UL/DL, MCS, DCM, coding, LDPC and STBC.
    data3: 'int'
    #: Spatial reuse, or STA-ID in an HE MU PPDU.
    data4: 'int'
    #: Bandwidth, guard interval, LTF symbol size, TxBF and PE disambiguity.
    data5: 'int'
    #: NSTS, Doppler and TXOP.
    data6: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'FieldType', data1: 'HEData1', data2: 'HEData2', data3: 'int',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin
                     data4: 'int', data5: 'int', data6: 'int') -> 'None': ...  # pylint: disable=unused-argument


@info_final
class HEMUFlags1(Data):
    """Data model for the HE-MU field's ``flags1``, value subfields and known bits.

    .. versionadded:: 1.6.0

    """

    #: SIG-B MCS, from HE-SIG-A.
    sig_b_mcs: 'int'
    #: SIG-B DCM, from HE-SIG-A.
    sig_b_dcm: 'int'
    #: Channel 1 center 26-tone RU value.
    ch1_center_26_tone_ru: 'int'
    #: Which of the subfields of this word and of ``flags2`` are known.
    known: 'HEMUFlags1Known'

    if TYPE_CHECKING:
        def __init__(self, sig_b_mcs: 'int', sig_b_dcm: 'int', ch1_center_26_tone_ru: 'int',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
                     known: 'HEMUFlags1Known') -> 'None': ...  # pylint: disable=unused-argument


@info_final
class HEMUFlags2(Data):
    """Data model for the HE-MU field's ``flags2``, value subfields and known bits.

    .. versionadded:: 1.6.0

    """

    #: Bandwidth from the Bandwidth field of HE-SIG-A, ``0`` for 20 MHz up to
    #: ``3`` for 160 or 80+80 MHz.
    bandwidth: 'int'
    #: SIG-B compression, from HE-SIG-A.
    sig_b_compression: 'int'
    #: Number of HE-SIG-B symbols or MU-MIMO users, less one, from HE-SIG-A.
    sig_b_symbols_users: 'int'
    #: Preamble puncturing, from the Bandwidth field of HE-SIG-A.
    preamble_puncturing: 'int'
    #: Channel 2 center 26-tone RU value.
    ch2_center_26_tone_ru: 'int'
    #: Which of the bandwidth and preamble puncturing are known.
    known: 'HEMUFlags2Known'

    if TYPE_CHECKING:
        def __init__(self, bandwidth: 'int', sig_b_compression: 'int', sig_b_symbols_users: 'int',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
                     preamble_puncturing: 'int', ch2_center_26_tone_ru: 'int',  # pylint: disable=unused-argument
                     known: 'HEMUFlags2Known') -> 'None': ...  # pylint: disable=unused-argument


@info_final
class HEMU(RadiotapField):
    """Data model for the HE-MU field, bit 24, from HE-SIG-A and HE-SIG-B."""

    #: SIG-B MCS and DCM, the channel 1 center 26-tone RU, and which subfields
    #: are known.
    flags1: 'HEMUFlags1'
    #: Bandwidth, SIG-B compression, SIG-B symbols or MU-MIMO users, preamble
    #: puncturing and the channel 2 center 26-tone RU.
    flags2: 'HEMUFlags2'
    #: RU_channel1, one octet per RU.
    ru_channel1: 'tuple[int, int, int, int]'
    #: RU_channel2, one octet per RU.
    ru_channel2: 'tuple[int, int, int, int]'

    if TYPE_CHECKING:
        def __init__(self, type: 'FieldType', flags1: 'HEMUFlags1', flags2: 'HEMUFlags2',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin
                     ru_channel1: 'tuple[int, int, int, int]',  # pylint: disable=unused-argument
                     ru_channel2: 'tuple[int, int, int, int]') -> 'None': ...  # pylint: disable=unused-argument


@info_final
class HEMUOtherUser(RadiotapField):
    """Data model for the HE-MU-other-user field, bit 25, a SIG-B user field."""

    #: B0-B14 of the HE-SIG-B user field.
    per_user_1: 'int'
    #: B15-B20 of the HE-SIG-B user field.
    per_user_2: 'int'
    #: Position of the user field, from ``0``.
    per_user_position: 'int'
    #: Which of the subfields are known.
    per_user_known: 'HEMUOtherUserKnown'

    if TYPE_CHECKING:
        def __init__(self, type: 'FieldType', per_user_1: 'int', per_user_2: 'int',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin
                     per_user_position: 'int', per_user_known: 'HEMUOtherUserKnown') -> 'None': ...  # pylint: disable=unused-argument


@info_final
class ZeroLengthPSDU(RadiotapField):
    """Data model for the 0-length-PSDU field, bit 26."""

    #: Type of the PPDU, the field radiotap.org names ``type``.
    psdu_type: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'FieldType', psdu_type: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin


@info_final
class LSIG(RadiotapField):
    """Data model for the L-SIG field, bit 27."""

    #: Which of the subfields in :attr:`data2` are known.
    data1: 'LSIGData1'
    #: Rate (bits 0-3) and length (bits 4-15).
    data2: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'FieldType', data1: 'LSIGData1', data2: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin


@info_final
class TLV(Data):
    """Data model for one item of the TLV fields in radiotap."""

    #: Type, from the same allocation as the presence bits.
    type: 'FieldType'
    #: Length of :attr:`data`, in octets, less the padding after it.
    length: 'int'
    #: The data, decoded where the type defines a layout :attr:`length` does
    #: not run past; the raw octets otherwise. Data short of the layout is
    #: decoded with the octets it lacks as zeros, and records the cut as
    #: ``__short_read__``.
    data: 'RadiotapField | VendorTLV | bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'FieldType', length: 'int',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin
                     data: 'RadiotapField | VendorTLV | bytes') -> 'None': ...  # pylint: disable=unused-argument


@info_final
class TLVFields(RadiotapField):
    """Data model for the TLV fields in radiotap, bit 28.

    The items fill the rest of the field-data region, each padded to a
    multiple of 4 octets.

    """

    #: The items, in order.
    tlvs: 'tuple[TLV, ...]'

    if TYPE_CHECKING:
        def __init__(self, type: 'FieldType', tlvs: 'tuple[TLV, ...]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin


@info_final
class RadiotapNamespace(RadiotapField):
    """Data model for the Radiotap Namespace field, bit 29 of a presence word.

    It has no contents. The presence word after the one carrying it starts
    the radiotap namespace afresh, from bit 0.

    """

    if TYPE_CHECKING:
        def __init__(self, type: 'FieldType') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin


@info_final
class VendorNamespace(RadiotapField):
    """Data model for the Vendor Namespace field, bit 30 of a presence word.

    The presence words after the one carrying it, up to the next namespace
    field, select fields of the vendor namespace, and the data of every one of
    them is in :attr:`data`, kept whole.

    """

    #: The vendor's IEEE 802 Organizationally Unique Identifier, 3 octets.
    oui: 'bytes'
    #: Vendor-specific namespace selector.
    sub_namespace: 'int'
    #: Octets of :attr:`data`, as the header gives it.
    skip_length: 'int'
    #: The vendor namespace's data, kept whole.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'FieldType', oui: 'bytes', sub_namespace: 'int',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin
                     skip_length: 'int', data: 'bytes') -> 'None': ...  # pylint: disable=unused-argument


@info_final
class S1G(RadiotapField):
    """Data model for the S1G field, TLV type 32."""

    #: Which of the subfields are known.
    known: 'S1GKnown'
    #: PPDU format, response indication, guard interval, NSS, bandwidth and MCS.
    data1: 'int'
    #: Color, uplink indication and RSSI.
    data2: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'FieldType', known: 'S1GKnown', data1: 'int', data2: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin


@info_final
class USIGCommon(Data):
    """Data model for the U-SIG field's ``common``, value subfields and known bits.

    .. versionadded:: 1.6.0

    """

    #: PHY version identifier.
    phy_version: 'int'
    #: Bandwidth, ``0`` for 20 MHz up to ``3`` for 160 MHz, and ``4`` and ``5`` for
    #: the two 320 MHz channelizations.
    bandwidth: 'int'
    #: UL/DL.
    ul_dl: 'int'
    #: BSS color.
    bss_color: 'int'
    #: TXOP.
    txop: 'int'
    #: Which of the subfields are known, and whether the U-SIG CRC failed and its
    #: validate bits were checked and found right.
    known: 'USIGCommonKnown'

    if TYPE_CHECKING:
        def __init__(self, phy_version: 'int', bandwidth: 'int', ul_dl: 'int', bss_color: 'int', txop: 'int',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
                     known: 'USIGCommonKnown') -> 'None': ...  # pylint: disable=unused-argument


@info_final
class USIG(RadiotapField):
    """Data model for the U-SIG field, TLV type 33."""

    #: The common subfields, and which are known.
    common: 'USIGCommon'
    #: Version-dependent subfields.
    value: 'int'
    #: Which bits of :attr:`value` are known.
    mask: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'FieldType', common: 'USIGCommon', value: 'int', mask: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin


@info_final
class EHT(RadiotapField):
    """Data model for the EHT field, TLV type 34."""

    #: Which of the subfields are known.
    known: 'EHTKnown'
    #: The nine data words.
    data: 'tuple[int, ...]'
    #: One word per user, as many as the TLV holds.
    user_info: 'tuple[int, ...]'

    if TYPE_CHECKING:
        def __init__(self, type: 'FieldType', known: 'EHTKnown', data: 'tuple[int, ...]',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin
                     user_info: 'tuple[int, ...]') -> 'None': ...  # pylint: disable=unused-argument


@info_final
class VendorTLV(Data):
    """Data model for the data of a vendor namespace TLV, type 30."""

    #: The vendor's IEEE 802 Organizationally Unique Identifier, 3 octets.
    oui: 'bytes'
    #: Vendor-specific subtype.
    subtype: 'int'
    #: Index of the presence bit the vendor data stands for.
    presence_type: 'int'
    #: Reserved, padding the vendor data to a 4-octet boundary.
    reserved: 'int'
    #: The vendor data, kept whole.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, oui: 'bytes', subtype: 'int', presence_type: 'int',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
                     reserved: 'int', data: 'bytes') -> 'None': ...  # pylint: disable=unused-argument


@info_final
class Radiotap(Protocol):
    """Data model for an IEEE 802.11 radiotap header.

    The fixed 8-octet start and the present-flags chain are decoded field by
    field; the optional-field region is kept whole as :attr:`fields`, which
    is what a rebuild writes, and decoded as :attr:`decoded`. See the module
    docstring's *Scope* section on :mod:`pcapkit.protocols.link.radiotap`.

    """

    #: Header revision; ``0`` is the only version radiotap.org defines, and
    #: the only one this package decodes.
    it_version: 'int'
    #: Padding octet, kept for alignment; not interpreted.
    it_pad: 'int'
    #: Total length of the radiotap header -- the fixed 8-octet start,
    #: every extended present-flags word, and the optional-field region
    #: they select -- in octets; the 802.11 MAC frame starts here. Kept
    #: exactly as captured, even where it disagrees with :attr:`present`
    #: and :attr:`fields`.
    it_len: 'int'
    #: Every present-flags word in the chain that was actually read, in
    #: order; index ``0`` is the mandatory first word (radiotap.org's own
    #: ``it_present``). Bit 31 of a word signals that another word
    #: follows; it is clear on the last word read, unless the capture ran
    #: out before a word it claimed would follow.
    present: 'tuple[int, ...]'
    #: The optional-field region :attr:`present` selects, kept whole.
    fields: 'bytes'
    #: The fields of :attr:`fields`, decoded in wire order, keyed by type:
    #: one per bit of :attr:`present` that selects data in the radiotap
    #: namespace or switches namespace. See :meth:`Radiotap.read
    #: <pcapkit.protocols.link.radiotap.Radiotap.read>`.
    decoded: 'OrderedMultiInfo[FieldType, RadiotapField]'

    if TYPE_CHECKING:
        def __init__(self, it_version: 'int', it_pad: 'int', it_len: 'int',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
                     present: 'tuple[int, ...]', fields: 'bytes',  # pylint: disable=unused-argument
                     decoded: 'OrderedMultiDict[FieldType, RadiotapField]') -> 'None': ...  # pylint: disable=unused-argument
