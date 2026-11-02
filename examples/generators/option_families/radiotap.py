# -*- coding: utf-8 -*-
"""The ``radiotap-field`` family: the fields of a radiotap header.

Each case is one field, built from keyword arguments by the field's
``_make_field_*``: a presence bit selects a field of the radiotap namespace,
and a TLV item carries a type from 32 on, which only a TLV carries. The
rebuild is from what the parse decoded. No capture is written, as no
envelope here carries a radiotap header.

A family module of :file:`examples/generators/options.py`, which loads it by
path and binds ``generator`` to itself before this body runs (#2615).

"""
# Deferring these is the design, as in options.py -- see its module docstring.
# pylint: disable=import-outside-toplevel

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

#: :file:`examples/generators/options.py`, which its loader binds here
#: before this body runs.
generator = globals()['generator']  # type: Any


def _radiotap_field_registry() -> 'Any':
    from pcapkit.protocols.link.radiotap import Radiotap
    return Radiotap.__field__


def _radiotap_field_overrides() -> 'dict[Any, dict[str, Any]]':
    from pcapkit.const.radiotap.field_type import FieldType as Enum_FieldType

    # Every subfield is given, as no field defaults one.
    return {
        Enum_FieldType.TSFT: {'mactime': 0x0102030405060708},
        Enum_FieldType.Flags: {'flags': 0x10},
        Enum_FieldType.Rate: {'rate': 2},
        Enum_FieldType.Channel: {'frequency': 2412, 'flags': 0x00A0},
        Enum_FieldType.FHSS: {'hop_set': 1, 'hop_pattern': 2},
        Enum_FieldType.Antenna_signal: {'signal': -40},
        Enum_FieldType.Antenna_noise: {'noise': -90},
        Enum_FieldType.Lock_quality: {'quality': 3},
        Enum_FieldType.TX_attenuation: {'attenuation': 4},
        Enum_FieldType.dB_TX_attenuation: {'attenuation': 5},
        Enum_FieldType.dBm_TX_power: {'power': -6},
        Enum_FieldType.Antenna: {'antenna': 1},
        Enum_FieldType.dB_antenna_signal: {'signal': 50},
        Enum_FieldType.dB_antenna_noise: {'noise': 20},
        Enum_FieldType.RX_flags: {'flags': 0x0002},
        Enum_FieldType.TX_flags: {'flags': 0x0008},
        Enum_FieldType.RTS_retries: {'retries': 3},
        Enum_FieldType.data_retries: {'retries': 1},
        Enum_FieldType.MCS: {'known': 0x27, 'flags': 0x25, 'mcs': 7},
        Enum_FieldType.A_MPDU_status: {'reference': 7, 'flags': 0x0105, 'delimiter_crc': 0xAB, 'reserved': 0},
        Enum_FieldType.VHT: {'known': 0x0244, 'flags': 0x05, 'bandwidth': 4, 'mcs_nss': (0x91, 0, 0, 0),
                             'coding': 0x01, 'group_id': 2, 'partial_aid': 0x1234},
        Enum_FieldType.timestamp: {'timestamp': 1, 'accuracy': 2, 'unit_position': 0x11, 'flags': 0x02},
        Enum_FieldType.HE: {'data1': 1, 'data2': 2, 'data3': 3, 'data4': 4, 'data5': 5, 'data6': 6},
        Enum_FieldType.HE_MU: {'flags1': 1, 'flags2': 2, 'ru_channel1': (1, 2, 3, 4), 'ru_channel2': (5, 6, 7, 8)},
        Enum_FieldType.HE_MU_other_user: {'per_user_1': 1, 'per_user_2': 2, 'per_user_position': 3,
                                          'per_user_known': 0x23},
        Enum_FieldType.FieldType_0_length_PSDU: {'psdu_type': 1},
        Enum_FieldType.L_SIG: {'data1': 0x0007, 'data2': 0x1234},
        Enum_FieldType.S1G: {'known': 0x0103, 'data1': 2, 'data2': 3},
        Enum_FieldType.U_SIG: {'common': 0x11, 'value': 0x22, 'mask': 0x33},
        Enum_FieldType.EHT: {'known': 3, 'data': tuple(range(9)), 'user_info': (0xA1, 0xA2)},
    }


def _radiotap_field_build(code: 'Any', kwargs: 'dict[str, Any]') -> 'Any':
    from pcapkit.const.radiotap.field_type import FieldType as Enum_FieldType
    from pcapkit.protocols.link.radiotap import Radiotap

    if code < Enum_FieldType.TLV_fields_in_radiotap:
        return Radiotap(present=(1 << code,), fields=[(code, dict(kwargs))])
    tlv = Enum_FieldType.TLV_fields_in_radiotap
    return Radiotap(present=(1 << tlv,), fields=[(tlv, {'tlvs': [{'type': code, 'data': dict(kwargs)}]})])


def _radiotap_parse(octets: 'bytes') -> 'Any':
    from pcapkit.protocols.link.radiotap import Radiotap
    return Radiotap(octets, len(octets))


def _radiotap_field_extract(parsed: 'Any') -> 'Any':
    return parsed.info.present, parsed.info.decoded


def _radiotap_field_rebuild(collection: 'Any') -> 'Any':
    from pcapkit.protocols.link.radiotap import Radiotap

    present, decoded = collection
    return Radiotap(present=present, fields=decoded)


#: The families this module adds.
FAMILIES = (
    # No capture -- see the module docstring.
    generator.Family('radiotap-field', _radiotap_field_registry, _radiotap_field_overrides,
                     _radiotap_field_build, _radiotap_parse, _radiotap_field_extract,
                     _radiotap_field_rebuild, capture=None, envelope=None),
)
