# -*- coding: utf-8 -*-
"""The ``dccp-option`` family: DCCP options.

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

#: Header fields shared by every constructed DCCP packet: a DCCP-Ack (type 3),
#: whose Acknowledgement Number the Ack Vector and Data Dropped options read
#: against (RFC 4340 sections 11.4 and 11.7). ``checksum`` is pinned, so a
#: mismatch points at the option under test and not at a recomputed checksum.
DCCP_BASE = {
    'srcport': 50000, 'dstport': 5001, 'type': 3, 'x': True, 'seq': 1, 'ack': 1,
    'checksum': b'\x00\x00', 'payload': b'',
}


def _dccp_registry() -> 'Any':
    from pcapkit.protocols.transport.dccp import DCCP
    return DCCP.__option__


def _dccp_overrides() -> 'dict[Any, dict[str, Any]]':
    from pcapkit.const.dccp.feature import Feature as Enum_Feature
    from pcapkit.const.dccp.option import Option as Enum_Option

    # Each default is an empty or zero field; these give every variable part
    # at least one octet, and the Elapsed Time its four-octet form.
    vector = [(0, 3), (1, 0), (3, 63)]
    return {
        Enum_Option.Change_L: {'feature': Enum_Feature.Congestion_Control_ID, 'value': b'\x02\x03'},
        Enum_Option.Confirm_L: {'feature': Enum_Feature.Congestion_Control_ID, 'value': b'\x02\x02\x03'},
        Enum_Option.Change_R: {'feature': Enum_Feature.Send_Ack_Vector, 'value': b'\x01'},
        Enum_Option.Confirm_R: {'feature': Enum_Feature.Send_Ack_Vector, 'value': b'\x01'},
        Enum_Option.Init_Cookie: {'cookie': b'\x01\x02\x03'},
        Enum_Option.NDP_Count: {'count': 0x0102},
        Enum_Option.Ack_Vector_Nonce_0: {'vector': vector},
        Enum_Option.Ack_Vector_Nonce_1: {'vector': vector},
        Enum_Option.Data_Dropped: {'vector': [(None, 5), (3, 2)]},
        Enum_Option.Timestamp: {'timestamp': 0x11223344},
        Enum_Option.Timestamp_Echo: {'timestamp': 0x11223344, 'elapsed': 0x1234},
        Enum_Option.Elapsed_Time: {'elapsed': 0x123456},
        Enum_Option.Data_Checksum: {'checksum': b'\x01\x02\x03\x04'},
    }


def _dccp_build(code: 'Any', kwargs: 'dict[str, Any]') -> 'Any':
    from pcapkit.protocols.transport.dccp import DCCP
    return DCCP(options=[(code, kwargs)], **DCCP_BASE)


def _dccp_parse(octets: 'bytes') -> 'Any':
    from pcapkit.protocols.transport.dccp import DCCP
    return DCCP(octets, len(octets))


def _dccp_extract(parsed: 'Any') -> 'Any':
    return parsed.info.options


def _dccp_rebuild(options: 'Any') -> 'Any':
    from pcapkit.protocols.transport.dccp import DCCP
    return DCCP(options=options, **DCCP_BASE)


#: The families this module adds.
FAMILIES = (
    generator.Family('dccp-option', _dccp_registry, _dccp_overrides,
                     _dccp_build, _dccp_parse, _dccp_extract, _dccp_rebuild,
                     capture='options-transport.pcap', envelope='ipv4', proto=33),
)
