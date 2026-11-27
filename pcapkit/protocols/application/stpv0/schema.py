# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for STP Configuration and TCN BPDUs"""

from typing import TYPE_CHECKING

from pcapkit.const.stp.bpdu_type import BPDUType as Enum_BPDUType
from pcapkit.const.stp.protocol_version import ProtocolVersion as Enum_ProtocolVersion
from pcapkit.corekit.fields.misc import ConditionalField, PayloadField
from pcapkit.corekit.fields.numbers import EnumField, UInt8Field, UInt16Field, UInt32Field
from pcapkit.corekit.fields.strings import BytesField
from pcapkit.protocols.schema import Schema, schema_final

__all__ = ['STPv0']

if TYPE_CHECKING:
    from typing import Any, Optional

    from pcapkit.protocols.protocol import ProtocolBase


def stp_config_body(packet: 'dict[str, Any]') -> 'bool':
    """Whether the BPDU is a Configuration BPDU, whose 31 octets follow the BPDU Type.

    Args:
        packet: The BPDU's fields unpacked so far.

    Returns:
        Whether its BPDU Type is not a TCN BPDU's, which ends after it.

    """
    return packet['type'] != Enum_BPDUType.TCN


@schema_final
class STPv0(Schema):
    """Header schema for a Configuration BPDU, 35 octets, or a TCN BPDU, 4 octets
    (IEEE 802.1D-2004 clause 9).

    .. versionadded:: 1.9.0

    """

    #: Protocol Identifier, zero.
    pid: 'int' = UInt16Field(default=0)
    #: Protocol Version Identifier.
    version: 'Enum_ProtocolVersion' = EnumField(length=1, namespace=Enum_ProtocolVersion)
    #: BPDU Type.
    type: 'Enum_BPDUType' = EnumField(length=1, namespace=Enum_BPDUType)
    #: Flags.
    flags: 'Optional[int]' = ConditionalField(UInt8Field(default=0), stp_config_body)
    #: Root Identifier.
    root_id: 'Optional[bytes]' = ConditionalField(BytesField(length=8, default=bytes(8)), stp_config_body)
    #: Root Path Cost.
    root_path_cost: 'Optional[int]' = ConditionalField(UInt32Field(default=0), stp_config_body)
    #: Bridge Identifier.
    bridge_id: 'Optional[bytes]' = ConditionalField(BytesField(length=8, default=bytes(8)), stp_config_body)
    #: Port Identifier.
    port_id: 'Optional[int]' = ConditionalField(UInt16Field(default=0), stp_config_body)
    #: Message Age, in units of 1/256 of a second.
    message_age: 'Optional[int]' = ConditionalField(UInt16Field(default=0), stp_config_body)
    #: Max Age, in units of 1/256 of a second.
    max_age: 'Optional[int]' = ConditionalField(UInt16Field(default=0), stp_config_body)
    #: Hello Time, in units of 1/256 of a second.
    hello_time: 'Optional[int]' = ConditionalField(UInt16Field(default=0), stp_config_body)
    #: Forward Delay, in units of 1/256 of a second.
    forward_delay: 'Optional[int]' = ConditionalField(UInt16Field(default=0), stp_config_body)
    #: Octets past the BPDU, which it does not define.
    payload: 'bytes' = PayloadField()

    if TYPE_CHECKING:
        def __init__(self, pid: 'int', version: 'Enum_ProtocolVersion | int', type: 'Enum_BPDUType | int',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin
                     flags: 'Optional[int]', root_id: 'Optional[bytes]', root_path_cost: 'Optional[int]',
                     bridge_id: 'Optional[bytes]', port_id: 'Optional[int]', message_age: 'Optional[int]',
                     max_age: 'Optional[int]', hello_time: 'Optional[int]', forward_delay: 'Optional[int]',
                     payload: 'bytes | ProtocolBase | Schema') -> 'None': ...
