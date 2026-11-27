# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for RSTP RST BPDUs"""

from typing import TYPE_CHECKING

from pcapkit.const.stp.bpdu_type import BPDUType as Enum_BPDUType
from pcapkit.const.stp.protocol_version import ProtocolVersion as Enum_ProtocolVersion
from pcapkit.corekit.fields.misc import ConditionalField, PayloadField
from pcapkit.corekit.fields.numbers import EnumField, UInt8Field, UInt16Field, UInt32Field
from pcapkit.corekit.fields.strings import BytesField
from pcapkit.protocols.schema import Schema, schema_final

__all__ = ['RSTP']

if TYPE_CHECKING:
    from typing import Any, Optional

    from pcapkit.protocols.protocol import ProtocolBase


def rstp_version_1_length(packet: 'dict[str, Any]') -> 'bool':
    """Whether the RST BPDU carries its Version 1 Length, the 36th octet.

    Args:
        packet: The BPDU's fields unpacked so far.

    Returns:
        Whether its version is 2; else, on packing, whether it is given, and on
        unpacking, whether octets are left, as IEEE 802.1Q-2022 clause 14.4
        decodes a BPDU of version 3 or more and 35 octets as an RST BPDU.

    """
    if packet['version'] == Enum_ProtocolVersion.RSTP:
        return True
    if 'version_1_length' in packet:
        return packet['version_1_length'] is not None
    return packet['__length__'] > 0


@schema_final
class RSTP(Schema):
    """Header schema for an RST BPDU, 36 octets (IEEE 802.1Q-2022 clause 14).

    .. versionadded:: 1.9.0

    """

    #: Protocol Identifier, zero.
    pid: 'int' = UInt16Field(default=0)
    #: Protocol Version Identifier.
    version: 'Enum_ProtocolVersion' = EnumField(length=1, namespace=Enum_ProtocolVersion)
    #: BPDU Type.
    type: 'Enum_BPDUType' = EnumField(length=1, namespace=Enum_BPDUType)
    #: Flags.
    flags: 'int' = UInt8Field()
    #: Root Identifier.
    root_id: 'bytes' = BytesField(length=8)
    #: Root Path Cost.
    root_path_cost: 'int' = UInt32Field()
    #: Bridge Identifier.
    bridge_id: 'bytes' = BytesField(length=8)
    #: Port Identifier.
    port_id: 'int' = UInt16Field()
    #: Message Age, in units of 1/256 of a second.
    message_age: 'int' = UInt16Field()
    #: Max Age, in units of 1/256 of a second.
    max_age: 'int' = UInt16Field()
    #: Hello Time, in units of 1/256 of a second.
    hello_time: 'int' = UInt16Field()
    #: Forward Delay, in units of 1/256 of a second.
    forward_delay: 'int' = UInt16Field()
    #: Version 1 Length, zero.
    version_1_length: 'Optional[int]' = ConditionalField(UInt8Field(default=0), rstp_version_1_length)
    #: Octets past the BPDU, which it does not define.
    payload: 'bytes' = PayloadField()

    if TYPE_CHECKING:
        def __init__(self, pid: 'int', version: 'Enum_ProtocolVersion | int', type: 'Enum_BPDUType | int',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin
                     flags: 'int', root_id: 'bytes', root_path_cost: 'int', bridge_id: 'bytes', port_id: 'int',
                     message_age: 'int', max_age: 'int', hello_time: 'int', forward_delay: 'int',
                     version_1_length: 'Optional[int]', payload: 'bytes | ProtocolBase | Schema') -> 'None': ...
