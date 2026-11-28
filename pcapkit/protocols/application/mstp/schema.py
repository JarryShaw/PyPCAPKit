# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for MSTP MST BPDUs"""

from typing import TYPE_CHECKING

from pcapkit.const.stp.bpdu_type import BPDUType as Enum_BPDUType
from pcapkit.const.stp.protocol_version import ProtocolVersion as Enum_ProtocolVersion
from pcapkit.corekit.fields.collections import ListField
from pcapkit.corekit.fields.misc import PayloadField, SchemaField
from pcapkit.corekit.fields.numbers import EnumField, UInt8Field, UInt16Field, UInt32Field
from pcapkit.corekit.fields.strings import BytesField
from pcapkit.protocols.schema import Schema, schema_final

__all__ = ['MSTP', 'MSTIMessage']

if TYPE_CHECKING:
    from typing import Any

    from pcapkit.protocols.protocol import ProtocolBase


def mstp_msti_length(packet: 'dict[str, Any]') -> 'int':
    """The octets of the MSTI Configuration Messages the Version 3 Length counts.

    Args:
        packet: The BPDU's fields unpacked so far.

    Returns:
        Its Version 3 Length past the 64 octets every MST BPDU has there, in whole
        messages of 16 octets and at most 64 of them, as :ieee:`802.1Q-2022` clause
        14.4 bounds it; zero for a length below 64.

    """
    extra = packet['version_3_length'] - 64
    return max(min(extra - extra % 16, 64 * 16), 0)


@schema_final
class MSTIMessage(Schema):
    """Header schema for an MSTI Configuration Message, 16 octets (:ieee:`802.1Q-2022` clause 14).

    .. versionadded:: 1.9.0

    """

    #: MSTI Flags.
    flags: 'int' = UInt8Field()
    #: MSTI Regional Root Identifier.
    regional_root_id: 'bytes' = BytesField(length=8)
    #: MSTI Internal Root Path Cost.
    internal_root_path_cost: 'int' = UInt32Field()
    #: MSTI Bridge Priority, its bits 5 to 8.
    bridge_priority: 'int' = UInt8Field()
    #: MSTI Port Priority, its bits 5 to 8.
    port_priority: 'int' = UInt8Field()
    #: MSTI Remaining Hops.
    remaining_hops: 'int' = UInt8Field()

    if TYPE_CHECKING:
        def __init__(self, flags: 'int', regional_root_id: 'bytes', internal_root_path_cost: 'int',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
                     bridge_priority: 'int', port_priority: 'int', remaining_hops: 'int') -> 'None': ...


@schema_final
class MSTP(Schema):
    """Header schema for an MST BPDU, 102 octets and its MSTI Configuration Messages
    (:ieee:`802.1Q-2022` clause 14).

    .. versionadded:: 1.9.0

    """

    #: Protocol Identifier, zero.
    pid: 'int' = UInt16Field(default=0)
    #: Protocol Version Identifier.
    version: 'Enum_ProtocolVersion' = EnumField(length=1, namespace=Enum_ProtocolVersion)
    #: BPDU Type.
    type: 'Enum_BPDUType' = EnumField(length=1, namespace=Enum_BPDUType)
    #: CIST Flags.
    flags: 'int' = UInt8Field()
    #: CIST Root Identifier.
    cist_root_id: 'bytes' = BytesField(length=8)
    #: CIST External Root Path Cost.
    cist_external_root_path_cost: 'int' = UInt32Field()
    #: CIST Regional Root Identifier.
    cist_regional_root_id: 'bytes' = BytesField(length=8)
    #: CIST Port Identifier.
    cist_port_id: 'int' = UInt16Field()
    #: Message Age, in units of 1/256 of a second.
    message_age: 'int' = UInt16Field()
    #: Max Age, in units of 1/256 of a second.
    max_age: 'int' = UInt16Field()
    #: Hello Time, in units of 1/256 of a second.
    hello_time: 'int' = UInt16Field()
    #: Forward Delay, in units of 1/256 of a second.
    forward_delay: 'int' = UInt16Field()
    #: Version 1 Length, zero.
    version_1_length: 'int' = UInt8Field(default=0)
    #: Version 3 Length.
    version_3_length: 'int' = UInt16Field()
    #: Configuration Identifier Format Selector, of the MST Configuration Identifier.
    format_selector: 'int' = UInt8Field()
    #: Configuration Name.
    config_name: 'bytes' = BytesField(length=32)
    #: Revision Level.
    revision_level: 'int' = UInt16Field()
    #: Configuration Digest.
    config_digest: 'bytes' = BytesField(length=16)
    #: CIST Internal Root Path Cost.
    cist_internal_root_path_cost: 'int' = UInt32Field()
    #: CIST Bridge Identifier.
    cist_bridge_id: 'bytes' = BytesField(length=8)
    #: CIST Remaining Hops.
    cist_remaining_hops: 'int' = UInt8Field()
    #: MSTI Configuration Messages.
    msti: 'list[MSTIMessage]' = ListField(
        length=mstp_msti_length,
        item_type=SchemaField(length=16, schema=MSTIMessage),
    )
    #: Octets past the BPDU, which it does not define.
    payload: 'bytes' = PayloadField()

    if TYPE_CHECKING:
        def __init__(self, pid: 'int', version: 'Enum_ProtocolVersion | int', type: 'Enum_BPDUType | int',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin
                     flags: 'int', cist_root_id: 'bytes', cist_external_root_path_cost: 'int',
                     cist_regional_root_id: 'bytes', cist_port_id: 'int', message_age: 'int', max_age: 'int',
                     hello_time: 'int', forward_delay: 'int', version_1_length: 'int', version_3_length: 'int',
                     format_selector: 'int', config_name: 'bytes', revision_level: 'int', config_digest: 'bytes',
                     cist_internal_root_path_cost: 'int', cist_bridge_id: 'bytes', cist_remaining_hops: 'int',
                     msti: 'list[MSTIMessage]', payload: 'bytes | ProtocolBase | Schema') -> 'None': ...
