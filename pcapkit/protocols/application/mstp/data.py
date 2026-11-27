# -*- coding: utf-8 -*-
"""data models for MSTP MST BPDUs"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data import Data, Protocol

if TYPE_CHECKING:
    from pcapkit.const.stp.bpdu_type import BPDUType
    from pcapkit.const.stp.port_role import PortRole
    from pcapkit.const.stp.protocol_version import ProtocolVersion
    from pcapkit.protocols.application.stp.data import BridgeID, Flags, PortID

__all__ = ['MSTP', 'ConfigID', 'MSTIFlags', 'MSTIMessage']


@info_final
class ConfigID(Data):
    """Data model for an MST Configuration Identifier, 51 octets."""

    #: Configuration Identifier Format Selector.
    format_selector: 'int'
    #: Configuration Name, its 32 octets as captured.
    name: 'bytes'
    #: Revision Level.
    revision_level: 'int'
    #: Configuration Digest, 16 octets.
    digest: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, format_selector: 'int', name: 'bytes', revision_level: 'int', digest: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class MSTIFlags(Data):
    """Data model for the MSTI Flags of an MSTI Configuration Message.

    Bit 1 is the least significant bit of the octet; bit 8 is the Master flag
    where the CIST Flags carry the Topology Change Acknowledgment flag.

    """

    #: Topology Change flag, bit 1.
    tc: 'bool'
    #: Proposal flag, bit 2.
    proposal: 'bool'
    #: Port Role, bits 3 and 4; its ``0`` is the Master Port.
    role: 'PortRole'
    #: Learning flag, bit 5.
    learning: 'bool'
    #: Forwarding flag, bit 6.
    forwarding: 'bool'
    #: Agreement flag, bit 7.
    agreement: 'bool'
    #: Master flag, bit 8.
    master: 'bool'

    if TYPE_CHECKING:
        def __init__(self, tc: 'bool', proposal: 'bool', role: 'PortRole', learning: 'bool',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
                     forwarding: 'bool', agreement: 'bool', master: 'bool') -> 'None': ...  # pylint: disable=unused-argument


@info_final
class MSTIMessage(Data):
    """Data model for an MSTI Configuration Message, 16 octets."""

    #: MSTI Flags.
    flags: 'MSTIFlags'
    #: MSTI Regional Root Identifier, whose System ID Extension is the MSTID.
    regional_root_id: 'BridgeID'
    #: MSTI Internal Root Path Cost.
    internal_root_path_cost: 'int'
    #: MSTI Bridge Priority, bits 5 to 8 of its octet, a multiple of 4096.
    bridge_priority: 'int'
    #: Bits 1 to 4 of the MSTI Bridge Priority octet, sent as zero.
    bridge_reserved: 'int'
    #: MSTI Port Priority, bits 5 to 8 of its octet, a multiple of 16.
    port_priority: 'int'
    #: Bits 1 to 4 of the MSTI Port Priority octet, sent as zero.
    port_reserved: 'int'
    #: MSTI Remaining Hops.
    remaining_hops: 'int'

    if TYPE_CHECKING:
        def __init__(self, flags: 'MSTIFlags', regional_root_id: 'BridgeID', internal_root_path_cost: 'int',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
                     bridge_priority: 'int', bridge_reserved: 'int', port_priority: 'int', port_reserved: 'int',
                     remaining_hops: 'int') -> 'None': ...


@info_final
class MSTP(Protocol):
    """Data model for an MST BPDU (IEEE 802.1Q-2022 clause 14).

    .. versionadded:: 1.9.0

    """

    #: Protocol Version Identifier, 3.
    protocol_version: 'ProtocolVersion'
    #: BPDU Type.
    type: 'BPDUType'
    #: CIST Flags.
    flags: 'Flags'
    #: CIST Root Identifier.
    cist_root_id: 'BridgeID'
    #: CIST External Root Path Cost.
    cist_external_root_path_cost: 'int'
    #: CIST Regional Root Identifier.
    cist_regional_root_id: 'BridgeID'
    #: CIST Port Identifier.
    cist_port_id: 'PortID'
    #: Message Age, in seconds.
    message_age: 'float'
    #: Max Age, in seconds.
    max_age: 'float'
    #: Hello Time, in seconds.
    hello_time: 'float'
    #: Forward Delay, in seconds.
    forward_delay: 'float'
    #: Version 1 Length, zero.
    version_1_length: 'int'
    #: Version 3 Length.
    version_3_length: 'int'
    #: MST Configuration Identifier.
    config_id: 'ConfigID'
    #: CIST Internal Root Path Cost.
    cist_internal_root_path_cost: 'int'
    #: CIST Bridge Identifier.
    cist_bridge_id: 'BridgeID'
    #: CIST Remaining Hops.
    cist_remaining_hops: 'int'
    #: MSTI Configuration Messages.
    msti: 'tuple[MSTIMessage, ...]'

    if TYPE_CHECKING:
        def __init__(self, protocol_version: 'ProtocolVersion', type: 'BPDUType', flags: 'Flags',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin
                     cist_root_id: 'BridgeID', cist_external_root_path_cost: 'int', cist_regional_root_id: 'BridgeID',
                     cist_port_id: 'PortID', message_age: 'float', max_age: 'float', hello_time: 'float',
                     forward_delay: 'float', version_1_length: 'int', version_3_length: 'int',
                     config_id: 'ConfigID', cist_internal_root_path_cost: 'int', cist_bridge_id: 'BridgeID',
                     cist_remaining_hops: 'int', msti: 'tuple[MSTIMessage, ...]') -> 'None': ...
