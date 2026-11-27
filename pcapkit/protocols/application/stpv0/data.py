# -*- coding: utf-8 -*-
"""data models for STP Configuration and TCN BPDUs"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data import Data, Protocol

if TYPE_CHECKING:
    from pcapkit.const.stp.bpdu_type import BPDUType
    from pcapkit.const.stp.protocol_version import ProtocolVersion
    from pcapkit.protocols.application.stp.data import BridgeID, PortID

__all__ = ['STPv0', 'ConfigFlags']


@info_final
class ConfigFlags(Data):
    """Data model for the flags of a Configuration BPDU, octet 5.

    Bit 1 is the least significant bit of the octet.

    """

    #: Topology Change flag, bit 1.
    tc: 'bool'
    #: Bits 2 to 7, unused and sent as zero.
    reserved: 'int'
    #: Topology Change Acknowledgment flag, bit 8.
    tc_ack: 'bool'

    if TYPE_CHECKING:
        def __init__(self, tc: 'bool', reserved: 'int', tc_ack: 'bool') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class STPv0(Protocol):
    """Data model for a Configuration or TCN BPDU (IEEE 802.1D-2004 clause 9).

    .. versionadded:: 1.9.0

    """

    #: Protocol Version Identifier, as captured.
    protocol_version: 'ProtocolVersion'
    #: BPDU Type.
    type: 'BPDUType'

    if TYPE_CHECKING:
        #: Flags, present only for a Configuration BPDU, as are the fields below.
        flags: 'ConfigFlags'
        #: Root Identifier.
        root_id: 'BridgeID'
        #: Root Path Cost.
        root_path_cost: 'int'
        #: Bridge Identifier.
        bridge_id: 'BridgeID'
        #: Port Identifier.
        port_id: 'PortID'
        #: Message Age, in seconds.
        message_age: 'float'
        #: Max Age, in seconds.
        max_age: 'float'
        #: Hello Time, in seconds.
        hello_time: 'float'
        #: Forward Delay, in seconds.
        forward_delay: 'float'

        def __init__(self, protocol_version: 'ProtocolVersion', type: 'BPDUType') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin
