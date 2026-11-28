# -*- coding: utf-8 -*-
"""data models for RSTP RST BPDUs"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data import Protocol

if TYPE_CHECKING:
    from typing import Optional

    from pcapkit.const.stp.bpdu_type import BPDUType
    from pcapkit.const.stp.protocol_version import ProtocolVersion
    from pcapkit.protocols.application.stp.data import BridgeID, Flags, PortID

__all__ = ['RSTP']


@info_final
class RSTP(Protocol):
    """Data model for an RST BPDU (:ieee:`802.1Q-2022` clause 14).

    .. versionadded:: 1.9.0

    """

    #: Protocol Version Identifier as captured, 2, or 3 or more for a BPDU
    #: that :ieee:`802.1Q-2022` clause 14.4 decodes as an RST BPDU.
    protocol_version: 'ProtocolVersion'
    #: BPDU Type.
    type: 'BPDUType'
    #: Flags.
    flags: 'Flags'
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
    #: Version 1 Length; :data:`None` for a BPDU of version 3 or more that ends
    #: before it.
    version_1_length: 'Optional[int]'

    if TYPE_CHECKING:
        def __init__(self, protocol_version: 'ProtocolVersion', type: 'BPDUType', flags: 'Flags',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin
                     root_id: 'BridgeID', root_path_cost: 'int', bridge_id: 'BridgeID', port_id: 'PortID',
                     message_age: 'float', max_age: 'float', hello_time: 'float', forward_delay: 'float',
                     version_1_length: 'Optional[int]') -> 'None': ...
