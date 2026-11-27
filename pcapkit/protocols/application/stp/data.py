# -*- coding: utf-8 -*-
"""data models shared by the Spanning Tree Protocol family

The identifiers and the flags below are encoded alike in every BPDU format
that carries them, so :class:`~pcapkit.protocols.application.stpv0.protocol.STPv0`,
:class:`~pcapkit.protocols.application.rstp.protocol.RSTP` and
:class:`~pcapkit.protocols.application.mstp.protocol.MSTP` share them.

"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data import Data

if TYPE_CHECKING:
    from pcapkit.const.stp.port_role import PortRole

__all__ = ['BridgeID', 'PortID', 'Flags']


@info_final
class BridgeID(Data):
    """Data model for a Bridge Identifier, eight octets (:ieee:`802.1D-2004` clause 9)."""

    #: Bridge Priority, the four most significant bits, a multiple of 4096.
    priority: 'int'
    #: System ID Extension, the next 12 bits; the MSTID in an MSTI Regional
    #: Root Identifier.
    extension: 'int'
    #: MAC address, the last six octets.
    address: 'str'

    if TYPE_CHECKING:
        def __init__(self, priority: 'int', extension: 'int', address: 'str') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class PortID(Data):
    """Data model for a Port Identifier, two octets (:ieee:`802.1D-2004` clause 9)."""

    #: Port Priority, the four most significant bits, a multiple of 16.
    priority: 'int'
    #: Port Number, the remaining 12 bits.
    number: 'int'

    if TYPE_CHECKING:
        def __init__(self, priority: 'int', number: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class Flags(Data):
    """Data model for the flags of an RST or MST BPDU, octet 5.

    Bit 1 is the least significant bit of the octet.

    """

    #: Topology Change flag, bit 1.
    tc: 'bool'
    #: Proposal flag, bit 2.
    proposal: 'bool'
    #: Port Role, bits 3 and 4; its ``0``, a Master Port in the MSTI Flags, is
    #: Unknown here (:ieee:`802.1D-2004`).
    role: 'PortRole'
    #: Learning flag, bit 5.
    learning: 'bool'
    #: Forwarding flag, bit 6.
    forwarding: 'bool'
    #: Agreement flag, bit 7.
    agreement: 'bool'
    #: Topology Change Acknowledgment flag, bit 8.
    tc_ack: 'bool'

    if TYPE_CHECKING:
        def __init__(self, tc: 'bool', proposal: 'bool', role: 'PortRole', learning: 'bool',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
                     forwarding: 'bool', agreement: 'bool', tc_ack: 'bool') -> 'None': ...  # pylint: disable=unused-argument
