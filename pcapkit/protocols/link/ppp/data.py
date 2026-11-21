# -*- coding: utf-8 -*-
"""data models for Point-to-Point Protocol"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data import Data, Protocol

if TYPE_CHECKING:
    from typing import Optional

    from pcapkit.const.ppp.protocol import Protocol as Enum_Protocol

__all__ = ['PPP', 'ControlPacket']


@info_final
class ControlPacket(Data):
    """Data model for a PPP control packet, read at header level."""

    #: Code.
    code: 'int'
    #: Identifier.
    identifier: 'int'
    #: Length, of the fixed fields and the data.
    length: 'int'
    #: Data, the options or message the code carries.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, code: 'int', identifier: 'int', length: 'int', data: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class PPP(Protocol):
    """Data model for PPP frames."""

    #: Address field, :data:`None` under Address-and-Control-Field-Compression.
    address: 'Optional[int]'
    #: Control field, :data:`None` under Address-and-Control-Field-Compression.
    control: 'Optional[int]'
    #: Protocol field.
    protocol: 'Enum_Protocol'
    #: Whether the Protocol field is one octet, under Protocol-Field-Compression.
    pfc: 'bool'
    #: Control packet, for a protocol number whose packets are read at header
    #: level; :data:`None` otherwise.
    control_packet: 'Optional[ControlPacket]'

    if TYPE_CHECKING:
        def __init__(self, address: 'Optional[int]', control: 'Optional[int]', protocol: 'Enum_Protocol',
                     pfc: 'bool', control_packet: 'Optional[ControlPacket]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
