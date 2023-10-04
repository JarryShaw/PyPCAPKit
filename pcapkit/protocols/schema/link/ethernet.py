# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for ethernet protocol"""

from typing import TYPE_CHECKING

from pcapkit.const.reg.ethertype import EtherType as Enum_EtherType
from pcapkit.corekit.fields.misc import PayloadField
from pcapkit.corekit.fields.numbers import EnumField
from pcapkit.corekit.fields.strings import BytesField
from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.protocols.schema.schema import Schema, schema_final

__all__ = ['Ethernet']

if TYPE_CHECKING:
    from typing import Any

    from pcapkit.protocols.protocol import ProtocolBase as Protocol


def callback_payload(self: 'PayloadField', packet: 'dict[str, Any]') -> 'None':
    """Callback function for :attr:`Ethernet.payload`."""
    from pcapkit.protocols.link.ethernet import Ethernet  # pylint: disable=import-outside-toplevel

    type_ = packet['type']
    protocol = Ethernet.__proto__[type_]
    if isinstance(protocol, ModuleDescriptor):
        protocol = protocol.klass
    self.protocol = protocol


@schema_final
class Ethernet(Schema):
    """Header schema for ethernet packet."""

    #: Destination MAC address.
    dst: 'bytes' = BytesField(length=6)
    #: Source MAC address.
    src: 'bytes' = BytesField(length=6)
    #: Protocol (internet layer).
    type: 'Enum_EtherType' = EnumField(length=2, namespace=Enum_EtherType)
    #: Payload.
    payload: 'bytes' = PayloadField(
        length=lambda pkt: pkt['__length__'],
        callback=callback_payload,
    )

    if TYPE_CHECKING:
        def __init__(self, dst: 'bytes', src: 'bytes', type: 'Enum_EtherType',
                     payload: 'bytes | Protocol | Schema') -> 'None': ...
