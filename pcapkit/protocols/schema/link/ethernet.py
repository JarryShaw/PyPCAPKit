# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for ethernet protocol"""

from typing import TYPE_CHECKING

from pcapkit.const.reg.ethertype import EtherType as Enum_EtherType
from pcapkit.corekit.fields.misc import PayloadField
from pcapkit.corekit.fields.numbers import EnumField
from pcapkit.corekit.fields.strings import BytesField
from pcapkit.protocols.schema.schema import Schema, schema_final

__all__ = ['Ethernet']

if TYPE_CHECKING:
    from typing import Any

    from pcapkit.protocols.protocol import ProtocolBase as Protocol


def callback_payload(self: 'PayloadField', packet: 'dict[str, Any]') -> 'None':
    """Callback function for :attr:`Ethernet.payload`.

    Args:
        self: Payload field to resolve.
        packet: Packet data, whose ``type`` names the next layer.

    Returns:
        :obj:`None`; the resolved class is assigned to ``self.protocol``.

    Important:
        The lookup goes through :meth:`ProtocolBase._lookup_next_layer
        <pcapkit.protocols.protocol.Protocol._lookup_next_layer>` rather than
        subscripting the registry. :attr:`Ethernet.__proto__
        <pcapkit.protocols.link.link.Link.__proto__>` *is*
        :attr:`Link.__proto__ <pcapkit.protocols.link.link.Link.__proto__>`, a
        class-level :class:`collections.defaultdict`, so reading a missing key
        inserted it -- every unregistered EtherType a parse saw was recorded as
        though somebody had registered it, and
        :meth:`Link.register <pcapkit.protocols.link.link.Link.register>`
        afterwards reported it as an overwrite. The helper reads the fallback
        without recording it, and memoises a
        :class:`~pcapkit.corekit.module.ModuleDescriptor` for a code that really
        is registered, which this did not.

    """
    from pcapkit.protocols.link.ethernet import Ethernet  # pylint: disable=import-outside-toplevel

    self.protocol = Ethernet._lookup_next_layer(  # pylint: disable=protected-access
        Ethernet.__proto__, packet['type'])


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
