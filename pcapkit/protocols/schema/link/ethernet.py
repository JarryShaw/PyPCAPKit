# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for ethernet protocol"""

import importlib
from typing import TYPE_CHECKING, cast

from pcapkit.const.reg.ethertype import EtherType as Enum_EtherType
from pcapkit.corekit.fields.misc import PayloadField
from pcapkit.corekit.fields.numbers import EnumField
from pcapkit.corekit.fields.strings import BytesField
from pcapkit.protocols.schema.schema import Schema

__all__ = ['Ethernet']

if TYPE_CHECKING:
    from typing import Any, Type

    from pcapkit.protocols.protocol import Protocol


def callback_payload(self: 'PayloadField', packet: 'dict[str, Any]') -> 'None':
    """Callback function for :attr:`Ethernet.payload`."""
    from pcapkit.protocols.link.ethernet import Ethernet  # pylint: disable=import-outside-toplevel

    type_ = packet['type']
    module, name = Ethernet.__proto__[type_]  # type: ignore[attr-defined]
    protocol = cast('Type[Protocol]', getattr(importlib.import_module(module), name))
    self.protocol = protocol


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
