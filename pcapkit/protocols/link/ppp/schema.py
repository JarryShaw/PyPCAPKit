# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for Point-to-Point Protocol"""

import collections
from typing import TYPE_CHECKING

from pcapkit.const.ppp.protocol import Protocol as Enum_Protocol
from pcapkit.corekit.fields.misc import (ConditionalField, ForwardMatchField, PayloadField,
                                         SchemaField, SwitchField)
from pcapkit.corekit.fields.numbers import EnumField, UInt8Field, UInt16Field
from pcapkit.corekit.fields.strings import BitField, BytesField
from pcapkit.protocols.schema import EnumSchema, Schema, schema_final
from pcapkit.utilities.logging import SPHINX_TYPE_CHECKING

__all__ = ['PPP', 'ControlPacket', 'ControlHeader']

if TYPE_CHECKING:
    from typing import Any, DefaultDict, Optional, Type

    from pcapkit.corekit.fields.field import FieldBase as Field
    from pcapkit.protocols.protocol import ProtocolBase

if SPHINX_TYPE_CHECKING:  # pragma: no cover
    from typing_extensions import TypedDict

    class ControlTest(TypedDict):
        """Fixed fields of a control packet, matched forward."""

        #: Code.
        code: int
        #: Identifier.
        identifier: int
        #: Length.
        length: int


def ppp_protocol_selector(pkt: 'dict[str, Any]') -> 'Field':
    """Selector function for :attr:`PPP.protocol` field.

    Args:
        pkt: Packet data.

    Returns:
        A one-octet field where the first octet of the Protocol field is odd,
        as Protocol-Field-Compression leaves it (:rfc:`1661#section-6.5`);
        otherwise a two-octet one.

    """
    if pkt['pfc'] & 0x01:
        return EnumField(length=1, namespace=Enum_Protocol)
    return EnumField(length=2, namespace=Enum_Protocol)


def ppp_is_control(pkt: 'dict[str, Any]') -> 'bool':
    """Whether the Protocol field names a control packet :class:`ControlPacket` has a layout for.

    Args:
        pkt: Packet data.

    Returns:
        Whether :attr:`PPP.control_packet` is present.

    """
    return ControlPacket.registry[pkt['protocol']] is not None  # pylint: disable=unsubscriptable-object


def ppp_control_selector(pkt: 'dict[str, Any]') -> 'Field':
    """Selector function for :attr:`PPP.control_packet` field.

    Args:
        pkt: Packet data.

    Returns:
        The layout :class:`ControlPacket` registers for the Protocol field, at
        the control packet's own Length, or at its fixed fields where that
        Length is below them, which :meth:`PPP.read
        <pcapkit.protocols.link.ppp.protocol.PPP.read>` then refuses.

    """
    return SchemaField(length=max(pkt['cp_test']['length'], 4),
                       schema=ControlPacket.registry[pkt['protocol']])  # pylint: disable=unsubscriptable-object


@schema_final
class PPP(Schema):
    """Header schema for PPP frames."""

    #: First two octets, matched forward, ``0xFF03`` opening the Address and
    #: Control fields of HDLC-like framing (:rfc:`1662#section-3.1`).
    test: 'int' = ForwardMatchField(UInt16Field())
    #: Address field, absent under Address-and-Control-Field-Compression.
    address: 'int' = ConditionalField(
        UInt8Field(default=0xFF),
        lambda pkt: pkt['test'] == 0xFF03,
    )
    #: Control field, absent under Address-and-Control-Field-Compression.
    control: 'int' = ConditionalField(
        UInt8Field(default=0x03),
        lambda pkt: pkt['test'] == 0xFF03,
    )
    #: First octet of the Protocol field, matched forward.
    pfc: 'int' = ForwardMatchField(UInt8Field())
    #: Protocol field.
    protocol: 'Enum_Protocol' = SwitchField(selector=ppp_protocol_selector)
    #: Fixed fields of the control packet, matched forward.
    cp_test: 'ControlTest' = ConditionalField(
        ForwardMatchField(BitField(length=4, namespace={
            'code': (0, 8),
            'identifier': (8, 8),
            'length': (16, 16),
        })),
        ppp_is_control,
    )
    #: Control packet, for a protocol number :class:`ControlPacket` registers.
    control_packet: 'ControlPacket' = ConditionalField(
        SwitchField(selector=ppp_control_selector),
        ppp_is_control,
    )
    #: Payload.
    payload: 'bytes' = PayloadField(length=lambda pkt: pkt['__length__'])

    if TYPE_CHECKING:
        def __init__(self, test: 'int', address: 'Optional[int]', control: 'Optional[int]',
                     pfc: 'int', protocol: 'Enum_Protocol | int', cp_test: 'Optional[ControlTest]',
                     control_packet: 'Optional[ControlPacket]',
                     payload: 'bytes | ProtocolBase | Schema') -> 'None': ...


class ControlPacket(EnumSchema[Enum_Protocol]):
    """Header schema for the control packets PPP carries, by the protocol number naming them.

    A protocol number with no layout registered here is carried as the next
    layer rather than read as a control packet.

    """

    __enum__: 'DefaultDict[Enum_Protocol, Type[ControlPacket]]' = collections.defaultdict(lambda: None)  # type: ignore[arg-type,return-value]

    if TYPE_CHECKING:
        code: 'int'
        identifier: 'int'
        length: 'int'
        data: 'bytes'


@schema_final
class ControlHeader(ControlPacket, code=[Enum_Protocol.Internet_Protocol_Control_Protocol,
                                         Enum_Protocol.IPv6_Control_Protocol,
                                         Enum_Protocol.Link_Control_Protocol,
                                         Enum_Protocol.Password_Authentication_Protocol,
                                         Enum_Protocol.Challenge_Handshake_Authentication_Protocol]):
    """Header schema for a control packet read at header level.

    LCP and the NCPs (:rfc:`1661#section-5`), PAP (:rfc:`1334#section-2.2`)
    and CHAP (:rfc:`1994#section-4`) open their packets with the same fixed
    fields; what follows them is kept as octets.

    """

    #: Code.
    code: 'int' = UInt8Field()
    #: Identifier.
    identifier: 'int' = UInt8Field()
    #: Length, of the fixed fields and the data.
    length: 'int' = UInt16Field()
    #: Data.
    data: 'bytes' = BytesField(length=lambda pkt: max(pkt['length'] - 4, 0))

    if TYPE_CHECKING:
        def __init__(self, code: 'int', identifier: 'int', length: 'int', data: 'bytes') -> 'None': ...
