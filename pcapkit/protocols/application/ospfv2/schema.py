# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for OSPFv2 protocol"""

from typing import TYPE_CHECKING

from pcapkit.const.ospf.authentication import Authentication as Enum_Authentication
from pcapkit.const.ospf.packet import Packet as Enum_Packet
from pcapkit.corekit.fields.ipaddress import IPv4AddressField
from pcapkit.corekit.fields.misc import PayloadField, SchemaField, SwitchField
from pcapkit.corekit.fields.numbers import EnumField, UInt8Field, UInt16Field, UInt32Field
from pcapkit.corekit.fields.strings import BytesField, PaddingField
from pcapkit.protocols.schema import Schema, schema_final

__all__ = ['OSPFv2', 'CryptographicAuthentication']

if TYPE_CHECKING:
    from ipaddress import IPv4Address
    from typing import Any

    from pcapkit.corekit.fields.field import FieldBase as Field
    from pcapkit.protocols.protocol import ProtocolBase


def ospf_auth_data_selector(pkt: 'dict[str, Any]') -> 'Field':
    """Selector function for :attr:`OSPFv2.auth_data` field.

    Args:
        pkt: Packet data.

    Returns:
        A :class:`~pcapkit.corekit.fields.misc.SchemaField` wrapped
        :class:`~pcapkit.protocols.application.ospfv2.schema.CryptographicAuthentication`
        instance if :attr:`OSPFv2.auth_type` is 2, and a
        :class:`~pcapkit.corekit.fields.strings.BytesField` instance otherwise.

    .. versionchanged:: 1.8.1

       Moved here from ``pcapkit.protocols.application.ospf.schema`` (:issue:`3105`).

    """
    if pkt['auth_type'] == Enum_Authentication.Cryptographic_authentication:
        return SchemaField(length=8, schema=CryptographicAuthentication)
    return BytesField(length=8)


@schema_final
class CryptographicAuthentication(Schema):
    """Header schema for OSPFv2 cryptographic authentication.

    .. versionadded:: 1.5.0

       Renamed from ``CrytographicAuthentication``, which
       :mod:`pcapkit.protocols.schema` exported as
       ``OSPF_CrytographicAuthentication`` (:issue:`1090`).

    .. versionremoved:: 1.5.0

       ``CrytographicAuthentication`` and ``OSPF_CrytographicAuthentication``,
       with no alias (:issue:`1090`).

    .. versionchanged:: 1.8.1

       Moved here from ``pcapkit.protocols.application.ospf.schema`` (:issue:`3105`).

    """

    #: Reserved bytes.
    reserved: 'bytes' = PaddingField(length=2)
    #: Key ID.
    key_id: 'int' = UInt8Field()
    #: Length.
    len: 'int' = UInt8Field()
    #: Sequence number.
    seq: 'int' = UInt32Field()

    if TYPE_CHECKING:
        def __init__(self, reserved: 'bytes', key_id: 'int', len: 'int', seq: 'int') -> 'None': ...


@schema_final
class OSPFv2(Schema):
    """Header schema for OSPFv2 packet: the 24-octet header of
    :rfc:`2328#appendix-A.3.1`.

    .. versionadded:: 1.8.1

       Renamed from ``OSPF`` in ``pcapkit.protocols.application.ospf.schema``
       (:issue:`3105`).

    """

    #: Version.
    version: 'int' = UInt8Field()
    #: Type.
    type: 'Enum_Packet' = EnumField(length=1, namespace=Enum_Packet)
    #: Length.
    length: 'int' = UInt16Field()
    #: Router ID.
    router_id: 'IPv4Address' = IPv4AddressField()
    #: Area ID.
    area_id: 'IPv4Address' = IPv4AddressField()
    #: Checksum.
    checksum: 'bytes' = BytesField(length=2)
    #: Authentication type.
    auth_type: 'Enum_Authentication' = EnumField(length=2, namespace=Enum_Authentication)
    #: Authentication data.
    auth_data: 'bytes | CryptographicAuthentication' = SwitchField(
        selector=ospf_auth_data_selector,
    )
    #: Payload.
    payload: 'bytes' = PayloadField(length=lambda pkt: pkt['length'] - 24)
    #: Octets captured past the Packet Length, such as the message digest
    #: that cryptographic authentication appends (:rfc:`2328#appendix-D.4.3`);
    #: compare :attr:`IPv4.trailer <pcapkit.protocols.internet.ipv4.schema.IPv4.trailer>`.
    trailer: 'bytes' = PayloadField(default=b'')

    if TYPE_CHECKING:
        def __init__(self, version: 'int', type: 'Enum_Packet', length: 'int',
                     router_id: 'IPv4Address | bytes | str | int',
                     area_id: 'IPv4Address | bytes | str | int',
                     checksum: 'bytes', auth_type: 'Enum_Authentication',
                     auth_data: 'bytes | CryptographicAuthentication',
                     payload: 'bytes | ProtocolBase | Schema',
                     trailer: 'bytes' = b'') -> 'None': ...
