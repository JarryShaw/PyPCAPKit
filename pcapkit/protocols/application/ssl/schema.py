# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for the TLS extensions the SSL family shares

:class:`Extension` is the layout of an ``extension_data`` field
(:rfc:`9846#section-4.3`), registered under its
:class:`~pcapkit.const.tls.extension_type.ExtensionType`. A layout that
differs by handshake message holds it in :attr:`~ServerNameExtension.data`,
chosen by the message the extension is read in: the schema of that message's
structure, or the raw octets in one its RFC defines no structure for.

"""

from typing import TYPE_CHECKING

from pcapkit.const.tls.extension_type import ExtensionType as Enum_ExtensionType
from pcapkit.const.tls.handshake_type import HandshakeType as Enum_HandshakeType
from pcapkit.corekit.fields.collections import ListField
from pcapkit.corekit.fields.misc import ConditionalField, SchemaField, SwitchField
from pcapkit.corekit.fields.numbers import UInt8Field, UInt16Field, UInt32Field
from pcapkit.corekit.fields.strings import BytesField
from pcapkit.protocols.schema import EnumSchema, Schema, schema_final

__all__ = [
    'Extension', 'UnknownExtension', 'Empty', 'Opaque8', 'Opaque16',
    'ServerName', 'ServerNameList', 'ServerNameExtension',
    'OCSPStatusRequest', 'CertificateStatusRequest', 'StatusRequestExtension',
    'NamedGroupList', 'ECPointFormatList', 'ECPointFormatsExtension',
    'SignatureSchemeList', 'ProtocolNameList',
    'SignedCertificateTimestampList', 'SignedCertificateTimestampExtension',
    'Padding', 'PaddingExtension', 'ExtendedMainSecretExtension',
    'CertificateCompressionAlgorithms', 'CompressCertificateExtension',
    'RecordSizeLimit', 'RecordSizeLimitExtension',
    'SessionTicket', 'SessionTicketExtension',
    'PskIdentity', 'OfferedPsks', 'PreSharedKeyServerHello', 'PreSharedKeyExtension',
    'EarlyDataExtension',
    'SupportedVersionsClientHello', 'SupportedVersionsServerHello', 'SupportedVersionsExtension',
    'Cookie', 'CookieExtension', 'PskKeyExchangeModes', 'PskKeyExchangeModesExtension',
    'PostHandshakeAuthExtension',
    'KeyShareEntry', 'KeyShareClientHello', 'KeyShareHelloRetryRequest', 'KeyShareServerHello',
    'KeyShareExtension', 'ConnectionId',
    'HpkeSymmetricCipherSuite', 'ECHClientHello', 'ECHHelloRetryRequest', 'ECHConfigExtension',
    'ECHConfigContents', 'ECHConfig', 'ECHEncryptedExtensions', 'ECHExtension',
    'RenegotiationInfo', 'RenegotiationInfoExtension',
]

if TYPE_CHECKING:
    from typing import Any, Callable, Optional, Type

    from pcapkit.corekit.fields.field import FieldBase

#: The ``ECHConfig`` version whose ``contents`` :rfc:`9849#section-4` defines.
_ECH_CONFIG_VERSION = int(Enum_ExtensionType.encrypted_client_hello)
#: Length of an ``ECHHelloRetryRequest``'s ``confirmation`` (:rfc:`9849#section-5`).
_ECH_CONFIRMATION_LENGTH = 8


def _item(schema: 'Type[Schema]') -> 'SchemaField':
    """An item of a vector of ``schema`` structures.

    Args:
        schema: Layout of the item.

    Returns:
        A field reading the item up to the end of its vector at most, so an item
        the vector ends inside records the cut rather than warns.

    """
    return SchemaField(schema=schema, packet={'__data_end__': True})


def _structure(*messages: 'Enum_HandshakeType | int', schema: 'Type[Schema]',
               **others: 'Type[Schema]') -> 'Callable[[dict[str, Any]], FieldBase]':
    """Select the structure of an ``extension_data`` by its handshake message.

    Args:
        *messages: Messages carrying ``schema``.
        schema: Structure of the extension in ``messages``.
        **others: Structures of the extension in other messages, by
            :class:`~pcapkit.const.tls.handshake_type.HandshakeType` name.

    Returns:
        A :class:`~pcapkit.corekit.fields.misc.SwitchField` selector. It packs a
        value by its own type; it reads the structure of the message named by
        the ``__msg_type__`` key, and the raw octets in any other message.

    """
    table = {int(message): schema for message in messages}
    table.update({int(getattr(Enum_HandshakeType, name)): value for name, value in others.items()})

    def selector(pkt: 'dict[str, Any]') -> 'FieldBase':
        value = pkt.get('data')
        if isinstance(value, Schema):
            return SchemaField(schema=type(value))
        if isinstance(value, bytes):
            return BytesField(length=len(value))
        layout = table.get(int(pkt.get('__msg_type__', -1)))
        if layout is None:
            return BytesField(length=pkt['__length__'])
        return SchemaField(length=pkt['__length__'], schema=layout, packet={'__data_end__': True})
    return selector


class Extension(EnumSchema[Enum_ExtensionType]):
    """Header schema for the ``extension_data`` of a TLS extension."""

    __default__ = lambda: UnknownExtension


@schema_final
class UnknownExtension(Extension):
    """Header schema for an ``extension_data`` with no structure, kept raw."""

    #: The octets.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['__length__'])

    if TYPE_CHECKING:
        def __init__(self, data: 'bytes') -> 'None': ...


@schema_final
class Empty(Schema):
    """Header schema for ``struct {} Empty`` (:rfc:`9846#section-3.6`)."""


@schema_final
class Opaque8(Schema):
    """Header schema for an ``opaque <..2^8-1>`` vector item."""

    #: Length of :attr:`data`.
    length: 'int' = UInt8Field()
    #: The octets.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['length'])

    if TYPE_CHECKING:
        def __init__(self, length: 'int', data: 'bytes') -> 'None': ...


@schema_final
class Opaque16(Schema):
    """Header schema for an ``opaque <..2^16-1>`` vector item."""

    #: Length of :attr:`data`.
    length: 'int' = UInt16Field()
    #: The octets.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['length'])

    if TYPE_CHECKING:
        def __init__(self, length: 'int', data: 'bytes') -> 'None': ...


@schema_final
class ServerName(Schema):
    """Header schema for a ``ServerName`` (:rfc:`6066#section-3`)."""

    #: ``NameType``.
    name_type: 'int' = UInt8Field()
    #: Length of :attr:`name`.
    length: 'int' = UInt16Field()
    #: ``HostName``.
    name: 'bytes' = BytesField(length=lambda pkt: pkt['length'])

    if TYPE_CHECKING:
        def __init__(self, name_type: 'int', length: 'int', name: 'bytes') -> 'None': ...


@schema_final
class ServerNameList(Schema):
    """Header schema for a ``ServerNameList`` (:rfc:`6066#section-3`)."""

    #: Length of :attr:`server_name_list`.
    length: 'int' = UInt16Field()
    #: Server names.
    server_name_list: 'list[ServerName]' = ListField(length=lambda pkt: pkt['length'], item_type=_item(ServerName))

    if TYPE_CHECKING:
        def __init__(self, length: 'int', server_name_list: 'list[ServerName]') -> 'None': ...


def _server_name_list(pkt: 'dict[str, Any]') -> 'FieldBase':
    """Select the ``server_name`` structure: the list, or the empty octets.

    Args:
        pkt: Packet data.

    Returns:
        A field packing a value by its own type, or reading the list unless
        there are no octets.

    """
    value = pkt.get('data')
    if isinstance(value, bytes):
        return BytesField(length=len(value))
    if value is None and pkt['__length__'] == 0:
        return BytesField(length=0)
    return SchemaField(length=pkt['__length__'], schema=ServerNameList, packet={'__data_end__': True})


@schema_final
class ServerNameExtension(Extension, code=Enum_ExtensionType.server_name):
    """Header schema for ``server_name``: a ``ServerNameList``, or the empty
    octets of a ``ServerHello`` and an ``EncryptedExtensions``."""

    #: The list, or the empty octets.
    data: 'ServerNameList | bytes' = SwitchField(selector=lambda pkt: _server_name_list(pkt))

    if TYPE_CHECKING:
        def __init__(self, data: 'ServerNameList | bytes') -> 'None': ...


@schema_final
class OCSPStatusRequest(Schema):
    """Header schema for an ``OCSPStatusRequest`` (:rfc:`6066#section-8`)."""

    #: Length of :attr:`responder_id_list`.
    responder_id_list_length: 'int' = UInt16Field()
    #: ``ResponderID`` values.
    responder_id_list: 'list[Opaque16]' = ListField(length=lambda pkt: pkt['responder_id_list_length'],
                                                    item_type=_item(Opaque16))
    #: Length of :attr:`request_extensions`.
    request_extensions_length: 'int' = UInt16Field()
    #: DER-encoded OCSP request ``Extensions``.
    request_extensions: 'bytes' = BytesField(length=lambda pkt: pkt['request_extensions_length'])

    if TYPE_CHECKING:
        def __init__(self, responder_id_list_length: 'int', responder_id_list: 'list[Opaque16]',
                     request_extensions_length: 'int', request_extensions: 'bytes') -> 'None': ...


@schema_final
class CertificateStatusRequest(Schema):
    """Header schema for a ``CertificateStatusRequest`` (:rfc:`6066#section-8`)."""

    #: ``CertificateStatusType``.
    status_type: 'int' = UInt8Field()
    #: The request, for ``ocsp``, the one type it is defined for.
    request: 'OCSPStatusRequest' = ConditionalField(
        SchemaField(length=lambda pkt: pkt['__length__'], schema=OCSPStatusRequest, packet={'__data_end__': True}),
        lambda pkt: pkt['status_type'] == 1,
    )

    if TYPE_CHECKING:
        def __init__(self, status_type: 'int', request: 'Optional[OCSPStatusRequest]') -> 'None': ...


@schema_final
class StatusRequestExtension(Extension, code=Enum_ExtensionType.status_request):
    """Header schema for ``status_request``."""

    #: A ``CertificateStatusRequest`` in a ``ClientHello``, empty in a ``ServerHello``.
    data: 'CertificateStatusRequest | Empty | bytes' = SwitchField(selector=_structure(
        Enum_HandshakeType.client_hello, schema=CertificateStatusRequest, server_hello=Empty))

    if TYPE_CHECKING:
        def __init__(self, data: 'CertificateStatusRequest | Empty | bytes') -> 'None': ...


@schema_final
class NamedGroupList(Extension, code=Enum_ExtensionType.supported_groups):
    """Header schema for ``supported_groups``, a ``NamedGroupList`` (:rfc:`9846#section-4.3.7`)."""

    #: Length of :attr:`named_group_list`.
    length: 'int' = UInt16Field()
    #: ``NamedGroup`` values.
    named_group_list: 'list[int]' = ListField(length=lambda pkt: pkt['length'], item_type=UInt16Field())

    if TYPE_CHECKING:
        def __init__(self, length: 'int', named_group_list: 'list[int]') -> 'None': ...


@schema_final
class ECPointFormatList(Schema):
    """Header schema for an ``ECPointFormatList`` (:rfc:`8422#section-5.1.2`)."""

    #: Length of :attr:`ec_point_format_list`.
    length: 'int' = UInt8Field()
    #: ``ECPointFormat`` values.
    ec_point_format_list: 'list[int]' = ListField(length=lambda pkt: pkt['length'], item_type=UInt8Field())

    if TYPE_CHECKING:
        def __init__(self, length: 'int', ec_point_format_list: 'list[int]') -> 'None': ...


@schema_final
class ECPointFormatsExtension(Extension, code=Enum_ExtensionType.ec_point_formats):
    """Header schema for ``ec_point_formats``."""

    #: An ``ECPointFormatList`` in a ``ClientHello`` or ``ServerHello``.
    data: 'ECPointFormatList | bytes' = SwitchField(selector=_structure(
        Enum_HandshakeType.client_hello, Enum_HandshakeType.server_hello, schema=ECPointFormatList))

    if TYPE_CHECKING:
        def __init__(self, data: 'ECPointFormatList | bytes') -> 'None': ...


@schema_final
class SignatureSchemeList(Extension, code=Enum_ExtensionType.signature_algorithms):
    """Header schema for ``signature_algorithms``, a ``SignatureSchemeList`` (:rfc:`9846#section-4.3.3`)."""

    #: Length of :attr:`supported_signature_algorithms`.
    length: 'int' = UInt16Field()
    #: ``SignatureScheme`` values.
    supported_signature_algorithms: 'list[int]' = ListField(length=lambda pkt: pkt['length'],
                                                            item_type=UInt16Field())

    if TYPE_CHECKING:
        def __init__(self, length: 'int', supported_signature_algorithms: 'list[int]') -> 'None': ...


@schema_final
class ProtocolNameList(Extension, code=Enum_ExtensionType.application_layer_protocol_negotiation):
    """Header schema for ``application_layer_protocol_negotiation``, a
    ``ProtocolNameList`` (:rfc:`7301#section-3.1`)."""

    #: Length of :attr:`protocol_name_list`.
    length: 'int' = UInt16Field()
    #: ``ProtocolName`` values.
    protocol_name_list: 'list[Opaque8]' = ListField(length=lambda pkt: pkt['length'], item_type=_item(Opaque8))

    if TYPE_CHECKING:
        def __init__(self, length: 'int', protocol_name_list: 'list[Opaque8]') -> 'None': ...


@schema_final
class SignedCertificateTimestampList(Schema):
    """Header schema for a ``SignedCertificateTimestampList`` (:rfc:`6962#section-3.3`)."""

    #: Length of :attr:`sct_list`.
    length: 'int' = UInt16Field()
    #: ``SerializedSCT`` values.
    sct_list: 'list[Opaque16]' = ListField(length=lambda pkt: pkt['length'], item_type=_item(Opaque16))

    if TYPE_CHECKING:
        def __init__(self, length: 'int', sct_list: 'list[Opaque16]') -> 'None': ...


@schema_final
class SignedCertificateTimestampExtension(Extension, code=Enum_ExtensionType.signed_certificate_timestamp):
    """Header schema for ``signed_certificate_timestamp``."""

    #: Empty in a ``ClientHello``, a ``SignedCertificateTimestampList`` in a ``ServerHello``.
    data: 'SignedCertificateTimestampList | Empty | bytes' = SwitchField(selector=_structure(
        Enum_HandshakeType.client_hello, schema=Empty, server_hello=SignedCertificateTimestampList))

    if TYPE_CHECKING:
        def __init__(self, data: 'SignedCertificateTimestampList | Empty | bytes') -> 'None': ...


@schema_final
class Padding(Schema):
    """Header schema for the ``padding`` of :rfc:`7685#section-3`."""

    #: The padding octets, as captured.
    padding: 'bytes' = BytesField(length=lambda pkt: pkt['__length__'])

    if TYPE_CHECKING:
        def __init__(self, padding: 'bytes') -> 'None': ...


@schema_final
class PaddingExtension(Extension, code=Enum_ExtensionType.padding):
    """Header schema for ``padding``."""

    #: The padding in a ``ClientHello``.
    data: 'Padding | bytes' = SwitchField(selector=_structure(Enum_HandshakeType.client_hello, schema=Padding))

    if TYPE_CHECKING:
        def __init__(self, data: 'Padding | bytes') -> 'None': ...


@schema_final
class ExtendedMainSecretExtension(Extension, code=Enum_ExtensionType.extended_main_secret):
    """Header schema for ``extended_main_secret`` (:rfc:`7627#section-5.1`)."""

    #: Empty in a ``ClientHello`` or ``ServerHello``.
    data: 'Empty | bytes' = SwitchField(selector=_structure(
        Enum_HandshakeType.client_hello, Enum_HandshakeType.server_hello, schema=Empty))

    if TYPE_CHECKING:
        def __init__(self, data: 'Empty | bytes') -> 'None': ...


@schema_final
class CertificateCompressionAlgorithms(Schema):
    """Header schema for a ``CertificateCompressionAlgorithms`` (:rfc:`8879#section-3`)."""

    #: Length of :attr:`algorithms`.
    length: 'int' = UInt8Field()
    #: ``CertificateCompressionAlgorithm`` values.
    algorithms: 'list[int]' = ListField(length=lambda pkt: pkt['length'], item_type=UInt16Field())

    if TYPE_CHECKING:
        def __init__(self, length: 'int', algorithms: 'list[int]') -> 'None': ...


@schema_final
class CompressCertificateExtension(Extension, code=Enum_ExtensionType.compress_certificate):
    """Header schema for ``compress_certificate``."""

    #: A ``CertificateCompressionAlgorithms`` in a ``ClientHello``.
    data: 'CertificateCompressionAlgorithms | bytes' = SwitchField(selector=_structure(
        Enum_HandshakeType.client_hello, schema=CertificateCompressionAlgorithms))

    if TYPE_CHECKING:
        def __init__(self, data: 'CertificateCompressionAlgorithms | bytes') -> 'None': ...


@schema_final
class RecordSizeLimit(Schema):
    """Header schema for a ``RecordSizeLimit`` (:rfc:`8449#section-4`)."""

    #: Largest record, in octets.
    record_size_limit: 'int' = UInt16Field()

    if TYPE_CHECKING:
        def __init__(self, record_size_limit: 'int') -> 'None': ...


@schema_final
class RecordSizeLimitExtension(Extension, code=Enum_ExtensionType.record_size_limit):
    """Header schema for ``record_size_limit``."""

    #: A ``RecordSizeLimit`` in a ``ClientHello``, ``ServerHello`` or ``EncryptedExtensions``.
    data: 'RecordSizeLimit | bytes' = SwitchField(selector=_structure(
        Enum_HandshakeType.client_hello, Enum_HandshakeType.server_hello, Enum_HandshakeType.encrypted_extensions,
        schema=RecordSizeLimit))

    if TYPE_CHECKING:
        def __init__(self, data: 'RecordSizeLimit | bytes') -> 'None': ...


@schema_final
class SessionTicket(Schema):
    """Header schema for a ``SessionTicket`` (:rfc:`5077#section-3.2`), with no length of its own."""

    #: The ticket.
    ticket: 'bytes' = BytesField(length=lambda pkt: pkt['__length__'])

    if TYPE_CHECKING:
        def __init__(self, ticket: 'bytes') -> 'None': ...


@schema_final
class SessionTicketExtension(Extension, code=Enum_ExtensionType.session_ticket):
    """Header schema for ``session_ticket``."""

    #: The ticket in a ``ClientHello`` or ``ServerHello``.
    data: 'SessionTicket | bytes' = SwitchField(selector=_structure(
        Enum_HandshakeType.client_hello, Enum_HandshakeType.server_hello, schema=SessionTicket))

    if TYPE_CHECKING:
        def __init__(self, data: 'SessionTicket | bytes') -> 'None': ...


@schema_final
class PskIdentity(Schema):
    """Header schema for a ``PskIdentity`` (:rfc:`9846#section-4.3.11`)."""

    #: Length of :attr:`identity`.
    length: 'int' = UInt16Field()
    #: The identity.
    identity: 'bytes' = BytesField(length=lambda pkt: pkt['length'])
    #: Obfuscated ticket age.
    obfuscated_ticket_age: 'int' = UInt32Field()

    if TYPE_CHECKING:
        def __init__(self, length: 'int', identity: 'bytes', obfuscated_ticket_age: 'int') -> 'None': ...


@schema_final
class OfferedPsks(Schema):
    """Header schema for an ``OfferedPsks`` (:rfc:`9846#section-4.3.11`)."""

    #: Length of :attr:`identities`.
    identities_length: 'int' = UInt16Field()
    #: The identities.
    identities: 'list[PskIdentity]' = ListField(length=lambda pkt: pkt['identities_length'],
                                                item_type=_item(PskIdentity))
    #: Length of :attr:`binders`.
    binders_length: 'int' = UInt16Field()
    #: ``PskBinderEntry`` values.
    binders: 'list[Opaque8]' = ListField(length=lambda pkt: pkt['binders_length'], item_type=_item(Opaque8))

    if TYPE_CHECKING:
        def __init__(self, identities_length: 'int', identities: 'list[PskIdentity]', binders_length: 'int',
                     binders: 'list[Opaque8]') -> 'None': ...


@schema_final
class PreSharedKeyServerHello(Schema):
    """Header schema for a ``ServerHello``'s ``pre_shared_key`` (:rfc:`9846#section-4.3.11`)."""

    #: Index of the identity selected.
    selected_identity: 'int' = UInt16Field()

    if TYPE_CHECKING:
        def __init__(self, selected_identity: 'int') -> 'None': ...


@schema_final
class PreSharedKeyExtension(Extension, code=Enum_ExtensionType.pre_shared_key):
    """Header schema for ``pre_shared_key``, a ``PreSharedKeyExtension``."""

    #: An ``OfferedPsks`` in a ``ClientHello``, the selection in a ``ServerHello``.
    data: 'OfferedPsks | PreSharedKeyServerHello | bytes' = SwitchField(selector=_structure(
        Enum_HandshakeType.client_hello, schema=OfferedPsks, server_hello=PreSharedKeyServerHello))

    if TYPE_CHECKING:
        def __init__(self, data: 'OfferedPsks | PreSharedKeyServerHello | bytes') -> 'None': ...


@schema_final
class EarlyDataExtension(Extension, code=Enum_ExtensionType.early_data):
    """Header schema for ``early_data``, an ``EarlyDataIndication`` (:rfc:`9846#section-4.3.10`)."""

    #: Empty in a ``ClientHello`` or ``EncryptedExtensions``.
    data: 'Empty | bytes' = SwitchField(selector=_structure(
        Enum_HandshakeType.client_hello, Enum_HandshakeType.encrypted_extensions, schema=Empty))

    if TYPE_CHECKING:
        def __init__(self, data: 'Empty | bytes') -> 'None': ...


@schema_final
class SupportedVersionsClientHello(Schema):
    """Header schema for a ``ClientHello``'s ``supported_versions`` (:rfc:`9846#section-4.3.1`)."""

    #: Length of :attr:`versions`.
    length: 'int' = UInt8Field()
    #: ``ProtocolVersion`` values.
    versions: 'list[int]' = ListField(length=lambda pkt: pkt['length'], item_type=UInt16Field())

    if TYPE_CHECKING:
        def __init__(self, length: 'int', versions: 'list[int]') -> 'None': ...


@schema_final
class SupportedVersionsServerHello(Schema):
    """Header schema for a ``ServerHello``'s ``supported_versions`` (:rfc:`9846#section-4.3.1`)."""

    #: ``ProtocolVersion`` selected.
    selected_version: 'int' = UInt16Field()

    if TYPE_CHECKING:
        def __init__(self, selected_version: 'int') -> 'None': ...


@schema_final
class SupportedVersionsExtension(Extension, code=Enum_ExtensionType.supported_versions):
    """Header schema for ``supported_versions``, a ``SupportedVersions``."""

    #: The versions in a ``ClientHello``, the selection in a ``ServerHello`` or ``HelloRetryRequest``.
    data: 'SupportedVersionsClientHello | SupportedVersionsServerHello | bytes' = SwitchField(selector=_structure(
        Enum_HandshakeType.client_hello, schema=SupportedVersionsClientHello,
        server_hello=SupportedVersionsServerHello, hello_retry_request=SupportedVersionsServerHello))

    if TYPE_CHECKING:
        def __init__(self, data: 'SupportedVersionsClientHello | SupportedVersionsServerHello | bytes') -> 'None': ...


@schema_final
class Cookie(Schema):
    """Header schema for a ``Cookie`` (:rfc:`9846#section-4.3.2`)."""

    #: Length of :attr:`cookie`.
    length: 'int' = UInt16Field()
    #: The cookie.
    cookie: 'bytes' = BytesField(length=lambda pkt: pkt['length'])

    if TYPE_CHECKING:
        def __init__(self, length: 'int', cookie: 'bytes') -> 'None': ...


@schema_final
class CookieExtension(Extension, code=Enum_ExtensionType.cookie):
    """Header schema for ``cookie``."""

    #: A ``Cookie`` in a ``ClientHello`` or ``HelloRetryRequest``.
    data: 'Cookie | bytes' = SwitchField(selector=_structure(
        Enum_HandshakeType.client_hello, Enum_HandshakeType.hello_retry_request, schema=Cookie))

    if TYPE_CHECKING:
        def __init__(self, data: 'Cookie | bytes') -> 'None': ...


@schema_final
class PskKeyExchangeModes(Schema):
    """Header schema for a ``PskKeyExchangeModes`` (:rfc:`9846#section-4.3.9`)."""

    #: Length of :attr:`ke_modes`.
    length: 'int' = UInt8Field()
    #: ``PskKeyExchangeMode`` values.
    ke_modes: 'list[int]' = ListField(length=lambda pkt: pkt['length'], item_type=UInt8Field())

    if TYPE_CHECKING:
        def __init__(self, length: 'int', ke_modes: 'list[int]') -> 'None': ...


@schema_final
class PskKeyExchangeModesExtension(Extension, code=Enum_ExtensionType.psk_key_exchange_modes):
    """Header schema for ``psk_key_exchange_modes``."""

    #: A ``PskKeyExchangeModes`` in a ``ClientHello``.
    data: 'PskKeyExchangeModes | bytes' = SwitchField(selector=_structure(
        Enum_HandshakeType.client_hello, schema=PskKeyExchangeModes))

    if TYPE_CHECKING:
        def __init__(self, data: 'PskKeyExchangeModes | bytes') -> 'None': ...


@schema_final
class PostHandshakeAuthExtension(Extension, code=Enum_ExtensionType.post_handshake_auth):
    """Header schema for ``post_handshake_auth`` (:rfc:`9846#section-4.3.6`)."""

    #: Empty in a ``ClientHello``.
    data: 'Empty | bytes' = SwitchField(selector=_structure(Enum_HandshakeType.client_hello, schema=Empty))

    if TYPE_CHECKING:
        def __init__(self, data: 'Empty | bytes') -> 'None': ...


@schema_final
class KeyShareEntry(Schema):
    """Header schema for a ``KeyShareEntry`` (:rfc:`9846#section-4.3.8`)."""

    #: ``NamedGroup``.
    group: 'int' = UInt16Field()
    #: Length of :attr:`key_exchange`.
    length: 'int' = UInt16Field()
    #: Key exchange information.
    key_exchange: 'bytes' = BytesField(length=lambda pkt: pkt['length'])

    if TYPE_CHECKING:
        def __init__(self, group: 'int', length: 'int', key_exchange: 'bytes') -> 'None': ...


@schema_final
class KeyShareClientHello(Schema):
    """Header schema for a ``KeyShareClientHello`` (:rfc:`9846#section-4.3.8`)."""

    #: Length of :attr:`client_shares`.
    length: 'int' = UInt16Field()
    #: Key shares offered.
    client_shares: 'list[KeyShareEntry]' = ListField(length=lambda pkt: pkt['length'],
                                                     item_type=_item(KeyShareEntry))

    if TYPE_CHECKING:
        def __init__(self, length: 'int', client_shares: 'list[KeyShareEntry]') -> 'None': ...


@schema_final
class KeyShareHelloRetryRequest(Schema):
    """Header schema for a ``KeyShareHelloRetryRequest`` (:rfc:`9846#section-4.3.8`)."""

    #: ``NamedGroup`` selected.
    selected_group: 'int' = UInt16Field()

    if TYPE_CHECKING:
        def __init__(self, selected_group: 'int') -> 'None': ...


@schema_final
class KeyShareServerHello(Schema):
    """Header schema for a ``KeyShareServerHello`` (:rfc:`9846#section-4.3.8`)."""

    #: Key share selected.
    server_share: 'KeyShareEntry' = SchemaField(length=lambda pkt: pkt['__length__'], schema=KeyShareEntry,
                                                packet={'__data_end__': True})

    if TYPE_CHECKING:
        def __init__(self, server_share: 'KeyShareEntry') -> 'None': ...


@schema_final
class KeyShareExtension(Extension, code=Enum_ExtensionType.key_share):
    """Header schema for ``key_share``."""

    #: The structure of a ``ClientHello``, ``HelloRetryRequest`` or ``ServerHello``.
    data: 'KeyShareClientHello | KeyShareHelloRetryRequest | KeyShareServerHello | bytes' = SwitchField(
        selector=_structure(Enum_HandshakeType.client_hello, schema=KeyShareClientHello,
                            hello_retry_request=KeyShareHelloRetryRequest, server_hello=KeyShareServerHello))

    if TYPE_CHECKING:
        def __init__(self, data: 'KeyShareClientHello | KeyShareHelloRetryRequest | KeyShareServerHello | bytes') -> 'None': ...  # pylint: disable=line-too-long


@schema_final
class ConnectionId(Extension, code=Enum_ExtensionType.connection_id):
    """Header schema for ``connection_id``, a ``ConnectionId`` (:rfc:`9146#section-3`)."""

    #: Length of :attr:`cid`.
    length: 'int' = UInt8Field()
    #: The connection ID.
    cid: 'bytes' = BytesField(length=lambda pkt: pkt['length'])

    if TYPE_CHECKING:
        def __init__(self, length: 'int', cid: 'bytes') -> 'None': ...


@schema_final
class HpkeSymmetricCipherSuite(Schema):
    """Header schema for an ``HpkeSymmetricCipherSuite`` (:rfc:`9849#section-4`)."""

    #: ``HpkeKdfId``.
    kdf_id: 'int' = UInt16Field()
    #: ``HpkeAeadId``.
    aead_id: 'int' = UInt16Field()

    if TYPE_CHECKING:
        def __init__(self, kdf_id: 'int', aead_id: 'int') -> 'None': ...


def _ech_outer(pkt: 'dict[str, Any]') -> 'bool':
    """Whether an ``ECHClientHello`` is of the ``outer`` type, 0."""
    return pkt['type'] == 0


@schema_final
class ECHClientHello(Schema):
    """Header schema for an ``ECHClientHello`` (:rfc:`9849#section-5`)."""

    #: Client hello type, ``ECHClientHelloType``, ``outer`` (0) or ``inner`` (1).
    type: 'int' = UInt8Field()
    #: Cipher suite, for ``outer``.
    cipher_suite: 'HpkeSymmetricCipherSuite' = ConditionalField(
        SchemaField(length=4, schema=HpkeSymmetricCipherSuite, packet={'__data_end__': True}), _ech_outer)
    #: ``config_id``, for ``outer``.
    config_id: 'int' = ConditionalField(UInt8Field(), _ech_outer)
    #: Length of :attr:`enc`, for ``outer``.
    enc_length: 'int' = ConditionalField(UInt16Field(), _ech_outer)
    #: Encapsulated key, for ``outer``.
    enc: 'bytes' = ConditionalField(BytesField(length=lambda pkt: pkt['enc_length']), _ech_outer)
    #: Length of :attr:`payload`, for ``outer``.
    payload_length: 'int' = ConditionalField(UInt16Field(), _ech_outer)
    #: Encrypted payload, for ``outer``.
    payload: 'bytes' = ConditionalField(BytesField(length=lambda pkt: pkt['payload_length']), _ech_outer)

    if TYPE_CHECKING:
        def __init__(self, type: 'int', cipher_suite: 'Optional[HpkeSymmetricCipherSuite]' = None,
                     config_id: 'Optional[int]' = None, enc_length: 'Optional[int]' = None,
                     enc: 'Optional[bytes]' = None, payload_length: 'Optional[int]' = None,
                     payload: 'Optional[bytes]' = None) -> 'None': ...


@schema_final
class ECHHelloRetryRequest(Schema):
    """Header schema for an ``ECHHelloRetryRequest`` (:rfc:`9849#section-5`)."""

    #: Acceptance confirmation.
    confirmation: 'bytes' = BytesField(length=_ECH_CONFIRMATION_LENGTH)

    if TYPE_CHECKING:
        def __init__(self, confirmation: 'bytes') -> 'None': ...


@schema_final
class ECHConfigExtension(Schema):
    """Header schema for an ``ECHConfigExtension`` (:rfc:`9849#section-4`)."""

    #: ``ECHConfigExtensionType``.
    type: 'int' = UInt16Field()
    #: Length of :attr:`data`.
    length: 'int' = UInt16Field()
    #: Extension data.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['length'])

    if TYPE_CHECKING:
        def __init__(self, type: 'int', length: 'int', data: 'bytes') -> 'None': ...


@schema_final
class ECHConfigContents(Schema):
    """Header schema for an ``ECHConfigContents`` (:rfc:`9849#section-4`), its
    ``HpkeKeyConfig`` inline, since that has no length of its own."""

    #: ``config_id`` of the ``HpkeKeyConfig``.
    config_id: 'int' = UInt8Field()
    #: ``HpkeKemId`` of the ``HpkeKeyConfig``.
    kem_id: 'int' = UInt16Field()
    #: Length of :attr:`public_key`.
    public_key_length: 'int' = UInt16Field()
    #: ``HpkePublicKey`` of the ``HpkeKeyConfig``.
    public_key: 'bytes' = BytesField(length=lambda pkt: pkt['public_key_length'])
    #: Length of :attr:`cipher_suites`.
    cipher_suites_length: 'int' = UInt16Field()
    #: Cipher suites of the ``HpkeKeyConfig``.
    cipher_suites: 'list[HpkeSymmetricCipherSuite]' = ListField(length=lambda pkt: pkt['cipher_suites_length'],
                                                                item_type=_item(HpkeSymmetricCipherSuite))
    #: Longest name the client may pad its inner name to.
    maximum_name_length: 'int' = UInt8Field()
    #: Length of :attr:`public_name`.
    public_name_length: 'int' = UInt8Field()
    #: Public name.
    public_name: 'bytes' = BytesField(length=lambda pkt: pkt['public_name_length'])
    #: Length of :attr:`extensions`.
    extensions_length: 'int' = UInt16Field()
    #: Configuration extensions.
    extensions: 'list[ECHConfigExtension]' = ListField(length=lambda pkt: pkt['extensions_length'],
                                                       item_type=_item(ECHConfigExtension))

    if TYPE_CHECKING:
        def __init__(self, config_id: 'int', kem_id: 'int', public_key_length: 'int', public_key: 'bytes',
                     cipher_suites_length: 'int', cipher_suites: 'list[HpkeSymmetricCipherSuite]',
                     maximum_name_length: 'int', public_name_length: 'int', public_name: 'bytes',
                     extensions_length: 'int', extensions: 'list[ECHConfigExtension]') -> 'None': ...


def _ech_config_contents(pkt: 'dict[str, Any]') -> 'FieldBase':
    """Select an ``ECHConfig``'s ``contents``: the structure of version ``0xFE0D``, or the octets.

    Args:
        pkt: Packet data.

    Returns:
        A field of :class:`ECHConfigContents` for version ``0xFE0D``, unless it
        packs octets given as they are, and of the octets otherwise.

    """
    if pkt['version'] == _ECH_CONFIG_VERSION and not isinstance(pkt.get('contents'), bytes):
        return SchemaField(length=pkt['length'], schema=ECHConfigContents, packet={'__data_end__': True})
    return BytesField(length=pkt['length'])


@schema_final
class ECHConfig(Schema):
    """Header schema for an ``ECHConfig`` (:rfc:`9849#section-4`)."""

    #: Version.
    version: 'int' = UInt16Field()
    #: Length of :attr:`contents`.
    length: 'int' = UInt16Field()
    #: The contents of version ``0xFE0D``; the raw octets of any other.
    contents: 'ECHConfigContents | bytes' = SwitchField(selector=lambda pkt: _ech_config_contents(pkt))

    if TYPE_CHECKING:
        def __init__(self, version: 'int', length: 'int', contents: 'ECHConfigContents | bytes') -> 'None': ...


@schema_final
class ECHEncryptedExtensions(Schema):
    """Header schema for an ``ECHEncryptedExtensions`` (:rfc:`9849#section-5`)."""

    #: Length of :attr:`retry_configs`.
    length: 'int' = UInt16Field()
    #: Retry configurations, an ``ECHConfigList``.
    retry_configs: 'list[ECHConfig]' = ListField(length=lambda pkt: pkt['length'], item_type=_item(ECHConfig))

    if TYPE_CHECKING:
        def __init__(self, length: 'int', retry_configs: 'list[ECHConfig]') -> 'None': ...


@schema_final
class ECHExtension(Extension, code=Enum_ExtensionType.encrypted_client_hello):
    """Header schema for ``encrypted_client_hello``."""

    #: An ``ECHClientHello``, ``ECHHelloRetryRequest`` or ``ECHEncryptedExtensions``.
    data: 'ECHClientHello | ECHHelloRetryRequest | ECHEncryptedExtensions | bytes' = SwitchField(
        selector=_structure(Enum_HandshakeType.client_hello, schema=ECHClientHello,
                            hello_retry_request=ECHHelloRetryRequest, encrypted_extensions=ECHEncryptedExtensions))

    if TYPE_CHECKING:
        def __init__(self, data: 'ECHClientHello | ECHHelloRetryRequest | ECHEncryptedExtensions | bytes') -> 'None': ...  # pylint: disable=line-too-long


@schema_final
class RenegotiationInfo(Schema):
    """Header schema for a ``RenegotiationInfo`` (:rfc:`5746#section-3.2`)."""

    #: Length of :attr:`renegotiated_connection`.
    length: 'int' = UInt8Field()
    #: ``verify_data`` of the previous handshake.
    renegotiated_connection: 'bytes' = BytesField(length=lambda pkt: pkt['length'])

    if TYPE_CHECKING:
        def __init__(self, length: 'int', renegotiated_connection: 'bytes') -> 'None': ...


@schema_final
class RenegotiationInfoExtension(Extension, code=Enum_ExtensionType.renegotiation_info):
    """Header schema for ``renegotiation_info``."""

    #: A ``RenegotiationInfo`` in a ``ClientHello`` or ``ServerHello``.
    data: 'RenegotiationInfo | bytes' = SwitchField(selector=_structure(
        Enum_HandshakeType.client_hello, Enum_HandshakeType.server_hello, schema=RenegotiationInfo))

    if TYPE_CHECKING:
        def __init__(self, data: 'RenegotiationInfo | bytes') -> 'None': ...
