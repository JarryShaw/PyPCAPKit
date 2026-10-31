# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for SSLv2 protocol"""

import struct
from typing import TYPE_CHECKING, cast

from pcapkit.const.sslv2.handshake_type import HandshakeType as Enum_HandshakeType
from pcapkit.const.sslv2.version import Version as Enum_Version
from pcapkit.corekit.fields.misc import (ConditionalField, ForwardMatchField, PayloadField,
                                         SchemaField, SwitchField)
from pcapkit.corekit.fields.numbers import EnumField, UInt8Field, UInt16Field
from pcapkit.corekit.fields.strings import BytesField
from pcapkit.protocols.schema.schema import EnumSchema, Schema, schema_final

__all__ = [
    'SSLv2',

    'HandshakeBody', 'UnknownHandshakeBody',
    'ClientHello', 'ServerHello',
]

if TYPE_CHECKING:
    from typing import Any, Optional

    from pcapkit.corekit.fields.field import FieldBase as Field
    from pcapkit.protocols.protocol import ProtocolBase


def sslv2_record_length(packet: 'dict[str, Any]') -> 'int':
    """Compute the SSLv2 ``RECORD-LENGTH`` from the already-parsed header octets.

    The record header carries the length split across two or three octets in
    a shape that depends on the high bit of its first octet, per the
    `SSLv2 draft`_, §4.1 (*SSL Record Header Format*):

    * if ``indicator & 0x80`` is set, the header is the 2-octet form and
      ``RECORD-LENGTH = ((indicator & 0x7f) << 8) | length_low``;
    * otherwise, the header is the 3-octet form (a third, ``padding`` octet
      follows) and ``RECORD-LENGTH = ((indicator & 0x3f) << 8) | length_low``.

    Args:
        packet: Packet data, with ``indicator`` and ``length_low`` already
            parsed (:attr:`SSLv2.indicator` and :attr:`SSLv2.length_low`).

    Returns:
        The record's declared length, header excluded.

    .. _SSLv2 draft: https://datatracker.ietf.org/doc/html/draft-hickman-netscape-ssl-00

    """
    indicator = cast('int', packet['indicator'])
    length_low = cast('int', packet['length_low'])
    if indicator & 0x80:
        return ((indicator & 0x7F) << 8) | length_low
    return ((indicator & 0x3F) << 8) | length_low


#: Octets of a hello body's own fixed-width sub-header a forward-match probe
#: ever needs to peek -- enough for the longer of the two,
#: ``SERVER-HELLO``'s 10-octet one (``CLIENT-HELLO``'s is 8).
_HELLO_PROBE_LENGTH = 10


def sslv2_hello_probe_length(packet: 'dict[str, Any]') -> 'int':
    """Compute :attr:`SSLv2.probe`'s forward-match length.

    Never more than the body actually declares (:func:`sslv2_record_length`
    minus the one octet :attr:`SSLv2.msg_type` already consumed), and never
    more than ``_HELLO_PROBE_LENGTH``.

    Args:
        packet: Packet data, with ``indicator``/``length_low`` already
            parsed (see :func:`sslv2_record_length`).

    Returns:
        The probe's length, in octets.

    """
    return min(_HELLO_PROBE_LENGTH, max(0, sslv2_record_length(packet) - 1))


def sslv2_hello_probe_is_plausible(msg_type: 'Enum_HandshakeType', probe: 'bytes',
                                  inner_length: 'int') -> 'bool':
    """Check a ``CLIENT-HELLO``/``SERVER-HELLO`` body's declared sub-field
    lengths against the record's own declared body length.

    A hello-tagged record that is actually ciphertext would otherwise decode
    random octets as ``*-LENGTH`` sub-fields that overrun or underrun the
    body. :func:`sslv2_body_selector` parses a body failing this check as
    :class:`UnknownHandshakeBody`, keeping its raw octets whole.

    Args:
        msg_type: The record's handshake message type; only ``CLIENT_HELLO``
            and ``SERVER_HELLO`` are checked, every other type is vacuously
            plausible.
        probe: The body's first ``min(10, inner_length)`` octets, forward-matched
            by :attr:`SSLv2.probe` -- not yet actually consumed.
        inner_length: The body's declared length (``RECORD-LENGTH`` minus the
            one octet :attr:`SSLv2.msg_type` already consumed).

    Returns:
        :data:`True` if the declared sub-field lengths add up to
        ``inner_length`` exactly, or if ``msg_type`` is not one this check
        applies to.

    """
    if msg_type == Enum_HandshakeType.CLIENT_HELLO:
        # ``client_version`` (2) + ``cipher_specs_length`` (2) +
        # ``session_id_length`` (2) + ``challenge_length`` (2) = 8.
        if len(probe) < 8:
            return False
        cipher_specs_length, session_id_length, challenge_length = struct.unpack('>HHH', probe[2:8])
        return 8 + cipher_specs_length + session_id_length + challenge_length == inner_length
    if msg_type == Enum_HandshakeType.SERVER_HELLO:
        # ``session_id_hit`` (1) + ``certificate_type`` (1) +
        # ``server_version`` (2) + ``certificate_length`` (2) +
        # ``cipher_specs_length`` (2) + ``connection_id_length`` (2) = 10.
        if len(probe) < 10:
            return False
        certificate_length, cipher_specs_length, connection_id_length = struct.unpack('>HHH', probe[4:10])
        return 10 + certificate_length + cipher_specs_length + connection_id_length == inner_length
    return True


def sslv2_body_selector(packet: 'dict[str, Any]') -> 'Field':
    """Selector function for :attr:`SSLv2.body` field.

    Args:
        packet: Packet data.

    Returns:
        A :class:`~pcapkit.corekit.fields.misc.SchemaField` wrapped
        :class:`HandshakeBody` instance, of whichever subclass
        :attr:`HandshakeBody.registry
        <pcapkit.protocols.schema.schema.EnumSchema.registry>` maps
        ``packet['msg_type']`` to, sized to the record's remaining declared length -- the record's own
        ``RECORD-LENGTH``, the one octet :attr:`SSLv2.msg_type` already
        consumed excluded. For ``CLIENT-HELLO``/``SERVER-HELLO``, falls back
        to :class:`UnknownHandshakeBody` when :func:`sslv2_hello_probe_is_plausible`
        rejects :attr:`SSLv2.probe` -- see that function for why.

    Note:
        A malformed ``RECORD-LENGTH = 0`` sizes the body to ``0``, not to the
        rest of the buffer; :meth:`~pcapkit.protocols.application.sslv2.SSLv2.read` reports it.

    """
    msg_type = cast('Enum_HandshakeType', packet['msg_type'])
    length = max(0, sslv2_record_length(packet) - 1)
    # ``probe`` is only present when parsing wire octets; a schema built by
    # ``make()`` (or rebuilt via ``from_dict()``) has none, and its body is
    # already the hello it was built as, so there is nothing to sanity-check.
    probe = cast('Optional[bytes]', packet.get('probe'))
    if probe is not None and not sslv2_hello_probe_is_plausible(msg_type, probe, length):
        schema = UnknownHandshakeBody  # type: type[HandshakeBody]
    else:
        schema = HandshakeBody.registry[msg_type]
    return SchemaField(length=length, schema=schema)


class HandshakeBody(EnumSchema[Enum_HandshakeType]):
    """Header schema for SSLv2 handshake message bodies.

    Unlike :class:`~pcapkit.protocols.schema.transport.tcp.Option` and its
    siblings, this base class declares no field of its own for the
    discriminator: :attr:`SSLv2.msg_type` already consumes that octet in the
    enclosing schema, before :attr:`SSLv2.body` dispatches here, so every
    concrete subclass's own first field starts at the body's first octet --
    the same arrangement
    :class:`~pcapkit.protocols.schema.application.httpv2.FrameType` uses for
    HTTP/2 frame payloads, where ``type`` is consumed by the outer
    :class:`~pcapkit.protocols.schema.application.httpv2.HTTP` schema.

    """

    __default__ = lambda: UnknownHandshakeBody


@schema_final
class UnknownHandshakeBody(HandshakeBody):
    """Header schema for an SSLv2 handshake message body kept as raw octets:
    every :class:`~pcapkit.const.sslv2.handshake_type.HandshakeType` other
    than ``CLIENT-HELLO`` and ``SERVER-HELLO``, and a hello-tagged body that
    fails :func:`sslv2_hello_probe_is_plausible`, e.g. ciphertext.

    Keeping the undissected body, rather than losing the whole record,
    matches :class:`~pcapkit.protocols.schema.application.httpv2.UnassignedFrame`.

    """

    #: Undissected message body.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['__length__'])

    if TYPE_CHECKING:
        def __init__(self, data: 'bytes') -> 'None': ...


@schema_final
class ClientHello(HandshakeBody, code=Enum_HandshakeType.CLIENT_HELLO):
    """Header schema for the SSLv2 ``CLIENT-HELLO`` handshake message."""

    #: Client's maximum supported version.
    client_version: 'Enum_Version' = EnumField(length=2, namespace=Enum_Version)
    #: Length of :attr:`cipher_specs`.
    cipher_specs_length: 'int' = UInt16Field()
    #: Length of :attr:`session_id`.
    session_id_length: 'int' = UInt16Field()
    #: Length of :attr:`challenge`.
    challenge_length: 'int' = UInt16Field()
    #: Cipher kinds the client supports, as a concatenation of 3-octet
    #: ``CIPHER-KIND`` entries.
    cipher_specs: 'bytes' = BytesField(length=lambda pkt: pkt['cipher_specs_length'])
    #: Session identifier, ``0`` or ``16`` octets.
    session_id: 'bytes' = BytesField(length=lambda pkt: pkt['session_id_length'])
    #: Client's challenge data, ``16``-``32`` octets.
    challenge: 'bytes' = BytesField(length=lambda pkt: pkt['challenge_length'])

    if TYPE_CHECKING:
        def __init__(self, client_version: 'Enum_Version', cipher_specs_length: 'int',
                     session_id_length: 'int', challenge_length: 'int', cipher_specs: 'bytes',
                     session_id: 'bytes', challenge: 'bytes') -> 'None': ...


@schema_final
class ServerHello(HandshakeBody, code=Enum_HandshakeType.SERVER_HELLO):
    """Header schema for the SSLv2 ``SERVER-HELLO`` handshake message."""

    #: Whether the client's proposed :attr:`ClientHello.session_id` was
    #: accepted; when set, :attr:`certificate_type`, :attr:`certificate` and
    #: :attr:`cipher_specs` carry no data.
    session_id_hit: 'int' = UInt8Field()
    #: Certificate type, ``SSL_CT_X509_CERTIFICATE (0x01)`` being the only one
    #: the draft defines.
    certificate_type: 'int' = UInt8Field()
    #: Server's selected version.
    server_version: 'Enum_Version' = EnumField(length=2, namespace=Enum_Version)
    #: Length of :attr:`certificate`.
    certificate_length: 'int' = UInt16Field()
    #: Length of :attr:`cipher_specs`.
    cipher_specs_length: 'int' = UInt16Field()
    #: Length of :attr:`connection_id`.
    connection_id_length: 'int' = UInt16Field()
    #: Server's certificate.
    certificate: 'bytes' = BytesField(length=lambda pkt: pkt['certificate_length'])
    #: Cipher kinds the server supports, as a concatenation of 3-octet
    #: ``CIPHER-KIND`` entries.
    cipher_specs: 'bytes' = BytesField(length=lambda pkt: pkt['cipher_specs_length'])
    #: Connection identifier, ``16``-``32`` octets.
    connection_id: 'bytes' = BytesField(length=lambda pkt: pkt['connection_id_length'])

    if TYPE_CHECKING:
        def __init__(self, session_id_hit: 'int', certificate_type: 'int',
                     server_version: 'Enum_Version', certificate_length: 'int',
                     cipher_specs_length: 'int', connection_id_length: 'int',
                     certificate: 'bytes', cipher_specs: 'bytes',
                     connection_id: 'bytes') -> 'None': ...


@schema_final
class SSLv2(Schema):
    """Header schema for SSLv2 packet.

    The record header is two or three octets, chosen by the high bit of its
    first octet -- see :func:`sslv2_record_length` -- rather than a fixed
    width, so :attr:`padding` is read only for the 3-octet form.
    :attr:`msg_type` is the one octet the `SSLv2 draft`_ puts at the front of
    every record's data rather than in the header proper, and it is read
    here, ahead of :attr:`body`, for the same reason
    :attr:`~pcapkit.protocols.schema.application.httpv2.HTTP.type` is read
    ahead of :attr:`~pcapkit.protocols.schema.application.httpv2.HTTP.frame`.

    .. _SSLv2 draft: https://datatracker.ietf.org/doc/html/draft-hickman-netscape-ssl-00

    """

    #: First octet of the record header. Its high bit (``0x80``) selects the
    #: header form, and (only for the 3-octet form) the next bit (``0x40``)
    #: is ``IS-ESCAPE``; see :func:`sslv2_record_length`.
    indicator: 'int' = UInt8Field()
    #: Second octet of the record header -- the low 8 bits of ``RECORD-LENGTH``.
    length_low: 'int' = UInt8Field()
    #: Third octet of the record header, present only for the 3-octet form.
    padding: 'int' = ConditionalField(
        UInt8Field(),
        lambda pkt: not (pkt['indicator'] & 0x80),
    )
    #: Handshake message type, the first octet of the record's data.
    msg_type: 'Enum_HandshakeType' = EnumField(length=1, namespace=Enum_HandshakeType)
    #: The body's first few octets, forward-matched (consuming nothing) so
    #: :func:`sslv2_body_selector` can sanity-check a ``CLIENT-HELLO``/
    #: ``SERVER-HELLO``'s own declared sub-field lengths before committing
    #: to decoding it as one; see :func:`sslv2_hello_probe_is_plausible`.
    probe: 'bytes' = ForwardMatchField(BytesField(length=sslv2_hello_probe_length))
    #: Handshake message body.
    body: 'HandshakeBody' = SwitchField(
        selector=sslv2_body_selector,
    )
    #: Octets after the record, e.g. the next record.
    payload: 'bytes' = PayloadField()

    if TYPE_CHECKING:
        def __init__(self, indicator: 'int', length_low: 'int', padding: 'Optional[int]',
                     msg_type: 'Enum_HandshakeType', body: 'bytes | HandshakeBody',
                     payload: 'bytes | ProtocolBase | Schema') -> 'None': ...
