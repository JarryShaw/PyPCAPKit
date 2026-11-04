# -*- coding: utf-8 -*-
"""An application-layer enumeration field takes a member or a code, never a name.

GitHub issue #2594, ruled in review of #2593 (#2489): an enumeration field of
``make()`` takes the member or an :class:`int` code, resolved with the
enumeration's ``get`` by ``Protocol._make_index``, and a name is refused rather
than resolved against an enumeration inferred from the caller's frame. #2617: a
code the field cannot carry, and a :obj:`bool` for a field wider than one bit,
raise :exc:`~pcapkit.utilities.exceptions.ProtocolError` rather than being
masked or written as a different value.

Each row of :data:`FIELDS` is one field of one maker, reached as a caller reaches
it -- through ``make()``, and through its ``frame=``, ``body=`` or ``content=``
for a frame, body or extension maker -- with the enumeration it holds and the
width of its field. ``make()`` is called directly, so that a value its own
checks let through cannot pass as refused because the parse of the octets
refuses them.

"""
from __future__ import annotations

import importlib
import importlib.util
import unittest
from typing import TYPE_CHECKING, NamedTuple
from unittest import mock

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any, Callable

HAS_PYCRATE = importlib.util.find_spec('pycrate_asn1dir') is not None

#: The one cipher kind of the SSLv2 hellos, which the draft requires at least
#: one of: ``SSL_CK_DES_192_EDE3_CBC_WITH_MD5``.
CIPHER_SPECS = b'\x07\x00\xc0'


def _load(path: str) -> 'Any':
    """The object ``path``, ``module:name``, names."""
    module, name = path.split(':')
    return getattr(importlib.import_module(module), name)


def _make(protocol: str, **kwargs: 'Any') -> bytes:
    """The octets ``make()`` of ``protocol``, ``module:class``, builds from ``kwargs``.

    Called on an instance that has parsed nothing, so that a value is refused by
    ``make()`` itself rather than by the parse of what it built.

    """
    return bytes(object.__new__(_load(protocol)).make(**kwargs))


def _member(path: str, name: str) -> 'Any':
    """The member ``name`` of the enumeration ``path``, ``module:class``."""
    return getattr(_load(path), name)


OSPF = 'pcapkit.protocols.application.ospf.protocol:OSPF'
HTTPV1 = 'pcapkit.protocols.application.httpv1.protocol:HTTPv1'
HTTPV2 = 'pcapkit.protocols.application.httpv2.protocol:HTTPv2'
TLS = 'pcapkit.protocols.application.tls.protocol:TLS'
DTLS = 'pcapkit.protocols.application.dtls.protocol:DTLS'
SSLV2 = 'pcapkit.protocols.application.sslv2.protocol:SSLv2'
NGAP = 'pcapkit.protocols.application.ngap.protocol:NGAP'

FRAME = 'pcapkit.const.http.frame:Frame'
SSLV2_TYPE = 'pcapkit.const.sslv2.handshake_type:HandshakeType'
PROCEDURE = 'pcapkit.const.ngap.procedure_code:ProcedureCode'


def _tls_extension(code: 'Any') -> bytes:
    """A TLS record carrying a ``ClientHello`` whose one extension is a ``(code, {})`` pair."""
    from pcapkit.const.tls.content_type import ContentType
    from pcapkit.const.tls.handshake_type import HandshakeType
    from pcapkit.protocols.application.ssl.data import ClientHello, Handshake

    hello = ClientHello(version=0x0303, random=bytes(32), session_id=b'', cookie=None,
                        cipher_suites=(0x1301,), compression_methods=(0,), extensions=((code, {}),))
    return _make(TLS, content_type=ContentType.handshake,
                 content=(Handshake(msg_type=HandshakeType.client_hello, length=0, body=hello),))


def _hello(name: str, **body: 'Any') -> bytes:
    """An SSLv2 record of the ``name`` hello, built from ``body``."""
    return _make(SSLV2, msg_type=_member(SSLV2_TYPE, name), body={'cipher_specs': CIPHER_SPECS, **body})


def _ngap(**kwargs: 'Any') -> bytes:
    """An ``NGSetupRequest`` with no IEs, built from ``kwargs``."""
    kwargs.setdefault('procedure', _member(PROCEDURE, 'NGSetup'))
    return _make(NGAP, message='NGSetupRequest', value={'protocolIEs': []}, **kwargs)


class Field(NamedTuple):
    """One enumeration field of one maker."""

    #: The maker, by name.
    maker: str
    #: The field, as the maker names its argument.
    field: str
    #: The enumeration the field holds, as ``module:class``.
    enum: str
    #: Width of the field, in bits.
    bits: int
    #: Name of the member to build with.
    member: str
    #: Builds the packet's octets with the field set to its one argument.
    build: 'Callable[[Any], bytes]'
    #: Codes that fit the field and fall outside the enumeration's own range.
    refused: 'tuple[int, ...]' = ()
    #: Module whose ``load_pycrate`` encodes the packet, for a maker that
    #: must refuse a value before it reaches the encoder.
    encoder: 'str | None' = None


FIELDS = (
    Field('OSPF.make', 'type', 'pcapkit.const.ospf.packet:Packet', 8, 'Link_State_Request',
          lambda value: _make(OSPF, type=value)),
    Field('OSPF.make', 'auth_type', 'pcapkit.const.ospf.authentication:Authentication', 16,
          'Simple_Password_Authentication', lambda value: _make(OSPF, auth_type=value)),
    # NOTE: 10 bits hold every three-digit status code; StatusCode's range stops at 999.
    Field('HTTPv1._make_start_line', 'status', 'pcapkit.const.http.status_code:StatusCode', 10,
          'CODE_404', lambda value: _make(HTTPV1, status=value), refused=(1000, 1023)),
    Field('HTTPv2.make', 'type', FRAME, 8, 'WINDOW_UPDATE',
          lambda value: _make(HTTPV2, type=value, sid=1)),
    Field('HTTPv2._make_http_rst_stream', 'error', 'pcapkit.const.http.error_code:ErrorCode', 32,
          'CANCEL',
          lambda value: _make(HTTPV2, type=_member(FRAME, 'RST_STREAM'), sid=1, frame={'error': value})),
    Field('HTTPv2._make_http_goaway', 'error', 'pcapkit.const.http.error_code:ErrorCode', 32,
          'PROTOCOL_ERROR',
          lambda value: _make(HTTPV2, type=_member(FRAME, 'GOAWAY'), frame={'error': value})),
    Field('HTTPv2._make_http_settings', 'settings (list)', 'pcapkit.const.http.setting:Setting', 16,
          'MAX_FRAME_SIZE',
          lambda value: _make(HTTPV2, type=_member(FRAME, 'SETTINGS'), frame={'settings': [(value, 16384)]})),
    Field('HTTPv2._make_http_settings', 'settings (dict)', 'pcapkit.const.http.setting:Setting', 16,
          'MAX_FRAME_SIZE',
          lambda value: _make(HTTPV2, type=_member(FRAME, 'SETTINGS'), frame={'settings': {value: 16384}})),
    Field('TLS.make', 'content_type', 'pcapkit.const.tls.content_type:ContentType', 8, 'alert',
          lambda value: _make(TLS, content_type=value, content=b'\x02\x28')),
    Field('SSL._make_tls_extensions', 'extensions', 'pcapkit.const.tls.extension_type:ExtensionType', 16,
          'server_name', _tls_extension),
    Field('DTLS.make', 'content_type', 'pcapkit.const.tls.content_type:ContentType', 8, 'alert',
          lambda value: _make(DTLS, content_type=value, content=b'\x02\x28')),
    Field('SSLv2.make', 'msg_type', SSLV2_TYPE, 8, 'CLIENT_FINISHED',
          lambda value: _make(SSLV2, msg_type=value, body=b'\x00' * 16)),
    Field('SSLv2._make_sslv2_client_hello', 'client_version', 'pcapkit.const.sslv2.version:Version', 16,
          'SSLv2', lambda value: _hello('CLIENT_HELLO', client_version=value)),
    Field('SSLv2._make_sslv2_server_hello', 'server_version', 'pcapkit.const.sslv2.version:Version', 16,
          'SSLv2', lambda value: _hello('SERVER_HELLO', server_version=value)),
    Field('NGAP.make', 'procedure', PROCEDURE, 8, 'NGSetup',
          lambda value: _ngap(procedure=value), encoder='pcapkit.protocols.application.ngap.protocol'),
    # NOTE: Criticality is an ENUMERATED of three, two bits in aligned PER.
    Field('NGAP.make', 'criticality', 'pcapkit.protocols.application.ngap.protocol:Criticality', 2, 'reject',
          lambda value: _ngap(criticality=value), encoder='pcapkit.protocols.application.ngap.protocol'),
)


class ApplicationMakeCodeTests(unittest.TestCase):
    """Each field refuses what it cannot carry, and builds a member and its code alike."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        from pcapkit.utilities.exceptions import ProtocolError

        self.ProtocolError = ProtocolError

    def assertRefused(self, row: 'Field', value: 'Any') -> None:  # pylint: disable=invalid-name
        """``row``'s maker raises ProtocolError for ``value``, before any encoder runs."""
        if row.encoder is None:
            with self.assertRaises(self.ProtocolError):
                row.build(value)
            return
        # NOTE: the encoder's own failure is a ProtocolError too, so it must not be reached.
        module = importlib.import_module(row.encoder)
        with mock.patch.object(module, 'load_pycrate', side_effect=AssertionError('reached the encoder')), \
                self.assertRaises(self.ProtocolError):
            row.build(value)

    def test_rows_name_real_members(self) -> None:
        for row in FIELDS:
            with self.subTest(maker=row.maker, field=row.field):
                enum = _load(row.enum)
                member = getattr(enum, row.member)
                self.assertIsInstance(member, enum)
                self.assertLess(int(member), 1 << row.bits)

    def test_code_past_the_field_is_refused(self) -> None:
        for row in FIELDS:
            for code in (1 << row.bits,) + row.refused:
                with self.subTest(maker=row.maker, field=row.field, code=code):
                    self.assertRefused(row, code)

    def test_bool_is_refused_for_a_wider_field(self) -> None:
        for row in FIELDS:
            if row.bits > 1:
                with self.subTest(maker=row.maker, field=row.field):
                    self.assertRefused(row, True)

    def test_name_is_refused(self) -> None:
        for row in FIELDS:
            with self.subTest(maker=row.maker, field=row.field, name=row.member):
                self.assertRefused(row, row.member)

    def test_member_and_code_build_the_same_octets(self) -> None:
        for row in FIELDS:
            with self.subTest(maker=row.maker, field=row.field):
                if row.encoder is not None and not HAS_PYCRATE:
                    self.skipTest('pycrate not installed')
                member = _member(row.enum, row.member)
                self.assertEqual(row.build(member), row.build(int(member)))


if __name__ == '__main__':
    unittest.main()
