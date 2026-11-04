# -*- coding: utf-8 -*-
"""GitHub issue #2762: an SSL family record rebuilds from its ``to_dict()`` as from its ``info``.

A :obj:`dict` carries no data model. So
:meth:`TLS.from_data <pcapkit.protocols.application.tls.protocol.TLS.from_data>` tells an
SSLv2 record it adopted by the header form SSLv2's data records, and
:meth:`DTLS._make_data <pcapkit.protocols.application.dtls.protocol.DTLS._make_data>` a
unified-header or ``tls12_cid`` record by the fields only that record has; testing the
class of the data instead rebuilds either as a legacy record, which raises. Each case is
a record of an SSLv2, TLS or DTLS version, as wire octets written out by hand, read with
the class that parses it and rebuilt from its ``info`` and its ``to_dict()``, and from
those of the TCP or UDP layer carrying it. Each rebuild gives the octets back, and each
parse is checked against the field values the specification gives the octets.

:mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import struct
import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any, Optional

#: Test tier (#1958): hand-picked round-trip cases, not a sweep.
__tier__ = 'ALL'

#: SSLv2 CLIENT-HELLO body (draft-hickman-netscape-ssl-00): version 3.1, three cipher
#: specs, no session ID, a 16-octet challenge.
CLIENT_HELLO = (b'\x01' + struct.pack('!HHHH', 0x0301, 9, 0, 16)
                + bytes.fromhex('01008000000400002f') + bytes(range(16)))
#: SSLv2 SERVER-HELLO body: no session hit, X.509 certificate, version 2, a 4-octet
#: certificate, one cipher spec and a 16-octet connection ID.
SERVER_HELLO = (b'\x04' + struct.pack('!BBHHHH', 0, 1, 0x0002, 4, 3, 16)
                + bytes.fromhex('deadbeef010080') + bytes(range(16, 32)))
#: SSLv2 CLIENT-MASTER-KEY, whose body this package keeps as octets.
CLIENT_MASTER_KEY = b'\x02' + bytes.fromhex('010080') + bytes(6)

#: TLS 1.3 ServerHello (:rfc:`8446#section-4.1.3`): legacy version 1.2, no session ID,
#: TLS_AES_128_GCM_SHA256, and ``supported_versions`` selecting 1.3.
TLS13_SERVER_HELLO = (b'\x03\x03' + bytes(range(32)) + b'\x00' + b'\x13\x01' + b'\x00'
                      + b'\x00\x06' + b'\x00\x2b\x00\x02\x03\x04')

#: Connection IDs of the records that carry one (:rfc:`9146`, :rfc:`9147`).
CID_12 = b'\xaa\xbb'
CID_13 = b'\x01\x02\x03\x04'


def _sslv2(body: 'bytes', *, three: 'bool' = False, escape: 'bool' = False, padding: 'int' = 0) -> 'bytes':
    """An SSLv2 record of ``body``, its first octet the MSG-TYPE, in the 2- or 3-octet header form."""
    if three:
        return struct.pack('!HB', (0x4000 if escape else 0) | len(body), padding) + body
    return struct.pack('!H', 0x8000 | len(body)) + body


def _tls(content_type: 'int', version: 'int', fragment: 'bytes') -> 'bytes':
    """A TLS record (:rfc:`8446#section-5.1`)."""
    return struct.pack('!BHH', content_type, version, len(fragment)) + fragment


def _dtls(content_type: 'int', version: 'int', epoch: 'int', seq: 'int', fragment: 'bytes',
          cid: 'bytes' = b'') -> 'bytes':
    """A legacy-header DTLS record (:rfc:`9147#section-4`), or a ``tls12_cid`` one with ``cid``."""
    return (struct.pack('!BHH', content_type, version, epoch) + seq.to_bytes(6, 'big') + cid
            + struct.pack('!H', len(fragment)) + fragment)


def _unified(first: 'int', seq: 'bytes', ciphertext: 'bytes', cid: 'bytes' = b'') -> 'bytes':
    """A DTLS 1.3 unified-header record (:rfc:`9147#section-4`), with its length if ``L`` is set."""
    length = struct.pack('!H', len(ciphertext)) if first & 0x04 else b''
    return bytes([first]) + cid + seq + length + ciphertext


def _tcp(payload: 'bytes') -> 'bytes':
    """A 20-octet TCP header, port 50000 to 443, PSH and ACK, plus ``payload``."""
    return struct.pack('!HHIIBBHHH', 50000, 443, 1, 1, 5 << 4, 0x18, 65535, 0, 0) + payload


def _udp(payload: 'bytes') -> 'bytes':
    """An 8-octet UDP header, port 50000 to 5684, plus ``payload``."""
    return struct.pack('!HHHH', 50000, 5684, 8 + len(payload), 0) + payload


#: ``(label, parser, octets, chain, fields, cids)``: the class that reads ``octets``, the
#: chain of aliases the record parses as below its transport layer, field values the
#: specification gives its first record, and the connection IDs its parse needs.
CASES = (
    ('SSLv2 CLIENT-HELLO, 2-octet header', 'TLS', _sslv2(CLIENT_HELLO), 'SSLv2',
     {'header_len': 2, 'two_byte_header': True, 'record_length': 34, 'msg_type': 1}, ()),
    ('SSLv2 CLIENT-HELLO, 3-octet header', 'TLS', _sslv2(CLIENT_HELLO, three=True), 'SSLv2',
     {'header_len': 3, 'two_byte_header': False, 'is_escape': False, 'padding': 0, 'record_length': 34}, ()),
    ('SSLv2 CLIENT-HELLO, 3-octet header, IS-ESCAPE and padding', 'TLS',
     _sslv2(CLIENT_HELLO, three=True, escape=True, padding=5), 'SSLv2',
     {'header_len': 3, 'is_escape': True, 'padding': 5, 'record_length': 34}, ()),
    ('SSLv2 SERVER-HELLO, 2-octet header', 'TLS', _sslv2(SERVER_HELLO), 'SSLv2',
     {'header_len': 2, 'record_length': 34, 'msg_type': 4}, ()),
    ('SSLv2 CLIENT-HELLO then CLIENT-MASTER-KEY', 'TLS', _sslv2(CLIENT_HELLO) + _sslv2(CLIENT_MASTER_KEY),
     'SSLv2:SSLv2', {'header_len': 2, 'msg_type': 1}, ()),
    ('SSLv2 CLIENT-HELLO, read by SSLv2', 'SSLv2', _sslv2(CLIENT_HELLO, three=True), 'SSLv2',
     {'header_len': 3, 'record_length': 34}, ()),
    ('SSLv3 alert', 'TLS', _tls(21, 0x0300, b'\x01\x00'), 'SSLv3', {'content_type': 21, 'version': 0x0300}, ()),
    ('SSLv3 alert, read by SSLv3', 'SSLv3', _tls(21, 0x0300, b'\x01\x00'), 'SSLv3', {'version': 0x0300}, ()),
    ('TLS 1.0 change_cipher_spec', 'TLS', _tls(20, 0x0301, b'\x01'), 'TLS 1.0',
     {'content_type': 20, 'version': 0x0301, 'length': 1}, ()),
    ('TLS 1.1 application_data', 'TLS', _tls(23, 0x0302, b'\xde\xad\xbe\xef'), 'TLS 1.1',
     {'content_type': 23, 'version': 0x0302, 'length': 4}, ()),
    ('TLS 1.3 ServerHello then TLS 1.2 change_cipher_spec', 'TLS',
     _tls(22, 0x0303, b'\x02' + len(TLS13_SERVER_HELLO).to_bytes(3, 'big') + TLS13_SERVER_HELLO)
     + _tls(20, 0x0303, b'\x01'), 'TLS 1.3:TLS 1.2', {'content_type': 22, 'version': 0x0303}, ()),
    ('DTLS 1.0 change_cipher_spec', 'DTLS', _dtls(20, 0xFEFF, 0, 1, b'\x01'), 'DTLS 1.0',
     {'content_type': 20, 'version': 0xFEFF, 'epoch': 0, 'sequence_number': 1}, ()),
    ('DTLS 1.2 application_data then DTLS 1.3 unified header', 'DTLS',
     _dtls(23, 0xFEFD, 1, 2, b'\xde\xad\xbe\xef') + _unified(0x2B, b'\x00\x03', bytes(range(16))),
     'DTLS 1.2:DTLS 1.3', {'content_type': 23, 'version': 0xFEFD, 'epoch': 1, 'sequence_number': 2}, ()),
    ('DTLS 1.3 unified header, 16-bit sequence and length (0x2f)', 'DTLS',
     _unified(0x2F, b'\x12\x34', bytes(range(20))), 'DTLS 1.3',
     {'epoch': 3, 'cid': None, 'sequence_number': 0x1234, 'sequence_long': True, 'length': 20}, ()),
    ('DTLS 1.3 unified header, 16-bit sequence, no length (0x2b)', 'DTLS',
     _unified(0x2B, b'\x00\x07', bytes(range(18))), 'DTLS 1.3',
     {'epoch': 3, 'sequence_number': 7, 'sequence_long': True, 'length': None}, ()),
    ('DTLS 1.3 unified header, 8-bit sequence and length (0x25)', 'DTLS',
     _unified(0x25, b'\x09', bytes(range(16))), 'DTLS 1.3',
     {'epoch': 1, 'sequence_number': 9, 'sequence_long': False, 'length': 16}, ()),
    ('DTLS 1.3 unified header with a connection ID (0x3f)', 'DTLS',
     _unified(0x3F, b'\x00\x01', bytes(range(16)), CID_13), 'DTLS 1.3',
     {'epoch': 3, 'cid': CID_13, 'sequence_number': 1, 'length': 16}, (CID_13,)),
    ('DTLS 1.2 tls12_cid record', 'DTLS', _dtls(25, 0xFEFD, 1, 5, bytes(range(24)), CID_12), 'DTLS 1.2',
     {'content_type': 25, 'version': 0xFEFD, 'epoch': 1, 'sequence_number': 5, 'cid': CID_12}, (CID_12,)),
)


class TestToDictRebuild(unittest.TestCase):
    """Each record rebuilds from ``to_dict()`` exactly as from its ``info``."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @staticmethod
    def _parser(name: 'str') -> 'Any':
        """The class ``name`` names."""
        from pcapkit.protocols.application.dtls.protocol import DTLS
        from pcapkit.protocols.application.sslv2.protocol import SSLv2
        from pcapkit.protocols.application.sslv3.protocol import SSLv3
        from pcapkit.protocols.application.tls.protocol import TLS

        return {'DTLS': DTLS, 'SSLv2': SSLv2, 'SSLv3': SSLv3, 'TLS': TLS}[name]

    @staticmethod
    def _context(cids: 'tuple[bytes, ...]') -> 'Optional[Any]':
        """A context that knows ``cids``, or :data:`None` without one."""
        from pcapkit.protocols.application.dtls.protocol import DTLSContext

        return DTLSContext(*cids) if cids else None

    @staticmethod
    def _chain(proto: 'Any', layers: 'int') -> 'str':
        """The aliases of ``proto`` and up to ``layers`` - 1 layers below it."""
        aliases = []
        for _ in range(layers):
            aliases.append(proto.alias)
            proto = proto.payload
        return ':'.join(aliases)

    def test_the_parse_matches_the_specification(self) -> None:
        for label, parser, octets, chain, fields, cids in CASES:
            with self.subTest(case=label):
                kwargs = {'__context__': self._context(cids)} if cids else {}
                parsed = self._parser(parser)(octets, len(octets), **kwargs)
                self.assertEqual(self._chain(parsed, chain.count(':') + 1), chain)
                for name, value in fields.items():
                    self.assertEqual(parsed.info[name], value, name)

    def test_the_record_rebuilds_from_its_info_and_its_dict(self) -> None:
        for label, parser, octets, chain, _, cids in CASES:
            cls = self._parser(parser)
            kwargs = {'__context__': self._context(cids)} if cids else {}
            info = cls(octets, len(octets), **kwargs).info
            for source, data in (('info', info), ('to_dict()', info.to_dict())):
                with self.subTest(case=label, source=source):
                    rebuilt = cls.from_data(data)
                    self.assertEqual(bytes(rebuilt).hex(), octets.hex())
                    self.assertEqual(self._chain(rebuilt, chain.count(':') + 1), chain)

    def test_the_dict_rebuilds_the_class_the_info_does(self) -> None:
        for label, parser, octets, _, _, cids in CASES:
            with self.subTest(case=label):
                cls = self._parser(parser)
                kwargs = {'__context__': self._context(cids)} if cids else {}
                info = cls(octets, len(octets), **kwargs).info
                self.assertIs(type(cls.from_data(info.to_dict())), type(cls.from_data(info)))

    def test_the_transport_layer_rebuilds_from_its_info_and_its_dict(self) -> None:
        from pcapkit.protocols.transport.tcp.protocol import TCP
        from pcapkit.protocols.transport.udp.protocol import UDP

        for label, parser, octets, chain, _, cids in CASES:
            if parser not in ('TLS', 'DTLS'):
                continue
            cls, wire = (UDP, _udp(octets)) if parser == 'DTLS' else (TCP, _tcp(octets))
            kwargs = {'__context__': self._context(cids)} if cids else {}
            transport = cls(wire, len(wire), **kwargs)
            self.assertEqual(self._chain(transport.payload, chain.count(':') + 1), chain, label)
            for source, data in (('info', transport.info), ('to_dict()', transport.info.to_dict())):
                with self.subTest(case=label, source=source):
                    # NOTE: the rebuilt layer parses its payload again, which a connection ID needs a context for.
                    rebuilt = cls.from_data(data, **kwargs)
                    self.assertEqual(bytes(rebuilt).hex(), wire.hex())
                    self.assertEqual(self._chain(rebuilt.payload, chain.count(':') + 1), chain)


if __name__ == '__main__':
    unittest.main()
