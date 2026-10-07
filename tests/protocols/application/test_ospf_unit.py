# -*- coding: utf-8 -*-
"""Unit tests for :mod:`pcapkit.protocols.application.ospf`.

Relocated from ``tests/protocols/link/test_link_unit.py`` with the module
itself, under :issue:`719`.
"""
from __future__ import annotations

import importlib.util
from ipaddress import ip_address
import types
import unittest
from unittest import mock

from tests._support import purge_modules, reimport_once_per_class

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


class DummyData(dict):
    __getattr__ = dict.__getitem__


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class OSPFUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        reimport_once_per_class(self)

    def tearDown(self) -> None:
        purge_modules(['pcapkit'])

    def test_ospf_index_is_its_transtype_and_make_data_preserves_header(self) -> None:
        from pcapkit.const.ospf.packet import Packet
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.application.ospf import OSPF

        data = DummyData(
            version=2,
            type=Packet.Hello,
            router_id='192.0.2.1',
            area_id='0.0.0.0',
            chksum=b'\x12\x34',
            autype=0,
            auth=b'\x00' * 8,
            __next_type__=None,
        )
        proto = object.__new__(OSPF)

        self.assertEqual(OSPF.__index__(), TransType.OSPFIGP)
        self.assertEqual(OSPF.__index__(), 89)
        self.assertEqual(proto.__length_hint__(), 24)
        values = OSPF._make_data(data)
        self.assertEqual(values['version'], 2)
        self.assertEqual(values['type'], Packet.Hello)
        self.assertEqual(values['router_id'], '192.0.2.1')
        self.assertEqual(values['area_id'], '0.0.0.0')
        self.assertEqual(values['checksum'], b'\x12\x34')
        self.assertEqual(values['auth_data'], b'\x00' * 8)
        self.assertIn('payload', values)

    def test_ospf_properties_read_make_and_auth_helpers(self) -> None:
        from pcapkit.const.ospf.authentication import Authentication
        from pcapkit.const.ospf.packet import Packet
        from pcapkit.protocols.data.application.ospf import \
            CryptographicAuthentication as DataCryptoAuth
        from pcapkit.protocols.application.ospf import OSPF
        from pcapkit.protocols.schema.application.ospf import \
            CryptographicAuthentication as SchemaCryptoAuth
        from pcapkit.protocols.schema.application.ospf import OSPF as SchemaOSPF
        from pcapkit.utilities.exceptions import ProtocolError

        ospf = object.__new__(OSPF)
        # ``name``/``alias`` read ``_version``, not ``_info``: both are needed
        # while ``read`` is still running, before ``_info`` exists.
        ospf._version = 2
        ospf._info = types.SimpleNamespace(version=2, type=Packet.Hello)

        self.assertEqual(ospf.name, 'Open Shortest Path First version 2')
        self.assertEqual(ospf.alias, 'OSPFv2')
        self.assertEqual(ospf.length, 24)
        self.assertEqual(ospf.type, Packet.Hello)

        reader = object.__new__(OSPF)
        reader.__header__ = SchemaOSPF(
            version=2,
            type=Packet.Database_Description,
            length=24,
            router_id='192.0.2.1',
            area_id='0.0.0.0',
            checksum=b'\x12\x34',
            auth_type=Authentication.No_Authentication,
            auth_data=b'\x00' * 8,
            payload=b'',
        )
        reader._decode_next_layer = mock.Mock(side_effect=lambda data, proto, length: data)
        data = reader.read()
        self.assertEqual(data.auth, b'\x00' * 8)
        self.assertEqual(str(data.router_id), '192.0.2.1')
        # No next-protocol field on the wire, so the -1 sentinel is dispatched.
        self.assertEqual(reader._decode_next_layer.call_args.args[1], -1)

        crypto_schema = SchemaCryptoAuth(key_id=1, len=16, seq=99)
        crypto_reader = object.__new__(OSPF)
        crypto_reader.__header__ = SchemaOSPF(
            version=2,
            type=Packet.Link_State_Request,
            length=0,
            router_id='192.0.2.2',
            area_id='0.0.0.1',
            checksum=b'\xab\xcd',
            auth_type=Authentication.Cryptographic_authentication,
            auth_data=crypto_schema,
            payload=b'payload',
        )
        crypto_reader.__cached__ = {}
        crypto_reader._data = b'\x00' * 32
        crypto_reader._decode_next_layer = mock.Mock(side_effect=lambda data, proto, length: data)
        crypto_data = crypto_reader.read()
        self.assertEqual(crypto_data.auth.key_id, 1)
        self.assertEqual(crypto_data.auth.seq, 99)

        maker = object.__new__(OSPF)
        schema = maker.make(
            version=3,
            type=Packet.Link_State_Update,
            router_id='192.0.2.3',
            area_id='0.0.0.2',
            checksum=b'\x56\x78',
            auth_type=Authentication.No_Authentication,
            auth_data=b'\x01' * 8,
            payload=b'abcd',
        )
        self.assertEqual(schema.length, 28)
        self.assertEqual(schema.auth_data, b'\x01' * 8)

        crypto_data_model = DataCryptoAuth(key_id=2, len=20, seq=100)
        crypto_schema_from_data = maker.make(
            auth_type=Authentication.Cryptographic_authentication,
            auth_data=crypto_data_model,
        )
        self.assertEqual(crypto_schema_from_data.auth_data.key_id, 2)
        self.assertIs(maker._make_encrypt_auth(crypto_schema), crypto_schema)
        crypto_schema_from_bytes = maker._make_encrypt_auth(b'\x00\x00\x02\x14' + b'\x00\x00\x00\x64')
        self.assertIsInstance(crypto_schema_from_bytes, SchemaCryptoAuth)
        self.assertEqual((crypto_schema_from_bytes.key_id, crypto_schema_from_bytes.len,
                          crypto_schema_from_bytes.seq), (2, 20, 100))
        self.assertEqual(maker._read_encrypt_auth(crypto_schema).len, 16)
        self.assertEqual(maker._read_id_numbers(b'\xc0\x00\x02\x04'), ip_address('192.0.2.4'))
        self.assertEqual(maker._make_id_numbers('192.0.2.5'), b'\xc0\x00\x02\x05')

        with self.assertRaises(ProtocolError):
            maker.make(auth_type=Authentication.No_Authentication, auth_data=crypto_data_model)
        with self.assertRaises(ProtocolError):
            maker._make_encrypt_auth(object())

    def test_ospf_id_numbers_rejects_a_bool(self) -> None:
        """A :obj:`bool` router/area ID must not be silently packed. See #540.

        Latent rather than live: nothing in this module calls ``_make_id_numbers``
        today -- ``OSPF.make`` builds ``router_id``/``area_id`` from its own
        arguments rather than through this helper -- so only a unit test (this one,
        and the pre-existing one above) reaches it. It is fixed alongside the three
        live sites anyway, so that it does not resurface the moment a future caller
        reaches it. Measured before the fix:

        .. code-block:: text

           OSPF._make_id_numbers(True) -> 00000001  (i.e. 0.0.0.1)
        """
        from pcapkit.protocols.application.ospf import OSPF
        from pcapkit.utilities.exceptions import BaseError, FieldValueError

        proto = object.__new__(OSPF)

        with self.assertRaises(FieldValueError) as context:
            proto._make_id_numbers(True)  # type: ignore[arg-type]
        self.assertIsInstance(context.exception, BaseError)
        self.assertIn('must not be a bool', str(context.exception))
        self.assertIn('int(True)', str(context.exception))

        # a real ID still converts normally
        self.assertEqual(proto._make_id_numbers('192.0.2.6'), b'\xc0\x00\x02\x06')

if __name__ == '__main__':
    unittest.main()
