# -*- coding: utf-8 -*-
"""Unit tests for the OSPF cryptographic-authentication names, #1090.

``CryptographicAuthentication`` is exported under that spelling from the OSPF
schema and data modules, with no alias for the misspelled
``CrytographicAuthentication``. The ``OSPF_`` aggregate names went with the
``pcapkit.protocols.schema`` and ``pcapkit.protocols.data`` aggregations (#2534).
"""
from __future__ import annotations

import importlib.util
import unittest

from tests._support import reimport_once_per_class

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class OSPFCryptographicAuthenticationUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_correctly_spelled_name_is_exported(self) -> None:
        from pcapkit.protocols.application.ospf import data as data_ospf
        from pcapkit.protocols.application.ospf import schema as schema_ospf

        for module in (schema_ospf, data_ospf):
            with self.subTest(module=module.__name__):
                self.assertIn('CryptographicAuthentication', module.__all__)
                self.assertEqual(module.CryptographicAuthentication.__name__,
                                 'CryptographicAuthentication')

    def test_misspelled_name_is_gone(self) -> None:
        from pcapkit.protocols.application.ospf import data as data_ospf
        from pcapkit.protocols.application.ospf import schema as schema_ospf

        for module in (schema_ospf, data_ospf):
            with self.subTest(module=module.__name__):
                self.assertNotIn('CrytographicAuthentication', module.__all__)
                self.assertFalse(hasattr(module, 'CrytographicAuthentication'))

    def test_auth_data_selector_picks_the_cryptographic_schema(self) -> None:
        from pcapkit.const.ospf.authentication import Authentication
        from pcapkit.corekit.fields.misc import SchemaField
        from pcapkit.corekit.fields.strings import BytesField
        from pcapkit.protocols.application.ospf.schema import (CryptographicAuthentication,
                                                               ospf_auth_data_selector)

        crypto_field = ospf_auth_data_selector({
            'auth_type': Authentication.Cryptographic_authentication,
        })
        self.assertIsInstance(crypto_field, SchemaField)
        self.assertIs(crypto_field.schema, CryptographicAuthentication)

        plain_field = ospf_auth_data_selector({'auth_type': Authentication.No_Authentication})
        self.assertIsInstance(plain_field, BytesField)
        self.assertEqual(plain_field.length, 8)


if __name__ == '__main__':
    unittest.main()
