# -*- coding: utf-8 -*-
"""Unit tests for the OSPF cryptographic-authentication names, :issue:`1090`.

``OSPF_CryptographicAuthentication`` is exported under that spelling, with no
alias for the misspelled ``OSPF_CrytographicAuthentication``, and both OSPF names
sit in the application-layer group of the :mod:`pcapkit.protocols.schema` and
:mod:`pcapkit.protocols.data` :attr:`__all__`.
"""
from __future__ import annotations

import importlib.util
import unittest

from tests._support import purge_modules, reimport_once_per_class

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class OSPFCryptographicAuthenticationUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        reimport_once_per_class(self)

    def tearDown(self) -> None:
        purge_modules(['pcapkit'])

    def _packages(self) -> 'list':
        import pcapkit.protocols.data as data
        import pcapkit.protocols.schema as schema
        return [schema, data]

    def test_correctly_spelled_name_is_exported(self) -> None:
        from pcapkit.protocols.data.application import ospf as data_ospf
        from pcapkit.protocols.schema.application import ospf as schema_ospf

        for package, module in zip(self._packages(), (schema_ospf, data_ospf)):
            with self.subTest(package=package.__name__):
                self.assertIn('OSPF_CryptographicAuthentication', package.__all__)
                self.assertIs(package.OSPF_CryptographicAuthentication,
                              module.CryptographicAuthentication)
                self.assertEqual(module.CryptographicAuthentication.__name__,
                                 'CryptographicAuthentication')

    def test_misspelled_name_is_gone(self) -> None:
        import pcapkit.protocols.data.application as data_application
        import pcapkit.protocols.schema.application as schema_application
        from pcapkit.protocols.data.application import ospf as data_ospf
        from pcapkit.protocols.schema.application import ospf as schema_ospf

        for package in self._packages() + [schema_application, data_application]:
            with self.subTest(package=package.__name__):
                self.assertNotIn('OSPF_CrytographicAuthentication', package.__all__)
                self.assertFalse(hasattr(package, 'OSPF_CrytographicAuthentication'))
        for module in (schema_ospf, data_ospf):
            with self.subTest(module=module.__name__):
                self.assertNotIn('CrytographicAuthentication', module.__all__)
                self.assertFalse(hasattr(module, 'CrytographicAuthentication'))

    def test_ospf_is_grouped_with_the_application_layer(self) -> None:
        # The groups in these __all__ literals are runs of names: OSPF has to sit
        # inside the application run, which FTP opens and HTTPv2 closes, and not
        # between the link-layer names it used to share a run with.
        for package in self._packages():
            names = package.__all__
            application = names[names.index('FTP'):names.index('HTTPv2_ContinuationFrame') + 1]
            with self.subTest(package=package.__name__):
                for name in ('OSPF', 'OSPF_CryptographicAuthentication'):
                    self.assertIn(name, application)
                for name in ('Ethernet', 'VLAN', 'ARP', 'L2TP'):
                    self.assertNotIn(name, application)

    def test_auth_data_selector_picks_the_cryptographic_schema(self) -> None:
        # Moved from tests/protocols/link/test_link_unit.py.
        from pcapkit.const.ospf.authentication import Authentication
        from pcapkit.corekit.fields.misc import SchemaField
        from pcapkit.corekit.fields.strings import BytesField
        from pcapkit.protocols.schema.application.ospf import (CryptographicAuthentication,
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
