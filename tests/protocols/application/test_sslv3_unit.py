# -*- coding: utf-8 -*-
"""Unit tests for :mod:`pcapkit.protocols.application.sslv3`.

#2529: a module holds one protocol class, named after it, so ``SSLv3`` has a
module of its own beside :mod:`pcapkit.protocols.application.tls`. Every case
builds its own octets.

"""
from __future__ import annotations

import importlib
import importlib.util
import unittest

from tests._support import reimport_once_per_class

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: An SSLv3 ``close_notify`` warning alert, :rfc:`6101#section-5.4.2`: content
#: type 21, version ``{3, 0}``, length 2, then level 1 and description 0.
SSLV3_ALERT = bytes.fromhex('15' '0300' '0002' '01' '00')


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class SSLv3ModuleTests(unittest.TestCase):
    """``SSLv3`` lives in its own module and keeps TLS's behaviour."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_sslv3_is_defined_in_its_own_module(self) -> None:
        from pcapkit.protocols.application.sslv3 import SSLv3
        from pcapkit.protocols.application.tls import TLS

        sslv3 = importlib.import_module('pcapkit.protocols.application.sslv3')
        self.assertEqual(SSLv3.__module__, 'pcapkit.protocols.application.sslv3')
        self.assertEqual(sslv3.__all__, ['SSLv3'])
        self.assertEqual(SSLv3.__bases__, (TLS,))

    def test_tls_module_holds_tls_alone(self) -> None:
        """#2529: one protocol class per module."""
        from pcapkit.protocols.protocol import ProtocolBase

        tls = importlib.import_module('pcapkit.protocols.application.tls')
        defined = [name for name, obj in vars(tls).items()
                   if isinstance(obj, type) and issubclass(obj, ProtocolBase)
                   and obj.__module__ == tls.__name__]
        self.assertEqual(tls.__all__, ['TLS'])
        self.assertEqual(defined, ['TLS'])

    def test_id_and_index(self) -> None:
        """``SSLv3`` narrows ``id()`` to itself and inherits the rest of TLS."""
        from pcapkit.protocols.application.sslv3 import SSLv3
        from pcapkit.protocols.application.tls import TLS

        self.assertEqual(SSLv3.id(), ('SSLv3',))
        self.assertEqual(TLS.id(), ('TLS',))
        self.assertEqual([name for name in vars(SSLv3) if not name.startswith('_')], ['id'])
        self.assertNotIn('__index__', vars(SSLv3))

    def test_top_level_names_are_the_new_homes_object(self) -> None:
        import pcapkit
        import pcapkit.all
        import pcapkit.protocols
        import pcapkit.protocols.application
        from pcapkit.protocols.application.sslv3 import SSLv3

        for package in (pcapkit, pcapkit.all, pcapkit.protocols, pcapkit.protocols.application):
            with self.subTest(package=package.__name__):
                self.assertIs(package.SSLv3, SSLv3)
                self.assertIn('SSLv3', package.__all__)
        self.assertIs(pcapkit.protocols.__proto__['SSLV3'], SSLv3)

    def test_parsed_tls_keeps_its_dynamic_sslv3_alias(self) -> None:
        """Dispatch binds TLS alone; legacy version ``0x0300`` reports ``SSLv3``."""
        from pcapkit.protocols.application.sslv3 import SSLv3
        from pcapkit.protocols.application.tls import TLS

        parsed = TLS(SSLV3_ALERT, len(SSLV3_ALERT))
        self.assertIs(type(parsed), TLS)
        self.assertEqual(parsed.alias, 'SSLv3')

        direct = SSLv3(SSLV3_ALERT, len(SSLV3_ALERT))
        self.assertEqual(direct.alias, 'SSLv3')
        self.assertEqual(direct.name, 'Secure Sockets Layer version 3')
        self.assertEqual((direct.info.content_type, direct.info.version, direct.info.length),
                         (21, 0x0300, 2))
        self.assertEqual((direct.info.content.level, direct.info.content.description), (1, 0))

        rebuilt = SSLv3.from_data(direct.info)
        self.assertIs(type(rebuilt), SSLv3)
        self.assertEqual(bytes(rebuilt), SSLV3_ALERT)


if __name__ == '__main__':
    unittest.main()
